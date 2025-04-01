// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.
//
// Original code:
// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    collections::HashMap,
    sync::{self, Arc, atomic::Ordering},
};

use log::trace;
use once_cell::sync::Lazy;
use pkcs11_sys::{
    CK_BYTE_PTR, CK_FLAGS, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG,
    CK_ULONG_PTR,
};
use tracing::debug;

use crate::{
    MError, MResult,
    core::{
        attribute::Attributes,
        mechanism::Mechanism,
        object::{Object, ObjectType},
    },
    objects_store::OBJECTS_STORE,
    traits::{
        EncryptionAlgorithm, KeyAlgorithm, PrivateKey, SearchOptions, SignatureAlgorithm, backend,
    },
};

// "Valid session handles in Cryptoki always have nonzero values."
#[cfg(not(target_os = "windows"))]
static NEXT_SESSION_HANDLE: sync::atomic::AtomicU64 = sync::atomic::AtomicU64::new(1);
#[cfg(target_os = "windows")]
static NEXT_SESSION_HANDLE: sync::atomic::AtomicU32 = sync::atomic::AtomicU32::new(1);

type SessionMap = HashMap<CK_SESSION_HANDLE, Session>;

static SESSIONS: Lazy<sync::Mutex<SessionMap>> = Lazy::new(Default::default);

#[derive(Debug)]
pub(crate) struct SignContext {
    pub algorithm: SignatureAlgorithm,
    pub private_key: Arc<dyn PrivateKey>,
    /// Payload stored for multipart `C_SignUpdate` operations.
    pub payload: Option<Vec<u8>>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct DecryptContext {
    pub remote_object_id: String,
    pub algorithm: EncryptionAlgorithm,
    /// Ciphertext stored for multipart `C_DecryptUpdate` operations.
    pub ciphertext: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct EncryptContext {
    pub remote_object_id: String,
    pub algorithm: EncryptionAlgorithm,
    /// Plaintext stored for multipart `C_EncryptUpdate` operations.
    pub plaintext: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
}

#[derive(Default)]
pub(crate) struct Session {
    flags: CK_FLAGS,
    /// The objects found by C_FindObjectsInit
    /// and that have not yet been read by C_FindObjects
    pub find_objects_ctx: Vec<CK_OBJECT_HANDLE>,
    pub sign_ctx: Option<SignContext>,
    pub decrypt_ctx: Option<DecryptContext>,
    pub encrypt_ctx: Option<EncryptContext>,
}

impl Session {
    pub(crate) fn update_find_objects_context(
        &mut self,
        object: Arc<Object>,
    ) -> MResult<CK_OBJECT_HANDLE> {
        let mut objects_store = OBJECTS_STORE.write().map_err(|e| {
            MError::ArgumentsBad(format!(
                "insert_in_find_context: failed to lock objects store: {e}"
            ))
        })?;
        let handle = objects_store.upsert(object)?;
        trace!("inserted object with id");
        self.find_objects_ctx.push(handle);
        Ok(handle)
    }

    pub(crate) fn load_find_context(&mut self, attributes: Attributes) -> MResult<()> {
        if attributes.is_empty() {
            return Err(MError::ArgumentsBad(
                "load_find_context: empty attributes".to_string(),
            ));
        }
        let search_class = attributes.get_class();

        match search_class {
            Ok(search_class) => self.load_find_context_by_class(attributes, search_class),
            Err(_) => {
                // Refresh store
                let res = backend()
                    .find_all_keys()?
                    .into_iter()
                    .map(|o| self.update_find_objects_context(o))
                    .collect::<MResult<Vec<_>>>()?;

                let label = attributes.get_label()?;
                let find_ctx = OBJECTS_STORE.read().map_err(|e| {
                    MError::ArgumentsBad(format!(
                        "load_find_context: failed to lock find context: {e}"
                    ))
                })?;
                debug!(
                    "load_find_context: loading for label: {label:?} and attributes: \
                     {attributes:?}"
                );
                debug!("load_find_context: display current store: {find_ctx}");
                let (object, handle) = find_ctx.get_using_id(&label).ok_or_else(|| {
                    MError::ArgumentsBad(format!(
                        "load_find_context: failed to get id from label: {label}"
                    ))
                })?;
                debug!(
                    "load_find_context: search by id: {} -> handle: {} -> object: {}:{}",
                    label,
                    handle,
                    object.name(),
                    object.remote_id()
                );
                self.clear_find_objects_ctx();
                self.add_to_find_objects_ctx(handle);
                Ok(())
            }
        }?;

        Ok(())
    }

    pub(crate) fn load_find_context_by_class(
        &mut self,
        attributes: Attributes,
        search_class: CK_OBJECT_CLASS,
    ) -> MResult<()> {
        if attributes.is_empty() {
            return Err(MError::ArgumentsBad(
                "load_find_context_by_class: empty attributes".to_string(),
            ));
        }
        let search_options = SearchOptions::try_from(&attributes)?;
        debug!(
            "load_find_context_by_class: loading for class: {search_class:?} and options: \
             {search_options:?}, attributes: {attributes:?}",
        );
        match search_options {
            SearchOptions::All => {
                self.clear_find_objects_ctx();
                match search_class {
                    pkcs11_sys::CKO_CERTIFICATE => {
                        attributes.ensure_X509_or_none()?;
                        let res = backend()
                            .find_all_certificates()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::Certificate(c)))
                            })
                            .collect::<MResult<Vec<_>>>()?;
                        debug!(
                            "load_find_context_by_class: added {} certificates with handles: {:?}",
                            res.len(),
                            res
                        );
                    }
                    pkcs11_sys::CKO_PUBLIC_KEY => {
                        let res = backend()
                            .find_all_public_keys()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::PublicKey(c)))
                            })
                            .collect::<MResult<Vec<_>>>()?;
                        debug!(
                            "load_find_context_by_class: added {} public keys with handles: {:?}",
                            res.len(),
                            res
                        );
                    }
                    pkcs11_sys::CKO_PRIVATE_KEY => {
                        let res = backend()
                            .find_all_private_keys()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::PrivateKey(c)))
                            })
                            .collect::<MResult<Vec<_>>>()?;
                        debug!(
                            "load_find_context_by_class: added {} private keys with handles: {:?}",
                            res.len(),
                            res
                        );
                    }
                    pkcs11_sys::CKO_DATA => {
                        let res = backend()
                            .find_all_data_objects()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::DataObject(c)))
                            })
                            .collect::<MResult<Vec<_>>>()?;
                        debug!(
                            "load_find_context_by_class: added {} data objects with handles: {:?}",
                            res.len(),
                            res
                        );
                    }
                    o => return Err(MError::Todo(format!("Object not supported: {o}"))),
                }
            }
            SearchOptions::Id(cka_id) => match search_class {
                pkcs11_sys::CKO_CERTIFICATE => {
                    let id = String::from_utf8(cka_id)?;
                    // Find certificates which have this CKA_ID as private key ID
                    let find_ctx = OBJECTS_STORE.read().map_err(|e| {
                        MError::ArgumentsBad(format!(
                            "load_find_context_by_class: failed to lock find context: {e}"
                        ))
                    })?;
                    let certificates = find_ctx.get_using_type(ObjectType::Certificate);
                    for (object, handle) in certificates {
                        match &*object {
                            Object::Certificate(c) => {
                                if c.private_key_id() == id {
                                    debug!(
                                        "load_find_context_by_class: search by id: {} -> handle: \
                                         {} -> certificate: {}:{}",
                                        id,
                                        handle,
                                        object.name(),
                                        object.remote_id()
                                    );
                                    self.clear_find_objects_ctx();
                                    self.add_to_find_objects_ctx(handle);
                                }
                            }
                            //TODO may be we should treat Public Keys the same as Certificates
                            o => {
                                return Err(MError::Todo(format!(
                                    "This should not happen, returning: {:?}",
                                    o.object_type()
                                )))
                            }
                        }
                    }
                }
                _ => {
                    let id = String::from_utf8(cka_id)?;

                    let find_ctx = OBJECTS_STORE.read().map_err(|e| {
                        MError::ArgumentsBad(format!(
                            "load_find_context_by_class: failed to lock find context: {e}",
                        ))
                    })?;
                    let (object, handle) = find_ctx.get_using_id(&id).ok_or_else(|| {
                        MError::ArgumentsBad(format!(
                            "load_find_context_by_class: id {id} not found in store"
                        ))
                    })?;
                    debug!(
                        "load_find_context_by_class: search by id: {} -> handle: {} -> object: \
                         {}:{}",
                        id,
                        handle,
                        object.name(),
                        object.remote_id()
                    );
                    self.clear_find_objects_ctx();
                    self.add_to_find_objects_ctx(handle);
                }
            },
        }
        Ok(())
    }

    /// Clear the unread index
    fn clear_find_objects_ctx(&mut self) {
        self.find_objects_ctx.clear();
    }

    /// Add to the unread index
    fn add_to_find_objects_ctx(&mut self, handle: CK_OBJECT_HANDLE) {
        self.find_objects_ctx.push(handle);
    }

    /// Sign the provided data, or stored payload if data is not provided.
    pub(crate) unsafe fn sign(
        &mut self,
        data: Option<&[u8]>,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    ) -> MResult<()> {
        let sign_ctx = match self.sign_ctx.as_mut() {
            Some(sign_ctx) => sign_ctx,
            None => return Err(MError::OperationNotInitialized(0)),
        };
        let data = data
            .or(sign_ctx.payload.as_deref())
            .ok_or(MError::OperationNotInitialized(0))?;
        let signature = match sign_ctx.private_key.sign(&sign_ctx.algorithm, data) {
            Ok(sig) => sig,
            Err(e) => {
                return Err(MError::ArgumentsBad(format!("signature failed: {e:?}")));
            }
        };
        if !pSignature.is_null() {
            // TODO(bweeks): This will cause a second sign call when this function is
            // called again with an appropriately-sized buffer. Do we really need to
            // sign twice for ECDSA? Consider storing the signature in the ctx for the next
            // call.
            if (unsafe { *pulSignatureLen } as usize) < signature.len() {
                return Err(MError::BufferTooSmall);
            }
            unsafe { std::slice::from_raw_parts_mut(pSignature, signature.len()) }
                .copy_from_slice(&signature);
            self.sign_ctx = None;
        }
        unsafe { *pulSignatureLen = signature.len().try_into().unwrap() };
        Ok(())
    }

    pub(crate) unsafe fn decrypt(
        &mut self,
        ciphertext: Vec<u8>,
        pData: CK_BYTE_PTR,
        pulDataLen: CK_ULONG_PTR,
    ) -> MResult<()> {
        let decrypt_ctx = match self.decrypt_ctx.as_mut() {
            Some(decrypt_ctx) => decrypt_ctx,
            None => return Err(MError::OperationNotInitialized(0)),
        };
        let cleartext = backend().decrypt(
            decrypt_ctx.remote_object_id.clone(),
            decrypt_ctx.algorithm,
            ciphertext,
            decrypt_ctx.iv.clone(),
        )?;
        if !pData.is_null() {
            if (unsafe { *pulDataLen } as usize) < cleartext.len() {
                return Err(MError::BufferTooSmall);
            }
            unsafe { std::slice::from_raw_parts_mut(pData, cleartext.len()) }
                .copy_from_slice(&cleartext);
            unsafe { *pulDataLen = cleartext.len() as CK_ULONG };
            self.decrypt_ctx = None;
        } else {
            unsafe { *pulDataLen = cleartext.len() as CK_ULONG };
        }
        Ok(())
    }

    pub(crate) unsafe fn encrypt(
        &mut self,
        cleartext: Vec<u8>,
        pEncryptedData: CK_BYTE_PTR,
        pulEncryptedDataLen: CK_ULONG_PTR,
    ) -> MResult<()> {
        let encrypt_ctx = match self.encrypt_ctx.as_mut() {
            Some(encrypt_ctx) => encrypt_ctx,
            None => return Err(MError::OperationNotInitialized(0)),
        };
        let ciphertext = backend().encrypt(
            encrypt_ctx.remote_object_id.clone(),
            encrypt_ctx.algorithm,
            cleartext,
            encrypt_ctx.iv.clone(),
        )?;
        unsafe { *pulEncryptedDataLen = ciphertext.len() as CK_ULONG };
        if !pEncryptedData.is_null() {
            if (unsafe { *pulEncryptedDataLen } as usize) < ciphertext.len() {
                return Err(MError::BufferTooSmall);
            }
            unsafe { std::slice::from_raw_parts_mut(pEncryptedData, ciphertext.len()) }
                .copy_from_slice(&ciphertext);
            self.encrypt_ctx = None;
        }
        Ok(())
    }

    pub(crate) unsafe fn generate_key(
        &mut self,
        mechanism: Mechanism,
        attributes: Attributes,
    ) -> MResult<CK_OBJECT_HANDLE> {
        if attributes.is_empty() {
            return Err(MError::ArgumentsBad(
                "generate_key: empty attributes".to_string(),
            ));
        }

        debug!(
            "generate_key: generating key with mechanism: {:?} and attributes: {:?}",
            mechanism, attributes
        );

        let mut objects_store = OBJECTS_STORE.write().map_err(|e| {
            MError::ArgumentsBad(format!("generate_key: failed to lock objects store: {e}"))
        })?;

        let algorithm = KeyAlgorithm::from(mechanism);
        let key_length = attributes.get_value_len()?;
        let sensitive = attributes.get_sensitive()?;
        let label = attributes.get_label()?;

        let object =
            backend().generate_key(algorithm, key_length.try_into()?, sensitive, Some(&label))?;
        let handle = objects_store.upsert(Arc::new(Object::SymmetricKey(object)))?;

        // let handle = objects_store.generate_key()?;
        debug!("generate_key: generated key with handle: {handle}");
        Ok(handle)
    }
}

fn ignore_sessions() -> bool {
    std::env::var("COSMIAN_PKCS11_IGNORE_SESSIONS")
        .unwrap_or("false".to_string())
        .to_lowercase()
        == "true"
}

pub(crate) fn create(flags: CK_FLAGS) -> CK_SESSION_HANDLE {
    if ignore_sessions() {
        {
            let mut session_map = SESSIONS.lock().expect("failed locking the sessions map");
            if session_map.is_empty() {
                session_map.insert(0, Session {
                    flags,
                    ..Default::default()
                });
            }
        }
        0
    } else {
        let handle = NEXT_SESSION_HANDLE.fetch_add(1, Ordering::SeqCst);
        SESSIONS
            .lock()
            .expect("failed locking the sessions map")
            .insert(handle, Session {
                flags,
                ..Default::default()
            });
        handle
    }
}

pub(crate) fn exists(handle: CK_SESSION_HANDLE) -> bool {
    SESSIONS
        .lock()
        .expect("failed locking the sessions map")
        .contains_key(&handle)
}

pub(crate) fn flags(handle: CK_SESSION_HANDLE) -> CK_FLAGS {
    SESSIONS
        .lock()
        .expect("failed locking the sessions map")
        .get(&handle)
        .unwrap()
        .flags
}

pub(crate) fn session<F>(h: CK_SESSION_HANDLE, callback: F) -> MResult<()>
where
    F: FnOnce(&mut Session) -> MResult<()>,
{
    let mut session_map = SESSIONS.lock().expect("failed locking the sessions map");
    let session = &mut session_map
        .get_mut(&h)
        .ok_or(MError::SessionHandleInvalid(h))?;
    debug!("session: {h} found");
    callback(session)
}

pub(crate) fn close(handle: CK_SESSION_HANDLE) -> bool {
    if !ignore_sessions() {
        return SESSIONS
            .lock()
            .expect("failed locking the sessions map")
            .remove(&handle)
            .is_some();
    }
    true
}

pub(crate) fn close_all() {
    SESSIONS
        .lock()
        .expect("failed locking the sessions map")
        .clear();
}
