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

use pkcs11_sys::{
    CK_BYTE_PTR, CK_FLAGS, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG,
    CK_ULONG_PTR,
};
use tracing::debug;

use crate::{
    MResultHelper, ModuleError, ModuleResult,
    core::{
        attribute::Attributes,
        mechanism::Mechanism,
        object::{Object, ObjectType},
    },
    objects_store::OBJECTS_STORE,
    traits::{DecryptContext, EncryptContext, KeyAlgorithm, SearchOptions, SignContext, backend},
};

// "Valid session handles in Cryptoki always have nonzero values."
#[cfg(not(target_os = "windows"))]
static NEXT_SESSION_HANDLE: sync::atomic::AtomicU64 = sync::atomic::AtomicU64::new(1);
#[cfg(target_os = "windows")]
static NEXT_SESSION_HANDLE: sync::atomic::AtomicU32 = sync::atomic::AtomicU32::new(1);

type SessionMap = HashMap<CK_SESSION_HANDLE, Session>;

static SESSIONS: std::sync::LazyLock<sync::Mutex<SessionMap>> =
    std::sync::LazyLock::new(Default::default);

#[derive(Default)]
pub(crate) struct Session {
    flags: CK_FLAGS,
    /// The objects found by `C_FindObjectsInit`
    /// and that have not yet been read by `C_FindObjects`
    pub find_objects_ctx: Vec<CK_OBJECT_HANDLE>,
    pub sign_ctx: Option<SignContext>,
    pub decrypt_ctx: Option<DecryptContext>,
    pub encrypt_ctx: Option<EncryptContext>,
}

impl Session {
    pub(crate) fn update_find_objects_context(
        &mut self,
        object: Arc<Object>,
    ) -> ModuleResult<CK_OBJECT_HANDLE> {
        let mut objects_store = OBJECTS_STORE.write()?;
        let handle = objects_store.upsert(object);
        self.find_objects_ctx.push(handle);
        Ok(handle)
    }

    pub(crate) fn load_find_context(&mut self, attributes: &Attributes) -> ModuleResult<()> {
        if attributes.is_empty() {
            return Err(ModuleError::BadArguments(
                "load_find_context: empty attributes".to_owned(),
            ));
        }
        // Find all keys, all certificates
        for object in backend().find_all_keys()? {
            self.update_find_objects_context(object)?;
        }

        let search_class = attributes.get_class();
        if let Ok(search_class) = search_class {
            self.load_find_context_by_class(attributes, search_class)
        } else {
            let label = attributes.get_label()?;
            let find_ctx = OBJECTS_STORE.read()?;
            debug!(
                "load_find_context: loading for label: {label:?} and attributes: {attributes:?}"
            );
            debug!("load_find_context: display current store: {find_ctx}");
            let (object, handle) = find_ctx.get_using_id(&label).ok_or_else(|| {
                ModuleError::BadArguments(format!(
                    "load_find_context: failed to get id from label: {label}"
                ))
            })?;
            debug!(
                "load_find_context: search by id: {label} -> handle: {} -> object: {}: {}",
                handle,
                object.name(),
                object.remote_id()
            );
            self.clear_find_objects_ctx();
            self.add_to_find_objects_ctx(handle);
            Ok(())
        }?;

        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    pub(crate) fn load_find_context_by_class(
        &mut self,
        attributes: &Attributes,
        search_class: CK_OBJECT_CLASS,
    ) -> ModuleResult<()> {
        if attributes.is_empty() {
            return Err(ModuleError::BadArguments(
                "load_find_context_by_class: empty attributes".to_owned(),
            ));
        }
        let search_options = SearchOptions::try_from(attributes)?;
        debug!(
            "load_find_context_by_class: loading for class: {search_class:?} and options: \
             {search_options:?}, attributes: {attributes:?}",
        );
        match search_options {
            SearchOptions::All => {
                self.clear_find_objects_ctx();
                let res = match search_class {
                    pkcs11_sys::CKO_CERTIFICATE => {
                        attributes.ensure_X509_or_none()?;
                        backend()
                            .find_all_certificates()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::Certificate(c)))
                            })
                            .collect::<ModuleResult<Vec<_>>>()?
                    }
                    pkcs11_sys::CKO_PUBLIC_KEY => backend()
                        .find_all_public_keys()?
                        .into_iter()
                        .map(|c| self.update_find_objects_context(Arc::new(Object::PublicKey(c))))
                        .collect::<ModuleResult<Vec<_>>>()?,
                    pkcs11_sys::CKO_PRIVATE_KEY => backend()
                        .find_all_private_keys()?
                        .into_iter()
                        .map(|c| self.update_find_objects_context(Arc::new(Object::PrivateKey(c))))
                        .collect::<ModuleResult<Vec<_>>>()?,
                    pkcs11_sys::CKO_SECRET_KEY => backend()
                        .find_all_symmetric_keys()?
                        .into_iter()
                        .map(|c| {
                            self.update_find_objects_context(Arc::new(Object::SymmetricKey(c)))
                        })
                        .collect::<ModuleResult<Vec<_>>>()?,
                    pkcs11_sys::CKO_DATA => backend()
                        .find_all_data_objects()?
                        .into_iter()
                        .map(|c| self.update_find_objects_context(Arc::new(Object::DataObject(c))))
                        .collect::<ModuleResult<Vec<_>>>()?,
                    o => return Err(ModuleError::Todo(format!("Object not supported: {o}"))),
                };
                debug!(
                    "load_find_context_by_class: added {} objects with handles: {:?}",
                    res.len(),
                    res
                );
            }

            SearchOptions::Id(cka_id) => {
                if search_class == pkcs11_sys::CKO_CERTIFICATE {
                    let id = String::from_utf8(cka_id)?;
                    // Find certificates which have this CKA_ID as private key ID
                    let find_ctx = OBJECTS_STORE.read()?;
                    let certificates = find_ctx.get_using_type(&ObjectType::Certificate);
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
                                return Err(ModuleError::Todo(format!(
                                    "This should not happen, returning: {:?}",
                                    o.object_type()
                                )))
                            }
                        }
                    }
                } else {
                    let id = String::from_utf8(cka_id)?;

                    let find_ctx = OBJECTS_STORE.read()?;
                    let (object, handle) = find_ctx.get_using_id(&id).ok_or_else(|| {
                        ModuleError::BadArguments(format!(
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
            }
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
    ) -> ModuleResult<()> {
        let Some(sign_ctx) = self.sign_ctx.as_mut() else {
            return Err(ModuleError::OperationNotInitialized(0))
        };
        let data = data
            .or(sign_ctx.payload.as_deref())
            .ok_or(ModuleError::OperationNotInitialized(0))?;
        let signature = match sign_ctx.private_key.sign(&sign_ctx.algorithm, data) {
            Ok(sig) => sig,
            Err(e) => {
                return Err(ModuleError::BadArguments(format!(
                    "signature failed: {e:?}"
                )));
            }
        };
        if !pSignature.is_null() {
            // TODO(bweeks): This will cause a second sign call when this function is
            // called again with an appropriately-sized buffer. Do we really need to
            // sign twice for ECDSA? Consider storing the signature in the ctx for the next
            // call.
            if (unsafe { usize::try_from(*pulSignatureLen)? }) < signature.len() {
                return Err(ModuleError::BufferTooSmall);
            }
            unsafe { std::slice::from_raw_parts_mut(pSignature, signature.len()) }
                .copy_from_slice(&signature);
            self.sign_ctx = None;
        }
        unsafe {
            *pulSignatureLen = signature.len().try_into()?;
        }
        Ok(())
    }

    pub(crate) unsafe fn decrypt(
        &mut self,
        ciphertext: Vec<u8>,
        pData: CK_BYTE_PTR,
        pulDataLen: CK_ULONG_PTR,
    ) -> ModuleResult<()> {
        let decrypt_ctx = self
            .decrypt_ctx
            .as_ref()
            .ok_or_else(|| ModuleError::OperationNotInitialized(0))?;
        let cleartext = backend().decrypt(decrypt_ctx, ciphertext)?;
        unsafe {
            if pData.is_null() {
                *pulDataLen = cleartext.len() as CK_ULONG;
            } else {
                if (usize::try_from(*pulDataLen)?) < cleartext.len() {
                    return Err(ModuleError::BufferTooSmall);
                }
                std::slice::from_raw_parts_mut(pData, cleartext.len()).copy_from_slice(&cleartext);
                *pulDataLen = cleartext.len() as CK_ULONG;
                self.decrypt_ctx = None;
            }
        }
        Ok(())
    }

    pub(crate) unsafe fn encrypt(
        &mut self,
        cleartext: Vec<u8>,
        pEncryptedData: CK_BYTE_PTR,
        pulEncryptedDataLen: CK_ULONG_PTR,
    ) -> ModuleResult<()> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_ref()
            .ok_or_else(|| ModuleError::OperationNotInitialized(0))?;
        let ciphertext = backend().encrypt(encrypt_ctx, cleartext)?;
        unsafe {
            *pulEncryptedDataLen = ciphertext.len() as CK_ULONG;
            if !pEncryptedData.is_null() {
                if (usize::try_from(*pulEncryptedDataLen)?) < ciphertext.len() {
                    return Err(ModuleError::BufferTooSmall);
                }
                std::slice::from_raw_parts_mut(pEncryptedData, ciphertext.len())
                    .copy_from_slice(&ciphertext);
                self.encrypt_ctx = None;
            }
        }
        Ok(())
    }

    pub(crate) unsafe fn generate_key(
        mechanism: Mechanism,
        attributes: &Attributes,
    ) -> ModuleResult<CK_OBJECT_HANDLE> {
        if attributes.is_empty() {
            return Err(ModuleError::BadArguments(
                "generate_key: empty attributes".to_owned(),
            ));
        }

        debug!(
            "generate_key: generating key with mechanism: {:?} and attributes: {:?}",
            mechanism, attributes
        );

        let mut objects_store = OBJECTS_STORE.write()?;

        let key_length = attributes.get_value_len()?;
        let sensitive = attributes.get_sensitive()?;
        let label = attributes.get_label()?;

        let object = backend().generate_key(
            KeyAlgorithm::try_from(mechanism)?,
            key_length.try_into()?,
            sensitive,
            Some(&label),
        )?;
        let handle = objects_store.upsert(Arc::new(Object::SymmetricKey(object)));

        debug!("generate_key: generated key with handle: {handle}");
        Ok(handle)
    }
}

fn ignore_sessions() -> bool {
    std::env::var("COSMIAN_PKCS11_IGNORE_SESSIONS")
        .unwrap_or("false".to_owned())
        .to_lowercase()
        == "true"
}

#[expect(clippy::expect_used)]
pub(crate) fn create(flags: CK_FLAGS) -> CK_SESSION_HANDLE {
    if ignore_sessions() {
        {
            let mut session_map = SESSIONS.lock().expect("failed locking the sessions map");
            if session_map.is_empty() {
                session_map.insert(
                    0,
                    Session {
                        flags,
                        ..Default::default()
                    },
                );
            }
        }
        0
    } else {
        let handle = NEXT_SESSION_HANDLE.fetch_add(1, Ordering::SeqCst);
        SESSIONS
            .lock()
            .expect("failed locking the sessions map")
            .insert(
                handle,
                Session {
                    flags,
                    ..Default::default()
                },
            );
        handle
    }
}

pub(crate) fn exists(handle: CK_SESSION_HANDLE) -> ModuleResult<bool> {
    Ok(SESSIONS
        .lock()
        .context("failed locking the sessions map")?
        .contains_key(&handle))
}

pub(crate) fn flags(handle: CK_SESSION_HANDLE) -> ModuleResult<CK_FLAGS> {
    Ok(SESSIONS
        .lock()
        .context("failed locking the sessions map")?
        .get(&handle)
        .ok_or_else(|| ModuleError::SessionHandleInvalid(handle))?
        .flags)
}

pub(crate) fn session<F>(h: CK_SESSION_HANDLE, callback: F) -> ModuleResult<()>
where
    F: FnOnce(&mut Session) -> ModuleResult<()>,
{
    let mut session_map = SESSIONS.lock().context("failed locking the sessions map")?;
    let session = session_map
        .get_mut(&h)
        .ok_or(ModuleError::SessionHandleInvalid(h))?;
    debug!("session: {h} found");
    callback(session)
}

pub(crate) fn close(handle: CK_SESSION_HANDLE) -> ModuleResult<bool> {
    if !ignore_sessions() {
        return Ok(SESSIONS
            .lock()
            .context("failed locking the sessions map")?
            .remove(&handle)
            .is_some());
    }
    Ok(true)
}

pub(crate) fn close_all() -> ModuleResult<()> {
    SESSIONS
        .lock()
        .context("failed locking the sessions map")?
        .clear();
    Ok(())
}
