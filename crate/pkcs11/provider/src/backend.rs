use std::sync::Arc;

use cosmian_cli::reexport::cosmian_kms_client::KmsClient;
use cosmian_kmip::kmip_2_1::{kmip_objects::ObjectType, kmip_types::KeyFormatType};
use cosmian_pkcs11_module::{
    ModuleError, ModuleResult,
    core::object::Object,
    traits::{
        Backend, Certificate, DataObject, DecryptContext, EncryptContext, KeyAlgorithm, PrivateKey,
        PublicKey, SearchOptions, SymmetricKey, Version,
    },
};
use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

use crate::{
    kms_object::{
        get_kms_object, get_kms_object_attributes, get_kms_objects, key_algorithm_from_attributes,
        kms_decrypt, kms_encrypt, kms_import_symmetric_key, locate_kms_objects,
    },
    pkcs11_certificate::Pkcs11Certificate,
    pkcs11_data_object::Pkcs11DataObject,
    pkcs11_error,
    pkcs11_private_key::Pkcs11PrivateKey,
    pkcs11_public_key::Pkcs11PublicKey,
    pkcs11_symmetric_key::Pkcs11SymmetricKey,
};

pub(crate) const COSMIAN_PKCS11_DISK_ENCRYPTION_TAG: &str = "disk-encryption";

pub(crate) struct CliBackend {
    kms_rest_client: KmsClient,
}

impl CliBackend {
    /// Instantiate a new `CliBackend` using the
    pub(crate) const fn instantiate(kms_rest_client: KmsClient) -> Self {
        Self { kms_rest_client }
    }
}

impl Backend for CliBackend {
    fn token_label(&self) -> [u8; 32] {
        *b"Cosmian-KMS                     "
    }

    fn token_manufacturer_id(&self) -> [u8; 32] {
        *b"Cosmian                         "
    }

    fn token_model(&self) -> [u8; 16] {
        *b"software        "
    }

    #[expect(clippy::indexing_slicing)]
    fn token_serial_number(&self) -> [u8; 16] {
        let version = env!("CARGO_PKG_VERSION").as_bytes();
        let len = version.len().min(16);
        let mut sn = [0x20; 16];
        sn[0..len].copy_from_slice(&version[..len]);
        sn
    }

    fn library_description(&self) -> [u8; 32] {
        *b"Cosmian KMS PKCS#11 provider    "
    }

    fn library_version(&self) -> Version {
        let version = env!("CARGO_PKG_VERSION");
        let mut split = version.split('.');
        let major = split.next().unwrap_or("0").parse::<u8>().unwrap_or(0);
        let minor = split.next().unwrap_or("0").parse::<u8>().unwrap_or(0);
        Version { major, minor }
    }

    fn find_certificate(
        &self,
        _query: SearchOptions,
    ) -> ModuleResult<Option<Arc<dyn Certificate>>> {
        trace!("find_certificate");
        Ok(None)
    }

    fn find_all_certificates(&self) -> ModuleResult<Vec<Arc<dyn Certificate>>> {
        trace!("find_all_certificates");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or_else(|_| COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned());
        let kms_objects = get_kms_objects(
            &self.kms_rest_client,
            &[disk_encryption_tag, "_cert".to_owned()],
            Some(KeyFormatType::X509),
        )?;
        let mut result = Vec::with_capacity(kms_objects.len());
        for dao in kms_objects {
            let data_object: Arc<dyn Certificate> = Arc::new(Pkcs11Certificate::try_from(dao)?);
            result.push(data_object);
        }
        Ok(result)
    }

    fn find_private_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn PrivateKey>> {
        trace!("find_private_key: {:?}", query);
        let id = match query {
            SearchOptions::Id(id) => id,
            SearchOptions::All => {
                return Err(ModuleError::Backend(Box::new(pkcs11_error!(
                    "find_private_key: find must be made using an ID"
                ))))
            }
        };
        let id = String::from_utf8(id)?;
        let kms_object = get_kms_object(&self.kms_rest_client, &id, KeyFormatType::PKCS8)?;
        Ok(Arc::new(Pkcs11PrivateKey::try_from_kms_object(kms_object)?))
    }

    fn find_public_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn PublicKey>> {
        trace!("find_public_key: {:?}", query);
        Err(ModuleError::Backend(Box::new(pkcs11_error!(
            "find_public_key: not implemented"
        ))))
    }

    fn find_all_private_keys(&self) -> ModuleResult<Vec<Arc<dyn PrivateKey>>> {
        trace!("find_all_private_keys");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or_else(|_| COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned());
        let mut private_keys = vec![];
        let ids = locate_kms_objects(&self.kms_rest_client, &[
            disk_encryption_tag,
            "_sk".to_owned(),
        ])?;
        for id in ids {
            let attributes = get_kms_object_attributes(&self.kms_rest_client, &id)?;
            let key_size = usize::try_from(attributes.cryptographic_length.ok_or(
                ModuleError::Cryptography("find_all_private_keys: missing key size".to_owned()),
            )?)?;
            let sk: Arc<dyn PrivateKey> = Arc::new(Pkcs11PrivateKey::new(
                id,
                key_algorithm_from_attributes(&attributes)?,
                key_size,
            ));
            private_keys.push(sk);
        }

        Ok(private_keys)
    }

    fn find_all_public_keys(&self) -> ModuleResult<Vec<Arc<dyn PublicKey>>> {
        warn!("find_all_public_keys not implemented");
        Ok(vec![])
    }

    fn find_data_object(&self, query: SearchOptions) -> ModuleResult<Option<Arc<dyn DataObject>>> {
        warn!("find_data_object: {:?}, not implemented", query);
        Ok(None)
    }

    fn find_all_data_objects(&self) -> ModuleResult<Vec<Arc<dyn DataObject>>> {
        trace!("find_all_data_objects");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or_else(|_| COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned());
        let kms_objects = get_kms_objects(
            &self.kms_rest_client,
            &[disk_encryption_tag, "_kk".to_owned()],
            Some(KeyFormatType::Raw),
        )?;
        let mut result = Vec::with_capacity(kms_objects.len());
        for dao in kms_objects {
            let data_object: Arc<dyn DataObject> = Arc::new(Pkcs11DataObject::try_from(dao)?);
            result.push(data_object);
        }
        Ok(result)
    }

    fn find_symmetric_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn SymmetricKey>> {
        trace!("find_symmetric_key: {:?}", query);
        let id = match query {
            SearchOptions::Id(id) => id,
            SearchOptions::All => {
                return Err(ModuleError::Backend(Box::new(pkcs11_error!(
                    "find_symmetric_key: find must be made using an ID"
                ))))
            }
        };
        let id = String::from_utf8(id)?;
        let kms_object = get_kms_object(
            &self.kms_rest_client,
            &id,
            KeyFormatType::TransparentSymmetricKey,
        )?;
        Ok(Arc::new(Pkcs11SymmetricKey::try_from_kms_object(
            kms_object,
        )?))
    }

    fn find_all_symmetric_keys(&self) -> ModuleResult<Vec<Arc<dyn SymmetricKey>>> {
        trace!("find_all_symmetric_keys");
        let mut symmetric_keys = vec![];
        let kms_ids = locate_kms_objects(&self.kms_rest_client, &[])?;
        for id in kms_ids {
            let attributes = get_kms_object_attributes(&self.kms_rest_client, &id)?;
            let key_size = usize::try_from(attributes.cryptographic_length.ok_or(
                ModuleError::Cryptography("find_all_symmetric_keys: missing key size".to_owned()),
            )?)?;
            let sk: Arc<dyn SymmetricKey> = Arc::new(Pkcs11SymmetricKey::new(
                id,
                key_algorithm_from_attributes(&attributes)?,
                key_size,
            ));
            symmetric_keys.push(sk);
        }

        Ok(symmetric_keys)
    }

    #[expect(clippy::cognitive_complexity)]
    fn find_all_keys(&self) -> ModuleResult<Vec<Arc<Object>>> {
        trace!("find_all_keys");
        let kms_ids = locate_kms_objects(&self.kms_rest_client, &[])?;
        let mut objects = Vec::with_capacity(kms_ids.len());
        for id in kms_ids {
            let attributes = get_kms_object_attributes(&self.kms_rest_client, &id)?;
            let Some(key_size) = attributes.cryptographic_length else {
                warn!("find_all_keys: missing key size, skipping {id}");
                continue;
            };
            let key_size = usize::try_from(key_size)?;
            let key_algorithm = key_algorithm_from_attributes(&attributes)?;
            let object =
                if let Some(object_type) = attributes.object_type {
                    match object_type {
                        ObjectType::SymmetricKey => Object::SymmetricKey(Arc::new(
                            Pkcs11SymmetricKey::new(id, key_algorithm, key_size),
                        )),
                        ObjectType::PrivateKey => Object::PrivateKey(Arc::new(
                            Pkcs11PrivateKey::new(id, key_algorithm, key_size),
                        )),
                        ObjectType::PublicKey => {
                            Object::PublicKey(Arc::new(Pkcs11PublicKey::new(id, key_algorithm)))
                        }
                        other => {
                            warn!("find_all_keys: unsupported object type: {other}, skipping {id}");
                            continue;
                        }
                    }
                } else {
                    warn!("find_all_keys: missing object type: skipping {id}");
                    continue;
                };
            objects.push(Arc::new(object));
        }

        trace!("find_all_keys: found {} keys", objects.len());
        Ok(objects)
    }

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        key_length: usize,
        sensitive: bool,
        label: Option<&str>,
    ) -> ModuleResult<Arc<dyn SymmetricKey>> {
        trace!("generate_key: {algorithm:?}-{key_length}, {label:?}");

        if algorithm != KeyAlgorithm::Aes256 {
            return Err(ModuleError::Backend(Box::new(pkcs11_error!(
                "generate_key: only support AES-256 algorithm"
            ))));
        }

        let kms_object = kms_import_symmetric_key(
            &self.kms_rest_client,
            algorithm,
            key_length,
            sensitive,
            label,
        )?;
        Ok(Arc::new(Pkcs11SymmetricKey::try_from_kms_object(
            kms_object,
        )?))
    }

    fn encrypt(&self, ctx: &EncryptContext, cleartext: Vec<u8>) -> ModuleResult<Vec<u8>> {
        debug!("encrypt: ctx: {ctx:?}");
        kms_encrypt(&self.kms_rest_client, ctx, cleartext).map_err(Into::into)
    }

    fn decrypt(
        &self,
        ctx: &DecryptContext,
        ciphertext: Vec<u8>,
    ) -> ModuleResult<Zeroizing<Vec<u8>>> {
        debug!("decrypt: decrypt_ctx: {ctx:?}");
        kms_decrypt(&self.kms_rest_client, ctx, ciphertext).map_err(Into::into)
    }
}
