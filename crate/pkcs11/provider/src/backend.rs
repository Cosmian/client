use std::sync::Arc;

use cosmian_cli::reexport::cosmian_kms_client::KmsClient;
use cosmian_kmip::kmip_2_1::kmip_types::KeyFormatType;
use cosmian_pkcs11_module::{
    MError, MResult,
    core::object::Object,
    traits::{
        Backend, Certificate, DataObject, EncryptionAlgorithm, KeyAlgorithm, PrivateKey, PublicKey,
        SearchOptions, SymmetricKey, Version,
    },
};
use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

use crate::{
    kms_object::{
        get_kms_object, get_kms_object_attributes, get_kms_objects, key_algorithm_from_attributes,
        kms_create, kms_decrypt, kms_encrypt, locate_kms_objects,
    },
    pkcs11_certificate::Pkcs11Certificate,
    pkcs11_data_object::Pkcs11DataObject,
    pkcs11_error,
    pkcs11_private_key::Pkcs11PrivateKey,
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

    fn find_certificate(&self, _query: SearchOptions) -> MResult<Option<Arc<dyn Certificate>>> {
        trace!("find_certificate");
        Ok(None)
    }

    fn find_all_certificates(&self) -> MResult<Vec<Arc<dyn Certificate>>> {
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

    fn find_private_key(&self, query: SearchOptions) -> MResult<Arc<dyn PrivateKey>> {
        trace!("find_private_key: {:?}", query);
        let id = match query {
            SearchOptions::Id(id) => id,
            SearchOptions::All => Err(MError::Backend(Box::new(pkcs11_error!(
                "find_private_key: find must be made using an ID"
            ))))?,
        };
        let id = String::from_utf8(id)?;
        let kms_object = get_kms_object(&self.kms_rest_client, &id, KeyFormatType::PKCS8)?;
        Ok(Arc::new(Pkcs11PrivateKey::try_from_kms_object(kms_object)?))
    }

    fn find_public_key(&self, query: SearchOptions) -> MResult<Arc<dyn PublicKey>> {
        trace!("find_public_key: {:?}", query);
        Err(MError::Backend(Box::new(pkcs11_error!(
            "find_public_key: not implemented"
        ))))
    }

    fn find_all_private_keys(&self) -> MResult<Vec<Arc<dyn PrivateKey>>> {
        trace!("find_all_private_keys");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or_else(|_| COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned());
        let mut private_keys = vec![];
        for id in locate_kms_objects(&self.kms_rest_client, &[
            disk_encryption_tag,
            "_sk".to_owned(),
        ])? {
            let attributes = get_kms_object_attributes(&self.kms_rest_client, &id)?;
            let key_size = attributes.cryptographic_length.ok_or(MError::Cryptography(
                "find_all_private_keys: missing key size".to_owned(),
            ))?;
            let sk: Arc<dyn PrivateKey> = Arc::new(Pkcs11PrivateKey::new(
                id,
                key_algorithm_from_attributes(&attributes)?,
                key_size,
            ));
            private_keys.push(sk);
        }

        Ok(private_keys)
    }

    fn find_all_public_keys(&self) -> MResult<Vec<Arc<dyn PublicKey>>> {
        warn!("find_all_public_keys not implemented");
        Ok(vec![])
    }

    fn find_data_object(&self, query: SearchOptions) -> MResult<Option<Arc<dyn DataObject>>> {
        warn!("find_data_object: {:?}, not implemented", query);
        Ok(None)
    }

    fn find_all_data_objects(&self) -> MResult<Vec<Arc<dyn DataObject>>> {
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

    fn find_all_symmetric_keys(&self) -> MResult<Vec<Arc<dyn SymmetricKey>>> {
        trace!("find_all_symmetric_keys");
        let mut symmetric_keys = vec![];
        for id in locate_kms_objects(&self.kms_rest_client, &[])? {
            let attributes = get_kms_object_attributes(&self.kms_rest_client, &id)?;
            let key_size = attributes.cryptographic_length.ok_or(MError::Cryptography(
                "find_all_symmetric_keys: missing key size".to_owned(),
            ))?;
            let sk: Arc<dyn SymmetricKey> = Arc::new(Pkcs11SymmetricKey::new(
                id,
                key_algorithm_from_attributes(&attributes)?,
                key_size,
            ));
            symmetric_keys.push(sk);
        }

        Ok(symmetric_keys)
    }

    fn find_all_keys(&self) -> MResult<Vec<Arc<Object>>> {
        trace!("find_all_keys");
        let kms_ids = locate_kms_objects(&self.kms_rest_client, &[])?;
        let mut objects = Vec::with_capacity(kms_ids.len());
        for id in kms_ids {
            let attributes = get_kms_object_attributes(&self.kms_rest_client, &id)?;
            let key_size = attributes.cryptographic_length.ok_or(MError::Cryptography(
                "find_all_keys: missing key size".to_owned(),
            ))?;
            let key_algorithm = key_algorithm_from_attributes(&attributes)?;
            let o = match attributes.object_type {
                Some(object_type) => match object_type {
                    cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey => {
                        Object::SymmetricKey(Arc::new(Pkcs11SymmetricKey::new(
                            id.clone(),
                            key_algorithm,
                            key_size,
                        )))
                    }
                    cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::PrivateKey => {
                        Object::PrivateKey(Arc::new(Pkcs11PrivateKey::new(
                            id,
                            key_algorithm,
                            key_size,
                        )))
                    }
                    _ => Err(MError::Backend(Box::new(pkcs11_error!(
                        "find_all_keys: unsupported object type"
                    ))))?,
                },
                None => Err(MError::Backend(Box::new(pkcs11_error!(
                    "find_all_symmetric_keys: missing object type"
                ))))?,
            };
            objects.push(Arc::new(o));
        }

        Ok(objects)
    }

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        key_length: usize,
        sensitive: bool,
        label: Option<&str>,
    ) -> MResult<Arc<dyn SymmetricKey>> {
        trace!("generate_key: {:?}, {:?}", algorithm, label);

        let kms_object = kms_create(
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

    fn encrypt(
        &self,
        remote_object_id: String,
        algorithm: EncryptionAlgorithm,
        cleartext: Vec<u8>,
        iv: Option<Vec<u8>>,
    ) -> MResult<Vec<u8>> {
        debug!(
            "encrypt: {:?}, cleartext length: {}, iv: {iv:?}",
            remote_object_id,
            cleartext.len()
        );
        kms_encrypt(
            &self.kms_rest_client,
            remote_object_id,
            algorithm,
            cleartext,
            iv,
        )
        .map_err(Into::into)
    }

    fn decrypt(
        &self,
        remote_object_id: String,
        algorithm: EncryptionAlgorithm,
        ciphertext: Vec<u8>,
        iv: Option<Vec<u8>>,
    ) -> MResult<Zeroizing<Vec<u8>>> {
        debug!(
            "decrypt: {:?}, cipher text length: {}, iv: {iv:?}",
            remote_object_id,
            ciphertext.len()
        );
        kms_decrypt(
            &self.kms_rest_client,
            remote_object_id,
            algorithm,
            ciphertext,
            iv,
        )
        .map_err(Into::into)
    }
}
