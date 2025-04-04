use std::sync::{Arc, RwLock};

use cosmian_pkcs11_module::{
    MError, MResult,
    traits::{KeyAlgorithm, SearchOptions, SymmetricKey, backend},
};
use tracing::error;
use zeroize::Zeroizing;

use crate::kms_object::{KmsObject, key_algorithm_from_attributes};

/// A PKCS11 Private Key implementation that may only hold remote
/// references to the actual private key
#[derive(Debug)]
pub(crate) struct Pkcs11SymmetricKey {
    remote_id: String,
    algorithm: KeyAlgorithm,
    key_size: i32,
    /// DER bytes of the private key - those are lazy loaded
    /// when the private key is used
    der_bytes: Arc<RwLock<Zeroizing<Vec<u8>>>>,
}

impl Pkcs11SymmetricKey {
    pub(crate) fn new(remote_id: String, algorithm: KeyAlgorithm, key_size: i32) -> Self {
        Self {
            remote_id,
            der_bytes: Arc::new(RwLock::new(Zeroizing::new(vec![]))),
            algorithm,
            key_size,
        }
    }

    pub(crate) fn try_from_kms_object(kms_object: KmsObject) -> MResult<Self> {
        let der_bytes = Arc::new(RwLock::new(
            kms_object
                .object
                .key_block()
                .map_err(|e| MError::Cryptography(e.to_string()))?
                .key_bytes()
                .map_err(|e| MError::Cryptography(e.to_string()))?,
        ));
        let key_size = kms_object.attributes.cryptographic_length.ok_or_else(|| {
            MError::Cryptography("try_from_kms_object: missing key size".to_owned())
        })?;
        let algorithm = key_algorithm_from_attributes(&kms_object.attributes)?;

        Ok(Self {
            remote_id: kms_object.remote_id,
            algorithm,
            key_size,
            der_bytes,
        })
    }
}

impl SymmetricKey for Pkcs11SymmetricKey {
    fn remote_id(&self) -> String {
        self.remote_id.clone()
    }

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn key_size(&self) -> i32 {
        self.key_size
    }

    fn pkcs8_der_bytes(&self) -> MResult<Zeroizing<Vec<u8>>> {
        let der_bytes = self
            .der_bytes
            .read()
            .map_err(|e| {
                error!("Failed to read DER bytes: {:?}", e);
                MError::Cryptography("Failed to read DER bytes".to_owned())
            })?
            .clone();
        if !der_bytes.is_empty() {
            return Ok(der_bytes);
        }
        let sk =
            backend().find_private_key(SearchOptions::Id(self.remote_id.clone().into_bytes()))?;
        let mut der_bytes = self.der_bytes.write().map_err(|e| {
            error!("Failed to write DER bytes: {:?}", e);
            MError::Cryptography("Failed to write DER bytes".to_owned())
        })?;
        *der_bytes = sk.pkcs8_der_bytes().map_err(|e| {
            error!("Failed to fetch the PKCS8 DER bytes: {:?}", e);
            MError::Cryptography("Failed to fetch the PKCS8 DER bytes".to_owned())
        })?;
        Ok(der_bytes.clone())
    }
}
