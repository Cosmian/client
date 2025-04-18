use std::sync::{Arc, RwLock};

use once_cell::sync::Lazy;
use zeroize::Zeroizing;

use super::SymmetricKey;
use crate::{
    ModuleResult,
    core::object::Object,
    traits::{
        Certificate, DataObject, EncryptionAlgorithm, KeyAlgorithm, PrivateKey, PublicKey,
        SearchOptions, Version,
    },
};

//  The Backend is first staged so it can be stored in a Box<dyn Backend>. This
//  allows the Backend to be reference with `&'static`.
static STAGED_BACKEND: RwLock<Option<Box<dyn Backend>>> = RwLock::new(None);
#[expect(clippy::expect_used)]
static BACKEND: Lazy<Box<dyn Backend>> = Lazy::new(|| {
    STAGED_BACKEND
        .write()
        .expect("Failed to acquire write lock")
        .take()
        .expect("Backend not initialized")
});

/// Stores a backend to later be returned by all calls `crate::backend()`.
#[expect(clippy::expect_used)]
pub fn register_backend(backend: Box<dyn Backend>) {
    *STAGED_BACKEND
        .write()
        .expect("Failed to acquire write lock") = Some(backend);
}

pub fn backend() -> &'static dyn Backend {
    BACKEND.as_ref()
}

pub trait Backend: Send + Sync {
    /// The token label
    /// e.g.
    /// `*b"Foo software token              "`
    fn token_label(&self) -> [u8; 32];
    /// The id of the manufacturer of the token
    fn token_manufacturer_id(&self) -> [u8; 32];
    /// The model of the token
    fn token_model(&self) -> [u8; 16];
    /// The serial number of the token
    fn token_serial_number(&self) -> [u8; 16];
    /// The description of this library
    fn library_description(&self) -> [u8; 32];
    /// The version of this library
    fn library_version(&self) -> Version;

    fn find_certificate(&self, query: SearchOptions) -> ModuleResult<Option<Arc<dyn Certificate>>>;
    fn find_all_certificates(&self) -> ModuleResult<Vec<Arc<dyn Certificate>>>;
    fn find_private_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn PrivateKey>>;
    fn find_public_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn PublicKey>>;
    fn find_all_private_keys(&self) -> ModuleResult<Vec<Arc<dyn PrivateKey>>>;
    fn find_all_public_keys(&self) -> ModuleResult<Vec<Arc<dyn PublicKey>>>;
    fn find_all_symmetric_keys(&self) -> ModuleResult<Vec<Arc<dyn SymmetricKey>>>;
    fn find_data_object(&self, query: SearchOptions) -> ModuleResult<Option<Arc<dyn DataObject>>>;
    fn find_all_data_objects(&self) -> ModuleResult<Vec<Arc<dyn DataObject>>>;
    fn find_all_keys(&self) -> ModuleResult<Vec<Arc<Object>>>;

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        key_length: usize,
        sensitive: bool,
        label: Option<&str>,
    ) -> ModuleResult<Arc<dyn SymmetricKey>>;

    fn encrypt(
        &self,
        remote_object_id: String,
        algorithm: EncryptionAlgorithm,
        cleartext: Vec<u8>,
        iv: Option<Vec<u8>>,
    ) -> ModuleResult<Vec<u8>>;

    fn decrypt(
        &self,
        remote_object_id: String,
        algorithm: EncryptionAlgorithm,
        ciphertext: Vec<u8>,
        iv: Option<Vec<u8>>,
    ) -> ModuleResult<Zeroizing<Vec<u8>>>;
}
