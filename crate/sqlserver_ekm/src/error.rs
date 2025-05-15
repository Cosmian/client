use cosmian_kms_client::KmsClientError;
use snafu::{Location, prelude::*};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SError {
    /// Error when creating the SQL Server module
    #[snafu(display("Failed to create SQL Server module: {message}"))]
    CreateModule { message: String, location: Location },

    /// Error when initializing the SQL Server module
    #[snafu(display("Failed to initialize SQL Server module: {message}"))]
    InitModule {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    /// Error when registering the SQL Server module
    #[snafu(display("Failed to register SQL Server module: {message}"))]
    RegisterModule { message: String, location: Location },

    /// TOML parsing error
    #[snafu(display("Failed to parse configuration"))]
    ParseConfig {
        source: toml::de::Error,
        #[snafu(implicit)]
        location: Location,
    },

    /// IO Error
    #[snafu(display("IO error: {message}"))]
    Io {
        message: String,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    /// Logging error
    #[snafu(display("Logging error: {message}"))]
    Logging {
        message: String,
        source: tracing_subscriber::util::TryInitError,
        #[snafu(implicit)]
        location: Location,
    },

    /// Error when getting the KMS client
    #[snafu(display("Failed to get KMS client: {message}"))]
    KmsClient {
        message: String,
        source: KmsClientError,
        #[snafu(implicit)]
        location: Location,
    },

    /// Error when recovering inputs from the C API
    #[snafu(display("{message}"))]
    Inputs {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    /// Error when creating a new key
    #[snafu(display("Failed to create key: {message}"))]
    CreateKey {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    /// Error when encrypting data
    #[snafu(display("Failed to encrypt data: {message}"))]
    EncryptData {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    /// Error when decrypting data
    #[snafu(display("Failed to decrypt data: {message}"))]
    DecryptData {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    /// Generic error for unexpected issues
    #[snafu(whatever, display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}
