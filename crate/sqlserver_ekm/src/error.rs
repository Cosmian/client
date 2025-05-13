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

    /// Error when getting the KMS client
    #[snafu(display("Failed to get KMS client: {message}"))]
    KmsClient { message: String, location: Location },

    /// Error when creating a new key
    #[snafu(display("Failed to create key: {message}"))]
    CreateKey { message: String, location: Location },

    /// Error when encrypting data
    #[snafu(display("Failed to encrypt data: {message}"))]
    EncryptData { message: String, location: Location },

    /// Error when decrypting data
    #[snafu(display("Failed to decrypt data: {message}"))]
    DecryptData { message: String, location: Location },

    /// Generic error for unexpected issues
    #[snafu(whatever, display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error>, Some)))]
        source: Option<Box<dyn std::error::Error>>,
    },
}
