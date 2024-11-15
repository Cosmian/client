use std::{array::TryFromSliceError, num::TryFromIntError, str::Utf8Error};

#[cfg(test)]
use assert_cmd::cargo::CargoError;
use cloudproof::reexport::crypto_core::CryptoCoreError;
use cloudproof_findex::{db_interfaces::DbInterfaceError, reexport::cosmian_findex};
use cosmian_config::ConfigError;
use hex::FromHexError;
use pem::PemError;
use thiserror::Error;

pub mod result;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug)]
pub enum CosmianError {
    // When a user requests an endpoint which does not exist
    #[error("Not Supported route: {0}")]
    RouteNotFound(String),

    // When a user requests something not supported by the server
    #[error("Not Supported: {0}")]
    NotSupported(String),

    // When a user requests something which is a non-sense
    #[error("Inconsistent operation: {0}")]
    InconsistentOperation(String),

    // When a user requests an id which does not exist
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    // Missing arguments in the request
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    // Any errors related to a bad behavior of the server but not related to the user input
    #[error("Server error: {0}")]
    ServerError(String),

    // Any actions of the user which is not allowed
    #[error("Access denied: {0}")]
    Unauthorized(String),

    // A cryptographic error
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),

    // Conversion errors
    #[error("Conversion error: {0}")]
    Conversion(String),

    // Invalid configuration file
    #[error("{0}")]
    Configuration(String),

    // Other errors
    #[error("invalid options: {0}")]
    UserError(String),

    // Other errors
    #[error("{0}")]
    Default(String),

    // Url parsing errors
    #[error(transparent)]
    UrlParsing(#[from] url::ParseError),

    // When an error occurs fetching Gmail API
    #[error("Error interacting with Gmail API: {0}")]
    GmailApiError(String),

    #[error(transparent)]
    KmsClientError(#[from] cosmian_kms_client::KmsClientError),

    #[error(transparent)]
    KmsCliError(#[from] cosmian_kms_cli::error::CliError),

    #[error(transparent)]
    FindexClientError(#[from] cosmian_findex_client::FindexClientError),

    #[error(transparent)]
    FindexCliError(#[from] cosmian_findex_cli::error::CliError),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    CsvError(#[from] csv::Error),
}

// todo(manu): remove all unnecessary conversions

impl From<der::Error> for CosmianError {
    fn from(e: der::Error) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<cloudproof::reexport::crypto_core::reexport::pkcs8::Error> for CosmianError {
    fn from(e: cloudproof::reexport::crypto_core::reexport::pkcs8::Error) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<cloudproof::reexport::cover_crypt::Error> for CosmianError {
    fn from(e: cloudproof::reexport::cover_crypt::Error) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<TryFromSliceError> for CosmianError {
    fn from(e: TryFromSliceError) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<serde_json::Error> for CosmianError {
    fn from(e: serde_json::Error) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<Utf8Error> for CosmianError {
    fn from(e: Utf8Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for CosmianError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<TryFromIntError> for CosmianError {
    fn from(e: TryFromIntError) -> Self {
        Self::Default(format!("{e}: Details: {e:?}"))
    }
}

impl From<cosmian_findex::Error<DbInterfaceError>> for CosmianError {
    fn from(e: cosmian_findex::Error<DbInterfaceError>) -> Self {
        Self::Cryptographic(e.to_string())
    }
}

impl From<DbInterfaceError> for CosmianError {
    fn from(e: DbInterfaceError) -> Self {
        Self::Cryptographic(e.to_string())
    }
}

impl From<uuid::Error> for CosmianError {
    fn from(e: uuid::Error) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<CryptoCoreError> for CosmianError {
    fn from(e: CryptoCoreError) -> Self {
        Self::Cryptographic(e.to_string())
    }
}

impl From<ConfigError> for CosmianError {
    fn from(e: ConfigError) -> Self {
        Self::Configuration(e.to_string())
    }
}

#[cfg(test)]
impl From<CargoError> for CosmianError {
    fn from(e: CargoError) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<base64::DecodeError> for CosmianError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<FromHexError> for CosmianError {
    fn from(e: FromHexError) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<PemError> for CosmianError {
    fn from(e: PemError) -> Self {
        Self::Conversion(format!("PEM error: {e}"))
    }
}

impl From<std::fmt::Error> for CosmianError {
    fn from(e: std::fmt::Error) -> Self {
        Self::Default(e.to_string())
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! cli_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::cli_error!($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::cli_error!($fmt, $($arg)*));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! cli_error {
    ($msg:literal) => {
        $crate::error::CosmianError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::CosmianError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::CosmianError::Default(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! cli_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::cli_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::cli_error!($fmt, $($arg)*))
    };
}

#[cfg(test)]
mod tests {

    use crate::error::result::CosmianResult;

    #[test]
    fn test_cli_error_interpolation() {
        let var = 42;
        let err = cli_error!("interpolate {var}");
        assert_eq!("interpolate 42", err.to_string());

        let err = bail();
        assert_eq!("interpolate 43", err.unwrap_err().to_string());

        let err = ensure();
        assert_eq!("interpolate 44", err.unwrap_err().to_string());
    }

    fn bail() -> CosmianResult<()> {
        let var = 43;
        if true {
            cli_bail!("interpolate {var}");
        }
        Ok(())
    }

    fn ensure() -> CosmianResult<()> {
        let var = 44;
        cli_ensure!(false, "interpolate {var}");
        Ok(())
    }
}
