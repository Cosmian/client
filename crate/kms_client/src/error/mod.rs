use std::io;

use cosmian_http_client::HttpClientError;
use cosmian_kms_client_utils::reexport::cosmian_kmip::{
    KmipError,
    kmip_2_1::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
use thiserror::Error;

pub(crate) mod result;

#[derive(Error, Debug)]
pub enum KmsClientError {
    #[error("Invalid conversion: {0}")]
    Conversion(String),

    #[error("{0}")]
    Default(String),

    #[error("Invalid KMIP Object: {0}: {1}")]
    InvalidKmipObject(ErrorReason, String),

    #[error("Invalid KMIP value: {0}: {1}")]
    InvalidKmipValue(ErrorReason, String),

    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    #[error("Kmip Not Supported: {0}: {1}")]
    KmipNotSupported(ErrorReason, String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("HTTP Client: {0}")]
    HttpClient(String),

    #[error(transparent)]
    PemError(#[from] pem::PemError),

    #[error("Ratls Error: {0}")]
    RatlsError(String),

    #[error("REST Request Failed: {0}")]
    RequestFailed(String),

    #[error("REST Response Conversion Failed: {0}")]
    ResponseFailed(String),

    #[error("TTLV Error: {0}")]
    TtlvError(String),

    #[error("Unexpected Error: {0}")]
    UnexpectedError(String),

    #[error(transparent)]
    UrlError(#[from] url::ParseError),

    #[error(transparent)]
    ConfigUtils(#[from] cosmian_kms_client_utils::reexport::cosmian_config_utils::ConfigUtilsError),

    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),
}

impl From<TtlvError> for KmsClientError {
    fn from(e: TtlvError) -> Self {
        Self::TtlvError(e.to_string())
    }
}

impl From<reqwest::Error> for KmsClientError {
    fn from(e: reqwest::Error) -> Self {
        Self::Default(format!("{e}: Details: {e:?}"))
    }
}

impl From<reqwest::header::InvalidHeaderValue> for KmsClientError {
    fn from(e: reqwest::header::InvalidHeaderValue) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<io::Error> for KmsClientError {
    fn from(e: io::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<der::Error> for KmsClientError {
    fn from(e: der::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<KmipError> for KmsClientError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s) => Self::InvalidKmipValue(r, s),
            KmipError::InvalidKmipObject(r, s) => Self::InvalidKmipObject(r, s),
            KmipError::KmipNotSupported(r, s) => Self::KmipNotSupported(r, s),
            KmipError::Kmip(r, s) => Self::KmipError(r, s),
            KmipError::NotSupported(s)
            | KmipError::Default(s)
            | KmipError::InvalidSize(s)
            | KmipError::InvalidTag(s)
            | KmipError::Derivation(s)
            | KmipError::ConversionError(s)
            | KmipError::IndexingSlicing(s)
            | KmipError::ObjectNotFound(s) => Self::NotSupported(s),
            KmipError::TryFromSliceError(e) => Self::Conversion(e.to_string()),
            KmipError::SerdeJsonError(e) => Self::Conversion(e.to_string()),
            KmipError::Deserialization(e) | KmipError::Serialization(e) => {
                Self::KmipNotSupported(ErrorReason::Codec_Error, e)
            }
            KmipError::DeserializationSize(expected, actual) => Self::KmipNotSupported(
                ErrorReason::Codec_Error,
                format!("Deserialization: invalid size: {actual}, expected: {expected}"),
            ),
        }
    }
}

impl From<cosmian_crypto_core::CryptoCoreError> for KmsClientError {
    fn from(e: cosmian_crypto_core::CryptoCoreError) -> Self {
        Self::UnexpectedError(e.to_string())
    }
}

impl From<HttpClientError> for KmsClientError {
    fn from(e: HttpClientError) -> Self {
        Self::HttpClient(e.to_string())
    }
}
/// Construct a server error from a string.
#[macro_export]
macro_rules! kms_client_error {
    ($msg:literal) => {
        $crate::KmsClientError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::KmsClientError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::KmsClientError::Default(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! kms_client_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::kms_client_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::kms_client_error!($fmt, $($arg)*))
    };
}
