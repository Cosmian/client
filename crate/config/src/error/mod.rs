use cosmian_config_utils::ConfigUtilsError;
use thiserror::Error;

pub(crate) mod result;

#[derive(Error, Debug)]
pub enum CosmianConfigError {
    #[error("{0}")]
    Default(String),

    #[error(transparent)]
    ConfigUtilsError(#[from] ConfigUtilsError),
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! config_error {
    ($msg:literal) => {
        $crate::ConfigError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::ConfigError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::ConfigError::Default(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! config_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::config_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::config_error!($fmt, $($arg)*))
    };
}
