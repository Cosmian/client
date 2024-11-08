use std::fmt::Display;

use super::ConfigError;

pub(crate) type ConfigResult<R> = Result<R, ConfigError>;

#[allow(dead_code)]
pub(crate) trait ConfigResultHelper<T> {
    fn context(self, context: &str) -> ConfigResult<T>;
    fn with_context<D, O>(self, op: O) -> ConfigResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> ConfigResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> ConfigResult<T> {
        self.map_err(|e| ConfigError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> ConfigResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| ConfigError::Default(format!("{}: {e}", op())))
    }
}

impl<T> ConfigResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> ConfigResult<T> {
        self.ok_or_else(|| ConfigError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> ConfigResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| ConfigError::Default(format!("{}", op())))
    }
}
