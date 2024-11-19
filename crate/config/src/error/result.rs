use std::fmt::Display;

use super::CosmianConfigError;

pub(crate) type CosmianConfigResult<R> = Result<R, CosmianConfigError>;

#[allow(dead_code)]
pub(crate) trait ConfigResultHelper<T> {
    fn context(self, context: &str) -> CosmianConfigResult<T>;
    fn with_context<D, O>(self, op: O) -> CosmianConfigResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> ConfigResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> CosmianConfigResult<T> {
        self.map_err(|e| CosmianConfigError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> CosmianConfigResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| CosmianConfigError::Default(format!("{}: {e}", op())))
    }
}

impl<T> ConfigResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> CosmianConfigResult<T> {
        self.ok_or_else(|| CosmianConfigError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> CosmianConfigResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| CosmianConfigError::Default(format!("{}", op())))
    }
}
