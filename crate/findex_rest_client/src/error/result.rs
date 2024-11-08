use std::fmt::Display;

use super::FindexRestClientError;

pub type FindexRestClientResult<R> = Result<R, FindexRestClientError>;

#[allow(dead_code)]
pub(crate) trait FindexRestClientResultHelper<T> {
    fn context(self, context: &str) -> FindexRestClientResult<T>;
    fn with_context<D, O>(self, op: O) -> FindexRestClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> FindexRestClientResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> FindexRestClientResult<T> {
        self.map_err(|e| FindexRestClientError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> FindexRestClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| FindexRestClientError::Default(format!("{}: {e}", op())))
    }
}

impl<T> FindexRestClientResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> FindexRestClientResult<T> {
        self.ok_or_else(|| FindexRestClientError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> FindexRestClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| FindexRestClientError::Default(format!("{}", op())))
    }
}
