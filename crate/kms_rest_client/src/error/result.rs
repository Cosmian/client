use std::fmt::Display;

use super::KmsRestClientError;

pub type KmsRestClientResult<R> = Result<R, KmsRestClientError>;

#[allow(dead_code)]
pub(crate) trait KmsRestClientResultHelper<T> {
    fn context(self, context: &str) -> KmsRestClientResult<T>;
    fn with_context<D, O>(self, op: O) -> KmsRestClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> KmsRestClientResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> KmsRestClientResult<T> {
        self.map_err(|e| KmsRestClientError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> KmsRestClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| KmsRestClientError::Default(format!("{}: {e}", op())))
    }
}

impl<T> KmsRestClientResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> KmsRestClientResult<T> {
        self.ok_or_else(|| KmsRestClientError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> KmsRestClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| KmsRestClientError::Default(format!("{}", op())))
    }
}
