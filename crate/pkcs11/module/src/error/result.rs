use std::fmt::Display;

use super::MError;

pub type MResult<R> = Result<R, MError>;

#[expect(dead_code)]
pub(crate) trait MResultHelper<T> {
    fn context(self, context: &str) -> MResult<T>;
    fn with_context<D, O>(self, op: O) -> MResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> MResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> MResult<T> {
        self.map_err(|e| MError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> MResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| MError::Default(format!("{}: {e}", op())))
    }
}

impl<T> MResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> MResult<T> {
        self.ok_or_else(|| MError::Default(context.to_owned()))
    }

    fn with_context<D, O>(self, op: O) -> MResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| MError::Default(format!("{}", op())))
    }
}
