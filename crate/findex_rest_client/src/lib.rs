pub use error::{result::FindexRestClientResult, FindexRestClientError};
pub use findex_rest_client::FindexRestClient;
pub use permission::Permission;

mod error;
mod findex_rest_client;
mod permission;
