use clap::Parser;
use cosmian_findex_rest_client::FindexRestClient;
use cosmian_kms_rest_client::KmsRestClient;

use super::{
    add_or_delete::AddOrDeleteAction, permissions::PermissionsAction, search::SearchAction,
};
use crate::error::result::CliResult;

/// Use Findex to create encrypted indexes over a dataset.
#[derive(Parser, Debug)]
pub enum FindexCommands {
    /// Create encrypted indexes
    Add(AddOrDeleteAction),
    /// Delete indexes
    Delete(AddOrDeleteAction),
    Search(SearchAction),
    #[command(subcommand)]
    Permissions(PermissionsAction),
}

impl FindexCommands {
    /// Processes the permissions action.
    ///
    /// # Arguments
    ///
    /// * `rest_client` - The Findex client used for the action.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem running the action.
    #[allow(clippy::future_not_send)]
    pub async fn process(
        &self,
        kms_rest_client: KmsRestClient,
        findex_rest_client: FindexRestClient,
    ) -> CliResult<()> {
        match self {
            Self::Add(action) => action.add(kms_rest_client, findex_rest_client).await?,
            Self::Delete(action) => action.delete(findex_rest_client).await?,
            Self::Search(action) => action.process(kms_rest_client, findex_rest_client).await?,
            Self::Permissions(action) => action.process(findex_rest_client).await?,
        };

        Ok(())
    }
}
