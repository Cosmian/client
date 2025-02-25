use clap::Subcommand;
use cosmian_findex_client::{RestClient, RestClientConfig};
use cosmian_kms_cli::reexport::cosmian_kms_client::KmsClient;

use super::{
    datasets::DatasetsAction,
    encrypt_and_index::EncryptAndIndexAction,
    findex::{insert_or_delete::InsertOrDeleteAction, search::SearchAction},
    login::LoginAction,
    logout::LogoutAction,
    permissions::PermissionsAction,
    search_and_decrypt::SearchAndDecryptAction,
    version::ServerVersionAction,
};
use crate::error::result::CosmianResult;

#[derive(Subcommand)]
pub enum FindexActions {
    /// Create new indexes
    Index(InsertOrDeleteAction),
    EncryptAndIndex(EncryptAndIndexAction),
    Search(SearchAction),
    SearchAndDecrypt(SearchAndDecryptAction),

    /// Delete indexed keywords
    Delete(InsertOrDeleteAction),

    #[command(subcommand)]
    Permissions(PermissionsAction),

    #[command(subcommand)]
    Datasets(DatasetsAction),

    Login(LoginAction),
    Logout(LogoutAction),

    ServerVersion(ServerVersionAction),
}

impl FindexActions {
    /// Actions that can be performed on the Findex server such as:
    /// - indexing, searching with or without datasets-encryption (indexes are always encrypted),
    /// - permissions management,
    /// - datasets management,
    /// - login and logout,
    ///
    /// # Errors
    /// Returns an error if the action fails
    #[allow(clippy::print_stdout)]
    pub async fn run(
        &self,
        findex_client: &mut RestClient,
        kms_client: KmsClient,
        findex_config: &mut RestClientConfig,
    ) -> CosmianResult<()> {
        let result = match self {
            // actions that don't edit the configuration
            Self::Datasets(action) => action.run(findex_client).await,
            Self::Permissions(action) => action.run(findex_client).await,
            Self::ServerVersion(action) => action.run(findex_client).await,
            Self::Delete(action) => {
                let deleted_keywords = action.delete(findex_client, kms_client).await?;
                Ok(format!("Deleted keywords: {deleted_keywords}"))
            }
            Self::Index(action) => {
                let inserted_keywords = action.insert(findex_client, kms_client).await?;
                Ok(format!("Inserted keywords: {inserted_keywords}"))
            }
            Self::Search(action) => {
                let search_results = action.run(findex_client, &kms_client).await?;
                Ok(format!("Search results: {search_results}"))
            }
            Self::EncryptAndIndex(action) => {
                Ok(action.run(findex_client, &kms_client).await?.to_string())
            }
            Self::SearchAndDecrypt(action) => {
                let res = action.run(findex_client, &kms_client).await?;
                Ok(format!("{res:?}"))
            }

            // actions that edit the configuration
            Self::Login(action) => action.run(findex_config).await,
            Self::Logout(action) => action.run(findex_config),
        };
        match result {
            Ok(output) => {
                println!("{output}");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
