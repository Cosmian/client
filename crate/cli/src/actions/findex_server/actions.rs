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
pub enum CoreFindexActions {
    /// Create new indexes
    Index(InsertOrDeleteAction),
    Search(SearchAction),
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

impl CoreFindexActions {
    /// Process the command line arguments
    ///
    /// # Arguments
    /// * `findex_client` - The Findex client
    /// * `config` - The Findex client configuration
    ///
    /// # Errors
    /// - If the configuration file is not found or invalid
    #[allow(clippy::print_stdout)]
    pub async fn run(
        &self, // we do not want to consume self because we need post processing for the login/logout commands
        findex_client: &mut RestClient,
        kms_client: KmsClient,
        config: &mut RestClientConfig,
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

            // actions that edit the configuration
            Self::Login(action) => action.run(config).await,
            Self::Logout(action) => action.run(config),
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

#[derive(Subcommand)]
pub enum FindexActions {
    EncryptAndIndex(EncryptAndIndexAction),
    SearchAndDecrypt(SearchAndDecryptAction),
    #[clap(flatten)]
    Findex(CoreFindexActions),
}

impl FindexActions {
    /// Combine Findex with KMS encryption
    ///
    /// # Errors
    /// Returns an error if the action fails
    pub async fn run(
        &self,
        findex_rest_client: &mut RestClient,
        kms_rest_client: &KmsClient,
        findex_config: &mut RestClientConfig,
    ) -> CosmianResult<()> {
        match self {
            Self::Findex(action) => {
                action
                    .run(findex_rest_client, kms_rest_client.clone(), findex_config)
                    .await
            }
            Self::EncryptAndIndex(action) => {
                action.run(findex_rest_client, kms_rest_client).await?;
                Ok(())
            }
            Self::SearchAndDecrypt(action) => {
                action.run(findex_rest_client, kms_rest_client).await?;
                Ok(())
            }
        }
    }
}
