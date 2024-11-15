use clap::Subcommand;
use cosmian_findex_cli::CoreFindexActions;
use cosmian_findex_client::FindexClient;
use cosmian_kms_client::KmsClient;

use super::{encrypt_and_add::EncryptAndAddAction, search_and_decrypt::SearchAndDecryptAction};
use crate::error::{result::CosmianResult, CosmianError};

#[derive(Subcommand)]
pub enum FindexActions {
    EncryptAndAdd(EncryptAndAddAction),
    SearchAndDecrypt(SearchAndDecryptAction),
    #[clap(flatten)]
    Findex(CoreFindexActions),
}

impl FindexActions {
    pub async fn run(
        &self,
        findex_rest_client: FindexClient,
        kms_rest_client: &KmsClient,
    ) -> CosmianResult<()> {
        match self {
            FindexActions::Findex(action) => action
                .run(findex_rest_client)
                .await
                .map_err(CosmianError::from),
            FindexActions::EncryptAndAdd(action) => {
                action.run(findex_rest_client, kms_rest_client).await
            }
            FindexActions::SearchAndDecrypt(action) => {
                action.run(findex_rest_client, kms_rest_client).await
            }
        }
    }
}
