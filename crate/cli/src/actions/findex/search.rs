use clap::Parser;
use cloudproof_findex::reexport::cosmian_findex::{Keyword, Keywords};
use cosmian_findex_rest_client::FindexRestClient;
use cosmian_kms_rest_client::KmsRestClient;
use tracing::trace;

use super::parameters::FindexParameters;
use crate::{
    actions::{console, findex::parameters::instantiate_findex},
    error::result::CliResult,
};

/// Search keywords over encrypted indexes
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SearchAction {
    #[clap(flatten)]
    pub(crate) findex_parameters: FindexParameters,

    /// The word to search. Can be repeated.
    #[clap(long)]
    pub(crate) keyword: Vec<String>,
}

impl SearchAction {
    /// Search indexed keywords.
    ///
    /// # Arguments
    ///
    /// * `rest_client` - The Findex server client instance used to communicate
    ///   with the Findex server server.
    ///
    /// # Errors
    ///
    /// Returns an error if the version query fails or if there is an issue
    /// writing to the console.
    #[allow(clippy::future_not_send)] // todo(manu): to remove this, changes must be done on `findex` repository
    pub async fn process(
        &self,
        _kms_rest_client: KmsRestClient,
        rest_client: FindexRestClient,
    ) -> CliResult<()> {
        let findex = instantiate_findex(rest_client, &self.findex_parameters.index_id).await?;
        let results = findex
            .search(
                &self.findex_parameters.user_key()?,
                &self.findex_parameters.label(),
                self.keyword
                    .clone()
                    .into_iter()
                    .map(|word| Keyword::from(word.as_bytes()))
                    .collect::<Keywords>(),
                &|_| async move { Ok(false) },
            )
            .await?;

        console::Stdout::new(&results.to_string()).write()?;
        trace!("Search results: {results}");

        Ok(())
    }
}
