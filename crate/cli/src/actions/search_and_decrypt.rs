use clap::Parser;
use cloudproof_findex::reexport::cosmian_findex::{Keyword, Keywords};
use cosmian_findex_cli::{
    actions::findex::{FindexParameters, instantiate_findex},
    reexports::{cosmian_findex_client::FindexRestClient, cosmian_findex_structs::Uuids},
};
use cosmian_kms_cli::{
    actions::symmetric::{DataEncryptionAlgorithm, DecryptAction, KeyEncryptionAlgorithm},
    reexport::cosmian_kms_client::KmsClient,
};
use tracing::trace;
use uuid::Uuid;

use crate::error::result::{CliResultHelper, CosmianResult};

/// Search keywords and decrypt the content of corresponding UUIDs.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SearchAndDecryptAction {
    #[clap(flatten)]
    pub(crate) findex_parameters: FindexParameters,

    /// The word to search. Can be repeated.
    #[clap(long)]
    pub(crate) keyword: Vec<String>,

    /// The public key unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = "kek-id", group = "key-tags")]
    pub(crate) key_encryption_key_id: String,

    /// Optional additional authentication data as a hex string.
    /// This data needs to be provided back for decryption.
    /// This data is ignored with XTS.
    #[clap(required = false, long, short = 'a')]
    pub(crate) authentication_data: Option<String>,
}

impl SearchAndDecryptAction {
    #[allow(clippy::future_not_send, clippy::print_stdout)]
    pub(crate) async fn run(
        &self,
        findex_rest_client: FindexRestClient,
        kms_rest_client: &KmsClient,
    ) -> CosmianResult<()> {
        let results =
            instantiate_findex(findex_rest_client.clone(), &self.findex_parameters.index_id)
                .await?
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
        trace!("Index search results: {results}");

        let mut uuids = Vec::new();
        for (_keyword, hashset) in results {
            for indexed_value in hashset {
                let uuid = Uuid::from_slice(indexed_value.as_ref())?;
                uuids.push(uuid);
            }
        }

        let encrypted_entries = findex_rest_client
            .get_entries(&self.findex_parameters.index_id, &Uuids::from(uuids))
            .await?;

        let authentication_data = self
            .authentication_data
            .as_deref()
            .map(hex::decode)
            .transpose()
            .with_context(|| "failed to decode the authentication data")?;

        let decrypt_action = DecryptAction::default();
        let mut results = Vec::with_capacity(encrypted_entries.len());
        for (_uuid, ciphertext) in encrypted_entries.iter() {
            let decrypted_record = decrypt_action
                .client_side_decrypt_with_buffer(
                    kms_rest_client,
                    KeyEncryptionAlgorithm::RFC5649,
                    DataEncryptionAlgorithm::AesGcm,
                    &self.key_encryption_key_id,
                    ciphertext,
                    authentication_data.clone(),
                )
                .await?;
            let decrypted_record_str = std::str::from_utf8(&decrypted_record)?;
            results.push(decrypted_record_str.to_string());
        }

        println!("Decrypted records: {results:?}");

        Ok(())
    }
}
