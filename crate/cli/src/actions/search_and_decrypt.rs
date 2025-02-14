use clap::Parser;
use cosmian_findex_cli::{
    actions::findex::{
        instantiated_findex::InstantiatedFindex, parameters::FindexParameters,
        retrieve_key_from_kms,
    },
    reexports::{
        cosmian_findex_client::{
            reexport::cosmian_findex::MemoryEncryptionLayer, FindexRestClient, KmsEncryptionLayer,
            RestClient,
        },
        cosmian_findex_structs::{Uuids, WORD_LENGTH},
    },
};
use cosmian_kms_cli::{
    actions::symmetric::{DataEncryptionAlgorithm, DecryptAction},
    reexport::cosmian_kms_client::KmsClient,
};
use tracing::trace;

use crate::{
    cli_bail, cli_error,
    error::result::{CliResultHelper, CosmianResult},
};

/// Search keywords and decrypt the content of corresponding UUIDs.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SearchAndDecryptAction {
    #[clap(flatten)]
    pub(crate) findex_parameters: FindexParameters,

    /// The word to search. Can be repeated.
    #[clap(long)]
    pub(crate) keyword: Vec<String>,

    /// The Key Encryption key (KEM) unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = "kek-id", group = "kem", conflicts_with = "dem")]
    pub(crate) key_encryption_key_id: Option<String>,

    /// The data encryption key (DEK) unique identifier.
    /// The key has been created in KMS.
    /// DEM supported are:
    /// - RFC5649
    /// - AES-GCM
    #[clap(
        required = false,
        long = "dek-id",
        group = "dem",
        conflicts_with = "kem"
    )]
    pub(crate) data_encryption_key_id: Option<String>,

    /// The data encryption algorithm.
    /// If not specified, aes-gcm is used.
    ///
    /// If no key encryption algorithm is specified, the data will be sent to
    /// the server and will be decrypted server side.
    #[clap(
        long = "data-encryption-algorithm",
        short = 'd',
        default_value = "aes-gcm"
    )]
    pub(crate) data_encryption_algorithm: DataEncryptionAlgorithm,

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
        rest_client: &RestClient,
        kms_rest_client: &KmsClient,
    ) -> CosmianResult<Vec<String>> {
        let memory = FindexRestClient::new(rest_client.clone(), self.findex_parameters.index_id);

        let search_results = if let Some(seed_key_id) = self.findex_parameters.seed_key_id.clone() {
            let seed = retrieve_key_from_kms(&seed_key_id, kms_rest_client.clone()).await?;

            let encryption_layer = MemoryEncryptionLayer::<WORD_LENGTH, _>::new(&seed, memory);

            let findex = InstantiatedFindex::new(encryption_layer);
            findex.search(self.keyword.clone()).await?
        } else {
            let hmac_key_id = self
                .findex_parameters
                .hmac_key_id
                .clone()
                .ok_or_else(|| cli_error!("The HMAC key ID is required for indexing"))?;
            let aes_xts_key_id = self
                .findex_parameters
                .aes_xts_key_id
                .clone()
                .ok_or_else(|| cli_error!("The AES XTS key ID is required for indexing"))?;

            let encryption_layer = KmsEncryptionLayer::<WORD_LENGTH, _>::new(
                kms_rest_client.clone(),
                hmac_key_id.clone(),
                aes_xts_key_id.clone(),
                memory,
            );

            let findex = InstantiatedFindex::new(encryption_layer);
            findex.search(self.keyword.clone()).await?
        };

        trace!("Search results: {search_results}");
        let uuids = Uuids::try_from(search_results)?;
        trace!("UUIDs of encrypted entries: {uuids}");
        let encrypted_entries = rest_client
            .get_entries(&self.findex_parameters.index_id, &uuids)
            .await?;

        let authentication_data = self
            .authentication_data
            .as_deref()
            .map(hex::decode)
            .transpose()
            .with_context(|| "failed to decode the authentication data")?;

        let decrypt_action = DecryptAction::default();
        let mut results = Vec::with_capacity(encrypted_entries.len());
        let mut decrypted_records = Vec::with_capacity(encrypted_entries.len());
        for (_uuid, ciphertext) in encrypted_entries.iter() {
            let decrypted_record = match (
                self.key_encryption_key_id.as_ref(),
                self.data_encryption_key_id.as_ref(),
            ) {
                (Some(key_encryption_key_id), None) => {
                    decrypt_action
                        .client_side_decrypt_with_buffer(
                            kms_rest_client,
                            self.data_encryption_algorithm,
                            key_encryption_key_id,
                            ciphertext,
                            authentication_data.clone(),
                        )
                        .await?
                }
                (None, Some(data_encryption_key_id)) => decrypt_action
                    .server_side_decrypt(
                        kms_rest_client,
                        self.data_encryption_algorithm.into(),
                        data_encryption_key_id,
                        ciphertext.clone(),
                        authentication_data.clone(),
                    )
                    .await?
                    .to_vec(),
                _ => {
                    cli_bail!(
                        "Either a key encryption key or a data encryption key must be provided"
                    )
                }
            };
            decrypted_records.push(decrypted_record);
        }

        for decrypted_record in decrypted_records {
            let decrypted_record_str = std::str::from_utf8(&decrypted_record)?;
            results.push(decrypted_record_str.to_string());
        }

        println!("Decrypted records: {results:?}");

        Ok(results)
    }
}
