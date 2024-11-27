use std::{
    collections::{HashMap, HashSet},
    fs::File,
    path::PathBuf,
};

use clap::Parser;
use cloudproof_findex::reexport::cosmian_findex::{
    Data, IndexedValue, IndexedValueToKeywordsMap, Keyword, Keywords,
};
use cosmian_findex_cli::{
    actions::findex::{FindexParameters, instantiate_findex},
    reexports::{
        cosmian_findex_client::FindexRestClient, cosmian_findex_structs::EncryptedEntries,
    },
};
use cosmian_kms_cli::{
    actions::symmetric::{DataEncryptionAlgorithm, EncryptAction, KeyEncryptionAlgorithm},
    reexport::cosmian_kms_client::KmsClient,
};
use tracing::trace;

use crate::error::result::{CliResultHelper, CosmianResult};

/// Encrypt entries and index the corresponding database UUIDs with the Findex. todo(manu): describe the action
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct EncryptAndIndexAction {
    #[clap(flatten)]
    pub(crate) findex_parameters: FindexParameters,

    /// The path to the CSV file containing the data to index
    #[clap(long)]
    pub(crate) csv: PathBuf,

    /// The public key unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = "kek-id", group = "key-tags")]
    pub(crate) key_encryption_key_id: String,

    /// Optional nonce/IV (or tweak for XTS) as a hex string.
    /// If not provided, a random value is generated.
    #[clap(required = false, long, short = 'n')]
    pub(crate) nonce: Option<String>,

    /// Optional additional authentication data as a hex string.
    /// This data needs to be provided back for decryption.
    /// This data is ignored with XTS.
    #[clap(required = false, long, short = 'a')]
    pub(crate) authentication_data: Option<String>,
}

impl EncryptAndIndexAction {
    pub(crate) async fn encrypt_entries(
        &self,
        csv: PathBuf,
        kms_rest_client: &KmsClient,
        key_encryption_key_id: &str,
        nonce: Option<Vec<u8>>,
        authentication_data: Option<Vec<u8>>,
    ) -> CosmianResult<(EncryptedEntries, IndexedValueToKeywordsMap)> {
        let mut encrypted_entries = EncryptedEntries::new();
        let mut indexed_value_to_keywords = Vec::new();

        let encrypt_action = EncryptAction::default();
        let file = File::open(csv.clone())?;
        let mut rdr = csv::Reader::from_reader(file);
        for result in rdr.byte_records() {
            // The iterator yields Result<StringRecord, Error>, so we check the
            // error here.
            let record = result?;
            trace!("CSV line: {record:?}");
            let record_bytes = record.as_slice();
            let encrypted_record = encrypt_action
                .client_side_encrypt_with_buffer(
                    kms_rest_client,
                    key_encryption_key_id,
                    KeyEncryptionAlgorithm::RFC5649,
                    DataEncryptionAlgorithm::AesGcm,
                    nonce.clone(),
                    record_bytes,
                    authentication_data.clone(),
                )
                .await?;
            let new_uuid = uuid::Uuid::new_v4();
            encrypted_entries.insert(new_uuid, encrypted_record);
            let indexed_value: IndexedValue<Keyword, Data> =
                IndexedValue::Data(Data::from(new_uuid.as_bytes().to_vec()));
            let keywords = record.iter().map(Keyword::from).collect::<HashSet<_>>();
            trace!("my keywords: {}", Keywords::from(keywords.clone()));
            indexed_value_to_keywords.push((indexed_value, keywords));
        }
        let indexed_value_to_keywords_map = IndexedValueToKeywordsMap::from(
            indexed_value_to_keywords
                .iter()
                .cloned()
                .collect::<HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>>(),
        );

        Ok((encrypted_entries, indexed_value_to_keywords_map))
    }

    /// Adds the data from the CSV file to the Findex index.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - There is an error instantiating the Findex client.
    /// - There is an error retrieving the user key or label from the Findex
    ///   parameters.
    /// - There is an error converting the CSV file to a hashmap.
    /// - There is an error adding the data to the Findex index.
    /// - There is an error writing the result to the console.
    #[allow(clippy::future_not_send, clippy::print_stdout)]
    pub async fn run(
        &self,
        findex_rest_client: FindexRestClient,
        kms_rest_client: &KmsClient,
    ) -> CosmianResult<()> {
        let nonce = self
            .nonce
            .as_deref()
            .map(hex::decode)
            .transpose()
            .with_context(|| "failed to decode the nonce")?;

        let authentication_data = self
            .authentication_data
            .as_deref()
            .map(hex::decode)
            .transpose()
            .with_context(|| "failed to decode the authentication data")?;

        let (encrypted_entries, indexed_value_to_keywords_map) = self
            .encrypt_entries(
                self.csv.clone(),
                kms_rest_client,
                &self.key_encryption_key_id,
                nonce,
                authentication_data,
            )
            .await?;

        findex_rest_client
            .add_entries(&self.findex_parameters.index_id, &encrypted_entries)
            .await?;

        let keywords = instantiate_findex(findex_rest_client, &self.findex_parameters.index_id)
            .await?
            .add(
                &self.findex_parameters.user_key()?,
                &self.findex_parameters.label(),
                indexed_value_to_keywords_map,
            )
            .await?;
        trace!("indexing done: keywords: {keywords}");

        let uuids = encrypted_entries.get_uuids();
        println!("Data behind those UUIDS were encrypted and indexed: {uuids}");

        Ok(())
    }
}
