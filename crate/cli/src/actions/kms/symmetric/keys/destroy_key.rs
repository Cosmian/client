use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::kms::{
        labels::KEY_ID,
        shared::{get_key_uid, utils::destroy},
    },
    error::result::CosmianResult,
};

/// Destroy a symmetric key.
///
/// The key must have been revoked first.
///
/// Keys belonging to external stores, such as HSMs,
/// are automatically removed.
///
/// When a key is destroyed but not removed in the KMS,
/// it can only be exported by the owner of the key,
/// and without its key material
#[derive(Parser, Debug)]
pub struct DestroyKeyAction {
    /// The key unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,

    /// If the key should be removed from the database
    /// If not specified, the key will be destroyed
    /// but its metadata will still be available in the database.
    /// Please note that the KMIP specification does not support the removal of objects.
    #[clap(long = "remove", default_value = "false", verbatim_doc_comment)]
    remove: bool,
}

impl DestroyKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        destroy(kms_rest_client, &id, self.remove).await
    }
}
