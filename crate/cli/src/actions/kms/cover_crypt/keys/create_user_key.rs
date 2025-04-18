use clap::Parser;
use cosmian_cover_crypt::AccessPolicy;
use cosmian_kms_client::{
    KmsClient,
    reexport::cosmian_kms_client_utils::cover_crypt_utils::build_create_covercrypt_usk_request,
};

use crate::{
    actions::console,
    error::result::{CosmianResult, CosmianResultHelper},
};

/// Create a new user secret key for an access policy, and index it under some
/// (optional) tags, that can later be used to retrieve the key.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct CreateUserKeyAction {
    /// The master secret key unique identifier
    #[clap(required = true)]
    master_secret_key_id: String,

    /// The access policy should be expressed as a boolean expression of
    /// attributes. For example (provided the corresponding attributes are
    /// defined in the MSK):
    ///
    /// `"(Department::HR || Department::MKG) && Security Level::Confidential"`
    #[clap(required = true)]
    access_policy: String,

    /// The tag to associate with the user decryption key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,

    /// Sensitive: if set, the key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    sensitive: bool,
}

impl CreateUserKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
        // Validate the access policy: side-effect only.
        AccessPolicy::parse(&self.access_policy).with_context(|| "bad access policy syntax")?;

        let request = build_create_covercrypt_usk_request(
            &self.access_policy,
            &self.master_secret_key_id,
            &self.tags,
            self.sensitive,
        )?;

        let response = kms_rest_client
            .create(request)
            .await
            .with_context(|| "user decryption key creation failed")?;

        let usk_uid = &response.unique_identifier;

        let mut stdout =
            console::Stdout::new("The user decryption key pair has been properly generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(usk_uid.to_owned());
        stdout.write()
    }
}
