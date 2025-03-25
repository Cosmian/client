use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_objects::ObjectType,
    kmip_2_1::requests::import_object_request,
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::import_utils::{
        ImportKeyFormat, KeyUsage, prepare_key_import_elements,
    },
};

use crate::{actions::console, error::result::CosmianResult};

/// Import a private or public key in the KMS.
///
/// When no unique id is specified, a unique id is generated.
///
/// By default, the format is expected to be JSON TTLV but
/// other formats can be specified with the option `-f`.
///   * json-ttlv (the default)
///   * pem (PKCS#1, PKCS#8, SEC1, SPKI): the function will attempt to detect the type of key and key format
///   * sec1: an elliptic curve private key in SEC1 DER format (NIST curves only - SECG SEC1-v2 #C.4)
///   * pkcs1-priv: an RSA private key in PKCS#1 DER format (RFC 8017)
///   * pkcs1-pub: an RSA public key in PKCS#1 DER format (RFC 8017)
///   * pkcs8: an RSA or Elliptic Curve private key in PKCS#8 DER format (RFC 5208 and 5958)
///   * spki: an RSA or Elliptic Curve public key in Subject Public Key Info DER format (RFC 5480)
///   * aes: the bytes of an AES symmetric key
///   * chacha20: the bytes of a `ChaCha20` symmetric key
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ImportKeyAction {
    /// The KMIP JSON TTLV key file.
    #[clap(required = true)]
    key_file: PathBuf,

    /// The unique id of the key; a random uuid
    /// is generated if not specified.
    #[clap(required = false)]
    key_id: Option<String>,

    /// The format of the key.
    #[clap(long, short = 'f', default_value = "json-ttlv")]
    key_format: ImportKeyFormat,

    /// For a private key: the corresponding KMS public key id if any.
    #[clap(long, short = 'p')]
    public_key_id: Option<String>,

    /// For a public key: the corresponding KMS private key id if any.
    #[clap(long, short = 'k')]
    private_key_id: Option<String>,

    /// For a public or private key: the corresponding certificate id if any.
    #[clap(long, short = 'c')]
    certificate_id: Option<String>,

    /// In the case of a JSON TTLV key,
    /// unwrap the key if it is wrapped before storing it.
    #[clap(long, short = 'u', required = false, default_value = "false")]
    unwrap: bool,

    /// Replace an existing key under the same id.
    #[clap(
        required = false,
        long = "replace",
        short = 'r',
        default_value = "false"
    )]
    replace_existing: bool,

    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,

    /// For what operations should the key be used.
    #[clap(long)]
    key_usage: Option<Vec<KeyUsage>>,

    /// Optional authenticated encryption additional data to use for AES256GCM authenticated encryption unwrapping
    #[clap(
        long,
        short = 'd',
        default_value = None,
    )]
    authenticated_additional_data: Option<String>,
}

impl ImportKeyAction {
    /// Run the import key action.
    ///
    /// # Errors
    ///
    /// This function can return a [`CosmianError`] if an error occurs during the import process.
    ///
    /// Possible error cases include:
    ///
    /// - Failed to read the key file.
    /// - Failed to parse the key file in the specified format.
    /// - Invalid key format specified.
    /// - Failed to assign cryptographic usage mask.
    /// - Failed to generate import attributes.
    /// - Failed to import the key.
    /// - Failed to write the response to stdout.
    ///
    /// [`CosmianError`]: ../error/result/enum.CosmianError.html
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
        let key_bytes = read_bytes_from_file(&self.key_file)?;
        let (object, import_attributes) = prepare_key_import_elements(
            &self.key_usage,
            &self.key_format,
            key_bytes,
            &self.certificate_id,
            &self.private_key_id,
            &self.public_key_id,
            self.unwrap,
            &self.authenticated_additional_data,
        )?;
        let object_type: ObjectType = object.object_type();

        // import the key
        let import_object_request = import_object_request(
            self.key_id.clone(),
            object,
            Some(import_attributes),
            self.unwrap,
            self.replace_existing,
            &self.tags,
        );
        let unique_identifier = kms_rest_client
            .import(import_object_request)
            .await?
            .unique_identifier;

        // print the response
        let stdout = format!(
            "The {:?} in file {:?} was imported with id: {}",
            object_type, &self.key_file, unique_identifier,
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(unique_identifier);
        stdout.write()?;

        Ok(())
    }
}
