use clap::Subcommand;
use cosmian_kms_client::KmsClient;
#[cfg(test)]
pub(crate) use cosmian_kms_client::reexport::cosmian_kms_client_utils::certificate_utils::Algorithm;

use self::{
    certify::CertifyAction, decrypt_certificate::DecryptCertificateAction,
    destroy_certificate::DestroyCertificateAction, encrypt_certificate::EncryptCertificateAction,
    export_certificate::ExportCertificateAction, import_certificate::ImportCertificateAction,
    revoke_certificate::RevokeCertificateAction, validate_certificate::ValidateCertificatesAction,
};
use crate::error::result::CosmianResult;

mod certify;
mod decrypt_certificate;
mod destroy_certificate;
mod encrypt_certificate;
mod export_certificate;
mod import_certificate;
mod revoke_certificate;
mod validate_certificate;

/// Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data
#[derive(Subcommand)]
pub enum CertificatesCommands {
    Certify(CertifyAction),
    Decrypt(DecryptCertificateAction),
    Encrypt(EncryptCertificateAction),
    Export(ExportCertificateAction),
    Import(ImportCertificateAction),
    Revoke(RevokeCertificateAction),
    Destroy(DestroyCertificateAction),
    Validate(ValidateCertificatesAction),
}

impl CertificatesCommands {
    /// Process the `Certificates` main commands.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the KMS server fails.
    ///
    pub async fn process(&self, client_connector: &KmsClient) -> CosmianResult<()> {
        match self {
            Self::Certify(action) => action.run(client_connector).await,
            Self::Decrypt(action) => action.run(client_connector).await,
            Self::Encrypt(action) => action.run(client_connector).await,
            Self::Export(action) => action.run(client_connector).await,
            Self::Import(action) => action.run(client_connector).await,
            Self::Revoke(action) => action.run(client_connector).await,
            Self::Destroy(action) => action.run(client_connector).await,
            Self::Validate(action) => action.run(client_connector).await,
        }
    }
}
