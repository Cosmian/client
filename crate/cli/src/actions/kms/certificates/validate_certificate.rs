use clap::Parser;
use cosmian_kms_client::{
    kmip_2_1::{kmip_types::ValidityIndicator, requests::build_validate_certificate_request},
    KmsClient,
};

use crate::{
    actions::{console, kms::labels::CERTIFICATE_ID},
    error::result::CosmianResult,
};

/// Validate a certificate.
///
/// A certificate or a chain of certificates is validated.
/// It means that the certificate chain is valid in terms of time, well-signed,
/// complete, and no components have been flagged as removed.
#[derive(Parser, Debug)]
pub struct ValidateCertificatesAction {
    /// One or more Unique Identifiers of Certificate Objects.
    #[clap(long = CERTIFICATE_ID, short = 'k')]
    certificate_id: Vec<String>,
    /// A Date-Time object indicating when the certificate chain needs to be
    /// valid. If omitted, the current date and time SHALL be assumed.
    #[clap(long = "validity-time", short = 't')]
    validity_time: Option<String>,
}

impl ValidateCertificatesAction {
    pub async fn run(&self, client_connector: &KmsClient) -> CosmianResult<()> {
        let request =
            build_validate_certificate_request(&self.certificate_id, self.validity_time.clone())?;
        let validity_indicator = client_connector.validate(request).await?.validity_indicator;
        console::Stdout::new(match validity_indicator {
            ValidityIndicator::Valid => "Valid",
            ValidityIndicator::Invalid => "Invalid",
            ValidityIndicator::Unknown => "Unknown",
        })
        .write()?;
        Ok(())
    }
}
