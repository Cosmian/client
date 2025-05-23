use clap::Subcommand;
use cosmian_kms_client::{KmsClient, KmsClientConfig};

#[cfg(not(feature = "fips"))]
use super::cover_crypt::CovercryptCommands;
use crate::{
    actions::kms::{
        access::AccessAction, attributes::AttributesCommands, bench::BenchAction,
        certificates::CertificatesCommands, elliptic_curves::EllipticCurveCommands,
        google::GoogleCommands, hash::HashAction, login::LoginAction, mac::MacAction,
        rsa::RsaCommands, shared::LocateObjectsAction, symmetric::SymmetricCommands,
        version::ServerVersionAction,
    },
    error::result::CosmianResult,
};

#[derive(Subcommand)]
pub enum KmsActions {
    #[command(subcommand)]
    AccessRights(AccessAction),
    #[command(subcommand)]
    Attributes(AttributesCommands),
    #[clap(hide = true)]
    Bench(BenchAction),
    #[cfg(not(feature = "fips"))]
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[command(subcommand)]
    Certificates(CertificatesCommands),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    #[command(subcommand)]
    Google(GoogleCommands),
    Locate(LocateObjectsAction),
    Login(LoginAction),
    /// Logout from the Identity Provider.
    ///
    /// The access token will be removed from the cosmian configuration file.
    Logout,
    Hash(HashAction),
    Mac(MacAction),
    #[command(subcommand)]
    Rsa(RsaCommands),
    ServerVersion(ServerVersionAction),
    #[command(subcommand)]
    Sym(SymmetricCommands),
}

impl KmsActions {
    /// Process the command line arguments
    ///
    /// # Errors
    /// - If the configuration file is not found or invalid
    pub async fn process(&self, kms_rest_client: KmsClient) -> CosmianResult<KmsClientConfig> {
        let mut new_config = kms_rest_client.config.clone();

        match self {
            Self::AccessRights(action) => action.process(kms_rest_client).await?,
            Self::Attributes(action) => action.process(kms_rest_client).await?,
            Self::Bench(action) => action.process(kms_rest_client).await?,
            #[cfg(not(feature = "fips"))]
            Self::Cc(action) => action.process(kms_rest_client).await?,
            Self::Certificates(action) => action.process(kms_rest_client).await?,
            Self::Ec(action) => action.process(kms_rest_client).await?,
            Self::Google(action) => action.process(kms_rest_client).await?,
            Self::Locate(action) => action.process(kms_rest_client).await?,
            Self::Login(action) => {
                let access_token = action.process(kms_rest_client.config).await?;
                new_config.http_config.access_token = Some(access_token);
            }
            Self::Logout => {
                new_config.http_config.access_token = None;
            }
            Self::Hash(action) => action.process(kms_rest_client).await?,
            Self::Mac(action) => action.process(kms_rest_client).await?,
            Self::Rsa(action) => action.process(kms_rest_client).await?,
            Self::ServerVersion(action) => action.process(kms_rest_client).await?,
            Self::Sym(action) => action.process(kms_rest_client).await?,
        }

        Ok(new_config)
    }
}
