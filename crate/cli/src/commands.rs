use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use cosmian_config::ClientConf;
use cosmian_findex_client::FindexClient;
use cosmian_kms_cli::{kms_process, KmsActions};
use cosmian_kms_client::KmsClient;
use cosmian_logger::log_init;
use tracing::info;

use crate::{
    actions::{findex::FindexActions, markdown::MarkdownAction},
    cli_error,
    error::result::CosmianResult,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommands,

    /// Configuration file location
    ///
    /// This is an alternative to the env variable `KMS_CLI_CONF`.
    /// Takes precedence over `KMS_CLI_CONF` env variable.
    #[arg(short, long)]
    pub conf: Option<PathBuf>,

    /// The URL of the KMS
    #[arg(long, action)]
    pub kms_url: Option<String>,

    /// The URL of the Findex server
    #[arg(long, action)]
    pub findex_url: Option<String>,

    /// Allow to connect using a self-signed cert or untrusted cert chain
    ///
    /// `accept_invalid_certs` is useful if the CLI needs to connect to an HTTPS KMS server
    /// running an invalid or insecure SSL certificate
    #[arg(long)]
    pub accept_invalid_certs: Option<bool>,

    /// Output the KMS JSON KMIP request and response.
    /// This is useful to understand JSON POST requests and responses
    /// required to programmatically call the KMS on the `/kmip/2_1` endpoint
    #[arg(long, default_value = "false")]
    pub json: bool,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum CliCommands {
    /// Handle KMS actions
    #[command(subcommand)]
    Kms(KmsActions),
    /// Handle Findex server actions
    #[command(subcommand)]
    Findex(FindexActions),
    /// Action to auto-generate doc in Markdown format
    /// Run `cargo run --bin ckms -- markdown documentation/docs/cli/main_commands.md`
    #[clap(hide = true)]
    Markdown(MarkdownAction),
}

/// Main function for the CKMS CLI application.
///
/// This function initializes logging, parses command-line arguments, and executes the appropriate
/// command based on the provided arguments. It supports various subcommands for interacting with
/// the CKMS, such as login, logout, locating objects, and more.
///
/// # Errors
///
/// This function will return an error if:
/// - The logging initialization fails.
/// - The command-line arguments cannot be parsed.
/// - The configuration file cannot be located or loaded.
/// - Any of the subcommands fail during their execution.
pub async fn cosmian_main() -> CosmianResult<()> {
    log_init(None);
    let opts = Cli::parse();

    let conf_path = ClientConf::location(opts.conf)?;
    let mut conf = ClientConf::load(&conf_path)?;

    // todo(manu): dispatch options directly in sub actions
    // Override the KMS options from the command line
    if let Some(kms_url) = opts.kms_url {
        info!(
            "Override KMS URL from configuration file with: {:?}",
            kms_url
        );
        conf.kms_config.http_config.server_url = kms_url;
    }
    if let Some(accept_invalid_certs) = opts.accept_invalid_certs {
        info!(
            "Override KMS and Findex-server `accept_invalid_certs` from configuration file with: \
             {:?}",
            accept_invalid_certs
        );
        conf.kms_config.http_config.accept_invalid_certs = accept_invalid_certs;
        // conf.findex_config.http_config.accept_invalid_certs = accept_invalid_certs;
    }
    // if let Some(findex_url) = opts.findex_url {
    //     info!(
    //         "Override Findex URL from configuration file with: {:?}",
    //         findex_url
    //     );
    //     conf.findex_config.http_config.server_url = findex_url;
    // }
    info!(
        "Override JSON from configuration file with: {:?}",
        opts.json
    );
    conf.kms_config.print_json = Some(opts.json);

    // Instantiate the KMS and Findex clients
    let kms_rest_client = KmsClient::new(conf.kms_config)?;

    match opts.command {
        CliCommands::Markdown(action) => {
            let command = <Cli as CommandFactory>::command();
            action.process(&command)?;
            return Ok(())
        }
        CliCommands::Kms(kms_actions) => {
            kms_process(kms_actions, kms_rest_client).await?;
        }
        CliCommands::Findex(findex_actions) => {
            let findex_config = conf.findex_config.ok_or_else(|| {
                cli_error!("Findex configuration is missing in the configuration file")
            })?;
            let findex_rest_client = FindexClient::new(findex_config)?;
            findex_actions
                .run(findex_rest_client, &kms_rest_client)
                .await?;
        }
    }

    Ok(())
}
