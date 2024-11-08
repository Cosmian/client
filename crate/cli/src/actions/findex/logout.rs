use std::path::PathBuf;

use clap::Parser;
use cosmian_config::{ClientConf, HttpClientConf};

use crate::error::result::CliResult;

/// Logout from the Identity Provider.
///
/// The access token will be removed from the ckms configuration file.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LogoutAction;

impl LogoutAction {
    /// Process the logout action.
    ///
    /// # Arguments
    ///
    /// * `conf_path` - The path to the ckms configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue loading or saving the configuration file.
    ///
    #[allow(clippy::print_stdout)]
    pub fn process(&self, conf_path: &PathBuf) -> CliResult<()> {
        let mut conf = ClientConf::load(conf_path)?;
        conf.findex_client_conf = Some(HttpClientConf {
            access_token: None,
            ..conf.findex_client_conf.unwrap()
        });
        conf.save(conf_path)?;

        println!("\nThe access token was removed from the KMS configuration file: {conf_path:?}");

        Ok(())
    }
}
