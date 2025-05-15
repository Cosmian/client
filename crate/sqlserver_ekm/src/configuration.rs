use std::path::PathBuf;

use cosmian_kms_client::KmsClientConfig;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use tracing::debug;

use crate::{IoSnafu, error::SError};

/// Determine the configuration file location.
///
/// The function checks the following locations in order:
/// 1. The supplied path (if provided)
/// 2. The ProgramData directory (if available)
/// 3. The user's home directory
/// 4. The current directory
/// 5. If none of the above locations exist, it returns an error.
///
/// # Arguments
/// * `supplied` - An optional path to check first.
///
/// # Returns
/// * `Ok(PathBuf)` - The path to the configuration file.
/// * `Err(SError)` - An error if the configuration file is not found.
fn choose_conf_location(supplied: Option<PathBuf>) -> Result<PathBuf, SError> {
    // Check if the supplied path exists
    if let Some(path) = supplied {
        if path.exists() {
            return Ok(path);
        }
    }
    if let Some(program_data) = option_env!("ProgramData").map(|s| PathBuf::from(s)) {
        let program_data_path = program_data.join("cosmian");
        if program_data_path.exists() {
            return Ok(program_data_path);
        }
    }
    //fetch the path from the user home directory using etcetera
    if let Ok(home_path) = etcetera::home_dir().map(|e| e.join("cosmian")) {
        if home_path.exists() {
            return Ok(home_path);
        }
    }
    // try the current directory
    if let Ok(current_dir) = std::env::current_dir() {
        let current_path = current_dir.join("cosmian");
        if current_path.exists() {
            return Ok(current_path);
        }
    }
    // whatever...
    whatever!("Unable to find the configuration file. Please provide a valid path.");
}

/// used for serialization
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn not(b: &bool) -> bool {
    !*b
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct ClientConfig {
    // accept_invalid_certs is useful if the cli needs to connect to an HTTPS server
    // running an invalid or unsecure SSL certificate
    #[serde(default)]
    #[serde(skip_serializing_if = "not")]
    pub accept_invalid_certs: bool,

    pub server_url: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_client_pkcs12_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_client_pkcs12_password: Option<String>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub verified_cert: Option<String>,
}

impl ClientConfig {
    /// Load the ClientConfig from a toml file.
    ///
    /// # Arguments
    /// * `path` - The path to the toml file.
    ///
    /// # Returns
    /// * `Result<ClientConfig, SError>` - The loaded configuration or an error.
    pub fn from_toml(path: &str) -> Result<Self, SError> {
        let content = std::fs::read_to_string(path).context(IoSnafu {
            message: format!("Failed to read configuration file: {}", path),
        })?;

        toml::from_str(&content).context(ParseSnafu {
            message: "Failed to parse configuration file as TOML",
        })
    }
}
