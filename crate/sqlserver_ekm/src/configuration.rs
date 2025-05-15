/// Configuration module for the SQL Server EKM.
///
/// This module handles the configuration of the SQL Server EKM client,
/// including loading configuration from various file locations and
/// serializing/deserializing configuration data.
///
/// The main components are:
/// - `choose_conf_location`: Determines the configuration file location based on a priority order.
/// - `ClientConfig`: Structure holding client configuration settings such as server URL and SSL certificates.
///
/// # Example
/// ```
/// use sqlserver_ekm::configuration::ClientConfig;
///
/// // Load client configuration from a TOML file
/// let config = ClientConfig::from_toml("path/to/config.toml").unwrap();
/// println!("Server URL: {}", config.server_url);
/// ```
use std::path::PathBuf;

use cosmian_kms_client::KmsClientConfig;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;

use crate::{
    IoSnafu,
    error::{ParseConfigSnafu, SError},
};

/// Determine the configuration file location.
///
/// This function checks for the configuration file in the following locations, in order:
/// 1. The path specified in the `COSMIAN_SQLSERVER_EKM_CONFIG` environment variable (if set).
/// 2. The `ProgramData` directory (e.g., `C:\ProgramData\cosmian\sql_server_ekm.toml` on Windows).
/// 3. The user's home directory (e.g., `~/.cosmian/sql_server_ekm.toml`) using the `etcetera` crate.
/// 4. The current working directory (e.g., `./cosmian/sql_server_ekm.toml`).
///
/// If the configuration file is not found in any of these locations, an error is returned.
///
/// # Returns
/// * `Ok(PathBuf)` - The path to the configuration file if found.
/// * `Err(SError)` - An error if the configuration file is not found.
///
/// # Errors
/// Returns an error if none of the checked locations contain the configuration file.
///
/// # Example
/// ```
/// use sqlserver_ekm::configuration::choose_conf_location;
///
/// match choose_conf_location() {
///     Ok(path) => println!("Configuration file found at: {:?}", path),
///     Err(err) => eprintln!("Error finding configuration file: {}", err),
/// }
/// ```
fn choose_conf_location() -> Result<PathBuf, SError> {
    // Check if the supplied path exists
    if let Some(path) = option_env!("COSMIAN_SQLSERVER_EKM_CONFIG").map(|s| PathBuf::from(s)) {
        if path.exists() {
            return Ok(path);
        }
    }
    if let Some(program_data) = option_env!("ProgramData").map(|s| PathBuf::from(s)) {
        let program_data_path = program_data.join("cosmian").join("sql_server_ekm.toml");
        if program_data_path.exists() {
            return Ok(program_data_path);
        }
    }
    //fetch the path from the user home directory using etcetera
    if let Ok(home_path) =
        etcetera::home_dir().map(|e| e.join("cosmian").join("sql_server_ekm.toml"))
    {
        if home_path.exists() {
            return Ok(home_path);
        }
    }
    // try the current directory
    if let Ok(current_dir) = std::env::current_dir() {
        let current_path = current_dir.join("cosmian").join("sql_server_ekm.toml");
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
    /// # Returns
    /// * `Result<ClientConfig, SError>` - The loaded configuration or an error.
    pub fn from_toml() -> Result<Self, SError> {
        let content = std::fs::read_to_string(choose_conf_location()?).context(IoSnafu {
            message: format!("Failed to read the configuration file"),
        })?;
        toml::from_str(&content).context(ParseConfigSnafu)
    }
}

impl From<ClientConfig> for KmsClientConfig {
    fn from(config: ClientConfig) -> Self {
        let mut kms_client_config = KmsClientConfig::default();
        kms_client_config.http_config.server_url = config.server_url;
        kms_client_config.http_config.accept_invalid_certs = config.accept_invalid_certs;
        kms_client_config.http_config.ssl_client_pkcs12_path = config.ssl_client_pkcs12_path;
        kms_client_config.http_config.ssl_client_pkcs12_password =
            config.ssl_client_pkcs12_password;
        kms_client_config
    }
}
