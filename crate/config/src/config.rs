use std::path::PathBuf;

use cosmian_config_utils::{location, ConfigUtils};
use cosmian_findex_config::FindexClientConfig;
use cosmian_kms_config::KmsClientConfig;
use serde::{Deserialize, Serialize};

use crate::error::CosmianConfigError;

pub const COSMIAN_CLI_CONF_ENV: &str = "COSMIAN_CLI_CONF";
pub(crate) const COSMIAN_CLI_CONF_DEFAULT_SYSTEM_PATH: &str = "/etc/cosmian/cosmian.toml";
pub(crate) const COSMIAN_CLI_CONF_PATH: &str = ".cosmian/cosmian.toml";

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct ClientConf {
    pub kms_config: KmsClientConfig,
    pub findex_config: Option<FindexClientConfig>,
}

impl Default for ClientConf {
    fn default() -> Self {
        Self {
            kms_config: KmsClientConfig::default(),
            findex_config: Some(FindexClientConfig::default()),
        }
    }
}

/// This method is used to configure the KMS CLI by reading a JSON configuration file.
///
/// The method looks for a JSON configuration file with the following structure:
///
/// ```json
/// {
///     "accept_invalid_certs": false,
///     "server_url": "http://127.0.0.1:9998",
///     "access_token": "AA...AAA",
///     "database_secret": "BB...BBB",
///     "ssl_client_pkcs12_path": "/path/to/client.p12",
///     "ssl_client_pkcs12_password": "password"
/// }
/// ```
/// The path to the configuration file is specified through the `COSMIAN_CLI_CONF` environment variable.
/// If the environment variable is not set, a default path is used.
/// If the configuration file does not exist at the path, a new file is created with default values.
///
/// This function returns a KMS client configured according to the settings specified in the configuration file.
impl ClientConf {
    pub fn location(conf: Option<PathBuf>) -> Result<PathBuf, CosmianConfigError> {
        Ok(location(
            conf,
            COSMIAN_CLI_CONF_ENV,
            COSMIAN_CLI_CONF_PATH,
            COSMIAN_CLI_CONF_DEFAULT_SYSTEM_PATH,
        )?)
    }
}

impl ConfigUtils for ClientConf {}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use cosmian_config_utils::{get_default_conf_path, ConfigUtils};
    use cosmian_logger::log_init;

    use super::{ClientConf, COSMIAN_CLI_CONF_ENV};
    use crate::config::COSMIAN_CLI_CONF_PATH;

    #[test]
    pub(crate) fn test_load() {
        log_init(None);
        // valid conf
        unsafe {
            env::set_var(COSMIAN_CLI_CONF_ENV, "../../test_data/configs/cosmian.toml");
        }
        let conf_path = ClientConf::location(None).unwrap();
        assert!(ClientConf::load(&conf_path).is_ok());

        // another valid conf
        unsafe {
            env::set_var(
                COSMIAN_CLI_CONF_ENV,
                "../../test_data/configs/cosmian_partial.toml",
            );
        }
        let conf_path = ClientConf::location(None).unwrap();
        assert!(ClientConf::load(&conf_path).is_ok());

        // Default conf file
        unsafe {
            env::remove_var(COSMIAN_CLI_CONF_ENV);
        }
        let _ = fs::remove_file(get_default_conf_path(COSMIAN_CLI_CONF_PATH).unwrap());
        let conf_path = ClientConf::location(None).unwrap();
        assert!(ClientConf::load(&conf_path).is_ok());
        assert!(
            get_default_conf_path(COSMIAN_CLI_CONF_PATH)
                .unwrap()
                .exists()
        );

        // invalid conf
        unsafe {
            env::set_var(
                COSMIAN_CLI_CONF_ENV,
                "../../test_data/configs/cosmian.bad.toml",
            );
        }
        let conf_path = ClientConf::location(None).unwrap();
        let e = ClientConf::load(&conf_path).err().unwrap().to_string();
        assert!(e.contains("missing field `server_url`"));

        // with a file
        unsafe {
            env::remove_var(COSMIAN_CLI_CONF_ENV);
        }
        let conf_path =
            ClientConf::location(Some(PathBuf::from("../../test_data/configs/cosmian.toml")))
                .unwrap();

        assert!(ClientConf::load(&conf_path).is_ok());
    }
}
