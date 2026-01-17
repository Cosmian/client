#![allow(deprecated)]

use std::{env, path::Path};

use cosmian_config_utils::ConfigUtils;
use test_kms_server::TestsContext;

use crate::config::ClientConfig;

pub(crate) const PROG_NAME: &str = "cosmian";

pub(crate) mod kms;

pub(crate) fn save_kms_cli_config(kms_ctx: &TestsContext) -> (String, String) {
    let owner_file_path = env::temp_dir()
        .join(format!("owner_{}.toml", kms_ctx.server_port))
        .to_string_lossy()
        .into_owned();
    if !Path::new(&owner_file_path).exists() {
        let conf = ClientConfig {
            kms_config: kms_ctx.owner_client_config.clone(),
            findex_config: None,
        };
        conf.to_toml(&owner_file_path)
            .expect("Failed to save owner test config");
    }

    let user_file_path = env::temp_dir()
        .join(format!("user_{}.toml", kms_ctx.server_port))
        .to_string_lossy()
        .into_owned();
    if !Path::new(&user_file_path).exists() {
        let conf = ClientConfig {
            kms_config: kms_ctx.user_client_config.clone(),
            findex_config: None,
        };
        conf.to_toml(&user_file_path)
            .expect("Failed to save user test config");
    }

    (owner_file_path, user_file_path)
}

pub(crate) fn force_save_kms_cli_config(kms_ctx: &TestsContext) -> (String, String) {
    let owner_file_path = env::temp_dir()
        .join(format!("owner_{}.toml", kms_ctx.server_port))
        .to_string_lossy()
        .into_owned();
    let conf = ClientConfig {
        kms_config: kms_ctx.owner_client_config.clone(),
        findex_config: None,
    };
    conf.to_toml(&owner_file_path)
        .expect("Failed to save owner test config");

    let user_file_path = env::temp_dir()
        .join(format!("user_{}.toml", kms_ctx.server_port))
        .to_string_lossy()
        .into_owned();
    let conf = ClientConfig {
        kms_config: kms_ctx.user_client_config.clone(),
        findex_config: None,
    };
    conf.to_toml(&user_file_path)
        .expect("Failed to save user test config");

    (owner_file_path, user_file_path)
}
