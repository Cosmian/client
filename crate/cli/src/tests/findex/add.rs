use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_config::COSMIAN_CLI_CONF_ENV;
use tracing::debug;

use crate::{
    actions::encrypt_and_add::EncryptAndAddAction,
    error::{result::CosmianResult, CosmianError},
    tests::{utils::recover_cmd_logs, PROG_NAME},
};

#[allow(clippy::unwrap_used)]
pub(crate) fn add_cmd(cli_conf_path: &str, action: EncryptAndAddAction) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    let mut args = vec![
        "encrypt-and-add".to_owned(),
        "--key".to_owned(),
        action.findex_parameters.key.clone(),
        "--label".to_owned(),
        action.findex_parameters.label,
        "--index-id".to_owned(),
        action.findex_parameters.index_id.to_string(),
        "--csv".to_owned(),
        action.csv.to_str().unwrap().to_owned(),
        "--kek-id".to_owned(),
        action.key_encryption_key_id.to_string(),
    ];
    if let Some(nonce) = action.nonce {
        args.push("--nonce".to_owned());
        args.push(nonce.to_string());
    }
    if let Some(authentication_data) = action.authentication_data {
        args.push("--authentication_data".to_owned());
        args.push(authentication_data.to_string());
    }

    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    cmd.arg("findex").args(args);
    debug!("cmd: {:?}", cmd);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let findex_output = std::str::from_utf8(&output.stdout)?;
        return Ok(findex_output.to_owned());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}
