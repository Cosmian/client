use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_config::COSMIAN_CLI_CONF_ENV;
use tracing::debug;

use crate::{
    actions::search_and_decrypt::SearchAndDecryptAction,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, utils::recover_cmd_logs},
};

pub(crate) fn search_cmd(
    cli_conf_path: &str,
    action: SearchAndDecryptAction,
) -> CosmianResult<String> {
    let mut args = vec![
        "search-and-decrypt".to_owned(),
        "--key".to_owned(),
        action.findex_parameters.key.clone(),
        "--label".to_owned(),
        action.findex_parameters.label,
        "--index-id".to_owned(),
        action.findex_parameters.index_id.to_string(),
        "--kek-id".to_owned(),
        action.key_encryption_key_id.to_string(),
    ];
    if let Some(authentication_data) = action.authentication_data {
        args.push("--authentication_data".to_owned());
        args.push(authentication_data);
    }

    for word in action.keyword {
        args.push("--keyword".to_owned());
        args.push(word);
    }
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    cmd.arg("findex-server").args(args);
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
