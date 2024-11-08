use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_config::KMS_CLI_CONF_ENV;
use tracing::debug;

use crate::{
    actions::findex::add_or_delete::AddOrDeleteAction,
    error::{result::CliResult, CliError},
    tests::kms::{utils::recover_cmd_logs, PROG_NAME},
};

#[allow(clippy::unwrap_used)]
pub(crate) fn add_or_delete_cmd(
    cli_conf_path: &str,
    command: &str,
    action: AddOrDeleteAction,
) -> CliResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    let args = vec![
        command.to_owned(),
        "--key".to_owned(),
        action.findex_parameters.key.clone(),
        "--label".to_owned(),
        action.findex_parameters.label,
        "--index-id".to_owned(),
        action.findex_parameters.index_id.to_string(),
        "--csv".to_owned(),
        action.csv.to_str().unwrap().to_owned(),
    ];
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    cmd.arg("findex").args(args);
    debug!("cmd: {:?}", cmd);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let findex_output = std::str::from_utf8(&output.stdout)?;
        return Ok(findex_output.to_owned());
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}
