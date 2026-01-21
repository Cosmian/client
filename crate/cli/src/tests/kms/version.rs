use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_logger::{error, info, log_init};
use test_kms_server::start_default_test_kms_server;

use super::KMS_SUBCOMMAND;
use crate::{
    config::COSMIAN_CLI_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{PROG_NAME, kms::utils::recover_cmd_logs, save_kms_cli_config},
};

const SUB_COMMAND: &str = "server-version";

/// Request server-version
pub(crate) fn server_version(cli_conf_path: &str, kms_url: &str) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    // for local test use: export KMS_URL=http://host.docker.internal:9998
    let args = vec![
        "--kms-url".to_owned(),
        kms_url.to_owned(),
        "--proxy-url".to_owned(),
        "http://localhost:8888".to_owned(),
        "--proxy-basic-auth-username".to_owned(),
        "myuser".to_owned(),
        "--proxy-basic-auth-password".to_owned(),
        "mypwd".to_owned(),
    ];

    cmd.args(args).arg(KMS_SUBCOMMAND).arg(SUB_COMMAND);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        return Ok(output.to_string());
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[ignore = "reason: needs a running squid proxy"]
#[tokio::test]
pub(crate) async fn test_server_version_using_forward_proxy() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Only run this test in GitHub Actions environment
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        // Check that KMS server is reachable before running the test
        let kms_url =
            std::env::var("KMS_URL").unwrap_or_else(|_| "http://localhost:9998".to_owned());
        let response = reqwest::get(&kms_url).await;
        if response.is_err() {
            error!("KMS server at {} is not reachable", kms_url);
            return Err(CosmianError::Default(
                "KMS server is not reachable".to_string(),
            ));
        }

        info!("Running test_server_version_using_forward_proxy with KMS_URL: {kms_url}");
        server_version(&owner_client_conf_path, &kms_url)?;
    }

    Ok(())
}
