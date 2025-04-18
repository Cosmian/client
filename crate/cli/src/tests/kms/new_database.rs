use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_client::{KmsClient, reexport::cosmian_config_utils::ConfigUtils};
use cosmian_logger::log_init;
use predicates::prelude::*;
use tempfile::TempDir;
use test_kms_server::{
    AuthenticationOptions, DEFAULT_SQLITE_PATH, MainDBConfig, generate_invalid_conf,
    start_default_test_kms_server, start_test_server_with_options,
};
use tracing::info;

use crate::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    config::COSMIAN_CLI_CONF_ENV,
    error::result::CosmianResult,
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            shared::{ExportKeyParams, export_key},
            symmetric::create_key::create_symmetric_key,
            utils::recover_cmd_logs,
        },
    },
};

#[tokio::test]
pub(crate) async fn test_new_database() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    if ctx
        .owner_client_conf
        .kms_config
        .http_config
        .database_secret
        .is_none()
    {
        info!("Skipping test_new_database as backend not sqlite-enc");
        return Ok(());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, &ctx.owner_client_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg("new-database");
    recover_cmd_logs(&mut cmd);
    cmd.assert().success().stdout(predicate::str::contains(
        "A new user encrypted database is configured",
    ));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_secrets_bad() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    if ctx
        .owner_client_conf
        .kms_config
        .http_config
        .database_secret
        .is_none()
    {
        info!("Skipping test_secrets_bad as backend not sqlite-enc");
        return Ok(());
    }

    let bad_conf_path = generate_invalid_conf(&ctx.owner_client_conf);

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, bad_conf_path);

    cmd.arg(KMS_SUBCOMMAND)
        .arg("ec")
        .args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Database secret is wrong"));

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_conf_does_not_exist() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    if ctx
        .owner_client_conf
        .kms_config
        .http_config
        .database_secret
        .is_none()
    {
        info!("Skipping test_conf_does_not_exist as backend not sqlite-enc");
        return Ok(());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(
        COSMIAN_CLI_CONF_ENV,
        "../../test_data/configs/kms_bad_group_id.bad",
    );

    cmd.arg(KMS_SUBCOMMAND)
        .arg("ec")
        .args(vec!["keys", "create"]);
    let output = recover_cmd_logs(&mut cmd);
    assert!(!output.status.success());
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_secrets_key_bad() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    if ctx
        .owner_client_conf
        .kms_config
        .http_config
        .database_secret
        .is_none()
    {
        info!("Skipping test_secrets_key_bad as backend not sqlite-enc");
        return Ok(());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, &ctx.owner_client_conf_path);
    cmd.arg(KMS_SUBCOMMAND)
        .arg("ec")
        .args(vec!["keys", "create"]);
    cmd.assert().success();

    let invalid_conf_path = generate_invalid_conf(&ctx.owner_client_conf);
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, invalid_conf_path);

    cmd.arg(KMS_SUBCOMMAND)
        .arg("ec")
        .args(vec!["keys", "create"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();

    Ok(())
}

#[tokio::test]
async fn test_multiple_databases() -> CosmianResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    // since we are going to rewrite the config, use a different port
    let ctx = start_test_server_with_options(
        MainDBConfig {
            database_type: Some("sqlite-enc".to_owned()),
            sqlite_path: PathBuf::from(DEFAULT_SQLITE_PATH),
            clear_database: true,
            ..MainDBConfig::default()
        },
        9997,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: false,
            use_client_cert: false,
            api_token_id: None,
            api_token: None,
        },
        None,
        None,
    )
    .await?;

    // create a symmetric key in the default encrypted database
    let key_1 = create_symmetric_key(&ctx.owner_client_conf_path, CreateKeyAction::default())?;
    // export the key 1
    // Export
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_1.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })
    .unwrap();

    // create a new encrypted database
    let kms_rest_client = KmsClient::new_with_config(ctx.owner_client_conf.kms_config.clone())?;
    let new_database_secret = kms_rest_client.new_database().await?;

    // update the CLI conf
    let mut new_conf = ctx.owner_client_conf.clone();
    new_conf.kms_config.http_config.database_secret = Some(new_database_secret);
    new_conf.to_toml(&ctx.owner_client_conf_path)?;

    // create a symmetric key in the default encrypted database
    let key_2 = create_symmetric_key(&ctx.owner_client_conf_path, CreateKeyAction::default())?;
    // export the key 1
    // Export
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_2.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })
    .unwrap();

    // go back to original conf
    ctx.owner_client_conf.to_toml(&ctx.owner_client_conf_path)?;

    // we should be able to export key_1 again
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_1.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    // go to new conf
    new_conf.to_toml(&ctx.owner_client_conf_path)?;

    // we should be able to export key_2 again
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: key_2.clone(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    // stop that server
    ctx.stop_server().await?;
    Ok(())
}
