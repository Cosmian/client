use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use base64::Engine;
use cosmian_kms_client::read_object_from_json_ttlv_file;
use cosmian_logger::log_init;
use tempfile::TempDir;
use test_kms_server::{
    AuthenticationOptions, MainDBConfig, TestsContext, start_test_server_with_options,
};
use tokio::fs;
use tracing::{info, trace};

use super::{KMS_SUBCOMMAND, utils::recover_cmd_logs};
use crate::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    config::COSMIAN_CLI_CONF_ENV,
    error::result::CosmianResult,
    tests::{
        PROG_NAME,
        kms::{
            access::SUB_COMMAND,
            shared::{ExportKeyParams, export_key},
            symmetric::create_key::create_symmetric_key,
        },
    },
};

fn run_owned_cli_command(owner_client_conf_path: &str) {
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(COSMIAN_CLI_CONF_ENV, owner_client_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(vec!["owned"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().success();
}

/// This function runs the CLI command with the provided configuration path and expects it to fail.
fn run_owned_cli_command_expect_failure(owner_client_conf_path: &str) {
    let mut cmd = Command::cargo_bin(PROG_NAME).expect(" cargo bin failed");
    cmd.env(COSMIAN_CLI_CONF_ENV, owner_client_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(vec!["owned"]);
    recover_cmd_logs(&mut cmd);
    cmd.assert().failure();
}

fn create_api_token(ctx: &TestsContext) -> CosmianResult<(String, String)> {
    // Create and export an API token
    let api_token_id =
        create_symmetric_key(&ctx.owner_client_conf_path, CreateKeyAction::default())?;
    trace!("Symmetric key created of unique identifier: {api_token_id:?}");

    // Export as default (JsonTTLV with Raw Key Format Type)
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: api_token_id.clone(),
        key_file: tmp_path.join("api_token").to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    let api_token = base64::engine::general_purpose::STANDARD.encode(
        read_object_from_json_ttlv_file(&tmp_path.join("api_token"))?
            .key_block()?
            .symmetric_key_bytes()?,
    );
    trace!("API token created: {api_token}");
    Ok((api_token_id, api_token))
}

// let us not make other test cases fail
const DEFAULT_KMS_SERVER_PORT: u16 = 9998;
const PORT: u16 = DEFAULT_KMS_SERVER_PORT + 5; // +5 since there are other KMS test servers running
// in parallel (see test_server.rs)

#[tokio::test]
pub(crate) async fn test_kms_all_authentications() -> CosmianResult<()> {
    // log_init(Some("error,cosmian_kms_server=info,cosmian_cli=info"));
    log_init(option_env!("RUST_LOG"));

    // delete the temp db dir holding `sqlite-data-auth-tests/kms.db`
    let _e = fs::remove_dir_all(PathBuf::from("./cosmian-kms")).await;

    // plaintext no auth
    info!("==> Testing server with no auth");
    let ctx = start_test_server_with_options(
        MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
            clear_database: true,
            ..MainDBConfig::default()
        },
        PORT,
        AuthenticationOptions::default(),
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    // Create an API auth token with admin rights for later
    let (api_token_id, api_token) = create_api_token(&ctx)?;
    ctx.stop_server().await?;

    let default_db_config = MainDBConfig {
        database_type: Some("sqlite".to_owned()),
        sqlite_path: PathBuf::from("./sqlite-data-auth-tests"),
        clear_database: false,
        ..MainDBConfig::default()
    };

    // plaintext JWT token auth
    info!("==> Testing server with JWT token over HTTP");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // tls token auth
    info!("==> Testing server with JWT token auth over HTTPS");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // Client Certificate authentication
    info!("==> Testing server with Client Certificate auth");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_https: true,
            use_client_cert: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 1: Both Client Certificates and JWT authentication enabled, user presents JWT token only
    info!(
        "==> Testing server with both Client Certificates and JWT auth - User sends JWT token only"
    );
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            use_client_cert: true,
            api_token_id: None,
            api_token: None,
            do_not_send_client_certificate: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 2: Both Client Certificates and API token authentication enabled, user presents API token only
    info!(
        "==> Testing server with both Client Certificates and API token auth -User sends API \
         token only"
    );
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: false,
            use_https: true,
            use_client_cert: true,
            api_token_id: Some(api_token_id.clone()),
            api_token: Some(api_token.clone()),
            do_not_send_client_certificate: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 3: Both JWT and API token authentication enabled, user presents API token only
    info!("==> Testing server with both JWT and API token auth - User sends the API token only");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            api_token_id: Some(api_token_id.clone()),
            api_token: Some(api_token.clone()),
            do_not_send_jwt_token: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 4: JWT authentication enabled, no token provided (failure case)
    info!("==> Testing server with JWT auth - User does not send the token (should fail)");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            do_not_send_jwt_token: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command_expect_failure(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 5: Client Certificate authentication enabled, no certificate provided (failure case)
    info!("==> Testing server with Client Certificate auth - missing certificate (should fail)");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_https: true,
            use_client_cert: true,
            do_not_send_client_certificate: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command_expect_failure(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 6: API token authentication enabled, no token provided (failure case)
    info!("==> Testing server with API token auth - missing token (should fail)");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_https: true,
            api_token_id: Some(api_token_id.clone()),
            api_token: Some(api_token.clone()),
            do_not_send_api_token: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command_expect_failure(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // SCENARIO 7: JWT authentication enabled, but no JWT token presented (failure case)
    info!("===> Testing server with JWT auth - but no JWT token sent (should fail)");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            do_not_send_jwt_token: true,
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command_expect_failure(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // Bad API token auth but JWT auth used at first
    info!("==> Testing server with bad API token auth but JWT auth used at first");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            api_token_id: Some("my_bad_token_id".to_owned()),
            api_token: Some("my_bad_token".to_owned()),
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // Bad API token auth, but cert auth used at first
    info!("==> Testing server with bad API token auth but cert auth used at first");
    let ctx = start_test_server_with_options(
        default_db_config.clone(),
        PORT,
        AuthenticationOptions {
            use_https: true,
            use_client_cert: true,
            api_token_id: Some("my_bad_token_id".to_string()),
            api_token: Some("my_bad_token".to_string()),
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // Bad API token and good JWT token auth but still cert auth used at first
    info!(
        "==> Testing server with bad API token and good JWT token auth but still cert auth used \
         at first"
    );
    let ctx = start_test_server_with_options(
        default_db_config,
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            use_client_cert: true,
            api_token_id: Some("my_bad_token_id".to_string()),
            api_token: Some("my_bad_token".to_string()),
            ..Default::default()
        },
        None,
        None,
        None,
    )
    .await?;
    run_owned_cli_command(&ctx.owner_client_conf_path);
    ctx.stop_server().await?;

    // delete the temp db dir
    let _e = fs::remove_dir_all(PathBuf::from("./cosmian-kms")).await;
    Ok(())
}
