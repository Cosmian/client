use std::{
    path::{Path, PathBuf},
    process::Command,
};

use assert_cmd::prelude::CommandCargoExt;
use base64::{Engine as _, engine::general_purpose};
use cosmian_kms_cli::{
    actions::kms::{
        secret_data::create_secret::CreateSecretDataAction,
        symmetric::keys::create_key::CreateKeyAction,
    },
    reexport::{
        cosmian_kms_client::{
            cosmian_kmip::kmip_2_1::kmip_types::{EncodingOption, WrappingMethod},
            read_object_from_json_ttlv_file,
        },
        cosmian_kms_crypto::reexport::cosmian_crypto_core::{
            CsRng,
            reexport::rand_core::{RngCore, SeedableRng},
        },
    },
};
use cosmian_logger::log_init;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    config::COSMIAN_CLI_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            secret_data::create_secret::create_secret_data,
            symmetric::create_key::create_symmetric_key,
            utils::{extract_uids::extract_wrapping_key, recover_cmd_logs},
        },
        save_kms_cli_config,
    },
};

/// Export an object (secret data or key) using the CLI command
pub(crate) fn export_object(
    cli_conf_path: &str,
    sub_command: &str,
    object_id: &str,
    object_file: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    let args: Vec<String> = if sub_command == "sym" {
        vec![
            "sym".to_owned(),
            "keys".to_owned(),
            "export".to_owned(),
            "--key-id".to_owned(),
            object_id.to_owned(),
            object_file.to_owned(),
        ]
    } else {
        vec![
            sub_command.to_owned(),
            "export".to_owned(),
            "--key-id".to_owned(),
            object_id.to_owned(),
            object_file.to_owned(),
        ]
    };

    cmd.arg(KMS_SUBCOMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Export a secret data using the CLI command
pub(crate) fn export_secret_data(
    cli_conf_path: &str,
    secret_id: &str,
    secret_file: &str,
) -> CosmianResult<()> {
    export_object(cli_conf_path, "secret-data", secret_id, secret_file)
}

/// Wrap a secret data using the CLI command
#[allow(clippy::too_many_arguments)]
pub(crate) fn wrap_secret_data(
    cli_conf_path: &str,
    key_file_in: &Path,
    key_file_out: Option<&PathBuf>,
    wrap_password: Option<String>,
    wrap_key_b64: Option<String>,
    wrap_key_id: Option<String>,
    wrap_key_file: Option<PathBuf>,
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    let mut args: Vec<String> = vec![
        "secret-data".to_owned(),
        "wrap".to_owned(),
        key_file_in.to_str().unwrap().to_owned(),
    ];

    if let Some(key_file_out) = key_file_out {
        args.push(key_file_out.to_str().unwrap().to_owned());
    }

    if let Some(wrap_password) = wrap_password {
        args.push("--wrap-password".to_owned());
        args.push(wrap_password);
    } else if let Some(wrap_key_b64) = wrap_key_b64 {
        args.push("--wrap-key-b64".to_owned());
        args.push(wrap_key_b64);
    } else if let Some(wrap_key_id) = wrap_key_id {
        args.push("--wrap-key-id".to_owned());
        args.push(wrap_key_id);
    } else if let Some(wrap_key_file) = wrap_key_file {
        args.push("--wrap-key-file".to_owned());
        args.push(wrap_key_file.to_str().unwrap().to_owned());
    }

    cmd.arg(KMS_SUBCOMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let wrap_output = std::str::from_utf8(&output.stdout)?;
        let b64_wrapping_key = extract_wrapping_key(wrap_output)
            .unwrap_or_default()
            .to_owned();
        return Ok(b64_wrapping_key);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Unwrap a secret data using the CLI command
#[allow(clippy::too_many_arguments)]
pub(crate) fn unwrap_secret_data(
    cli_conf_path: &str,
    key_file_in: &Path,
    key_file_out: Option<&PathBuf>,
    unwrap_key_b64: Option<String>,
    unwrap_key_id: Option<String>,
    unwrap_key_file: Option<PathBuf>,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    let mut args: Vec<String> = vec![
        "secret-data".to_owned(),
        "unwrap".to_owned(),
        key_file_in.to_str().unwrap().to_owned(),
    ];

    if let Some(key_file_out) = key_file_out {
        args.push(key_file_out.to_str().unwrap().to_owned());
    }

    if let Some(unwrap_key_b64) = unwrap_key_b64 {
        args.push("--unwrap-key-b64".to_owned());
        args.push(unwrap_key_b64);
    } else if let Some(unwrap_key_id) = unwrap_key_id {
        args.push("--unwrap-key-id".to_owned());
        args.push(unwrap_key_id);
    } else if let Some(unwrap_key_file) = unwrap_key_file {
        args.push("--unwrap-key-file".to_owned());
        args.push(unwrap_key_file.to_str().unwrap().to_owned());
    }

    cmd.arg(KMS_SUBCOMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Test secret data wrap and unwrap using password
#[tokio::test]
pub(crate) async fn test_secret_data_wrap_unwrap_with_password() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let temp_dir = TempDir::new()?;

    // Create a secret data
    let secret_data_id = create_secret_data(
        &owner_client_conf_path,
        &CreateSecretDataAction {
            secret_value: Some("test-secret-password".to_owned()),
            tags: vec!["test".to_owned()],
            ..Default::default()
        },
    )?;

    // Export the secret data to a file
    let secret_file = temp_dir.path().join("secret.json");
    export_secret_data(
        &owner_client_conf_path,
        &secret_data_id,
        secret_file.to_str().unwrap(),
    )?;

    // Read the original secret data bytes
    let original_object = read_object_from_json_ttlv_file(&secret_file)?;
    let original_secret_bytes = original_object.key_block()?.key_bytes()?;

    // Wrap the secret data using a password
    let b64_wrapping_key = wrap_secret_data(
        &owner_client_conf_path,
        &secret_file,
        None,
        Some("password123".to_owned()),
        None,
        None,
        None,
    )?;

    // Verify the secret data is now wrapped
    let wrapped_object = read_object_from_json_ttlv_file(&secret_file)?;
    assert!(wrapped_object.key_wrapping_data().is_some());
    assert_eq!(
        wrapped_object.key_wrapping_data().unwrap().wrapping_method,
        WrappingMethod::Encrypt
    );
    assert_eq!(
        wrapped_object.key_wrapping_data().unwrap().encoding_option,
        Some(EncodingOption::TTLVEncoding)
    );
    assert_ne!(
        wrapped_object.key_block()?.wrapped_key_bytes()?,
        original_secret_bytes
    );

    // Unwrap the secret data using the returned base64 key
    unwrap_secret_data(
        &owner_client_conf_path,
        &secret_file,
        None,
        Some(b64_wrapping_key),
        None,
        None,
    )?;

    // Verify the secret data is unwrapped and matches the original
    let unwrapped_object = read_object_from_json_ttlv_file(&secret_file)?;
    assert!(unwrapped_object.key_wrapping_data().is_none());
    assert_eq!(
        unwrapped_object.key_block()?.key_bytes()?,
        original_secret_bytes
    );

    Ok(())
}

/// Test secret data wrap and unwrap using base64 encoded key
#[tokio::test]
pub(crate) async fn test_secret_data_wrap_unwrap_with_base64_key() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let temp_dir = TempDir::new()?;

    // Create a secret data
    let secret_data_id = create_secret_data(
        &owner_client_conf_path,
        &CreateSecretDataAction {
            secret_value: Some("another-test-secret".to_owned()),
            tags: vec!["test-b64".to_owned()],
            ..Default::default()
        },
    )?;

    // Export the secret data to a file
    let secret_file = temp_dir.path().join("secret_b64.json");
    export_secret_data(
        &owner_client_conf_path,
        &secret_data_id,
        secret_file.to_str().unwrap(),
    )?;

    // Read the original secret data bytes
    let original_object = read_object_from_json_ttlv_file(&secret_file)?;
    let original_secret_bytes = original_object.key_block()?.key_bytes()?;

    // Generate a random 32-byte key and encode it as base64
    let mut rng = CsRng::from_entropy();
    let mut wrapping_key = vec![0u8; 32];
    rng.fill_bytes(&mut wrapping_key);
    let key_b64 = general_purpose::STANDARD.encode(&wrapping_key);

    // Wrap the secret data using the base64 key
    wrap_secret_data(
        &owner_client_conf_path,
        &secret_file,
        None,
        None,
        Some(key_b64.clone()),
        None,
        None,
    )?;

    // Verify the secret data is now wrapped
    let wrapped_object = read_object_from_json_ttlv_file(&secret_file)?;
    assert!(wrapped_object.key_wrapping_data().is_some());
    assert_eq!(
        wrapped_object.key_wrapping_data().unwrap().wrapping_method,
        WrappingMethod::Encrypt
    );
    assert_eq!(
        wrapped_object.key_wrapping_data().unwrap().encoding_option,
        Some(EncodingOption::TTLVEncoding)
    );
    assert_ne!(
        wrapped_object.key_block()?.wrapped_key_bytes()?,
        original_secret_bytes
    );

    // Unwrap the secret data using the same base64 key
    unwrap_secret_data(
        &owner_client_conf_path,
        &secret_file,
        None,
        Some(key_b64),
        None,
        None,
    )?;

    // Verify the secret data is unwrapped and matches the original
    let unwrapped_object = read_object_from_json_ttlv_file(&secret_file)?;
    assert!(unwrapped_object.key_wrapping_data().is_none());
    assert_eq!(
        unwrapped_object.key_block()?.key_bytes()?,
        original_secret_bytes
    );

    Ok(())
}

/// Test secret data wrap and unwrap using a key stored in the KMS (using key ID)
///
/// Note: This test is currently disabled because of a limitation where
/// symmetric keys in Raw format are not supported for wrapping in the
/// current implementation. The wrap functionality works with:
/// - Password-derived keys
/// - Base64-encoded keys
/// - Some specific key file formats (not Raw)
#[tokio::test]
pub(crate) async fn test_secret_data_wrap_unwrap_with_kms_key() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let temp_dir = TempDir::new()?;

    // Create a symmetric key in the KMS for wrapping
    let wrapping_key_id =
        create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;

    // Create a secret data
    let secret_data_id = create_secret_data(
        &owner_client_conf_path,
        &CreateSecretDataAction {
            secret_value: Some("kms-wrapped-secret".to_owned()),
            tags: vec!["test-kms".to_owned()],
            ..Default::default()
        },
    )?;

    // Export the secret data to a file
    let secret_file = temp_dir.path().join("secret_kms.json");
    export_secret_data(
        &owner_client_conf_path,
        &secret_data_id,
        secret_file.to_str().unwrap(),
    )?;

    // Read the original secret data bytes
    let original_object = read_object_from_json_ttlv_file(&secret_file)?;
    let original_secret_bytes = original_object.key_block()?.key_bytes()?;

    // Wrap the secret data using the KMS key ID (not file)
    wrap_secret_data(
        &owner_client_conf_path,
        &secret_file,
        None,
        None,
        None,
        Some(wrapping_key_id.clone()),
        None,
    )?;

    // Verify the secret data is now wrapped
    let wrapped_object = read_object_from_json_ttlv_file(&secret_file)?;
    assert!(wrapped_object.key_wrapping_data().is_some());
    assert_eq!(
        wrapped_object.key_wrapping_data().unwrap().wrapping_method,
        WrappingMethod::Encrypt
    );
    assert_eq!(
        wrapped_object.key_wrapping_data().unwrap().encoding_option,
        Some(EncodingOption::TTLVEncoding)
    );
    assert_ne!(
        wrapped_object.key_block()?.wrapped_key_bytes()?,
        original_secret_bytes
    );

    // Unwrap the secret data using the same KMS key ID
    unwrap_secret_data(
        &owner_client_conf_path,
        &secret_file,
        None,
        None,
        Some(wrapping_key_id),
        None,
    )?;

    // Verify the secret data is unwrapped and matches the original
    let unwrapped_object = read_object_from_json_ttlv_file(&secret_file)?;
    assert!(unwrapped_object.key_wrapping_data().is_none());
    assert_eq!(
        unwrapped_object.key_block()?.key_bytes()?,
        original_secret_bytes
    );

    Ok(())
}
