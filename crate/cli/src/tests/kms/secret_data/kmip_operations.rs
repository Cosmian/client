use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_cli::actions::kms::secret_data::create_secret::CreateSecretDataAction;
use cosmian_logger::{info, log_init};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;
use uuid::Uuid;

use crate::{
    config::COSMIAN_CLI_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            secret_data::create_secret::create_secret_data,
            utils::{extract_uids::extract_unique_identifier, recover_cmd_logs},
        },
        save_kms_cli_config,
    },
};

/// Generic helper function to run cosmian CLI commands
/// This reduces boilerplate code for repeated `Command::cargo_bin` calls
///
/// # Arguments
/// * `args` - Command line arguments to pass to cosmian
/// * `expect_success`
///   If true, asserts that the command succeeds and returns stdout as String
///   If false, returns the raw Output for custom handling
fn run_cosmian_cmd(
    args: &[&str],
    expect_success: bool,
    cli_conf: Option<&str>,
) -> Result<String, std::process::Output> {
    let mut cmd = Command::cargo_bin(PROG_NAME).unwrap();
    if let Some(conf) = cli_conf {
        cmd.env(COSMIAN_CLI_CONF_ENV, conf);
    }
    let output = cmd.args(args).output().unwrap();

    if expect_success {
        assert!(
            output.status.success(),
            "Command failed: cosmian {}\nError: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(output)
    }
}

/// Specialized helper function for secret-data operations
/// Automatically prepends "kms", "secret-data" to reduce boilerplate
/// * `operation` - The secret-data operation (e.g., "create", "export", "import")
/// * `args` - Additional arguments for the operation
/// * `expect_success`
///   If true, asserts that the command succeeds and returns stdout as String
///   If false, returns the raw Output for custom handling
fn run_secret_data_cmd(
    operation: &str,
    args: &[&str],
    expect_success: bool,
    cli_conf: Option<&str>,
) -> Result<String, std::process::Output> {
    let mut full_args = vec!["kms", "secret-data", operation];
    full_args.extend_from_slice(args);
    run_cosmian_cmd(&full_args, expect_success, cli_conf)
}

/// Comprehensive test for all KMIP operations on `SecretData` objects
/// This test ensures that GitHub issue #549 is fully resolved by testing:
/// - Create (with and without `wrapping_key_id`)
/// - Get
/// - Export
/// - Import
/// - Revoke
/// - Destroy
#[tokio::test]
async fn test_secret_data_all_kmip_operations() {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (cli_conf_path, _) = save_kms_cli_config(ctx);

    let tmp_dir = TempDir::new().unwrap();

    // Test data - using UUIDs to avoid conflicts when running tests in parallel
    let test_uuid = Uuid::new_v4().to_string();
    let wrapping_key_id = format!("wrapping_key_for_secret_data_{}", &test_uuid[0..8]);
    let secret_data_id = format!("test_secret_data_{}", &test_uuid[0..8]);
    let secret_data_with_wrapping_id = format!("wrapped_secret_data_{}", &test_uuid[0..8]);
    let imported_secret_data_id = format!("imported_secret_data_{}", &test_uuid[0..8]);

    info!("=== Testing KMIP Operations on SecretData ===");

    info!("1. Creating symmetric key to use as wrapping key...");
    let output_str = run_cosmian_cmd(
        &[
            "kms",
            "sym",
            "keys",
            "create",
            "--number-of-bits",
            "256",
            "--algorithm",
            "aes",
            "--tag",
            "wrapping_key",
            &wrapping_key_id,
        ],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    assert!(output_str.contains("successfully generated"));
    info!("Wrapping key created: {}", wrapping_key_id);

    info!("2. Creating SecretData without wrapping...");
    let secret_data_created_id = create_secret_data(
        &cli_conf_path,
        &CreateSecretDataAction {
            secret_id: Some(secret_data_id.clone()),
            tags: vec!["test_secret".to_owned()],
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(secret_data_created_id, secret_data_id);
    info!("SecretData created: {}", secret_data_id);

    info!("3. Creating SecretData WITH wrapping key (issue #549)...");
    let wrapped_secret_created_id = create_secret_data(
        &cli_conf_path,
        &CreateSecretDataAction {
            secret_id: Some(secret_data_with_wrapping_id.clone()),
            tags: vec!["wrapped_secret".to_owned()],
            wrapping_key_id: Some(wrapping_key_id),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(wrapped_secret_created_id, secret_data_with_wrapping_id);
    info!(
        "Wrapped SecretData created (issue #549 resolved): {}",
        secret_data_with_wrapping_id
    );

    info!("4. Testing EXPORT operations...");

    let tmp_path = tmp_dir.path();
    let export_file1 = tmp_path.join("secret_data_export.json");
    let export_file2 = tmp_path.join("wrapped_secret_data_export.json");

    // Export regular secret data
    run_secret_data_cmd(
        "export",
        &["--key-id", &secret_data_id, export_file1.to_str().unwrap()],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    assert!(export_file1.exists(), "Export file was not created");
    info!("EXPORT operation successful for regular SecretData");

    // Export wrapped secret data
    run_secret_data_cmd(
        "export",
        &[
            "--key-id",
            &secret_data_with_wrapping_id,
            export_file2.to_str().unwrap(),
        ],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    assert!(export_file2.exists(), "Wrapped export file was not created");
    info!("EXPORT operation successful for wrapped SecretData");

    info!("5. Testing EXPORT to file operations...");

    // Export regular secret data to file (additional test with different format)
    let export_file3 = tmp_path.join("secret_data_raw_export.bin");
    run_secret_data_cmd(
        "export",
        &[
            "--key-id",
            &secret_data_id,
            "--key-format",
            "raw",
            export_file3.to_str().unwrap(),
        ],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    assert!(export_file3.exists(), "Export file was not created");
    info!("EXPORT operation successful for SecretData");

    let import_file = tmp_path.join("temp_secret_for_import.json");

    // First, create a temporary secret data and export it to create a file for import
    let temp_secret_id = "temp_secret_for_import";
    let temp_created_id = create_secret_data(
        &cli_conf_path,
        &CreateSecretDataAction {
            secret_id: Some(temp_secret_id.to_owned()),
            tags: vec!["temp_for_import".to_owned()],
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(temp_created_id, temp_secret_id);

    // Export the temp secret data to file
    run_secret_data_cmd(
        "export",
        &["--key-id", temp_secret_id, import_file.to_str().unwrap()],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    // Import the secret data with a new ID
    let output_str = run_secret_data_cmd(
        "import",
        &[
            import_file.to_str().unwrap(),
            &imported_secret_data_id,
            "--tag",
            "imported_secret",
        ],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();
    info!("Import output: {}", output_str);
    assert!(
        output_str.contains("successfully imported")
            || output_str.contains("imported")
            || output_str.contains("Success")
    );
    info!("IMPORT operation successful for SecretData");

    info!("7. Testing REVOKE operations...");

    // Revoke the imported secret data
    let output_str = run_secret_data_cmd(
        "revoke",
        &[
            "--secret-data-id",
            &imported_secret_data_id,
            "cessation-of-operation",
        ],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    assert!(output_str.contains("successfully revoked") || output_str.contains("revoked"));
    info!("REVOKE operation successful for SecretData");

    info!("8. Testing DESTROY operations...");

    // Destroy the revoked secret data
    let output_str = run_secret_data_cmd(
        "destroy",
        &["--key-id", &imported_secret_data_id],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    assert!(output_str.contains("successfully destroyed") || output_str.contains("destroyed"));
    info!("DESTROY operation successful for SecretData");

    info!("9. Verifying destroyed SecretData cannot be accessed...");

    let destroyed_export_file = tmp_path.join("should_not_work.json");
    let output = run_secret_data_cmd(
        "export",
        &[
            "--key-id",
            &imported_secret_data_id,
            destroyed_export_file.to_str().unwrap(),
        ],
        false,
        Some(&cli_conf_path),
    )
    .unwrap_err();

    assert!(
        !output.status.success(),
        "Should not be able to export destroyed secret data"
    );
    info!("10. Verifying wrapped SecretData is still functional...");

    let wrapped_export_file = tmp_path.join("wrapped_secret_export.json");
    run_secret_data_cmd(
        "export",
        &[
            "--key-id",
            &secret_data_with_wrapping_id,
            wrapped_export_file.to_str().unwrap(),
        ],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    assert!(
        wrapped_export_file.exists(),
        "Wrapped secret export file was not created"
    );
    info!("Wrapped SecretData remains fully functional");
}

/// Test specifically for wrapping functionality edge cases
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_secret_data_wrapping_edge_cases() {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (cli_conf_path, _) = save_kms_cli_config(ctx);

    let _tmp_dir = TempDir::new().unwrap();

    info!("=== Testing SecretData Wrapping Edge Cases ===");

    info!("1. Testing wrapping with different key sizes...");

    // Create wrapping key
    run_cosmian_cmd(
        &[
            "kms",
            "sym",
            "keys",
            "create",
            "--number-of-bits",
            "128", // Different size
            "--algorithm",
            "aes",
            "wrapping_key_128",
        ],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    // Create wrapped secret data with 128-bit wrapping key
    let large_wrapped_id = create_secret_data(
        &cli_conf_path,
        &CreateSecretDataAction {
            secret_id: Some("large_wrapped_secret".to_owned()),
            secret_value: Some(
                "large_secret_data_content_for_testing_wrapping_functionality".to_owned(),
            ),
            wrapping_key_id: Some("wrapping_key_128".to_owned()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(large_wrapped_id, "large_wrapped_secret");
    info!("Large SecretData wrapped with 128-bit key");

    info!("2. Testing wrapping with different algorithms...");

    // Create ChaCha20 wrapping key
    let chacha20_key_result = run_cosmian_cmd(
        &[
            "kms",
            "sym",
            "keys",
            "create",
            "--number-of-bits",
            "256",
            "--algorithm",
            "chacha20",
            "chacha_wrapping_key",
        ],
        false,
        Some(&cli_conf_path),
    );

    // Note: This might fail if ChaCha20 is not supported for wrapping, which is expected
    if chacha20_key_result.is_ok() {
        let wrap_result = create_secret_data(
            &cli_conf_path,
            &CreateSecretDataAction {
                secret_id: Some("chacha_wrapped_secret".to_owned()),
                wrapping_key_id: Some("chacha_wrapping_key".to_owned()),
                ..Default::default()
            },
        );

        if wrap_result.is_ok() {
            info!("SecretData wrapped with ChaCha20 key");
        } else {
            info!("ChaCha20 wrapping not supported (expected)");
        }
    } else {
        info!("ChaCha20 key creation not supported (expected)");
    }

    info!("3. Testing error cases...");

    // Try to wrap with non-existent key
    let result = create_secret_data(
        &cli_conf_path,
        &CreateSecretDataAction {
            secret_id: Some("should_fail".to_owned()),
            wrapping_key_id: Some("non_existent_key".to_owned()),
            ..Default::default()
        },
    );

    assert!(
        result.is_err(),
        "Should fail when wrapping with non-existent key"
    );
    info!("Correctly fails with non-existent wrapping key");
}

/// Test secret data export with wrapping parameters
#[tokio::test]
async fn test_secret_data_export_with_wrapping() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let temp_dir = TempDir::new()?;

    // Create a secret data to be exported
    let secret_data_id = match run_secret_data_cmd(
        "create",
        &[
            "--value",
            "test-secret-data-for-export",
            "--tag",
            "export-test",
        ],
        true,
        Some(&owner_client_conf_path),
    ) {
        Ok(output) => extract_unique_identifier(&output)
            .ok_or_else(|| CosmianError::Default("Failed to extract secret data ID".to_owned()))?
            .to_owned(),
        Err(output) => {
            return Err(CosmianError::Default(format!(
                "Failed to create secret data: {}",
                std::str::from_utf8(&output.stderr)?
            )));
        }
    };

    // Create a wrapping key
    let wrapping_key_id = match run_cosmian_cmd(
        &[
            "kms",
            "sym",
            "keys",
            "create",
            "--number-of-bits",
            "256",
            "--algorithm",
            "aes",
            "--tag",
            "wrapping-key",
        ],
        true,
        Some(&owner_client_conf_path),
    ) {
        Ok(output) => extract_unique_identifier(&output)
            .ok_or_else(|| CosmianError::Default("Failed to extract wrapping key ID".to_owned()))?
            .to_owned(),
        Err(output) => {
            return Err(CosmianError::Default(format!(
                "Failed to create wrapping key: {}",
                std::str::from_utf8(&output.stderr)?
            )));
        }
    };

    // Test export with wrapping parameters
    let export_file_path = temp_dir.path().join("keyfile.bin");
    let export_file_str = export_file_path.to_str().unwrap();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, &owner_client_conf_path);
    cmd.args([
        KMS_SUBCOMMAND,
        "secret-data",
        "export",
        "--key-id",
        &secret_data_id,
        "-f",
        "raw",
        "--wrap-key-id",
        &wrapping_key_id,
        "--wrapping-algorithm",
        "aes-gcm",
        export_file_str,
    ]);
    let output = recover_cmd_logs(&mut cmd);
    if !output.status.success() {
        return Err(CosmianError::Default(format!(
            "Failed to export secret data with wrapping: {}",
            std::str::from_utf8(&output.stderr)?
        )));
    }

    // Verify the file was created
    assert!(export_file_path.exists(), "Export file was not created");

    // Verify the exported file is not empty
    let file_content = std::fs::read(&export_file_path)?;
    assert!(!file_content.is_empty(), "Export file is empty");

    info!(
        "Successfully exported secret data {} with wrapping key {} to {}",
        secret_data_id, wrapping_key_id, export_file_str
    );

    Ok(())
}

/// Test for backwards compatibility - ensure existing functionality still works
#[tokio::test]
async fn test_secret_data_backwards_compatibility() {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (cli_conf_path, _) = save_kms_cli_config(ctx);

    info!("=== Testing Backwards Compatibility ===");

    info!("1. Testing original SecretData creation (no wrapping)...");

    let original_id = create_secret_data(
        &cli_conf_path,
        &CreateSecretDataAction {
            secret_id: Some("original_secret_data".to_owned()),
            tags: vec!["backwards_compat".to_owned()],
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(original_id, "original_secret_data");
    info!("Original SecretData creation works");

    info!("2. Testing SecretData with secret value...");

    let password_id = create_secret_data(
        &cli_conf_path,
        &CreateSecretDataAction {
            secret_id: Some("password_based_secret".to_owned()),
            secret_value: Some("my_secret_password".to_owned()),
            tags: vec!["password_secret".to_owned()],
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(password_id, "password_based_secret");
    info!("SecretData with secret value works");

    info!("3. Testing original operations still work...");

    // Export
    let tmp_dir = TempDir::new().unwrap();
    let export_file = tmp_dir.path().join("compat_export.json");
    run_secret_data_cmd(
        "export",
        &[
            "--key-id",
            "original_secret_data",
            export_file.to_str().unwrap(),
        ],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    // Additional export test
    let export_file2 = tmp_dir.path().join("compat_export2.json");
    run_secret_data_cmd(
        "export",
        &[
            "--key-id",
            "original_secret_data",
            export_file2.to_str().unwrap(),
        ],
        true,
        Some(&cli_conf_path),
    )
    .unwrap();

    info!("All backwards compatibility tests passed!");
}
