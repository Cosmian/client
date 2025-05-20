#[cfg(not(feature = "fips"))]
use cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::ExportKeyFormat;
use cosmian_kms_client::reexport::cosmian_kms_client_utils::{
    create_utils::SymmetricAlgorithm, symmetric_utils::DataEncryptionAlgorithm,
};
use cosmian_logger::log_init;
#[cfg(not(feature = "fips"))]
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server_with_utimaco_hsm;
#[cfg(not(feature = "fips"))]
use tracing::info;
use uuid::Uuid;

#[cfg(not(feature = "fips"))]
use crate::tests::kms::{
    rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair},
    shared::{ExportKeyParams, export_key},
};
use crate::{
    actions::kms::symmetric::{KeyEncryptionAlgorithm, keys::create_key::CreateKeyAction},
    error::result::CosmianResult,
    tests::kms::symmetric::{
        create_key::create_symmetric_key, encrypt_decrypt::run_encrypt_decrypt_test,
    },
};

#[tokio::test]
pub(crate) async fn test_wrap_with_aes_gcm() -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms_server=debug"));
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let wrapping_key_id = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            sensitive: true,
            ..Default::default()
        },
    )?;
    // println!("Wrapping key id: {wrapping_key_id}" );
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            wrapping_key_id: Some(wrapping_key_id),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub(crate) async fn test_wrap_with_rsa_oaep() -> CosmianResult<()> {
    log_init(None);
    // log_init(Some("debug"));
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &ctx.owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    println!("Wrapping key id: {public_key_id}");
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            wrapping_key_id: Some(public_key_id),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &ctx.owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub(crate) async fn test_unwrap_on_export() -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &ctx.owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    info!("===> Wrapping key id: {public_key_id}");
    let dek = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Aes,
            wrapping_key_id: Some(public_key_id),
            ..Default::default()
        },
    )?;
    info!("===> DEK id: {dek}");
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: dek,
        key_file: tmp_path.join("dek.pem").to_str().unwrap().to_owned(),
        unwrap: true,
        key_format: Some(ExportKeyFormat::Raw),
        ..Default::default()
    })?;
    Ok(())
}
