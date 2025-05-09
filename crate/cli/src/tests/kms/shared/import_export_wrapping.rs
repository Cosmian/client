use cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kms_client::{
    cosmian_kmip::kmip_2_1::{
        kmip_objects::Object,
        kmip_types::{CryptographicAlgorithm, LinkType, UniqueIdentifier, WrappingMethod},
    },
    kmip_2_1::{
        kmip_attributes::Attributes, kmip_data_structures::KeyValue,
        requests::create_symmetric_key_kmip_object,
    },
    read_object_from_json_ttlv_file,
    reexport::cosmian_kms_client_utils::import_utils::KeyUsage,
    write_kmip_object_to_file,
};
#[cfg(not(feature = "fips"))]
use cosmian_kms_crypto::crypto::elliptic_curves::operation::create_x25519_key_pair;
use cosmian_kms_crypto::crypto::wrap::unwrap_key_block;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;
use tracing::{debug, trace};

use super::ExportKeyParams;
use crate::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    error::result::CosmianResult,
    tests::kms::{
        cover_crypt::master_key_pair::create_cc_master_key_pair,
        elliptic_curve,
        shared::{ImportKeyParams, export::export_key, import::import_key},
        symmetric::create_key::create_symmetric_key,
    },
};

#[tokio::test]
pub(crate) async fn test_import_export_wrap_rfc_5649() -> CosmianResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;
    // Generate a symmetric wrapping key
    let wrap_key_path = tmp_path.join("wrap.key");
    let mut rng = CsRng::from_entropy();
    let mut wrap_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut wrap_key_bytes);
    let wrap_key = create_symmetric_key_kmip_object(
        &wrap_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),

            ..Default::default()
        },
    )?;
    write_kmip_object_to_file(&wrap_key, &wrap_key_path)?;

    // import the wrapping key
    trace!("importing wrapping key");
    let wrap_key_uid = import_key(ImportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_string(),
        key_file: wrap_key_path.to_str().unwrap().to_string(),
        ..Default::default()
    })?;

    // test CC
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--specification",
        "../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_client_conf_path,
        "cc",
        &private_key_id,
        &wrap_key_uid,
        &wrap_key,
    )?;

    // test ec
    let (private_key_id, _public_key_id) = elliptic_curve::create_key_pair::create_ec_key_pair(
        &ctx.owner_client_conf_path,
        "nist-p256",
        &[],
        false,
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_client_conf_path,
        "ec",
        &private_key_id,
        &wrap_key_uid,
        &wrap_key,
    )?;

    // test sym
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, CreateKeyAction::default())?;
    test_import_export_wrap_private_key(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        &wrap_key_uid,
        &wrap_key,
    )?;

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub(crate) async fn test_import_export_wrap_ecies() -> CosmianResult<()> {
    use cosmian_kms_client::kmip_0::kmip_types::CryptographicUsageMask;

    cosmian_logger::log_init(None);
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;
    // Generate a symmetric wrapping key
    let wrap_private_key_uid = "wrap_private_key_uid";
    let wrap_public_key_uid = "wrap_public_key_uid";
    let wrap_key_pair = create_x25519_key_pair(
        wrap_private_key_uid,
        wrap_public_key_uid,
        &CryptographicAlgorithm::EC,
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        },
        Some(Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Decrypt | CryptographicUsageMask::UnwrapKey,
            ),
            ..Default::default()
        }),
        Some(Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::WrapKey,
            ),
            ..Default::default()
        }),
    )?;
    // Write the private key to a file and import it
    let wrap_private_key_path = tmp_path.join("wrap.private.key");
    write_kmip_object_to_file(wrap_key_pair.private_key(), &wrap_private_key_path)?;
    import_key(ImportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "ec".to_string(),
        key_file: wrap_private_key_path.to_str().unwrap().to_string(),
        key_id: Some(wrap_private_key_uid.to_string()),
        replace_existing: true,
        ..Default::default()
    })?;
    // Write the public key to a file and import it
    let wrap_public_key_path = tmp_path.join("wrap.public.key");
    write_kmip_object_to_file(wrap_key_pair.public_key(), &wrap_public_key_path)?;
    import_key(ImportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "ec".to_string(),
        key_file: wrap_public_key_path.to_str().unwrap().to_string(),
        key_id: Some(wrap_public_key_uid.to_string()),
        replace_existing: true,
        ..Default::default()
    })?;

    // test CC
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &ctx.owner_client_conf_path,
        "--specification",
        "../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_client_conf_path,
        "cc",
        &private_key_id,
        wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )?;

    debug!("testing EC keys");
    let (private_key_id, _public_key_id) = elliptic_curve::create_key_pair::create_ec_key_pair(
        &ctx.owner_client_conf_path,
        "nist-p256",
        &[],
        false,
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_client_conf_path,
        "ec",
        &private_key_id,
        wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )?;

    debug!("testing symmetric keys");
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, CreateKeyAction::default())?;
    test_import_export_wrap_private_key(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )?;
    Ok(())
}

fn test_import_export_wrap_private_key(
    cli_conf_path: &str,
    sub_command: &str,
    private_key_id: &str,
    wrapping_key_uid: &str,
    unwrapping_key: &Object,
) -> CosmianResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Export the private key without wrapping
    let private_key_file = tmp_path.join("master_private.key");
    let export_params = ExportKeyParams {
        cli_conf_path: cli_conf_path.to_string(),
        sub_command: sub_command.to_string(),
        key_id: private_key_id.to_string(),
        key_file: private_key_file.to_str().unwrap().to_string(),
        ..Default::default()
    };
    export_key(export_params)?;
    let private_key = read_object_from_json_ttlv_file(&private_key_file)?;

    // Export the private key with wrapping
    let wrapped_private_key_file = tmp_path.join("wrapped_master_private.key");
    export_key(ExportKeyParams {
        cli_conf_path: cli_conf_path.to_string(),
        sub_command: sub_command.to_string(),
        key_id: private_key_id.to_string(),
        key_file: wrapped_private_key_file.to_str().unwrap().to_string(),
        wrap_key_id: Some(wrapping_key_uid.to_string()),
        ..Default::default()
    })?;

    // test the exported private key with wrapping
    {
        let mut wrapped_private_key = read_object_from_json_ttlv_file(&wrapped_private_key_file)?;
        let wrapped_key_wrapping_data = wrapped_private_key.key_wrapping_data().unwrap();
        assert_eq!(
            wrapped_key_wrapping_data.wrapping_method,
            WrappingMethod::Encrypt
        );
        assert_eq!(
            wrapped_key_wrapping_data
                .encryption_key_information
                .clone()
                .unwrap()
                .unique_identifier,
            UniqueIdentifier::TextString(wrapping_key_uid.to_owned())
        );
        assert!(
            wrapped_key_wrapping_data
                .encryption_key_information
                .clone()
                .unwrap()
                .cryptographic_parameters
                .is_none()
        );
        unwrap_key_block(wrapped_private_key.key_block_mut()?, unwrapping_key)?;
        assert!(wrapped_private_key.key_block()?.key_value == private_key.key_block()?.key_value);
    }

    // test the unwrapping on import
    {
        // import the wrapped key, unwrapping it on import
        let unwrapped_key_id = import_key(ImportKeyParams {
            cli_conf_path: cli_conf_path.to_string(),
            sub_command: sub_command.to_string(),
            key_file: wrapped_private_key_file.to_str().unwrap().to_string(),
            unwrap: true,
            replace_existing: true,
            ..Default::default()
        })?;
        // re-export it as registered and check it was correctly unwrapped
        let re_exported_key_file = tmp_path.join("re_exported_master_private.key");
        export_key(ExportKeyParams {
            cli_conf_path: cli_conf_path.to_string(),
            sub_command: sub_command.to_string(),
            key_id: unwrapped_key_id,
            key_file: re_exported_key_file.to_str().unwrap().to_string(),
            ..Default::default()
        })?;
        let re_exported_key = read_object_from_json_ttlv_file(&re_exported_key_file)?;
        let re_exported_key_material = {
            let Some(KeyValue::Structure { key_material, .. }) =
                &re_exported_key.key_block()?.key_value
            else {
                panic!("Key value is not a structure");
            };
            key_material
        };
        let private_key_key_material = {
            let Some(KeyValue::Structure { key_material, .. }) =
                &private_key.key_block()?.key_value
            else {
                panic!("Key value is not a structure");
            };
            key_material
        };
        assert_eq!(re_exported_key_material, private_key_key_material);
        assert_eq!(
            re_exported_key
                .key_block()?
                .attributes()?
                .get_link(LinkType::PublicKeyLink),
            private_key
                .key_block()?
                .attributes()?
                .get_link(LinkType::PublicKeyLink)
        );
        assert!(re_exported_key.key_wrapping_data().is_none());
    }

    // test the unwrapping on export
    {
        // import the wrapped key, un wrapping it on import
        let wrapped_key_id = import_key(ImportKeyParams {
            cli_conf_path: cli_conf_path.to_string(),
            sub_command: sub_command.to_string(),
            key_file: wrapped_private_key_file.to_str().unwrap().to_string(),
            key_usage_vec: Some(vec![KeyUsage::Unrestricted]),
            replace_existing: true,
            ..Default::default()
        })?;
        // re-export it as registered and check it was correctly unwrapped
        let exported_unwrapped_key_file = tmp_path.join("exported_unwrapped_master_private.key");
        export_key(ExportKeyParams {
            cli_conf_path: cli_conf_path.to_string(),
            sub_command: sub_command.to_string(),
            key_id: wrapped_key_id,
            key_file: exported_unwrapped_key_file.to_str().unwrap().to_string(),
            unwrap: true,
            ..Default::default()
        })?;
        let mut exported_unwrapped_key =
            read_object_from_json_ttlv_file(&exported_unwrapped_key_file)?;
        // keys should be identical save for the UniqueIdentifier attribute
        let exp_attrs = exported_unwrapped_key.key_block_mut()?.attributes_mut()?;
        exp_attrs.unique_identifier = private_key
            .key_block()?
            .attributes()?
            .unique_identifier
            .clone();

        assert_eq!(
            exported_unwrapped_key.key_block()?.key_value,
            private_key.key_block()?.key_value
        );
        assert!(exported_unwrapped_key.key_wrapping_data().is_none());
    }

    Ok(())
}
