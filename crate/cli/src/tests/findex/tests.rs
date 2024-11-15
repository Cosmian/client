use cosmian_findex_cli::actions::findex::FindexParameters;
use cosmian_logger::log_init;
use uuid::Uuid;

use super::{add::add_cmd, search::search_cmd};
use crate::{
    actions::{encrypt_and_add::EncryptAndAddAction, search_and_decrypt::SearchAndDecryptAction},
    error::result::CosmianResult,
    tests::kms::create_key::create_symmetric_key,
};

#[allow(dead_code)]
fn add(cli_conf_path: &str, index_id: &Uuid, kek_id: &str) -> CosmianResult<()> {
    // create_symmetric_key(cli_conf_path, )
    add_cmd(
        cli_conf_path,
        EncryptAndAddAction {
            findex_parameters: FindexParameters {
                key: "11223344556677889900AABBCCDDEEFF".to_owned(),
                label: "My Findex label".to_owned(),
                index_id: index_id.to_owned(),
            },
            csv: "../../test_data/datasets/smallpop.csv".into(),
            key_encryption_key_id: kek_id.to_owned(),
            nonce: None,
            authentication_data: None,
        },
    )?;
    Ok(())
}

// fn delete(cli_conf_path: &str, index_id: &Uuid) -> CliResult<()> {
//     add_or_delete_cmd(
//         cli_conf_path,
//         "delete",
//         AddOrDeleteAction {
//             findex_parameters: FindexParameters {
//                 key: "11223344556677889900AABBCCDDEEFF".to_owned(),
//                 label: "My Findex label".to_owned(),
//                 index_id: index_id.to_owned(),
//             },
//             csv: "../../test_data/datasets/smallpop.csv".into(),
//         },
//     )?;
//     Ok(())
// }

fn search(cli_conf_path: &str, index_id: &Uuid, kek_id: &str) -> CosmianResult<String> {
    search_cmd(
        cli_conf_path,
        SearchAndDecryptAction {
            findex_parameters: FindexParameters {
                key: "11223344556677889900AABBCCDDEEFF".to_owned(),
                label: "My Findex label".to_owned(),
                index_id: index_id.to_owned(),
            },
            keyword: vec!["Southborough".to_owned(), "Northbridge".to_owned()],
            key_encryption_key_id: kek_id.to_owned(),
            authentication_data: None,
        },
    )
}

#[allow(clippy::panic_in_result_fn)]
fn add_search_delete(cli_conf_path: &str, index_id: &Uuid, kek_id: &str) -> CosmianResult<()> {
    add(cli_conf_path, index_id, kek_id)?;

    // make sure searching returns the expected results
    let search_results = search(cli_conf_path, index_id, kek_id)?;
    assert!(search_results.contains("States9686")); // for Southborough
    assert!(search_results.contains("States14061")); // for Northbridge

    // delete(cli_conf_path, index_id)?;

    // // make sure no results are returned after deletion
    // let search_results = search(cli_conf_path, index_id)?;
    // assert!(!search_results.contains("States9686")); // for Southborough
    // assert!(!search_results.contains("States14061")); // for Northbridge

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_encrypt_and_add_no_auth() -> CosmianResult<()> {
    log_init(None);
    let cli_conf_path = "../../test_data/configs/cosmian.json";

    let kek_id = create_symmetric_key(cli_conf_path, None, None, None, &[])?;

    add_search_delete(cli_conf_path, &Uuid::new_v4(), &kek_id)?;
    Ok(())
}

// #[tokio::test]
// pub(crate) async fn test_findex_cert_auth() -> CliResult<()> {
//     log_init(None);
//     // let ctx = start_default_test_kms_server_with_cert_auth().await;
//     let ctx = start_default_test_findex_server_with_cert_auth().await;

//     let index_id = create_index_id_cmd(&ctx.owner_client_conf_path)?;
//     trace!("index_id: {index_id}");

//     add_search_delete(&ctx.owner_client_conf_path, &index_id)?;
//     Ok(())
// }

// #[allow(clippy::panic_in_result_fn, clippy::unwrap_used)]
// #[tokio::test]
// pub(crate) async fn test_findex_grant_and_revoke_permission() -> CliResult<()> {
//     log_init(None);
//     // let ctx = start_default_test_kms_server_with_cert_auth().await;
//     let ctx = start_default_test_findex_server_with_cert_auth().await;

//     let index_id = create_index_id_cmd(&ctx.owner_client_conf_path)?;
//     trace!("index_id: {index_id}");

//     add(&ctx.owner_client_conf_path, &index_id)?;

//     // Grant read permission to the client
//     grant_permission_cmd(
//         &ctx.owner_client_conf_path,
//         &GrantPermission {
//             user: "user.client@acme.com".to_owned(),
//             index_id,
//             permission: Permission::Read,
//         },
//     )?;

//     // User can read...
//     let search_results = search(&ctx.user_client_conf_path, &index_id)?;
//     assert!(search_results.contains("States9686")); // for Southborough
//     assert!(search_results.contains("States14061")); // for Northbridge

//     // ... but not write
//     assert!(add(&ctx.user_client_conf_path, &index_id).is_err());

//     // Grant write permission
//     grant_permission_cmd(
//         &ctx.owner_client_conf_path,
//         &GrantPermission {
//             user: "user.client@acme.com".to_owned(),
//             index_id,
//             permission: Permission::Write,
//         },
//     )?;

//     // User can read...
//     let search_results = search(&ctx.user_client_conf_path, &index_id)?;
//     assert!(search_results.contains("States9686")); // for Southborough
//     assert!(search_results.contains("States14061")); // for Northbridge

//     // ... and write
//     add(&ctx.user_client_conf_path, &index_id)?;

//     // Try to escalade privileges from `read` to `admin`
//     grant_permission_cmd(
//         &ctx.user_client_conf_path,
//         &GrantPermission {
//             user: "user.client@acme.com".to_owned(),
//             index_id,
//             permission: Permission::Admin,
//         },
//     )
//     .unwrap_err();

//     revoke_permission_cmd(
//         &ctx.owner_client_conf_path,
//         &RevokePermission {
//             user: "user.client@acme.com".to_owned(),
//             index_id,
//         },
//     )?;

//     search(&ctx.user_client_conf_path, &index_id).unwrap_err();

//     Ok(())
// }

// #[allow(clippy::panic_in_result_fn)]
// #[tokio::test]
// pub(crate) async fn test_findex_no_permission() -> CliResult<()> {
//     log_init(None);
//     let ctx = start_default_test_findex_server_with_cert_auth().await;

//     assert!(add_search_delete(&ctx.user_client_conf_path, &Uuid::new_v4()).is_err());
//     Ok(())
// }
