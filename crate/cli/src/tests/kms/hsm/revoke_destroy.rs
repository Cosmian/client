use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server_with_utimaco_hsm;
use tracing::debug;
use uuid::Uuid;

use crate::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    error::result::CosmianResult,
    tests::kms::{
        shared::{ExportKeyParams, destroy, export_key, revoke},
        symmetric::create_key::create_symmetric_key,
    },
};

#[tokio::test]
async fn test_revoke_symmetric_key() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    // sym
    let key_id = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            ..Default::default()
        },
    )?;

    // revoke
    match revoke(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        "revocation test",
    ) {
        Ok(()) => {
            debug!("revocation successful");
        }
        Err(_) => {
            debug!("revocation not supported");
        }
    }

    // The key is always removed when it is an HSM
    destroy(&ctx.owner_client_conf_path, "sym", &key_id, true)?;

    let res = export_key(ExportKeyParams {
        cli_conf_path: ctx.owner_client_conf_path.clone(),
        sub_command: "sym".to_string(),
        key_id,
        key_file: "/tmp/key".to_string(),
        ..Default::default()
    });
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Object not found"));
    Ok(())
}
