use cosmian_logger::log_init;
use test_findex_server::{AuthenticationOptions, get_db_config, start_test_server_with_options};
use tracing::{info, trace};

use crate::error::result::CosmianResult;

// let us not make other test cases fail
const PORT: u16 = 6667;

// TODO(hatem): make those chose their db from the env

#[tokio::test]
pub(crate) async fn test_all_authentications() -> CosmianResult<()> {
    log_init(None);
    let test_db = get_db_config();
    trace!(
        "TESTS: using db {:?} on {:?}",
        test_db.database_type, test_db.database_url
    );
    // plaintext no auth
    info!("Testing server with no auth");
    let ctx = start_test_server_with_options(
        test_db.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: false,
            use_https: false,
            use_client_cert: false,
        },
    )
    .await?;
    ctx.stop_server().await?;

    // plaintext JWT token auth
    info!("Testing server with JWT token auth");
    let ctx = start_test_server_with_options(
        test_db.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: false,
            use_client_cert: false,
        },
    )
    .await?;
    ctx.stop_server().await?;

    // tls token auth
    info!("Testing server with TLS token auth");
    let ctx = start_test_server_with_options(
        test_db.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            use_client_cert: false,
        },
    )
    .await?;
    ctx.stop_server().await?;

    // tls client cert auth
    info!("Testing server with TLS client cert auth");
    let ctx = start_test_server_with_options(
        test_db.clone(),
        PORT,
        AuthenticationOptions {
            use_jwt_token: false,
            use_https: true,
            use_client_cert: true,
        },
    )
    .await?;
    ctx.stop_server().await?;

    // Good JWT token auth but still cert auth used at first
    info!(
        "Testing server with bad API token and good JWT token auth but still cert auth used at \
         first"
    );
    let ctx = start_test_server_with_options(
        test_db,
        PORT,
        AuthenticationOptions {
            use_jwt_token: true,
            use_https: true,
            use_client_cert: true,
        },
    )
    .await?;
    ctx.stop_server().await?;

    Ok(())
}
