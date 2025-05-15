mod api;
mod configuration;
mod error;
mod logging;
// mod ms_crypto;

use std::sync::OnceLock;

use configuration::ClientConfig;
use cosmian_kms_client::KmsClient;
use error::{IoSnafu, KmsClientSnafu, LoggingSnafu};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::error::SError;

static CLIENT: OnceLock<Result<KmsClient, SError>> = OnceLock::new();

fn get_client() -> &'static Result<KmsClient, SError> {
    CLIENT.get_or_init(|| {
        logging::init_logging()?;
        let kms_client = KmsClient::new_with_config(ClientConfig::from_toml()?.into()).context(
            KmsClientSnafu {
                message: "Failed to initialize KMS client",
            },
        )?;
        Ok(kms_client)
    })
}

#[derive(Serialize, Deserialize)]
struct KmsRequest {
    key_id: String,
    data: String,
    key: Option<String>,
    iv: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct KmsResponse {
    data: String,
}

fn send_to_kms(
    operation: &str,
    key_id: &str,
    data: &[u8],
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let client = Client::new();

    let request = KmsRequest {
        key_id: key_id.to_string(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data),
        key: key.map(|k| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k)),
        iv: iv.map(|i| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, i)),
    };

    let kms_url = std::env::var("COSMIAN_KMS_URL")
        .unwrap_or_else(|_| "https://your-cosmian-kms-url".to_string());

    let response = client
        .post(&format!("{}/{}", kms_url, operation))
        .header("Content-Type", "application/json")
        .header(
            "Authorization",
            format!(
                "Bearer {}",
                std::env::var("COSMIAN_KMS_TOKEN")
                    .unwrap_or_else(|_| "your-auth-token".to_string())
            ),
        )
        .json(&request)
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("KMS operation failed: {}", response.status()));
    }

    let response_body: KmsResponse = response
        .json()
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &response_body.data,
    )
    .map_err(|e| format!("Failed to decode response data: {}", e))
}

// ```sql
// -- Create the cryptographic provider
// CREATE CRYPTOGRAPHIC PROVIDER CosmianEkmProvider
// FROM FILE = 'C:\path\to\your\cosmian_sql_ekm.dll';
//
// -- Create a master key that uses the EKM provider
// CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongPassword123';
//
// -- Create an asymmetric key that uses the EKM provider
// CREATE ASYMMETRIC KEY CosmianManagedKey
// FROM PROVIDER CosmianEkmProvider
// WITH PROVIDER_KEY_NAME = 'your-key-id-in-cosmian-kms';
//
// -- Use the key to encrypt a database column
// CREATE DATABASE ENCRYPTION KEY
// WITH ALGORITHM = AES_256
// ENCRYPTION BY SERVER ASYMMETRIC KEY CosmianManagedKey;
//
// -- Enable TDE
// ALTER DATABASE YourDatabase
// SET ENCRYPTION ON;
// ```
