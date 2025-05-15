mod api;
mod configuration;
mod error;
mod ms_crypto;

use std::{fs, fs::OpenOptions, path::PathBuf, str::FromStr, sync::OnceLock};

use cosmian_kms_client::{KmsClient, KmsClientConfig};
use error::{IoSnafu, LoggingSnafu};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use tracing::Level;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    EnvFilter, Registry, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

use crate::error::SError;

static CLIENT: OnceLock<Result<KmsClient, SError>> = OnceLock::new();

fn get_client() -> &'static Result<KmsClient, SError> {
    CLIENT.get_or_init(|| {
        init_logging()?;
        let config = KmsClientConfig::default();
        // KmsClient::new_with_config()
        Ok(())
    })
}

fn init_logging() -> Result<(), SError> {
    let debug_level =
        std::env::var("COSMIAN_PKCS11_LOGGING_LEVEL").unwrap_or_else(|_| "info".to_owned());
    let log_home = etcetera::home_dir()
        .map(|e| e.join("cosmian"))
        .unwrap_or("cosmian".into());
    log_to_file(
        "cosmian-sqlserver.log",
        Level::from_str(&debug_level).unwrap_or(Level::INFO),
        &log_home,
    )
}

fn log_to_file(log_name: &str, level: Level, log_home: &PathBuf) -> Result<(), SError> {
    // Use `create_dir_all` to create the directory and all its parent directories
    // if they do not exist.
    let log_home = PathBuf::from(log_home);
    if !log_home.exists() {
        fs::create_dir_all(&log_home).context(IoSnafu {
            message: format!("Failed to create log directory: {:?}", log_home),
        })?;
    }

    let log_path = log_home.join(format!("{log_name}.log"));
    // Open the file in append mode, or create it if it doesn't exist.
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
        .context(IoSnafu {
            message: format!("Failed to open log file: {}", log_path.display()),
        })?;
    // Set up the logging configuration
    let env_filter = EnvFilter::new(format!("info,cosmian_cosmian_sqlserver_ekm={level}").as_str());
    Registry::default()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::sync::Mutex::new(file))
                .with_span_events(FmtSpan::ENTER),
        )
        .with(env_filter)
        .with(ErrorLayer::default())
        .try_init()
        .context(LoggingSnafu {
            message: "Failed to initialize logging",
        })?;
    Ok(())
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
