use std::{fs, fs::OpenOptions, path::PathBuf, str::FromStr, sync::OnceLock};

use snafu::prelude::*;
use tracing::Level;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    EnvFilter, Registry, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

use crate::{IoSnafu, LoggingSnafu, error::SError};

/// Initialize logging for the SQL Server EKM module.
pub(crate) fn init_logging() -> Result<(), SError> {
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

/// Log to a file with the specified log name, level, and home directory.
///
/// # Arguments
/// * `log_name` - The name of the log file.
/// * `level` - The logging level.
/// * `log_home` - The home directory for the log file.
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
