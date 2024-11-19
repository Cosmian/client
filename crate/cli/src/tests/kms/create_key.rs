use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_config::COSMIAN_CLI_CONF_ENV;
use regex::{Regex, RegexBuilder};

use crate::{
    error::{result::CosmianResult, CosmianError},
    tests::{utils::recover_cmd_logs, PROG_NAME},
};

//todo(manu): create a test crate
pub(crate) fn extract_uid<'a>(text: &'a str, pattern: &'a str) -> Option<&'a str> {
    let formatted = format!(r"^\s*{pattern}: (?P<uid>.+?)[\s\.]*?$");
    let uid_regex: Regex = RegexBuilder::new(formatted.as_str())
        .multi_line(true)
        .build()
        .unwrap();
    uid_regex
        .captures(text)
        .and_then(|cap| cap.name("uid").map(|uid| uid.as_str()))
}

/// Create a symmetric key via the CLI
pub(crate) fn create_symmetric_key(
    cli_conf_path: &str,
    number_of_bits: Option<usize>,
    wrap_key_b64: Option<&str>,
    algorithm: Option<&str>,
    tags: &[&str],
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    let mut args = vec!["sym", "keys", "create"];
    let num_s;
    if let Some(number_of_bits) = number_of_bits {
        num_s = number_of_bits.to_string();
        args.extend(vec!["--number-of-bits", &num_s]);
    }
    if let Some(wrap_key_b64) = wrap_key_b64 {
        args.extend(vec!["--bytes-b64", wrap_key_b64]);
    }
    if let Some(algorithm) = algorithm {
        args.extend(vec!["--algorithm", algorithm]);
    }
    // add tags
    for tag in tags {
        args.push("--tag");
        args.push(tag);
    }
    cmd.arg("kms").args(args);

    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::str::from_utf8(&output.stdout)?;
        let unique_identifier = extract_uid(output, "Unique identifier").ok_or_else(|| {
            CosmianError::Default("failed extracting the unique identifier".to_owned())
        })?;
        return Ok(unique_identifier.to_string())
    }

    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_create_symmetric_key() -> CosmianResult<()> {
    // AES 256 bit key
    create_symmetric_key(
        "../../test_data/configs/cosmian.toml",
        None,
        None,
        None,
        &[],
    )?;

    Ok(())
}
