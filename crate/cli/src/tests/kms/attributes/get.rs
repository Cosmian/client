use std::{collections::HashMap, process::Command};

use assert_cmd::cargo::CommandCargoExt;
use cosmian_kms_client::kmip_2_1::kmip_types::Tag;
use serde_json::Value;

use crate::{
    actions::kms::attributes::CLinkType,
    config::COSMIAN_CLI_CONF_ENV,
    error::{
        CosmianError,
        result::{CosmianResult, CosmianResultHelper},
    },
    tests::{
        PROG_NAME,
        kms::{KMS_SUBCOMMAND, utils::recover_cmd_logs},
    },
};

pub(crate) fn get_attributes(
    cli_conf_path: &str,
    uid: &str,
    attribute_tags: &[Tag],
    attribute_link_types: &[CLinkType],
) -> CosmianResult<HashMap<String, Value>> {
    let temp_file = tempfile::NamedTempFile::new()?;
    let mut args: Vec<String> = [
        "get",
        "--id",
        uid,
        "--output-file",
        temp_file
            .path()
            .to_str()
            .context("failed converting path to string")?,
    ]
    .iter()
    .map(std::string::ToString::to_string)
    .collect();

    for tag in attribute_tags {
        args.push("--attribute".to_owned());
        args.push(tag.to_string());
    }

    for link_type in attribute_link_types {
        args.push("--link-type".to_owned());
        args.push(link_type.to_string());
    }

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(COSMIAN_CLI_CONF_ENV, cli_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg("attributes").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let output = std::fs::read_to_string(temp_file.path())?;
        let output: HashMap<String, Value> = serde_json::from_str(&output)?;
        return Ok(output)
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}
