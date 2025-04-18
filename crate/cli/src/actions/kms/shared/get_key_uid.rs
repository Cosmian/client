use tracing::trace;

use crate::{cli_bail, error::result::CosmianResult};

pub(crate) fn get_key_uid(
    key_id: Option<&String>,
    tags: Option<&Vec<String>>,
    argument_name: &str,
) -> CosmianResult<String> {
    let id = if let Some(kid) = key_id {
        kid.clone()
    } else if let Some(tags) = tags {
        serde_json::to_string(tags)?
    } else {
        cli_bail!("Either --{argument_name} or one or more --tag must be specified")
    };
    trace!("Key UID: {id}");
    Ok(id)
}
