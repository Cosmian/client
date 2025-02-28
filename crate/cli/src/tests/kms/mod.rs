mod access;
mod attributes;
mod auth_tests;
mod certificates;
#[cfg(not(feature = "fips"))]
mod cover_crypt;
mod elliptic_curve;
mod google_cmd;
mod hash;
mod hsm;
mod mac;
mod new_database;
mod rsa;
mod shared;
mod symmetric;
pub(crate) mod utils;

const PROG_NAME: &str = "cosmian";
const KMS_SUBCOMMAND: &str = "kms";
