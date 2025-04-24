#![deny(
    nonstandard_style,
    refining_impl_trait,
    future_incompatible,
    keyword_idents,
    let_underscore,
    unreachable_pub,
    unsafe_code,
    unused,
    clippy::all,
    clippy::suspicious,
    clippy::complexity,
    clippy::perf,
    clippy::style,
    clippy::pedantic,
    clippy::cargo,
    clippy::nursery,

    // restriction lints
    clippy::unwrap_used,
    clippy::get_unwrap,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_asserts_for_indexing,
    clippy::unwrap_in_result,
    clippy::assertions_on_result_states,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::renamed_function_params,
    clippy::verbose_file_reads,
    clippy::str_to_string,
    clippy::string_to_string,
    clippy::unreachable,
    clippy::as_conversions,
    clippy::print_stdout,
    clippy::empty_structs_with_brackets,
    clippy::unseparated_literal_suffix,
    clippy::map_err_ignore,
    clippy::redundant_clone,
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions,
    clippy::redundant_pub_crate
)]

use std::{ptr::addr_of_mut, str::FromStr};

use cosmian_pkcs11_module::{pkcs11::FUNC_LIST, traits::register_backend};
use pkcs11_sys::{CK_FUNCTION_LIST_PTR_PTR, CK_RV, CKR_OK};
use tracing::Level;

use crate::{kms_object::get_kms_client, logging::initialize_logging};

mod backend;
mod error;
mod kms_object;
mod logging;
mod pkcs11_certificate;
mod pkcs11_data_object;
mod pkcs11_private_key;
mod pkcs11_public_key;
mod pkcs11_symmetric_key;

/// # Safety
/// This function is the first one called by the PKCS#11 library client
/// to get the PKCS#11 functions list.
/// # Panics
/// When KMS client cannot be instantiated.
#[unsafe(no_mangle)]
#[expect(clippy::expect_used, unsafe_code)]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    let debug_level =
        std::env::var("COSMIAN_PKCS11_LOGGING_LEVEL").unwrap_or_else(|_| "info".to_owned());
    initialize_logging("cosmian-pkcs11", Level::from_str(&debug_level).ok(), None);
    // Instantiate a backend with a kms client using the `cosmian.toml` file in the local default directory.
    register_backend(Box::new(backend::CliBackend::instantiate(
        get_kms_client().expect("failed getting the KMS client from the current configuration"),
    )));
    unsafe {
        // Update the function list with this PKCS#11 entry function
        FUNC_LIST.C_GetFunctionList = Some(C_GetFunctionList);
        // Return the function list to the client application using the output parameters
        *pp_function_list = addr_of_mut!(FUNC_LIST);
    }
    CKR_OK
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic_in_result_fn)]
mod tests;
