use std::{
    os::raw::{c_char, c_int, c_uchar},
    ptr, slice,
};

use tracing::{error, info, instrument};

use crate::error::InputsSnafu;

#[repr(C)]
pub struct EkmKeyData {
    key_id: *const c_char,
    key_data: *const c_uchar,
    key_data_len: c_int,
}

#[instrument]
#[unsafe(no_mangle)]
pub extern "C" fn encrypt_key(
    master_key: *const c_uchar,
    master_key_len: c_int,
    key_to_encrypt: *const c_uchar,
    key_to_encrypt_len: c_int,
    encrypted_key: *mut *mut c_uchar,
    encrypted_key_len: *mut c_int,
) -> c_int {
    // Safety: We're working with raw pointers, ensure parameters are valid
    if master_key.is_null()
        || key_to_encrypt.is_null()
        || encrypted_key.is_null()
        || encrypted_key_len.is_null()
    {
        error!(
            "{:?}",
            InputsSnafu {
                message: "Invalid parameters: master_key, key_to_encrypt, encrypted_key, or \
                          encrypted_key_len is null"
            }
            .build()
        );
        return 0; // Error
    }

    let result = std::panic::catch_unwind(|| {
        // Convert master key to key_id string
        let master_key_slice =
            unsafe { slice::from_raw_parts(master_key, master_key_len as usize) };
        let key_id = match std::str::from_utf8(master_key_slice) {
            Ok(s) => s.to_string(),
            Err(e) => {
                error!(
                    "{:?}",
                    InputsSnafu {
                        message: format!("Invalid UTF-8 in master_key: {}", e)
                    }
                    .build()
                );
                return 0;
            }
        };

        // Get key data to encrypt
        let key_data =
            unsafe { slice::from_raw_parts(key_to_encrypt, key_to_encrypt_len as usize) };

        info!("Key ID: {}", key_id);
        info!("Key data to encrypt: {:?}", key_data);

        // // Send to Cosmian KMS
        // match send_to_kms(
        //     "encrypt",
        //     &key_id,
        //     &encrypted_data,
        //     Some(&key_material),
        //     Some(&iv),
        // ) {
        //     Ok(final_data) => {
        //         // Allocate memory for the result that SQL Server will free.
        //         let result_len = final_data.len();
        //         let result_ptr = unsafe { libc::malloc(result_len) as *mut c_uchar };
        //         if result_ptr.is_null() {
        //             return 0;
        //         }

        //         unsafe {
        //             ptr::copy_nonoverlapping(final_data.as_ptr(), result_ptr, result_len);
        //             *encrypted_key = result_ptr;
        //             *encrypted_key_len = result_len as c_int;
        //         }

        //         1 // Success
        //     }
        //     Err(_) => 0, // Error
        // }

        0
    });

    result.unwrap_or(0)
}

#[instrument]
#[unsafe(no_mangle)]
pub extern "C" fn decrypt_key(
    master_key: *const c_uchar,
    master_key_len: c_int,
    encrypted_key: *const c_uchar,
    encrypted_key_len: c_int,
    decrypted_key: *mut *mut c_uchar,
    decrypted_key_len: *mut c_int,
) -> c_int {
    // Safety checks
    if master_key.is_null()
        || encrypted_key.is_null()
        || decrypted_key.is_null()
        || decrypted_key_len.is_null()
    {
        error!(
            "{:?}",
            InputsSnafu {
                message: "Invalid parameters: master_key, encrypted_key, decrypted_key, or \
                          decrypted_key_len is null"
            }
            .build()
        );
        return 0;
    }

    let result = std::panic::catch_unwind(|| {
        // Convert master key to key_id string
        let master_key_slice =
            unsafe { slice::from_raw_parts(master_key, master_key_len as usize) };
        let key_id = match std::str::from_utf8(master_key_slice) {
            Ok(s) => s.to_string(),
            Err(_) => {
                error!(
                    "{:?}",
                    InputsSnafu {
                        message: "Invalid UTF-8 in master_key"
                    }
                    .build()
                );
                return 0
            }
        };

        // Get the encrypted data
        let encrypted_data =
            unsafe { slice::from_raw_parts(encrypted_key, encrypted_key_len as usize) };

        info!("Key ID: {}", key_id);
        info!("Encrypted data: {:?}", encrypted_data);

        // // Decrypt using Cosmian KMS

        // // Send to KMS for unwrapping
        // match send_to_kms("decrypt", &key_id, encrypted_data, None, None) {
        //     Ok(unwrapped_data) => {
        //         // Extract the key, IV and encrypted data
        //         if unwrapped_data.len() < 48 {
        //             return 0; // Insufficient data
        //         }

        //         let key = &unwrapped_data[0..32];
        //         let iv = &unwrapped_data[32..48];
        //         let encrypted_bytes = &unwrapped_data[48..];

        //         // Decrypt locally using MSCAPI
        //         match decrypt_with_mscapi(encrypted_bytes, key, iv) {
        //             Ok(decrypted) => {
        //                 // Allocate memory for the result that SQL Server will free
        //                 let result_len = decrypted.len();
        //                 let result_ptr = unsafe { libc::malloc(result_len) as *mut c_uchar };
        //                 if result_ptr.is_null() {
        //                     return 0;
        //                 }

        //                 unsafe {
        //                     ptr::copy_nonoverlapping(decrypted.as_ptr(), result_ptr, result_len);
        //                     *decrypted_key = result_ptr;
        //                     *decrypted_key_len = result_len as c_int;
        //                 }

        //                 1 // Success
        //             }
        //             Err(_) => 0,
        //         }
        //     }
        //     Err(_) => 0,
        // }
        0
    });

    result.unwrap_or(0)
}

#[instrument]
#[unsafe(no_mangle)]
pub extern "C" fn sign_data(
    key_id: *const c_char,
    data: *const c_uchar,
    data_len: c_int,
    signature: *mut *mut c_uchar,
    signature_len: *mut c_int,
) -> c_int {
    // Safety checks
    if key_id.is_null() || data.is_null() || signature.is_null() || signature_len.is_null() {
        error!(
            "{:?}",
            InputsSnafu {
                message: "Invalid parameters: key_id, data, signature, or signature_len is null"
            }
            .build()
        );
        return 0; // Error
    }

    let result = std::panic::catch_unwind(|| {
        // Convert key_id to a Rust string

        let key_id_str = match unsafe { std::ffi::CStr::from_ptr(key_id) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                error!(
                    "{:?}",
                    InputsSnafu {
                        message: "Invalid UTF-8 in key_id"
                    }
                    .build()
                );
                return 0;
            }
        };

        // Get the data to sign
        let data_slice = unsafe { slice::from_raw_parts(data, data_len as usize) };

        info!("Key ID: {}", key_id_str);
        info!("Data to sign: {:?}", data_slice);
        // // Send to Cosmian KMS for signing

        // // Perform signing operation (replace with your signing logic)
        // let signed_data = match perform_signing_operation(key_id_str, data_slice) {
        //     Ok(sig) => sig,
        //     Err(_) => return 0,
        // };

        // // Allocate memory for the signature
        // let sig_len = signed_data.len();
        // let sig_ptr = unsafe { libc::malloc(sig_len) as *mut c_uchar };
        // if sig_ptr.is_null() {
        //     return 0;
        // }

        // unsafe {
        //     ptr::copy_nonoverlapping(signed_data.as_ptr(), sig_ptr, sig_len);
        //     *signature = sig_ptr;
        //     *signature_len = sig_len as c_int;
        // }

        // 1 // Success
        0
    });

    result.unwrap_or(0)
}

#[instrument]
#[unsafe(no_mangle)]
pub extern "C" fn verify_signature(
    key_id: *const c_char,
    data: *const c_uchar,
    data_len: c_int,
    signature: *const c_uchar,
    signature_len: c_int,
) -> c_int {
    // Safety checks
    if key_id.is_null() || data.is_null() || signature.is_null() {
        error!(
            "{:?}",
            InputsSnafu {
                message: "Invalid parameters: key_id, data, or signature is null"
            }
            .build()
        );
        return 0; // Error
    }

    let result = std::panic::catch_unwind(|| {
        // Convert key_id to a Rust string
        let key_id_str = match unsafe { std::ffi::CStr::from_ptr(key_id) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                error!(
                    "{:?}",
                    InputsSnafu {
                        message: "Invalid UTF-8 in key_id"
                    }
                    .build()
                );
                return 0;
            }
        };

        // Get the data and signature
        let data_slice = unsafe { slice::from_raw_parts(data, data_len as usize) };
        let signature_slice = unsafe { slice::from_raw_parts(signature, signature_len as usize) };

        info!("Key ID: {}", key_id_str);
        info!("Data to verify: {:?}", data_slice);
        info!("Signature: {:?}", signature_slice);

        // // Perform signature verification (replace with your verification logic)
        // match perform_verification_operation(key_id_str, data_slice, signature_slice) {
        //     Ok(true) => 1,  // Signature is valid
        //     Ok(false) => 0, // Signature is invalid
        //     Err(_) => 0,    // Error
        // }
        0
    });

    result.unwrap_or(0)
}

#[instrument]
#[unsafe(no_mangle)]
pub extern "C" fn get_key_metadata(key_id: *const c_char, metadata: *mut *mut c_char) -> c_int {
    // Safety checks
    if key_id.is_null() || metadata.is_null() {
        error!(
            "{:?}",
            InputsSnafu {
                message: "Invalid parameters: key_id or metadata is null"
            }
            .build()
        );
        return 0; // Error
    }

    let result = std::panic::catch_unwind(|| {
        // Convert key_id to a Rust string
        let key_id_str = match unsafe { std::ffi::CStr::from_ptr(key_id) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                error!(
                    "{:?}",
                    InputsSnafu {
                        message: "Invalid UTF-8 in key_id"
                    }
                    .build()
                );
                return 0;
            }
        };

        info!("Key ID: {}", key_id_str);

        // // Retrieve metadata (replace with your metadata retrieval logic)
        // let key_metadata = match retrieve_key_metadata(key_id_str) {
        //     Ok(meta) => meta,
        //     Err(_) => return 0,
        // };

        // // Allocate memory for the metadata string
        // let meta_cstring = std::ffi::CString::new(key_metadata).map_err(|_| 0)?;
        // let meta_ptr = meta_cstring.into_raw();
        // unsafe {
        //     *metadata = meta_ptr;
        // }

        // 1 // Success
        0
    });

    result.unwrap_or(0)
}

#[instrument]
#[unsafe(no_mangle)]
pub extern "C" fn cleanup() {
    // Perform any necessary cleanup operations
    // For example, closing connections or freeing resources
    info!("Cleaning up resources...");
}
