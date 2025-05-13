use std::{
    os::raw::{c_char, c_int, c_uchar},
    ptr, slice,
};

use crate::send_to_kms;

#[repr(C)]
pub struct EkmKeyData {
    key_id: *const c_char,
    key_data: *const c_uchar,
    key_data_len: c_int,
}

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
        return 0; // Error
    }

    let result = std::panic::catch_unwind(|| {
        // Convert master key to key_id string
        let master_key_slice =
            unsafe { slice::from_raw_parts(master_key, master_key_len as usize) };
        let key_id = match std::str::from_utf8(master_key_slice) {
            Ok(s) => s.to_string(),
            Err(_) => return 0, // Invalid UTF-8
        };

        // Get key data to encrypt
        let key_data =
            unsafe { slice::from_raw_parts(key_to_encrypt, key_to_encrypt_len as usize) };

        // Perform local encryption using MSCAPI
        let (encrypted_data, key_material, iv) = match encrypt_with_mscapi(key_data) {
            Ok(result) => result,
            Err(_) => return 0,
        };

        // Send to Cosmian KMS
        match send_to_kms(
            "encrypt",
            &key_id,
            &encrypted_data,
            Some(&key_material),
            Some(&iv),
        ) {
            Ok(final_data) => {
                // Allocate memory for the result that SQL Server will free.
                let result_len = final_data.len();
                let result_ptr = unsafe { libc::malloc(result_len) as *mut c_uchar };
                if result_ptr.is_null() {
                    return 0;
                }

                unsafe {
                    ptr::copy_nonoverlapping(final_data.as_ptr(), result_ptr, result_len);
                    *encrypted_key = result_ptr;
                    *encrypted_key_len = result_len as c_int;
                }

                1 // Success
            }
            Err(_) => 0, // Error
        }
    });

    result.unwrap_or_else(|_| 0)
}

#[no_mangle]
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
        return 0;
    }

    let result = std::panic::catch_unwind(|| {
        // Convert master key to key_id string
        let master_key_slice =
            unsafe { slice::from_raw_parts(master_key, master_key_len as usize) };
        let key_id = match std::str::from_utf8(master_key_slice) {
            Ok(s) => s.to_string(),
            Err(_) => return 0,
        };

        // Get the encrypted data
        let encrypted_data =
            unsafe { slice::from_raw_parts(encrypted_key, encrypted_key_len as usize) };

        // Send to KMS for unwrapping
        match send_to_kms("decrypt", &key_id, encrypted_data, None, None) {
            Ok(unwrapped_data) => {
                // Extract the key, IV and encrypted data
                if unwrapped_data.len() < 48 {
                    return 0; // Insufficient data
                }

                let key = &unwrapped_data[0..32];
                let iv = &unwrapped_data[32..48];
                let encrypted_bytes = &unwrapped_data[48..];

                // Decrypt locally using MSCAPI
                match decrypt_with_mscapi(encrypted_bytes, key, iv) {
                    Ok(decrypted) => {
                        // Allocate memory for the result that SQL Server will free
                        let result_len = decrypted.len();
                        let result_ptr = unsafe { libc::malloc(result_len) as *mut c_uchar };
                        if result_ptr.is_null() {
                            return 0;
                        }

                        unsafe {
                            ptr::copy_nonoverlapping(decrypted.as_ptr(), result_ptr, result_len);
                            *decrypted_key = result_ptr;
                            *decrypted_key_len = result_len as c_int;
                        }

                        1 // Success
                    }
                    Err(_) => 0,
                }
            }
            Err(_) => 0,
        }
    });

    result.unwrap_or_else(|_| 0)
}
