use std::{
    os::raw::{c_char, c_int, c_uchar},
    ptr, slice,
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use winapi::um::wincrypt::{
    CALG_AES_256, CALG_SHA_256, CRYPT_EXPORTABLE, CRYPT_VERIFYCONTEXT, CryptAcquireContextA,
    CryptCreateHash, CryptDecrypt, CryptDeriveKey, CryptDestroyHash, CryptDestroyKey, CryptEncrypt,
    CryptHashData, CryptReleaseContext, HCRYPTHASH, HCRYPTKEY, HCRYPTPROV, PROV_RSA_AES,
};

#[repr(C)]
pub struct EkmKeyData {
    key_id: *const c_char,
    key_data: *const c_uchar,
    key_data_len: c_int,
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

fn encrypt_with_mscapi(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let mut prov: HCRYPTPROV = 0;
    let mut hash: HCRYPTHASH = 0;
    let mut key: HCRYPTKEY = 0;

    unsafe {
        // Acquire crypto context
        if CryptAcquireContextA(
            &mut prov,
            ptr::null_mut(),
            ptr::null_mut(),
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        ) == 0
        {
            return Err("Failed to acquire crypto context".to_string());
        }

        // Create hash for key derivation
        if CryptCreateHash(prov, CALG_SHA_256, 0, 0, &mut hash) == 0 {
            CryptReleaseContext(prov, 0);
            return Err("Failed to create hash".to_string());
        }

        // Generate random key material
        let key_material: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        // Hash the key material
        if CryptHashData(hash, key_material.as_ptr(), key_material.len() as u32, 0) == 0 {
            CryptDestroyHash(hash);
            CryptReleaseContext(prov, 0);
            return Err("Failed to hash data".to_string());
        }

        // Derive encryption key
        if CryptDeriveKey(prov, CALG_AES_256, hash, CRYPT_EXPORTABLE, &mut key) == 0 {
            CryptDestroyHash(hash);
            CryptReleaseContext(prov, 0);
            return Err("Failed to derive key".to_string());
        }

        // Generate random IV
        let iv: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();

        // Encrypt the data
        let mut buf = data.to_vec();
        let mut data_len = buf.len() as u32;

        if CryptEncrypt(
            key,
            0,
            1,
            0,
            buf.as_mut_ptr(),
            &mut data_len,
            buf.capacity() as u32,
        ) == 0
        {
            CryptDestroyKey(key);
            CryptDestroyHash(hash);
            CryptReleaseContext(prov, 0);
            return Err("Failed to encrypt data".to_string());
        }

        buf.truncate(data_len as usize);

        // Cleanup
        CryptDestroyKey(key);
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);

        Ok((buf, key_material, iv))
    }
}

fn decrypt_with_mscapi(data: &[u8], key_material: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let mut prov: HCRYPTPROV = 0;
    let mut hash: HCRYPTHASH = 0;
    let mut key: HCRYPTKEY = 0;

    unsafe {
        // Acquire crypto context
        if CryptAcquireContextA(
            &mut prov,
            ptr::null_mut(),
            ptr::null_mut(),
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        ) == 0
        {
            return Err("Failed to acquire crypto context".to_string());
        }

        // Create hash for key derivation
        if CryptCreateHash(prov, CALG_SHA_256, 0, 0, &mut hash) == 0 {
            CryptReleaseContext(prov, 0);
            return Err("Failed to create hash".to_string());
        }

        // Hash the key material
        if CryptHashData(hash, key_material.as_ptr(), key_material.len() as u32, 0) == 0 {
            CryptDestroyHash(hash);
            CryptReleaseContext(prov, 0);
            return Err("Failed to hash data".to_string());
        }

        // Derive decryption key
        if CryptDeriveKey(prov, CALG_AES_256, hash, CRYPT_EXPORTABLE, &mut key) == 0 {
            CryptDestroyHash(hash);
            CryptReleaseContext(prov, 0);
            return Err("Failed to derive key".to_string());
        }

        // Decrypt the data
        let mut buf = data.to_vec();
        let mut data_len = buf.len() as u32;

        if CryptDecrypt(key, 0, 1, 0, buf.as_mut_ptr(), &mut data_len) == 0 {
            CryptDestroyKey(key);
            CryptDestroyHash(hash);
            CryptReleaseContext(prov, 0);
            return Err("Failed to decrypt data".to_string());
        }

        buf.truncate(data_len as usize);

        // Cleanup
        CryptDestroyKey(key);
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);

        Ok(buf)
    }
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
