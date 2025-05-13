use std::ptr;

use winapi::um::wincrypt::{
    CALG_AES_256, CALG_SHA_256, CRYPT_EXPORTABLE, CRYPT_VERIFYCONTEXT, CryptAcquireContextA,
    CryptCreateHash, CryptDecrypt, CryptDeriveKey, CryptDestroyHash, CryptDestroyKey, CryptEncrypt,
    CryptHashData, CryptReleaseContext, HCRYPTHASH, HCRYPTKEY, HCRYPTPROV, PROV_RSA_AES,
};

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
