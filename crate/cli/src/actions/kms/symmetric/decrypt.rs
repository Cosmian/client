use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use clap::Parser;
use cosmian_kms_client::{
    ExportObjectParams, KmsClient, export_object,
    kmip_2_1::{
        kmip_data_structures::KeyWrappingData,
        kmip_types::{
            BlockCipherMode, CryptographicAlgorithm, CryptographicParameters, KeyFormatType,
        },
        requests::{create_symmetric_key_kmip_object, decrypt_request},
    },
    read_bytes_from_file,
};
#[cfg(not(feature = "fips"))]
use cosmian_kms_crypto::crypto::symmetric::symmetric_ciphers::{
    CHACHA20_POLY1305_IV_LENGTH, CHACHA20_POLY1305_MAC_LENGTH,
};
use cosmian_kms_crypto::crypto::{
    symmetric::symmetric_ciphers::{
        AES_128_GCM_IV_LENGTH, AES_128_GCM_MAC_LENGTH, AES_128_XTS_MAC_LENGTH,
        AES_128_XTS_TWEAK_LENGTH, Mode, RFC5649_16_IV_LENGTH, RFC5649_16_MAC_LENGTH, SymCipher,
        decrypt,
    },
    wrap::unwrap_key_block,
};
use tracing::trace;
use zeroize::Zeroizing;

use crate::{
    actions::{
        console,
        kms::{
            labels::KEY_ID,
            shared::get_key_uid,
            symmetric::{DataEncryptionAlgorithm, KeyEncryptionAlgorithm},
        },
    },
    cli_bail,
    error::{
        CosmianError,
        result::{CosmianResult, CosmianResultHelper},
    },
};

/// Decrypt a file using a symmetric key.
///
/// Decryption can happen in two ways:
///  - server side: the data is sent to the server and decrypted server side.
///  - client side: The encapsulated/wrapped data encryption key (DEK) is read from the input file
///    and decrypted server side using the key encryption algorithm and the key encryption key (KEK)
///    identified by `--key-id`. Once the DEK is recovered, the data is decrypted client side
///    using the data encryption algorithm.
///
/// To decrypt the data server side, do not specify the key encryption algorithm.
///
/// The bytes written from the input are expected to be the concatenation of
///   - if client side decryption is used:
///         - the length of the encapsulated DEK as an unsigned LEB128 integer
///         - the encapsulated DEK
///   - the nonce used for data encryption (or tweak for XTS)
///   - the encrypted data (same size as the plaintext)
///   - the authentication tag generated by the data encryption algorithm (none, for XTS)
///
/// Note: server side decryption is not a streaming call:
/// the data is entirely loaded in memory before being encrypted.
#[derive(Parser, Debug, Default)]
#[clap(verbatim_doc_comment)]
pub struct DecryptAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The private key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,

    /// The data encryption algorithm.
    /// If not specified, aes-gcm is used.
    ///
    /// If no key encryption algorithm is specified, the data will be sent to the server
    /// and will be decrypted server side.
    #[clap(
        long = "data-encryption-algorithm",
        short = 'd',
        default_value = "aes-gcm",
        verbatim_doc_comment
    )]
    data_encryption_algorithm: DataEncryptionAlgorithm,

    /// The optional key encryption algorithm used to decrypt the data encryption key.
    ///
    /// If not specified:
    ///   - the decryption of the data is performed server side using the key identified by
    ///     `--key-id`
    ///
    /// If specified:
    ///  - the data encryption key (DEK) is unwrapped (i.e., decrypted) server side
    ///    using the key encryption algorithm and the key identified by `--key-id`.
    ///  - the data is decrypted client side with the data encryption algorithm and using
    ///    the DEK.
    #[clap(long = "key-encryption-algorithm", short = 'e', verbatim_doc_comment)]
    key_encryption_algorithm: Option<KeyEncryptionAlgorithm>,

    /// The encrypted output file path
    #[clap(long, short = 'o')]
    output_file: Option<PathBuf>,

    /// Optional authentication data that was supplied during encryption as a hex string.
    #[clap(long, short = 'a')]
    authentication_data: Option<String>,
}

impl DecryptAction {
    pub(crate) async fn run(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
        // Recover the unique identifier or set of tags
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Write the decrypted file
        let output_file_name = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.clone().with_extension("plain"));

        let mut output_file =
            File::create(&output_file_name).context("Fail to write the plaintext file")?;

        if let Some(key_encryption_algorithm) = self.key_encryption_algorithm {
            self.client_side_decrypt_with_file(
                kms_rest_client,
                key_encryption_algorithm,
                self.data_encryption_algorithm,
                &id,
                &self.input_file,
                &mut output_file,
                self.authentication_data
                    .as_deref()
                    .map(hex::decode)
                    .transpose()?,
            )
            .await?;
        } else {
            // Read the file to decrypt
            let ciphertext = read_bytes_from_file(&self.input_file)
                .with_context(|| "Cannot read bytes from the file to decrypt")?;
            // Decrypt the ciphertext server side
            let plaintext = self
                .server_side_decrypt(
                    kms_rest_client,
                    self.data_encryption_algorithm.into(),
                    &id,
                    ciphertext,
                    self.authentication_data
                        .as_deref()
                        .map(hex::decode)
                        .transpose()?,
                )
                .await?;
            output_file
                .write_all(&plaintext)
                .context("failed to write the plaintext  file")?;
        }

        // Print the output file name to the console and return
        let stdout = format!("The decrypted file is available at {output_file_name:?}");
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(())
    }

    /// Delegate decryption to the server.
    ///
    /// # Errors
    /// - If the cryptographic algorithm is not supported
    /// - If the block cipher mode is not supported
    /// - If the key id is not specified
    pub async fn server_side_decrypt(
        &self,
        kms_rest_client: &KmsClient,
        cryptographic_parameters: CryptographicParameters,
        key_id: &str,
        mut ciphertext: Vec<u8>,
        aad: Option<Vec<u8>>,
    ) -> CosmianResult<Zeroizing<Vec<u8>>> {
        // Extract the nonce, the encrypted data, and the tag
        let (nonce_size, tag_size) = match &cryptographic_parameters
            .cryptographic_algorithm
            .unwrap_or(CryptographicAlgorithm::AES)
        {
            CryptographicAlgorithm::AES => match cryptographic_parameters
                .block_cipher_mode
                .unwrap_or(BlockCipherMode::GCM)
            {
                BlockCipherMode::GCM | BlockCipherMode::GCMSIV => {
                    (AES_128_GCM_IV_LENGTH, AES_128_GCM_MAC_LENGTH)
                }
                BlockCipherMode::XTS => (AES_128_XTS_TWEAK_LENGTH, AES_128_XTS_MAC_LENGTH),
                BlockCipherMode::NISTKeyWrap => (RFC5649_16_IV_LENGTH, RFC5649_16_MAC_LENGTH),
                _ => cli_bail!("Unsupported block cipher mode"),
            },
            #[cfg(not(feature = "fips"))]
            CryptographicAlgorithm::ChaCha20Poly1305 | CryptographicAlgorithm::ChaCha20 => {
                (CHACHA20_POLY1305_IV_LENGTH, CHACHA20_POLY1305_MAC_LENGTH)
            }
            a => cli_bail!("Unsupported cryptographic algorithm: {:?}", a),
        };
        if nonce_size + tag_size > ciphertext.len() {
            cli_bail!("The ciphertext is too short to contain the nonce/tweak and the tag")
        }
        let nonce = ciphertext.drain(..nonce_size).collect::<Vec<_>>();
        let tag = ciphertext
            .drain(ciphertext.len() - tag_size..)
            .collect::<Vec<_>>();

        // Create the kmip query
        let decrypt_request = decrypt_request(
            key_id,
            Some(nonce),
            ciphertext,
            Some(tag),
            aad,
            Some(cryptographic_parameters),
        );

        // Query the KMS with your kmip data and get the key pair ids
        let decrypt_response = kms_rest_client
            .decrypt(decrypt_request)
            .await
            .context("Can't execute the query on the kms server")?;

        decrypt_response.data.context("the plain text is empty")
    }

    #[allow(clippy::too_many_arguments)]
    async fn client_side_decrypt_with_file(
        &self,
        kms_rest_client: &KmsClient,
        key_encryption_algorithm: KeyEncryptionAlgorithm,
        data_encryption_algorithm: DataEncryptionAlgorithm,
        key_id: &str,
        input_file_name: &Path,
        output_file: &mut File,
        aad: Option<Vec<u8>>,
    ) -> CosmianResult<()> {
        // Additional authenticated data (AAD) for AEAD ciphers
        // (empty for XTS)
        let aad = match data_encryption_algorithm {
            DataEncryptionAlgorithm::AesXts => vec![],
            DataEncryptionAlgorithm::AesGcm => aad.unwrap_or_default(),
            #[cfg(not(feature = "fips"))]
            DataEncryptionAlgorithm::AesGcmSiv | DataEncryptionAlgorithm::Chacha20Poly1305 => {
                aad.unwrap_or_default()
            }
        };
        // Open the input file
        let mut input_file = File::open(input_file_name)?;
        // read the encapsulation length as a LEB128 encoded u64
        let encaps_length = leb128::read::unsigned(&mut input_file).map_err(|e| {
            CosmianError::Default(format!(
                "Failed to read the encapsulation length from the encrypted file: {e}"
            ))
        })?;
        // read the encapsulated data
        #[allow(clippy::cast_possible_truncation)]
        let mut encapsulation = vec![0; encaps_length as usize];
        input_file.read_exact(&mut encapsulation)?;
        // recover the DEK
        let dek = self
            .server_side_decrypt(
                kms_rest_client,
                key_encryption_algorithm.into(),
                key_id,
                encapsulation,
                None,
            )
            .await?;
        // determine the DEM parameters
        let dem_cryptographic_parameters: CryptographicParameters =
            data_encryption_algorithm.into();
        let cipher = SymCipher::from_algorithm_and_key_size(
            dem_cryptographic_parameters
                .cryptographic_algorithm
                .unwrap_or(CryptographicAlgorithm::AES),
            dem_cryptographic_parameters.block_cipher_mode,
            dek.len(),
        )?;
        //read the nonce
        let mut nonce = vec![0; cipher.nonce_size()];
        input_file.read_exact(&mut nonce)?;
        // decrypt the file
        let mut stream_cipher = cipher.stream_cipher(Mode::Decrypt, &dek, &nonce, &aad)?;
        let tag_size = cipher.tag_size();
        // read the file by chunks
        let mut chunk = vec![0; 2 ^ 16]; //64K
        let mut read_buffer = vec![];
        loop {
            let bytes_read = input_file.read(&mut chunk)?;
            if bytes_read == 0 {
                break;
            }
            chunk.truncate(bytes_read);
            let available_bytes = [read_buffer.as_slice(), &chunk].concat();
            // keep at least the tag size in the local buffer
            if available_bytes.len() > tag_size {
                // process all bytes except the tag length last bytes
                let num_bytes_to_process = available_bytes.len() - tag_size;
                let output = stream_cipher.update(&available_bytes[..num_bytes_to_process])?;
                output_file.write_all(&output)?;
                // keep the remaining bytes in the read buffer
                read_buffer = available_bytes[num_bytes_to_process..].to_vec();
            } else {
                // put everything in the read buffer
                read_buffer = available_bytes;
            }
        }
        // recover the tag from the read_buffer
        if read_buffer.len() < tag_size {
            cli_bail!("The tag is missing from the encrypted file")
        }
        // write the remaining bytes before the tag
        let remaining = &read_buffer[..read_buffer.len() - cipher.tag_size()];
        if !remaining.is_empty() {
            let output = stream_cipher.update(remaining)?;
            output_file.write_all(&output)?;
        }
        let tag = &read_buffer[read_buffer.len() - cipher.tag_size()..];
        output_file.write_all(&stream_cipher.finalize_decryption(tag)?)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments, dead_code)]
    /// Decrypt a buffer using a symmetric key.
    /// # Errors
    /// - If the key encryption algorithm is not supported
    /// - If the data encryption algorithm is not supported
    /// - If the key id is not specified
    pub async fn client_side_decrypt_with_buffer(
        &self,
        kms_rest_client: &KmsClient,
        data_encryption_algorithm: DataEncryptionAlgorithm,
        key_encapsulation_key_id: &str,
        ciphertext: &[u8],
        aad: Option<Vec<u8>>,
    ) -> CosmianResult<Vec<u8>> {
        trace!(
            "Decrypting buffer with data encryption algorithm {:?}, key id {:?}, ciphertext: {:?}",
            data_encryption_algorithm, key_encapsulation_key_id, ciphertext
        );

        // First export the KEK locally
        let unwrapping_key = export_object(
            kms_rest_client,
            key_encapsulation_key_id,
            ExportObjectParams {
                key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
                ..ExportObjectParams::default()
            },
        )
        .await?
        .1;

        // Then read the encapsulated data
        let mut ct = ciphertext;
        // Additional authenticated data (AAD) for AEAD ciphers
        // (empty for XTS)
        let aad = match data_encryption_algorithm {
            DataEncryptionAlgorithm::AesXts => vec![],
            DataEncryptionAlgorithm::AesGcm => aad.unwrap_or_default(),
            #[cfg(not(feature = "fips"))]
            DataEncryptionAlgorithm::AesGcmSiv | DataEncryptionAlgorithm::Chacha20Poly1305 => {
                aad.unwrap_or_default()
            }
        };
        // Open the input file
        // read the encapsulation length as a LEB128 encoded u64
        let encaps_length = leb128::read::unsigned(&mut ct).map_err(|e| {
            CosmianError::Default(format!(
                "Failed to read the encapsulation length from the encrypted file: {e}"
            ))
        })?;

        // read the encapsulated data
        #[allow(clippy::cast_possible_truncation)]
        let mut encapsulation = vec![0; encaps_length as usize];
        ct.read_exact(&mut encapsulation)?;

        // Create the KMIP object corresponding to the DEK
        let mut dek_object =
            create_symmetric_key_kmip_object(&encapsulation, CryptographicAlgorithm::AES, false)?;
        dek_object.key_block_mut()?.key_wrapping_data = Some(KeyWrappingData::default());

        // recover the DEK
        unwrap_key_block(dek_object.key_block_mut()?, &unwrapping_key)?;
        let dek = dek_object.key_block()?.key_bytes()?;

        // determine the DEM parameters
        let dem_cryptographic_parameters: CryptographicParameters =
            data_encryption_algorithm.into();
        let sym_cipher = SymCipher::from_algorithm_and_key_size(
            dem_cryptographic_parameters
                .cryptographic_algorithm
                .unwrap_or(CryptographicAlgorithm::AES),
            dem_cryptographic_parameters.block_cipher_mode,
            dek.len(),
        )?;
        //read the nonce
        let mut nonce = vec![0; sym_cipher.nonce_size()];

        ct.read_exact(&mut nonce)?;

        // decrypt the file
        // let mut stream_cipher = cipher.stream_cipher(Mode::Decrypt, &dek, &nonce, &aad)?;
        let tag_size = sym_cipher.tag_size();

        let (ciphertext, tag) = ct.split_at(ct.len() - tag_size);

        let cleartext = decrypt(sym_cipher, &dek, &nonce, &aad, ciphertext, tag)?;

        Ok(cleartext.to_vec())
    }
}
