// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.
//
//Original code:
// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::slice;

use pkcs11_sys::{
    CK_MECHANISM, CK_MECHANISM_TYPE, CK_RSA_PKCS_PSS_PARAMS, CKG_MGF1_SHA1, CKG_MGF1_SHA224,
    CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512, CKM_AES_CBC_PAD, CKM_AES_KEY_GEN, CKM_ECDSA,
    CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_SHA_1, CKM_SHA1_RSA_PKCS, CKM_SHA224, CKM_SHA256,
    CKM_SHA256_RSA_PKCS, CKM_SHA384, CKM_SHA384_RSA_PKCS, CKM_SHA512, CKM_SHA512_RSA_PKCS,
};
use tracing::{debug, error};

use crate::{
    MError, not_null,
    traits::{DigestType, EncryptionAlgorithm, KeyAlgorithm, SignatureAlgorithm},
};

pub const SUPPORTED_SIGNATURE_MECHANISMS: &[CK_MECHANISM_TYPE] = &[
    CKM_RSA_PKCS,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_ECDSA,
    CKM_RSA_PKCS_PSS,
];

#[derive(Debug)]
pub enum Mechanism {
    AesKeyGen,
    AesCbcPad {
        iv: Vec<u8>,
    },
    Ecdsa,
    RsaPkcs,
    RsaPkcsSha1,
    RsaPkcsSha256,
    RsaPkcsSha384,
    RsaPkcsSha512,
    RsaPss {
        digest_algorithm: DigestType,
        mask_generation_function: DigestType,
        salt_length: u64,
    },
}

#[expect(clippy::missing_safety_doc)]
pub unsafe fn parse_mechanism(mechanism: CK_MECHANISM) -> Result<Mechanism, MError> {
    debug!("parse_mechanism: {mechanism:?}");
    match mechanism.mechanism {
        CKM_AES_KEY_GEN => Ok(Mechanism::AesKeyGen),
        CKM_AES_CBC_PAD => {
            let iv = unsafe {
                slice::from_raw_parts(
                    mechanism.pParameter.cast::<u8>(),
                    mechanism.ulParameterLen as usize,
                )
            };
            debug!("parse_mechanism: iv: {iv:?}");
            Ok(Mechanism::AesCbcPad { iv: iv.to_vec() })
        }
        CKM_ECDSA => Ok(Mechanism::Ecdsa),
        CKM_RSA_PKCS => Ok(Mechanism::RsaPkcs),
        CKM_SHA1_RSA_PKCS => Ok(Mechanism::RsaPkcsSha1),
        CKM_SHA256_RSA_PKCS => Ok(Mechanism::RsaPkcsSha256),
        CKM_SHA384_RSA_PKCS => Ok(Mechanism::RsaPkcsSha384),
        CKM_SHA512_RSA_PKCS => Ok(Mechanism::RsaPkcsSha512),
        CKM_RSA_PKCS_PSS => {
            //  Bind to locals to prevent unaligned reads https://github.com/rust-lang/rust/issues/82523
            let mechanism_type = mechanism.mechanism;
            let parameter_ptr = mechanism.pParameter;
            let parameter_len = mechanism.ulParameterLen;
            not_null!(parameter_ptr, "parse_mechanism: parameter_ptr");
            if (parameter_len as usize) != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                error!(
                    "pParameter incorrect: {} != {}",
                    parameter_len,
                    std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
                );
                return Err(MError::MechanismInvalid(mechanism_type));
            }
            //  TODO(kcking): check alignment as well?
            let params: CK_RSA_PKCS_PSS_PARAMS =
                unsafe { parameter_ptr.cast::<CK_RSA_PKCS_PSS_PARAMS>().read() };
            let mgf = params.mgf;
            let hash_alg = params.hashAlg;
            let salt_len = params.sLen;

            let mgf = match mgf {
                CKG_MGF1_SHA1 => DigestType::Sha1,
                CKG_MGF1_SHA224 => DigestType::Sha224,
                CKG_MGF1_SHA256 => DigestType::Sha256,
                CKG_MGF1_SHA384 => DigestType::Sha384,
                CKG_MGF1_SHA512 => DigestType::Sha512,
                _ => {
                    error!("Unsupported mgf: {}", mgf);
                    return Err(MError::MechanismInvalid(mechanism_type));
                }
            };

            let hash_alg = match hash_alg {
                CKM_SHA_1 => DigestType::Sha1,
                CKM_SHA224 => DigestType::Sha224,
                CKM_SHA256 => DigestType::Sha256,
                CKM_SHA384 => DigestType::Sha384,
                CKM_SHA512 => DigestType::Sha512,
                _ => {
                    error!("Unsupported hashAlg: {}", hash_alg);
                    return Err(MError::MechanismInvalid(mechanism_type));
                }
            };

            #[expect(clippy::unnecessary_cast)]
            Ok(Mechanism::RsaPss {
                digest_algorithm: hash_alg,
                mask_generation_function: mgf,
                //  Cast needed on windows
                salt_length: salt_len as u64,
            })
        }
        _ => Err(MError::MechanismInvalid(mechanism.mechanism)),
    }
}

impl From<Mechanism> for CK_MECHANISM_TYPE {
    fn from(mechanism: Mechanism) -> Self {
        match mechanism {
            Mechanism::AesKeyGen => CKM_AES_KEY_GEN,
            Mechanism::AesCbcPad { .. } => CKM_AES_CBC_PAD,
            Mechanism::Ecdsa => CKM_ECDSA,
            Mechanism::RsaPkcs => CKM_RSA_PKCS,
            Mechanism::RsaPkcsSha1 => CKM_SHA1_RSA_PKCS,
            Mechanism::RsaPkcsSha256 => CKM_SHA256_RSA_PKCS,
            Mechanism::RsaPkcsSha384 => CKM_SHA384_RSA_PKCS,
            Mechanism::RsaPkcsSha512 => CKM_SHA512_RSA_PKCS,
            Mechanism::RsaPss { .. } => CKM_RSA_PKCS_PSS,
        }
    }
}

impl From<Mechanism> for SignatureAlgorithm {
    fn from(mechanism: Mechanism) -> Self {
        match mechanism {
            Mechanism::Ecdsa => Self::Ecdsa,
            Mechanism::RsaPkcs => Self::RsaPkcs1v15Raw,
            Mechanism::RsaPkcsSha1 => Self::RsaPkcs1v15Sha1,
            Mechanism::RsaPkcsSha256 => Self::RsaPkcs1v15Sha256,
            Mechanism::RsaPkcsSha384 => Self::RsaPkcs1v15Sha512,
            Mechanism::RsaPkcsSha512 => Self::RsaPkcs1v15Sha384,
            Mechanism::RsaPss {
                digest_algorithm,
                mask_generation_function,
                salt_length,
            } => Self::RsaPss {
                digest: digest_algorithm,
                mask_generation_function,
                salt_length,
            },
            x => panic!("Unsupported signature algorithm: {x:?}"),
        }
    }
}

impl From<Mechanism> for EncryptionAlgorithm {
    fn from(mechanism: Mechanism) -> Self {
        match mechanism {
            Mechanism::RsaPkcs => Self::RsaPkcs1v15,
            Mechanism::AesCbcPad { .. } => Self::AesCbcPad,
            x => panic!("Unsupported encryption algorithm: {x:?}"),
        }
    }
}

impl From<Mechanism> for KeyAlgorithm {
    fn from(mechanism: Mechanism) -> Self {
        match mechanism {
            Mechanism::AesKeyGen => Self::Aes256,
            x => panic!("Unsupported key gen algorithm: {x:?}"),
        }
    }
}
