// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.
//
// Original code:
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
use pkcs11_sys::{
    CK_ATTRIBUTE_TYPE, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID,
    CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_FUNCTION_NOT_PARALLEL, CKR_FUNCTION_NOT_SUPPORTED, CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID, CKR_MECHANISM_INVALID, CKR_NEED_TO_CREATE_THREADS,
    CKR_OBJECT_HANDLE_INVALID, CKR_OPERATION_NOT_INITIALIZED, CKR_RANDOM_NO_RNG,
    CKR_SESSION_HANDLE_INVALID, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SLOT_ID_INVALID,
    CKR_TOKEN_WRITE_PROTECTED,
};
use thiserror::Error;

use crate::core::attribute::AttributeType;

pub(crate) mod result;
pub use result::MResult;

#[derive(Error, Debug)]
pub enum MError {
    #[error("pkcs11 error: {0}")]
    Default(String),
    // Cryptoki errors.
    #[error("bad arguments: {0}")]
    ArgumentsBad(String),
    #[error("{0} is not a valid attribute type")]
    AttributeTypeInvalid(CK_ATTRIBUTE_TYPE),
    #[error("the value for attribute {0} is invalid")]
    AttributeValueInvalid(AttributeType),
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("cryptoki module has already been initialized")]
    CryptokiAlreadyInitialized,
    #[error("cryptoki module has not been initialized")]
    CryptokiNotInitialized,
    #[error("function not parallel")]
    FunctionNotParallel,
    #[error("function not supported")]
    FunctionNotSupported,
    #[error("key handle {0} is invalid")]
    KeyHandleInvalid(CK_OBJECT_HANDLE),
    #[error("module cannot function without being able to spawn threads")]
    NeedToCreateThreads,
    #[error("{0} is not a valid mechanism")]
    MechanismInvalid(CK_MECHANISM_TYPE),
    #[error("object {0} is invalid")]
    ObjectHandleInvalid(CK_OBJECT_HANDLE),
    #[error("operation has not been initialized, session: {0}")]
    OperationNotInitialized(CK_SESSION_HANDLE),
    #[error("no random number generator")]
    RandomNoRng,
    #[error("session handle {0} is invalid")]
    SessionHandleInvalid(CK_SESSION_HANDLE),
    #[error("token does not support parallel sessions")]
    SessionParallelNotSupported,
    #[error("slot id {0} is invalid")]
    SlotIdInvalid(CK_SLOT_ID),
    #[error("token is write protected")]
    TokenWriteProtected,
    // Other errors.
    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    FromVecWithNul(#[from] std::ffi::FromVecWithNulError),
    #[error("{0} is a null pointer")]
    NullPtr(String),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    // Catch-all for backend-related errors.
    #[error(transparent)]
    Backend(#[from] Box<dyn std::error::Error>),
    #[error(transparent)]
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[error(transparent)]
    Pkcs1DerError(#[from] pkcs1::der::Error),
    #[error(transparent)]
    ConstOidError(#[from] const_oid::Error),
    #[error("Oid: {0}")]
    Oid(String),
    #[error("{0}")]
    Todo(String),
    #[error("cryptographic error: {0}")]
    Cryptography(String),
}

impl From<MError> for CK_RV {
    fn from(e: MError) -> Self {
        match e {
            MError::ArgumentsBad(_) => CKR_ARGUMENTS_BAD,
            MError::AttributeTypeInvalid(_) => CKR_ATTRIBUTE_TYPE_INVALID,
            MError::AttributeValueInvalid(_) => CKR_ATTRIBUTE_VALUE_INVALID,
            MError::BufferTooSmall => CKR_BUFFER_TOO_SMALL,
            MError::CryptokiAlreadyInitialized => CKR_CRYPTOKI_ALREADY_INITIALIZED,
            MError::CryptokiNotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
            MError::FunctionNotParallel => CKR_FUNCTION_NOT_PARALLEL,
            MError::FunctionNotSupported => CKR_FUNCTION_NOT_SUPPORTED,
            MError::KeyHandleInvalid(_) => CKR_KEY_HANDLE_INVALID,
            MError::MechanismInvalid(_) => CKR_MECHANISM_INVALID,
            MError::NeedToCreateThreads => CKR_NEED_TO_CREATE_THREADS,
            MError::ObjectHandleInvalid(_) => CKR_OBJECT_HANDLE_INVALID,
            MError::OperationNotInitialized(_) => CKR_OPERATION_NOT_INITIALIZED,
            MError::RandomNoRng => CKR_RANDOM_NO_RNG,
            MError::SessionHandleInvalid(_) => CKR_SESSION_HANDLE_INVALID,
            MError::SessionParallelNotSupported => CKR_SESSION_PARALLEL_NOT_SUPPORTED,
            MError::SlotIdInvalid(_) => CKR_SLOT_ID_INVALID,
            MError::TokenWriteProtected => CKR_TOKEN_WRITE_PROTECTED,

            MError::Backend(_)
            | MError::Default(_)
            | MError::Bincode(_)
            | MError::ConstOidError(_)
            | MError::FromUtf8(_)
            | MError::FromVecWithNul(_)
            | MError::NullPtr(_)
            | MError::Todo(_)
            | MError::Cryptography(_)
            | MError::TryFromInt(_)
            | MError::Pkcs1DerError(_)
            | MError::Oid(_)
            | MError::TryFromSlice(_) => CKR_GENERAL_ERROR,
        }
    }
}
