use std::{ptr, ptr::addr_of_mut, sync::Arc};

use cosmian_logger::log_init;
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_C_INITIALIZE_ARGS, CK_FALSE, CK_INVALID_HANDLE, CK_KEY_TYPE, CK_MECHANISM,
    CK_TRUE, CKA_CLASS, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, CKA_SENSITIVE, CKA_VALUE_LEN,
    CKK_AES, CKM_AES_CBC_PAD, CKM_AES_KEY_GEN, CKM_DSA, CKO_PRIVATE_KEY, CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_FUNCTION_NOT_PARALLEL, CKR_MECHANISM_INVALID, CKR_OBJECT_HANDLE_INVALID,
    CKR_SESSION_HANDLE_INVALID, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SLOT_ID_INVALID,
};
use serial_test::serial;
use zeroize::Zeroizing;

use super::*;
use crate::{
    core::mechanism::AES_IV_SIZE,
    traits::{
        Backend, Certificate, DataObject, EncryptionAlgorithm, KeyAlgorithm, PrivateKey, PublicKey,
        SearchOptions, SymmetricKey, Version, register_backend,
    },
};

struct DummySymKey;

impl SymmetricKey for DummySymKey {
    fn remote_id(&self) -> String {
        "dummy_key".to_owned()
    }

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Aes256
    }

    fn key_size(&self) -> usize {
        32
    }

    fn raw_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![0; self.key_size()]))
    }
}

struct TestBackend;

impl Backend for TestBackend {
    fn token_label(&self) -> [u8; 32] {
        *b"Foo software token              "
    }

    fn token_manufacturer_id(&self) -> [u8; 32] {
        *b"Foo manufacturer id             "
    }

    fn token_model(&self) -> [u8; 16] {
        *b"Foo model       "
    }

    fn token_serial_number(&self) -> [u8; 16] {
        *b"1234567890abcdef"
    }

    fn library_description(&self) -> [u8; 32] {
        *b"Foo PKCS#11 library             "
    }

    fn library_version(&self) -> Version {
        Version { major: 1, minor: 0 }
    }

    fn find_certificate(
        &self,
        _query: SearchOptions,
    ) -> ModuleResult<Option<Arc<dyn Certificate>>> {
        Ok(None)
    }

    fn find_all_certificates(&self) -> ModuleResult<Vec<Arc<dyn Certificate>>> {
        Ok(vec![])
    }

    fn find_private_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn PrivateKey>> {
        Err(MError::FunctionNotSupported)
    }

    fn find_public_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn PublicKey>> {
        Err(MError::FunctionNotSupported)
    }

    fn find_all_private_keys(&self) -> ModuleResult<Vec<Arc<dyn PrivateKey>>> {
        Ok(vec![])
    }

    fn find_all_public_keys(&self) -> ModuleResult<Vec<Arc<dyn PublicKey>>> {
        Ok(vec![])
    }

    fn find_data_object(&self, _query: SearchOptions) -> ModuleResult<Option<Arc<dyn DataObject>>> {
        Ok(None)
    }

    fn find_all_data_objects(&self) -> ModuleResult<Vec<Arc<dyn DataObject>>> {
        Ok(vec![])
    }

    fn find_symmetric_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn SymmetricKey>> {
        Err(MError::FunctionNotSupported)
    }

    fn find_all_symmetric_keys(&self) -> ModuleResult<Vec<Arc<dyn SymmetricKey>>> {
        Ok(vec![])
    }

    fn find_all_keys(&self) -> ModuleResult<Vec<Arc<Object>>> {
        Ok(vec![])
    }

    fn generate_key(
        &self,
        _algorithm: KeyAlgorithm,
        _key_length: usize,
        _sensitive: bool,
        _label: Option<&str>,
    ) -> ModuleResult<Arc<dyn SymmetricKey>> {
        Ok(Arc::new(DummySymKey {}))
    }

    fn encrypt(
        &self,
        _remote_object_id: String,
        _algorithm: EncryptionAlgorithm,
        cleartext: Vec<u8>,
        _iv: Option<Vec<u8>>,
    ) -> ModuleResult<Vec<u8>> {
        Ok(vec![0; cleartext.len() + AES_IV_SIZE])
    }

    fn decrypt(
        &self,
        _remote_object_id: String,
        _algorithm: EncryptionAlgorithm,
        _data: Vec<u8>,
        _iv: Option<Vec<u8>>,
    ) -> ModuleResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![0; 32]))
    }
}

cryptoki_fn!(
    unsafe fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) {
        not_null!(ppFunctionList, "C_GetFunctionList: ppFunctionList");
        unsafe { *ppFunctionList = addr_of_mut!(FUNC_LIST) };
        register_backend(Box::new(TestBackend {}));
        Ok(())
    }
);

pub(crate) fn test_init() {
    log_init(None);
    if !INITIALIZED.load(Ordering::SeqCst) {
        let func_list = &mut CK_FUNCTION_LIST::default();
        // Update the function list with this PKCS#11 entry function
        func_list.C_GetFunctionList = Some(C_GetFunctionList);
        unsafe {
            C_GetFunctionList(&mut std::ptr::from_mut(func_list));
        }
    }
}

#[test]
#[serial]
fn get_initialize() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        { C_Initialize(ptr::null_mut()) },
        CKR_CRYPTOKI_ALREADY_INITIALIZED
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    let mut args = CK_C_INITIALIZE_ARGS::default();
    assert_eq!(
        { C_Initialize((&mut args as CK_C_INITIALIZE_ARGS_PTR).cast::<std::ffi::c_void>()) },
        CKR_OK
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    // Expect CKR_ARGUMENTS_BAD if pReserved is not null.
    args.pReserved = (1 as *mut u32).cast::<std::ffi::c_void>();
    assert_eq!(
        { C_Initialize((&mut args as CK_C_INITIALIZE_ARGS_PTR).cast::<std::ffi::c_void>()) },
        CKR_ARGUMENTS_BAD
    );
}

#[test]
#[serial]
fn finalize() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    // Expect CKR_ARGUMENTS_BAD if pReserved is not null.
    assert_eq!(
        C_Finalize((1 as *mut u32).cast::<std::ffi::c_void>()),
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut info = CK_INFO::default();
    unsafe {
        assert_eq!(C_GetInfo(&mut info), CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(C_GetInfo(ptr::null_mut()), CKR_ARGUMENTS_BAD);
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(C_GetInfo(&mut info), CKR_CRYPTOKI_NOT_INITIALIZED);
    }
}

#[test]
#[serial]
fn get_function_list() {
    test_init();
    let mut function_list = CK_FUNCTION_LIST::default();
    let mut function_list_pointer: *mut CK_FUNCTION_LIST = &mut function_list;
    unsafe {
        assert_eq!(C_GetFunctionList(&mut function_list_pointer), CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if ppFunctionList is null.
        assert_eq!(C_GetFunctionList(ptr::null_mut()), CKR_ARGUMENTS_BAD);
    }
}

#[test]
#[serial]
fn get_slot_list() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut count = 0;
    assert_eq!(
        unsafe { C_GetSlotList(CK_FALSE, ptr::null_mut(), &mut count) },
        CKR_OK
    );
    assert_eq!(count, 1);
    // Expect CKR_ARGUMENTS_BAD if pulCount is null.
    assert_eq!(
        unsafe { C_GetSlotList(CK_FALSE, ptr::null_mut(), ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    // Expect CKR_BUFFER_TOO_SMALL if pulCount is less than the number of
    // slots.
    let mut count = 0;
    let mut slot_list = vec![0; 0];
    assert_eq!(
        unsafe { C_GetSlotList(CK_FALSE, slot_list.as_mut_ptr(), &mut count) },
        CKR_BUFFER_TOO_SMALL
    );
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_slot_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut slot_info = CK_SLOT_INFO::default();
    unsafe {
        assert_eq!(C_GetSlotInfo(SLOT_ID, &mut slot_info), CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(C_GetSlotInfo(SLOT_ID, ptr::null_mut()), CKR_ARGUMENTS_BAD);
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(
            C_GetSlotInfo(SLOT_ID + 1, ptr::null_mut()),
            CKR_SLOT_ID_INVALID
        );
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }
}

#[test]
#[serial]
fn get_token_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    unsafe {
        assert_eq!(
            C_GetTokenInfo(SLOT_ID, &mut CK_TOKEN_INFO::default()),
            CKR_OK
        );
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(
            C_GetTokenInfo(SLOT_ID + 1, ptr::null_mut()),
            CKR_SLOT_ID_INVALID
        );
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(C_GetSlotInfo(SLOT_ID, ptr::null_mut()), CKR_ARGUMENTS_BAD);
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            C_GetTokenInfo(SLOT_ID, &mut CK_TOKEN_INFO::default()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }
}

#[test]
#[serial]
fn get_mechanism_list() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut count = 0;
    unsafe {
        assert_eq!(
            C_GetMechanismList(SLOT_ID, ptr::null_mut(), &mut count),
            CKR_OK
        );
        assert_ne!(count, 0);
        let mut mechanisms =
            Vec::<CK_MECHANISM_TYPE>::with_capacity(usize::try_from(count).unwrap());
        assert_eq!(
            C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &mut count),
            CKR_OK
        );
        mechanisms.set_len(usize::try_from(count).unwrap());
        assert_eq!(mechanisms, *SUPPORTED_SIGNATURE_MECHANISMS);
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(
            C_GetMechanismList(SLOT_ID + 1, ptr::null_mut(), &mut count),
            CKR_SLOT_ID_INVALID
        );
        // Expect CKR_ARGUMENTS_BAD if pulCount is null.
        assert_eq!(
            C_GetMechanismList(SLOT_ID, ptr::null_mut(), ptr::null_mut()),
            CKR_ARGUMENTS_BAD
        );
        // Expect CKR_BUFFER_TOO_SMALL if pulCount is less than the number of
        // mechanisms.
        assert_eq!(
            C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &mut (count - 1)),
            CKR_BUFFER_TOO_SMALL
        );
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            C_GetMechanismList(SLOT_ID, ptr::null_mut(), ptr::null_mut()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }
}

#[test]
#[serial]
fn get_mechanism_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut info = CK_MECHANISM_INFO::default();
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], &mut info,) },
        CKR_OK
    );
    // Expect CKR_MECHANISM_INVALID if type is an unsupported mechanism.
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, CKM_DSA, &mut info) },
        CKR_MECHANISM_INVALID
    );
    // Expect CKR_ARGUMENTS_BAD if pInfo is null.
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], ptr::null_mut(),) },
        CKR_ARGUMENTS_BAD
    );
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], ptr::null_mut(),) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn open_session() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let flags = CKF_SERIAL_SESSION;
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID, flags, ptr::null_mut(), None, &mut handle) },
        CKR_OK
    );
    // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID + 1, flags, ptr::null_mut(), None, &mut handle,) },
        CKR_SLOT_ID_INVALID
    );
    // Expect CKR_SESSION_PARALLEL_NOT_SUPPORTED if CKF_SERIAL_SESSION flag
    // is not set.
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID, 0, ptr::null_mut(), None, &mut handle) },
        CKR_SESSION_PARALLEL_NOT_SUPPORTED
    );
    // Expect CKR_ARGUMENTS_BAD if phSession is null.
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID, flags, ptr::null_mut(), None, ptr::null_mut(),) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn close_session() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    assert_eq!(C_CloseSession(handle), CKR_OK);
    // Expect CKR_SESSION_HANDLE_INVALID if the session has already been closed.
    assert_eq!(C_CloseSession(handle), CKR_SESSION_HANDLE_INVALID);
    // Expect CKR_SESSION_HANDLE_INVALID if hSession is not a valid handle.
    assert_eq!(
        { C_CloseSession(CK_INVALID_HANDLE) },
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_session_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    let mut session_info = CK_SESSION_INFO::default();
    assert_eq!(
        unsafe { C_GetSessionInfo(handle, &mut session_info) },
        CKR_OK
    );
    // Expect CKR_SESSION_HANDLE_INVALID if hSession is not a valid handle.
    assert_eq!(
        unsafe { C_GetSessionInfo(CK_INVALID_HANDLE, &mut session_info) },
        CKR_SESSION_HANDLE_INVALID
    );
    // Expect CKR_ARGUMENTS_BAD if pInfo is null.
    assert_eq!(
        unsafe { C_GetSessionInfo(handle, ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_attribute_value() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut session_h = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut session_h,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE::default()];
    assert_eq!(
        unsafe {
            C_GetAttributeValue(
                session_h,
                CK_INVALID_HANDLE,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            )
        },
        CKR_OBJECT_HANDLE_INVALID
    );
    assert_eq!(C_CloseSession(session_h), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        unsafe { C_GetAttributeValue(session_h, 0, template.as_mut_ptr(), 0) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn find_objects_init() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: std::ptr::from_ref::<CK_ULONG>(&CKO_PRIVATE_KEY) as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn find_objects() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: std::ptr::from_ref::<CK_ULONG>(&CKO_PRIVATE_KEY) as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    let mut objects = vec![CK_OBJECT_HANDLE::default()];
    let mut count = 0;
    assert_eq!(
        unsafe { C_FindObjects(handle, objects.as_mut_ptr(), 1, &mut count) },
        CKR_OK
    );
    assert_eq!(count, 0);
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        unsafe { C_FindObjects(handle, ptr::null_mut(), 0, ptr::null_mut()) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn find_objects_final() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: std::ptr::from_ref::<CK_ULONG>(&CKO_PRIVATE_KEY) as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_function_status() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut session_h = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut session_h,
            )
        },
        CKR_OK
    );
    assert_eq!(
        { C_GetFunctionStatus(session_h) },
        CKR_FUNCTION_NOT_PARALLEL
    );
    assert_eq!(C_CloseSession(session_h), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn cancel_function() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut session_h = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut session_h,
            )
        },
        CKR_OK
    );
    assert_eq!(
        { C_GetFunctionStatus(session_h) },
        CKR_FUNCTION_NOT_PARALLEL
    );
    assert_eq!(C_CloseSession(session_h), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

fn generate_key(session_h: CK_ULONG) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: [0_u8; 16].as_mut_ptr().cast::<std::ffi::c_void>(),
        ulParameterLen: 16,
    };
    let pMechanism: CK_MECHANISM_PTR = &mut mechanism;

    let mut sym_key_template = vec![
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: std::ptr::from_ref(&CKK_AES) as CK_VOID_PTR,
            ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: "sk_id".as_ptr() as CK_VOID_PTR,
            ulValueLen: "sk_id".len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE,
            pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE,
            pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
            ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN,
            pValue: std::ptr::from_ref(&(16 as CK_ULONG)) as CK_VOID_PTR,
            ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
        },
    ];

    let mut key_handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_GenerateKey(
                session_h,
                pMechanism,
                sym_key_template.as_mut_ptr(),
                sym_key_template.len() as CK_ULONG,
                &mut key_handle,
            )
        },
        CKR_OK
    );

    // Expect key_handle to be a valid handle.
    assert_ne!(key_handle, CK_INVALID_HANDLE);
    key_handle
}

/// Encryption test: call to `C_EncryptInit` and `C_Encrypt`
fn encrypt(session_h: CK_ULONG, key_handle: CK_OBJECT_HANDLE, plaintext: Vec<u8>) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: [0_u8; AES_IV_SIZE].as_mut_ptr().cast::<std::ffi::c_void>(),
        ulParameterLen: AES_IV_SIZE as CK_ULONG,
    };
    let pMechanism: CK_MECHANISM_PTR = &mut mechanism;

    let mut encrypted_data = vec![0_u8; plaintext.len() + AES_IV_SIZE];
    let mut encrypted_data_len = encrypted_data.len() as CK_ULONG;
    let mut pt = plaintext;

    assert_eq!(
        unsafe { C_EncryptInit(session_h, pMechanism, key_handle) },
        CKR_OK
    );

    assert_eq!(
        unsafe {
            C_Encrypt(
                session_h,
                pt.as_mut_ptr(),
                pt.len() as CK_ULONG,
                encrypted_data.as_mut_ptr(),
                &mut encrypted_data_len,
            )
        },
        CKR_OK
    );

    // Expect encrypted_data_len to be the length of the encrypted data.
    assert_ne!(encrypted_data_len, 0);
    encrypted_data
}

/// Decryption test: call to `C_DecryptInit` and `C_Decrypt`
#[expect(clippy::cast_possible_truncation)]
fn decrypt(session_h: CK_ULONG, key_handle: CK_OBJECT_HANDLE, encrypted_data: Vec<u8>) -> Vec<u8> {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: [0_u8; AES_IV_SIZE].as_mut_ptr().cast::<std::ffi::c_void>(),
        ulParameterLen: AES_IV_SIZE as CK_ULONG,
    };
    let pMechanism: CK_MECHANISM_PTR = &mut mechanism;

    let mut encrypted_data = encrypted_data;
    let mut decrypted_data = vec![0_u8; encrypted_data.len()];
    let mut decrypted_data_len = decrypted_data.len() as CK_ULONG;

    assert_eq!(
        unsafe { C_DecryptInit(session_h, pMechanism, key_handle) },
        CKR_OK
    );

    assert_eq!(
        unsafe {
            C_Decrypt(
                session_h,
                encrypted_data.as_mut_ptr(),
                encrypted_data.len() as CK_ULONG,
                decrypted_data.as_mut_ptr(),
                &mut decrypted_data_len,
            )
        },
        CKR_OK
    );

    // Expect decrypted_data_len to be the length of the decrypted data.
    assert_ne!(decrypted_data_len, 0);
    decrypted_data[..decrypted_data_len as usize].to_vec()
}

#[test]
#[serial]
fn test_generate_key() -> ModuleResult<()> {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );

    let key_handle = generate_key(handle);
    // call to encrypt() test function
    let plaintext = vec![0_u8; 32];
    let encrypted_data = encrypt(handle, key_handle, plaintext.clone());
    // call to decrypt() test function
    let decrypted_data = decrypt(handle, key_handle, encrypted_data);
    assert_eq!(decrypted_data, plaintext);

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    Ok(())
}
