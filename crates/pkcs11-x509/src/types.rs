//! PKCS#11 (Cryptoki v2.40) type definitions, hand-written.
//!
//! Copied from `pkcs11-gpg/src/pkcs11_types.rs` and extended. Every constant
//! below was checked against `/usr/include/p11-kit-1/p11-kit/pkcs11.h`
//! (p11-kit 0.26.2, CRYPTOKI 3.2); the number after each constant is its line
//! in that header. The test `types_match_installed_header` re-checks all of
//! them against the header whenever it is installed.
//!
//! v2.40 names are used where 3.x renamed a constant:
//!   CKF_EC_NAMEDCURVE (v2.40) == CKF_EC_OID (3.x), both 1<<23 (header 661/662)
//!   CKK_EC == CKK_ECDSA (deprecated alias, 749)
//!   CKA_EC_PARAMS == CKA_ECDSA_PARAMS (deprecated alias, 497)
//! Not defined here: CKK_EC_EDWARDS / CKM_EDDSA (3.0 only), CKM_ECDSA_SHA256
//! (not offered), CKF_EC_CURVENAME (3.x only).

pub type CK_ULONG = std::os::raw::c_ulong;
pub type CK_BYTE = u8;
pub type CK_BBOOL = CK_BYTE;
pub type CK_CHAR = CK_BYTE;
pub type CK_UTF8CHAR = CK_BYTE;
pub type CK_FLAGS = CK_ULONG;
pub type CK_RV = CK_ULONG;
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_OBJECT_CLASS = CK_ULONG;
pub type CK_KEY_TYPE = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;
pub type CK_CERTIFICATE_TYPE = CK_ULONG;
pub type CK_USER_TYPE = CK_ULONG;
pub type CK_VOID_PTR = *mut std::os::raw::c_void;
pub type CK_BYTE_PTR = *mut CK_BYTE;
pub type CK_ULONG_PTR = *mut CK_ULONG;
pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;
pub type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;
pub type CK_NOTIFY =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_ULONG, CK_VOID_PTR) -> CK_RV>;

/// Generates the constants plus `ALL_CONSTANTS` (name, value) for the header test.
macro_rules! constants {
    ($( $name:ident : $ty:ty = $val:expr ; )*) => {
        $( #[allow(dead_code)] pub const $name: $ty = $val; )*
        #[cfg(test)]
        pub const ALL_CONSTANTS: &[(&str, u64)] = &[ $( (stringify!($name), $name as u64) ),* ];
    };
}

constants! {
    CK_TRUE: CK_BBOOL = 1;                                   // 3060
    CK_FALSE: CK_BBOOL = 0;                                  // 3059
    CK_INVALID_HANDLE: CK_ULONG = 0;                         // 1551
    CK_UNAVAILABLE_INFORMATION: CK_ULONG = CK_ULONG::MAX;    // 1549 ((unsigned long)-1)
    CK_EFFECTIVELY_INFINITE: CK_ULONG = 0;                   // 1550

    // Object classes
    CKO_CERTIFICATE: CK_OBJECT_CLASS = 1;                    // 1302
    CKO_PUBLIC_KEY: CK_OBJECT_CLASS = 2;                     // 1303
    CKO_PRIVATE_KEY: CK_OBJECT_CLASS = 3;                    // 1304
    CKO_SECRET_KEY: CK_OBJECT_CLASS = 4;                     // 1305

    // Certificates
    CKC_X_509: CK_CERTIFICATE_TYPE = 0;                      // 602
    CK_CERTIFICATE_CATEGORY_TOKEN_USER: CK_ULONG = 1;        // 597

    // Key type / mechanism
    CKK_EC: CK_KEY_TYPE = 3;                                 // 750
    CKM_ECDSA: CK_MECHANISM_TYPE = 0x1041;                   // 1146

    // Attributes
    CKA_CLASS: CK_ATTRIBUTE_TYPE = 0x0;                      // 434
    CKA_TOKEN: CK_ATTRIBUTE_TYPE = 0x1;                      // 435
    CKA_PRIVATE: CK_ATTRIBUTE_TYPE = 0x2;                    // 436
    CKA_LABEL: CK_ATTRIBUTE_TYPE = 0x3;                      // 437
    CKA_VALUE: CK_ATTRIBUTE_TYPE = 0x11;                     // 440
    CKA_CERTIFICATE_TYPE: CK_ATTRIBUTE_TYPE = 0x80;          // 442
    CKA_ISSUER: CK_ATTRIBUTE_TYPE = 0x81;                    // 443
    CKA_SERIAL_NUMBER: CK_ATTRIBUTE_TYPE = 0x82;             // 444
    CKA_TRUSTED: CK_ATTRIBUTE_TYPE = 0x86;                   // 448
    CKA_CERTIFICATE_CATEGORY: CK_ATTRIBUTE_TYPE = 0x87;      // 449
    CKA_KEY_TYPE: CK_ATTRIBUTE_TYPE = 0x100;                 // 456
    CKA_SUBJECT: CK_ATTRIBUTE_TYPE = 0x101;                  // 457
    CKA_ID: CK_ATTRIBUTE_TYPE = 0x102;                       // 458
    CKA_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x103;                // 459
    CKA_DECRYPT: CK_ATTRIBUTE_TYPE = 0x105;                  // 461
    CKA_UNWRAP: CK_ATTRIBUTE_TYPE = 0x107;                   // 463
    CKA_SIGN: CK_ATTRIBUTE_TYPE = 0x108;                     // 464
    CKA_VERIFY: CK_ATTRIBUTE_TYPE = 0x10A;                   // 466
    CKA_DERIVE: CK_ATTRIBUTE_TYPE = 0x10C;                   // 468
    CKA_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x162;              // 489
    CKA_NEVER_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x164;        // 491
    CKA_ALWAYS_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x165;         // 492
    CKA_MODIFIABLE: CK_ATTRIBUTE_TYPE = 0x170;               // 494
    CKA_COPYABLE: CK_ATTRIBUTE_TYPE = 0x171;                 // 495
    CKA_DESTROYABLE: CK_ATTRIBUTE_TYPE = 0x172;              // 496
    CKA_EC_PARAMS: CK_ATTRIBUTE_TYPE = 0x180;                // 498
    CKA_EC_POINT: CK_ATTRIBUTE_TYPE = 0x181;                 // 499
    CKA_ALWAYS_AUTHENTICATE: CK_ATTRIBUTE_TYPE = 0x202;      // 502

    // Slot / token / session / init flags
    CKF_TOKEN_PRESENT: CK_FLAGS = 1 << 0;                    // 644
    CKF_TOKEN_INITIALIZED: CK_FLAGS = 1 << 10;               // 714
    CKF_RW_SESSION: CK_FLAGS = 1 << 1;                       // 702
    CKF_SERIAL_SESSION: CK_FLAGS = 1 << 2;                   // 703
    CKF_LIBRARY_CANT_CREATE_OS_THREADS: CK_FLAGS = 1 << 0;   // 649
    CKF_OS_LOCKING_OK: CK_FLAGS = 1 << 1;                    // 650

    // Mechanism flags
    CKF_SIGN: CK_FLAGS = 1 << 11;                            // 679
    CKF_EC_F_P: CK_FLAGS = 1 << 20;                          // 658
    CKF_EC_NAMEDCURVE: CK_FLAGS = 1 << 23;                   // 662 (3.x: CKF_EC_OID, 661)
    CKF_EC_UNCOMPRESS: CK_FLAGS = 1 << 24;                   // 663

    // Session states
    CKS_RO_PUBLIC_SESSION: CK_ULONG = 0;                     // 1507
    CKS_RO_USER_FUNCTIONS: CK_ULONG = 1;                     // 1508
    CKS_RW_PUBLIC_SESSION: CK_ULONG = 2;                     // 1509
    CKS_RW_USER_FUNCTIONS: CK_ULONG = 3;                     // 1510

    // User types
    CKU_SO: CK_USER_TYPE = 0;                                // 1524
    CKU_USER: CK_USER_TYPE = 1;                              // 1525
    CKU_CONTEXT_SPECIFIC: CK_USER_TYPE = 2;                  // 1526

    // Return values
    CKR_OK: CK_RV = 0x0;                                     // 1396
    CKR_SLOT_ID_INVALID: CK_RV = 0x3;                        // 1399 (pkcs11-gpg has 0x65 = CKR_KEY_CHANGED)
    CKR_GENERAL_ERROR: CK_RV = 0x5;                          // 1400
    CKR_FUNCTION_FAILED: CK_RV = 0x6;                        // 1401
    CKR_ARGUMENTS_BAD: CK_RV = 0x7;                          // 1402
    CKR_CANT_LOCK: CK_RV = 0xA;                              // 1405
    CKR_ATTRIBUTE_READ_ONLY: CK_RV = 0x10;                   // 1406
    CKR_ATTRIBUTE_SENSITIVE: CK_RV = 0x11;                   // 1407
    CKR_ATTRIBUTE_TYPE_INVALID: CK_RV = 0x12;                // 1408
    CKR_ATTRIBUTE_VALUE_INVALID: CK_RV = 0x13;               // 1409
    CKR_ACTION_PROHIBITED: CK_RV = 0x1B;                     // 1410
    CKR_DATA_LEN_RANGE: CK_RV = 0x21;                        // 1412
    CKR_DEVICE_ERROR: CK_RV = 0x30;                          // 1413
    CKR_FUNCTION_NOT_PARALLEL: CK_RV = 0x51;                 // 1420
    CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x54;                // 1421
    CKR_KEY_HANDLE_INVALID: CK_RV = 0x60;                    // 1422
    CKR_KEY_FUNCTION_NOT_PERMITTED: CK_RV = 0x68;            // 1429
    CKR_MECHANISM_INVALID: CK_RV = 0x70;                     // 1432
    CKR_MECHANISM_PARAM_INVALID: CK_RV = 0x71;               // 1433
    CKR_OBJECT_HANDLE_INVALID: CK_RV = 0x82;                 // 1434
    CKR_OPERATION_ACTIVE: CK_RV = 0x90;                      // 1435
    CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x91;             // 1436
    CKR_SESSION_CLOSED: CK_RV = 0xB0;                        // 1442
    CKR_SESSION_HANDLE_INVALID: CK_RV = 0xB3;                // 1444
    CKR_SESSION_PARALLEL_NOT_SUPPORTED: CK_RV = 0xB4;        // 1445
    CKR_SESSION_READ_ONLY: CK_RV = 0xB5;                     // 1446
    CKR_TEMPLATE_INCOMPLETE: CK_RV = 0xD0;                   // 1452
    CKR_TEMPLATE_INCONSISTENT: CK_RV = 0xD1;                 // 1453
    CKR_USER_ALREADY_LOGGED_IN: CK_RV = 0x100;               // 1460
    CKR_USER_NOT_LOGGED_IN: CK_RV = 0x101;                   // 1461
    CKR_USER_TYPE_INVALID: CK_RV = 0x103;                    // 1463
    CKR_BUFFER_TOO_SMALL: CK_RV = 0x150;                     // 1475
    CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x190;             // 1479
    CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x191;         // 1480
    CKR_FUNCTION_REJECTED: CK_RV = 0x200;                    // 1490
}

// ---------------------------------------------------------------------------
// Structures (layout as in the header; Linux PKCS#11 structs are not packed)
// ---------------------------------------------------------------------------

pub type CK_CREATEMUTEX = Option<unsafe extern "C" fn(*mut CK_VOID_PTR) -> CK_RV>;
pub type CK_DESTROYMUTEX = Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_LOCKMUTEX = Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_UNLOCKMUTEX = Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>;

/// Header 1624-1632.
#[repr(C)]
pub struct CK_C_INITIALIZE_ARGS {
    pub create_mutex: CK_CREATEMUTEX,
    pub destroy_mutex: CK_DESTROYMUTEX,
    pub lock_mutex: CK_LOCKMUTEX,
    pub unlock_mutex: CK_UNLOCKMUTEX,
    pub flags: CK_FLAGS,
    pub reserved: CK_VOID_PTR,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

#[repr(C)]
pub struct CK_INFO {
    pub cryptoki_version: CK_VERSION,
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub library_description: [CK_UTF8CHAR; 32],
    pub library_version: CK_VERSION,
}

#[repr(C)]
pub struct CK_SLOT_INFO {
    pub slot_description: [CK_UTF8CHAR; 64],
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
}

#[repr(C)]
pub struct CK_TOKEN_INFO {
    pub label: [CK_UTF8CHAR; 32],
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub model: [CK_UTF8CHAR; 16],
    pub serial_number: [CK_CHAR; 16],
    pub flags: CK_FLAGS,
    pub max_session_count: CK_ULONG,
    pub session_count: CK_ULONG,
    pub max_rw_session_count: CK_ULONG,
    pub rw_session_count: CK_ULONG,
    pub max_pin_len: CK_ULONG,
    pub min_pin_len: CK_ULONG,
    pub total_public_memory: CK_ULONG,
    pub free_public_memory: CK_ULONG,
    pub total_private_memory: CK_ULONG,
    pub free_private_memory: CK_ULONG,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
    pub utc_time: [CK_CHAR; 16],
}

#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub p_parameter: CK_VOID_PTR,
    pub parameter_len: CK_ULONG,
}

#[repr(C)]
pub struct CK_MECHANISM_INFO {
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}

#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub attr_type: CK_ATTRIBUTE_TYPE,
    pub p_value: CK_VOID_PTR,
    pub value_len: CK_ULONG,
}

#[repr(C)]
pub struct CK_SESSION_INFO {
    pub slot_id: CK_SLOT_ID,
    pub state: CK_ULONG,
    pub flags: CK_FLAGS,
    pub device_error: CK_ULONG,
}

// Function pointer types for CK_FUNCTION_LIST
pub type CK_C_Initialize = Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_C_Finalize = Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_C_GetInfo = Option<unsafe extern "C" fn(*mut CK_INFO) -> CK_RV>;
pub type CK_C_GetSlotList =
    Option<unsafe extern "C" fn(CK_BBOOL, *mut CK_SLOT_ID, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetSlotInfo = Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_SLOT_INFO) -> CK_RV>;
pub type CK_C_GetTokenInfo = Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_TOKEN_INFO) -> CK_RV>;
pub type CK_C_GetMechanismList =
    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetMechanismInfo =
    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut CK_MECHANISM_INFO) -> CK_RV>;
pub type CK_C_InitToken =
    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR) -> CK_RV>;
pub type CK_C_InitPIN =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_SetPIN = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
>;
pub type CK_C_OpenSession = Option<
    unsafe extern "C" fn(
        CK_SLOT_ID,
        CK_FLAGS,
        CK_VOID_PTR,
        CK_NOTIFY,
        *mut CK_SESSION_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_CloseSession = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_CloseAllSessions = Option<unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV>;
pub type CK_C_GetSessionInfo =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_SESSION_INFO) -> CK_RV>;
pub type CK_C_GetOperationState =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_SetOperationState = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_Login =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_Logout = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_CreateObject = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_CopyObject = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DestroyObject =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_GetObjectSize =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetAttributeValue = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV,
>;
pub type CK_C_SetAttributeValue = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV,
>;
pub type CK_C_FindObjectsInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV>;
pub type CK_C_FindObjects = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR) -> CK_RV,
>;
pub type CK_C_FindObjectsFinal = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_EncryptInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_Encrypt = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_EncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_EncryptFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_DecryptInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_Decrypt = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_DigestInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM) -> CK_RV>;
pub type CK_C_Digest = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DigestUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_DigestKey =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_DigestFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_SignInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_Sign = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SignUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_SignFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_SignRecoverInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_SignRecover = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_VerifyInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_Verify = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
>;
pub type CK_C_VerifyUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_VerifyFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_VerifyRecoverInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_VerifyRecover = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DigestEncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptDigestUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SignEncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptVerifyUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_GenerateKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_GenerateKeyPair = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_WrapKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_UnwrapKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DeriveKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        CK_OBJECT_HANDLE,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SeedRandom =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_GenerateRandom =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_GetFunctionStatus = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_CancelFunction = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_WaitForSlotEvent =
    Option<unsafe extern "C" fn(CK_FLAGS, *mut CK_SLOT_ID, CK_VOID_PTR) -> CK_RV>;

#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub c_initialize: CK_C_Initialize,
    pub c_finalize: CK_C_Finalize,
    pub c_get_info: CK_C_GetInfo,
    pub c_get_function_list: Option<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV>,
    pub c_get_slot_list: CK_C_GetSlotList,
    pub c_get_slot_info: CK_C_GetSlotInfo,
    pub c_get_token_info: CK_C_GetTokenInfo,
    pub c_get_mechanism_list: CK_C_GetMechanismList,
    pub c_get_mechanism_info: CK_C_GetMechanismInfo,
    pub c_init_token: CK_C_InitToken,
    pub c_init_pin: CK_C_InitPIN,
    pub c_set_pin: CK_C_SetPIN,
    pub c_open_session: CK_C_OpenSession,
    pub c_close_session: CK_C_CloseSession,
    pub c_close_all_sessions: CK_C_CloseAllSessions,
    pub c_get_session_info: CK_C_GetSessionInfo,
    pub c_get_operation_state: CK_C_GetOperationState,
    pub c_set_operation_state: CK_C_SetOperationState,
    pub c_login: CK_C_Login,
    pub c_logout: CK_C_Logout,
    pub c_create_object: CK_C_CreateObject,
    pub c_copy_object: CK_C_CopyObject,
    pub c_destroy_object: CK_C_DestroyObject,
    pub c_get_object_size: CK_C_GetObjectSize,
    pub c_get_attribute_value: CK_C_GetAttributeValue,
    pub c_set_attribute_value: CK_C_SetAttributeValue,
    pub c_find_objects_init: CK_C_FindObjectsInit,
    pub c_find_objects: CK_C_FindObjects,
    pub c_find_objects_final: CK_C_FindObjectsFinal,
    pub c_encrypt_init: CK_C_EncryptInit,
    pub c_encrypt: CK_C_Encrypt,
    pub c_encrypt_update: CK_C_EncryptUpdate,
    pub c_encrypt_final: CK_C_EncryptFinal,
    pub c_decrypt_init: CK_C_DecryptInit,
    pub c_decrypt: CK_C_Decrypt,
    pub c_decrypt_update: CK_C_DecryptUpdate,
    pub c_decrypt_final: CK_C_DecryptFinal,
    pub c_digest_init: CK_C_DigestInit,
    pub c_digest: CK_C_Digest,
    pub c_digest_update: CK_C_DigestUpdate,
    pub c_digest_key: CK_C_DigestKey,
    pub c_digest_final: CK_C_DigestFinal,
    pub c_sign_init: CK_C_SignInit,
    pub c_sign: CK_C_Sign,
    pub c_sign_update: CK_C_SignUpdate,
    pub c_sign_final: CK_C_SignFinal,
    pub c_sign_recover_init: CK_C_SignRecoverInit,
    pub c_sign_recover: CK_C_SignRecover,
    pub c_verify_init: CK_C_VerifyInit,
    pub c_verify: CK_C_Verify,
    pub c_verify_update: CK_C_VerifyUpdate,
    pub c_verify_final: CK_C_VerifyFinal,
    pub c_verify_recover_init: CK_C_VerifyRecoverInit,
    pub c_verify_recover: CK_C_VerifyRecover,
    pub c_digest_encrypt_update: CK_C_DigestEncryptUpdate,
    pub c_decrypt_digest_update: CK_C_DecryptDigestUpdate,
    pub c_sign_encrypt_update: CK_C_SignEncryptUpdate,
    pub c_decrypt_verify_update: CK_C_DecryptVerifyUpdate,
    pub c_generate_key: CK_C_GenerateKey,
    pub c_generate_key_pair: CK_C_GenerateKeyPair,
    pub c_wrap_key: CK_C_WrapKey,
    pub c_unwrap_key: CK_C_UnwrapKey,
    pub c_derive_key: CK_C_DeriveKey,
    pub c_seed_random: CK_C_SeedRandom,
    pub c_generate_random: CK_C_GenerateRandom,
    pub c_get_function_status: CK_C_GetFunctionStatus,
    pub c_cancel_function: CK_C_CancelFunction,
    pub c_wait_for_slot_event: CK_C_WaitForSlotEvent,
}

// Safety: The function list is read-only after initialization and contains only function pointers.
unsafe impl Sync for CK_FUNCTION_LIST {}
unsafe impl Send for CK_FUNCTION_LIST {}

/// Pad/truncate a string into a fixed-size PKCS#11 field (space-padded, no NUL).
pub fn pad_str<const N: usize>(s: &str) -> [CK_UTF8CHAR; N] {
    let mut buf = [b' '; N];
    let bytes = s.as_bytes();
    let len = bytes.len().min(N);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}
