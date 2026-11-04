//! km_pkcs11_x509 — PKCS#11 module for KeyMaster X.509 keys.
//!
//! A thin client of km-x509-sa's socket (newline-delimited JSON-RPC
//! `list` / `sign` / `import`). Each KeyMaster key is shown as a private key,
//! a public key and, once a certificate is enrolled, a certificate object.
//! Signing is `CKM_ECDSA` over a caller-supplied 32-byte digest; certificates
//! are imported with `C_CreateObject`. See doc/x509/pkcs11-module.md.
//!
//! Only `C_GetFunctionList` is exported; everything else is reached through
//! the function list.

#![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]

mod client;
mod create;
mod find;
mod objects;
mod session;
mod sign;
mod stubs;
mod token;
mod types;

#[cfg(test)]
mod tests;

use types::*;

/// Run an entry point's body; a panic becomes `CKR_GENERAL_ERROR` instead of
/// unwinding into (and aborting) the host application.
pub(crate) fn guard<F: FnOnce() -> CK_RV>(f: F) -> CK_RV {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(CKR_GENERAL_ERROR)
}

/// Diagnostics on stderr, only with `KM_PKCS11_X509_DEBUG=1`. Callers must
/// never pass digests, DER, signatures or key paths.
pub(crate) fn debug_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("KM_PKCS11_X509_DEBUG").is_ok_and(|v| v == "1"))
}

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if $crate::debug_enabled() {
            eprintln!("km_pkcs11_x509: {}", format!($($arg)*));
        }
    };
}
pub(crate) use debug_log;

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    c_initialize: Some(token::c_initialize),
    c_finalize: Some(token::c_finalize),
    c_get_info: Some(token::c_get_info),
    c_get_function_list: Some(C_GetFunctionList),
    c_get_slot_list: Some(token::c_get_slot_list),
    c_get_slot_info: Some(token::c_get_slot_info),
    c_get_token_info: Some(token::c_get_token_info),
    c_get_mechanism_list: Some(token::c_get_mechanism_list),
    c_get_mechanism_info: Some(token::c_get_mechanism_info),
    c_init_token: Some(stubs::c_init_token),
    c_init_pin: Some(stubs::c_init_pin),
    c_set_pin: Some(stubs::c_set_pin),
    c_open_session: Some(session::c_open_session),
    c_close_session: Some(session::c_close_session),
    c_close_all_sessions: Some(session::c_close_all_sessions),
    c_get_session_info: Some(session::c_get_session_info),
    c_get_operation_state: Some(stubs::c_get_operation_state),
    c_set_operation_state: Some(stubs::c_set_operation_state),
    c_login: Some(session::c_login),
    c_logout: Some(session::c_logout),
    c_create_object: Some(create::c_create_object),
    c_copy_object: Some(find::c_copy_object),
    c_destroy_object: Some(find::c_destroy_object),
    c_get_object_size: Some(find::c_get_object_size),
    c_get_attribute_value: Some(find::c_get_attribute_value),
    c_set_attribute_value: Some(find::c_set_attribute_value),
    c_find_objects_init: Some(find::c_find_objects_init),
    c_find_objects: Some(find::c_find_objects),
    c_find_objects_final: Some(find::c_find_objects_final),
    c_encrypt_init: Some(stubs::c_encrypt_init),
    c_encrypt: Some(stubs::c_encrypt),
    c_encrypt_update: Some(stubs::c_encrypt_update),
    c_encrypt_final: Some(stubs::c_encrypt_final),
    c_decrypt_init: Some(stubs::c_decrypt_init),
    c_decrypt: Some(stubs::c_decrypt),
    c_decrypt_update: Some(stubs::c_decrypt_update),
    c_decrypt_final: Some(stubs::c_decrypt_final),
    c_digest_init: Some(stubs::c_digest_init),
    c_digest: Some(stubs::c_digest),
    c_digest_update: Some(stubs::c_digest_update),
    c_digest_key: Some(stubs::c_digest_key),
    c_digest_final: Some(stubs::c_digest_final),
    c_sign_init: Some(sign::c_sign_init),
    c_sign: Some(sign::c_sign),
    c_sign_update: Some(stubs::c_sign_update),
    c_sign_final: Some(stubs::c_sign_final),
    c_sign_recover_init: Some(stubs::c_sign_recover_init),
    c_sign_recover: Some(stubs::c_sign_recover),
    c_verify_init: Some(stubs::c_verify_init),
    c_verify: Some(stubs::c_verify),
    c_verify_update: Some(stubs::c_verify_update),
    c_verify_final: Some(stubs::c_verify_final),
    c_verify_recover_init: Some(stubs::c_verify_recover_init),
    c_verify_recover: Some(stubs::c_verify_recover),
    c_digest_encrypt_update: Some(stubs::c_digest_encrypt_update),
    c_decrypt_digest_update: Some(stubs::c_decrypt_digest_update),
    c_sign_encrypt_update: Some(stubs::c_sign_encrypt_update),
    c_decrypt_verify_update: Some(stubs::c_decrypt_verify_update),
    c_generate_key: Some(stubs::c_generate_key),
    c_generate_key_pair: Some(stubs::c_generate_key_pair),
    c_wrap_key: Some(stubs::c_wrap_key),
    c_unwrap_key: Some(stubs::c_unwrap_key),
    c_derive_key: Some(stubs::c_derive_key),
    c_seed_random: Some(stubs::c_seed_random),
    c_generate_random: Some(stubs::c_generate_random),
    c_get_function_status: Some(stubs::c_get_function_status),
    c_cancel_function: Some(stubs::c_cancel_function),
    c_wait_for_slot_event: Some(stubs::c_wait_for_slot_event),
};

/// The PKCS#11 entry point. Valid before `C_Initialize`.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    guard(|| {
        if pp_function_list.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // Callers only read the list; it is never written through this pointer.
        *pp_function_list = std::ptr::addr_of!(FUNCTION_LIST) as *mut CK_FUNCTION_LIST;
        CKR_OK
    })
}
