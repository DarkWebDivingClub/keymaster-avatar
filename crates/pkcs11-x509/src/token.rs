//! C_Initialize / C_Finalize and the info, slot, token and mechanism queries.
//! None of these touch km-x509-sa's socket.

use crate::client;
use crate::guard;
use crate::session::{self, with_module, Module, SLOT_ID};
use crate::types::*;

/// Token strings (spec: frozen once an OpenVPN config or Firefox profile
/// refers to them).
pub const MANUFACTURER: &str = "DWDC";
pub const LIBRARY_DESCRIPTION: &str = "KeyMaster X.509 PKCS#11";
pub const TOKEN_LABEL: &str = "KeyMaster X.509";
pub const TOKEN_MODEL: &str = "KeyMaster";
pub const TOKEN_SERIAL: &str = "0000000000000001";
pub const SLOT_DESCRIPTION: &str = "KeyMaster X.509";

/// The only mechanism, and its key size in bits (P-256).
pub const MECHANISMS: &[CK_MECHANISM_TYPE] = &[CKM_ECDSA];
const EC_KEY_BITS: CK_ULONG = 256;

fn library_version() -> CK_VERSION {
    CK_VERSION {
        major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0),
        minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0),
    }
}

/// Check CK_C_INITIALIZE_ARGS (v2.40 §5.4). We only ever use OS locking.
unsafe fn check_init_args(args: CK_VOID_PTR) -> CK_RV {
    if args.is_null() {
        return CKR_OK;
    }
    let a = &*(args as *const CK_C_INITIALIZE_ARGS);
    if !a.reserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let set = [
        a.create_mutex.is_some(),
        a.destroy_mutex.is_some(),
        a.lock_mutex.is_some(),
        a.unlock_mutex.is_some(),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    match set {
        0 => CKR_OK,
        4 if a.flags & CKF_OS_LOCKING_OK != 0 => CKR_OK,
        4 => CKR_CANT_LOCK,
        _ => CKR_ARGUMENTS_BAD,
    }
}

pub unsafe extern "C" fn c_initialize(init_args: CK_VOID_PTR) -> CK_RV {
    guard(|| {
        let rv = check_init_args(init_args);
        if rv != CKR_OK {
            return rv;
        }
        let mut state = session::lock();
        if state.is_some() {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        *state = Some(Module::new());
        CKR_OK
    })
}

pub unsafe extern "C" fn c_finalize(reserved: CK_VOID_PTR) -> CK_RV {
    guard(|| {
        if !reserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut state = session::lock();
        if state.is_none() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        *state = None; // all sessions, operations, the cache and the login go
        drop(state);
        client::drop_connection_if_idle();
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_info(info: *mut CK_INFO) -> CK_RV {
    guard(|| {
        with_module(|_| {
            if info.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            let out = &mut *info;
            out.cryptoki_version = CK_VERSION {
                major: 2,
                minor: 40,
            };
            out.manufacturer_id = pad_str(MANUFACTURER);
            out.flags = 0;
            out.library_description = pad_str(LIBRARY_DESCRIPTION);
            out.library_version = library_version();
            CKR_OK
        })
    })
}

/// The two-call convention for an output array of CK_ULONGs.
unsafe fn write_list(items: &[CK_ULONG], out: *mut CK_ULONG, count: CK_ULONG_PTR) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let n = items.len() as CK_ULONG;
    if out.is_null() {
        *count = n;
        return CKR_OK;
    }
    if *count < n {
        *count = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(items.as_ptr(), out, items.len());
    *count = n;
    CKR_OK
}

pub unsafe extern "C" fn c_get_slot_list(
    _token_present: CK_BBOOL,
    slot_list: *mut CK_SLOT_ID,
    count: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| with_module(|_| write_list(&[SLOT_ID], slot_list, count)))
}

pub unsafe extern "C" fn c_get_slot_info(slot_id: CK_SLOT_ID, info: *mut CK_SLOT_INFO) -> CK_RV {
    guard(|| {
        with_module(|_| {
            if slot_id != SLOT_ID {
                return CKR_SLOT_ID_INVALID;
            }
            if info.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            let out = &mut *info;
            out.slot_description = pad_str(SLOT_DESCRIPTION);
            out.manufacturer_id = pad_str(MANUFACTURER);
            out.flags = CKF_TOKEN_PRESENT;
            out.hardware_version = library_version();
            out.firmware_version = library_version();
            CKR_OK
        })
    })
}

pub unsafe extern "C" fn c_get_token_info(slot_id: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) -> CK_RV {
    guard(|| {
        with_module(|m| {
            if slot_id != SLOT_ID {
                return CKR_SLOT_ID_INVALID;
            }
            if info.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            let out = &mut *info;
            out.label = pad_str(TOKEN_LABEL);
            out.manufacturer_id = pad_str(MANUFACTURER);
            out.model = pad_str(TOKEN_MODEL);
            out.serial_number = pad_str(TOKEN_SERIAL);
            // No CKF_LOGIN_REQUIRED, no CKF_WRITE_PROTECTED.
            out.flags = CKF_TOKEN_INITIALIZED;
            out.max_session_count = CK_EFFECTIVELY_INFINITE;
            out.session_count = m.sessions.len() as CK_ULONG;
            out.max_rw_session_count = CK_EFFECTIVELY_INFINITE;
            out.rw_session_count = m.sessions.values().filter(|s| s.rw).count() as CK_ULONG;
            out.max_pin_len = 0;
            out.min_pin_len = 0;
            out.total_public_memory = CK_UNAVAILABLE_INFORMATION;
            out.free_public_memory = CK_UNAVAILABLE_INFORMATION;
            out.total_private_memory = CK_UNAVAILABLE_INFORMATION;
            out.free_private_memory = CK_UNAVAILABLE_INFORMATION;
            out.hardware_version = library_version();
            out.firmware_version = library_version();
            out.utc_time = pad_str("");
            CKR_OK
        })
    })
}

pub unsafe extern "C" fn c_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        with_module(|_| {
            if slot_id != SLOT_ID {
                return CKR_SLOT_ID_INVALID;
            }
            write_list(MECHANISMS, list, count)
        })
    })
}

pub unsafe extern "C" fn c_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    info: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    guard(|| {
        with_module(|_| {
            if slot_id != SLOT_ID {
                return CKR_SLOT_ID_INVALID;
            }
            if info.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            if mechanism != CKM_ECDSA {
                return CKR_MECHANISM_INVALID;
            }
            let out = &mut *info;
            out.min_key_size = EC_KEY_BITS;
            out.max_key_size = EC_KEY_BITS;
            out.flags = CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;
            CKR_OK
        })
    })
}
