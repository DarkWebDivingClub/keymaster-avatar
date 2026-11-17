//! Module state, sessions and login.
//!
//! All state lives in one `STATE` mutex, held only for short CPU-only work and
//! never during socket I/O. Functions that talk to km-x509-sa copy what they
//! need, unlock, do the I/O, then lock again and re-check that the same module
//! instance and session still exist.
//!
//! Login applies to the whole module (PKCS#11 v2.40): C_Login makes every
//! session a user session; C_Logout, or closing the last session, ends it.

use crate::guard;
use crate::objects::Store;
use crate::types::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

pub const SLOT_ID: CK_SLOT_ID = 0;

pub struct FindOp {
    pub handles: Vec<CK_OBJECT_HANDLE>,
    pub position: usize,
}

pub struct SignOp {
    pub path: String,
}

pub struct Session {
    pub rw: bool,
    pub find: Option<FindOp>,
    pub sign: Option<SignOp>,
}

pub struct Module {
    /// Distinguishes this C_Initialize from a later one (I/O re-check).
    pub instance: u64,
    pub sessions: BTreeMap<CK_SESSION_HANDLE, Session>,
    next_session: CK_SESSION_HANDLE,
    pub logged_in: bool,
    pub store: Store,
}

impl Module {
    pub fn new() -> Module {
        static INSTANCES: AtomicU64 = AtomicU64::new(1);
        Module {
            instance: INSTANCES.fetch_add(1, Ordering::Relaxed),
            sessions: BTreeMap::new(),
            next_session: 0,
            logged_in: false,
            store: Store::default(),
        }
    }

    /// The session state value for CK_SESSION_INFO.
    pub fn session_state(&self, s: &Session) -> CK_ULONG {
        match (s.rw, self.logged_in) {
            (false, false) => CKS_RO_PUBLIC_SESSION,
            (false, true) => CKS_RO_USER_FUNCTIONS,
            (true, false) => CKS_RW_PUBLIC_SESSION,
            (true, true) => CKS_RW_USER_FUNCTIONS,
        }
    }
}

static STATE: Mutex<Option<Module>> = Mutex::new(None);

/// Lock the module state. A poisoned lock (a panic while held) is recovered;
/// the state itself is only ever changed by complete assignments.
pub fn lock() -> MutexGuard<'static, Option<Module>> {
    STATE.lock().unwrap_or_else(|p| p.into_inner())
}

/// Run `f` on the initialized module, else CKR_CRYPTOKI_NOT_INITIALIZED.
pub fn with_module<F: FnOnce(&mut Module) -> CK_RV>(f: F) -> CK_RV {
    match lock().as_mut() {
        Some(m) => f(m),
        None => CKR_CRYPTOKI_NOT_INITIALIZED,
    }
}

/// Run `f` with the module and a valid session handle.
pub fn with_session<F: FnOnce(&mut Module, CK_SESSION_HANDLE) -> CK_RV>(
    h: CK_SESSION_HANDLE,
    f: F,
) -> CK_RV {
    with_module(|m| {
        if m.sessions.contains_key(&h) {
            f(m, h)
        } else {
            CKR_SESSION_HANDLE_INVALID
        }
    })
}

pub unsafe extern "C" fn c_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    guard(|| {
        with_module(|m| {
            if slot_id != SLOT_ID {
                return CKR_SLOT_ID_INVALID;
            }
            if ph_session.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            if flags & CKF_SERIAL_SESSION == 0 {
                return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
            }
            m.next_session += 1;
            let h = m.next_session;
            m.sessions.insert(
                h,
                Session {
                    rw: flags & CKF_RW_SESSION != 0,
                    find: None,
                    sign: None,
                },
            );
            *ph_session = h;
            CKR_OK
        })
    })
}

pub unsafe extern "C" fn c_close_session(h: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| {
        with_session(h, |m, h| {
            m.sessions.remove(&h);
            if m.sessions.is_empty() {
                m.logged_in = false;
            }
            CKR_OK
        })
    })
}

pub unsafe extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    guard(|| {
        with_module(|m| {
            if slot_id != SLOT_ID {
                return CKR_SLOT_ID_INVALID;
            }
            m.sessions.clear();
            m.logged_in = false;
            CKR_OK
        })
    })
}

pub unsafe extern "C" fn c_get_session_info(
    h: CK_SESSION_HANDLE,
    info: *mut CK_SESSION_INFO,
) -> CK_RV {
    guard(|| {
        with_session(h, |m, h| {
            if info.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            let s = &m.sessions[&h];
            let out = &mut *info;
            out.slot_id = SLOT_ID;
            out.state = m.session_state(s);
            out.flags = CKF_SERIAL_SESSION | if s.rw { CKF_RW_SESSION } else { 0 };
            out.device_error = 0;
            CKR_OK
        })
    })
}

/// No PIN exists: any PIN (even NULL) is accepted. What login should mean on
/// the phone is an open question for 37.2.
pub unsafe extern "C" fn c_login(
    h: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    _pin: CK_BYTE_PTR,
    _pin_len: CK_ULONG,
) -> CK_RV {
    guard(|| {
        with_session(h, |m, _| match user_type {
            CKU_USER if m.logged_in => CKR_USER_ALREADY_LOGGED_IN,
            CKU_USER => {
                m.logged_in = true;
                CKR_OK
            }
            // No key has CKA_ALWAYS_AUTHENTICATE, so no operation ever asks for it.
            CKU_CONTEXT_SPECIFIC => CKR_OPERATION_NOT_INITIALIZED,
            _ => CKR_USER_TYPE_INVALID, // CKU_SO: there is no security officer
        })
    })
}

pub unsafe extern "C" fn c_logout(h: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| {
        with_session(h, |m, _| {
            if !m.logged_in {
                return CKR_USER_NOT_LOGGED_IN;
            }
            m.logged_in = false;
            CKR_OK
        })
    })
}
