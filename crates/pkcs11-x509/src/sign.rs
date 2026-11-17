//! CKM_ECDSA signing through km-x509-sa `sign`.
//!
//! The input is the digest and must be exactly 32 bytes (SHA-256); anything
//! else is CKR_DATA_LEN_RANGE. Future option, not implemented: pass the
//! leftmost 256 bits of a longer digest (standard ECDSA truncation) if a
//! consumer sends SHA-384. The output is raw 64-byte r‖s, as CKM_ECDSA
//! defines it.

use crate::client::{self, map_error, RpcError};
use crate::find::refresh;
use crate::guard;
use crate::objects::Class;
use crate::session::{lock, with_session, SignOp};
use crate::types::*;

pub const SIGNATURE_LEN: CK_ULONG = 64;
pub const DIGEST_LEN: usize = 32;

pub unsafe extern "C" fn c_sign_init(
    h: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    guard(|| {
        with_session(h, |m, h| {
            if mechanism.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            if m.sessions[&h].sign.is_some() {
                return CKR_OPERATION_ACTIVE;
            }
            let mech = &*mechanism;
            if mech.mechanism != CKM_ECDSA {
                return CKR_MECHANISM_INVALID;
            }
            if !mech.p_parameter.is_null() || mech.parameter_len != 0 {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            let path = match m.store.lookup(key) {
                Some((k, Class::Private)) => k.path.clone(),
                Some((_, Class::Public)) => return CKR_KEY_FUNCTION_NOT_PERMITTED,
                Some((_, Class::Cert)) | None => return CKR_KEY_HANDLE_INVALID,
            };
            if let Some(s) = m.sessions.get_mut(&h) {
                s.sign = Some(SignOp { path });
            }
            CKR_OK
        })
    })
}

pub unsafe extern "C" fn c_sign(
    h: CK_SESSION_HANDLE,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        // 1. Under the lock: the two-call cases, then take the operation.
        let mut job = None;
        let rv = with_session(h, |m, h| {
            let instance = m.instance;
            let Some(s) = m.sessions.get_mut(&h) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            if s.sign.is_none() {
                return CKR_OPERATION_NOT_INITIALIZED;
            }
            if signature_len.is_null() || (data.is_null() && data_len > 0) {
                s.sign = None;
                return CKR_ARGUMENTS_BAD;
            }
            if signature.is_null() {
                *signature_len = SIGNATURE_LEN; // size query: the operation stays active
                return CKR_OK;
            }
            if *signature_len < SIGNATURE_LEN {
                *signature_len = SIGNATURE_LEN; // stays active
                return CKR_BUFFER_TOO_SMALL;
            }
            let op = s.sign.take().expect("checked above");
            if data_len as usize != DIGEST_LEN {
                return CKR_DATA_LEN_RANGE;
            }
            let mut digest = [0u8; DIGEST_LEN];
            digest.copy_from_slice(std::slice::from_raw_parts(data, DIGEST_LEN));
            job = Some((instance, op.path, digest));
            CKR_OK
        });
        let Some((instance, path, digest)) = job else {
            return rv;
        };

        // 2. Ask km-x509-sa (no state lock held).
        let result = client::client().sign(&path, &digest);
        let sig = match result {
            Ok(sig) => sig,
            Err(e) => {
                if matches!(&e, RpcError::Rpc { code: -32603, message } if message == "unknown-path")
                {
                    // The key list changed under us: refresh now, best effort.
                    let _ = refresh(instance);
                }
                return map_error(&e);
            }
        };

        // 3. The session must still exist.
        let state = lock();
        match state.as_ref().filter(|m| m.instance == instance) {
            Some(m) if m.sessions.contains_key(&h) => {
                std::ptr::copy_nonoverlapping(sig.as_ptr(), signature, sig.len());
                *signature_len = SIGNATURE_LEN;
                CKR_OK
            }
            Some(_) => CKR_SESSION_CLOSED,
            None => CKR_CRYPTOKI_NOT_INITIALIZED,
        }
    })
}
