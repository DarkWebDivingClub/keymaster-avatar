//! Functions this module does not offer.

use crate::types::*;

macro_rules! stub {
    ($name:ident ( $($arg:ident : $ty:ty),* $(,)? )) => {
        stub!(CKR_FUNCTION_NOT_SUPPORTED; $name($($arg: $ty),*));
    };
    ($rv:ident; $name:ident ( $($arg:ident : $ty:ty),* $(,)? )) => {
        pub unsafe extern "C" fn $name($(_: $ty),*) -> CK_RV {
            crate::guard(|| $rv)
        }
    };
}

stub!(c_init_token(slot: CK_SLOT_ID, pin: CK_BYTE_PTR, pin_len: CK_ULONG, label: CK_BYTE_PTR));
stub!(c_init_pin(s: CK_SESSION_HANDLE, pin: CK_BYTE_PTR, pin_len: CK_ULONG));
stub!(
    c_set_pin(
        s: CK_SESSION_HANDLE,
        old: CK_BYTE_PTR,
        old_len: CK_ULONG,
        new: CK_BYTE_PTR,
        new_len: CK_ULONG,
    )
);
stub!(c_get_operation_state(s: CK_SESSION_HANDLE, st: CK_BYTE_PTR, len: CK_ULONG_PTR));
stub!(
    c_set_operation_state(
        s: CK_SESSION_HANDLE,
        st: CK_BYTE_PTR,
        len: CK_ULONG,
        enc: CK_OBJECT_HANDLE,
        auth: CK_OBJECT_HANDLE,
    )
);
stub!(c_encrypt_init(s: CK_SESSION_HANDLE, m: *mut CK_MECHANISM, k: CK_OBJECT_HANDLE));
stub!(
    c_encrypt(s: CK_SESSION_HANDLE, d: CK_BYTE_PTR, dl: CK_ULONG, e: CK_BYTE_PTR, el: CK_ULONG_PTR)
);
stub!(
    c_encrypt_update(
        s: CK_SESSION_HANDLE,
        p: CK_BYTE_PTR,
        pl: CK_ULONG,
        e: CK_BYTE_PTR,
        el: CK_ULONG_PTR,
    )
);
stub!(c_encrypt_final(s: CK_SESSION_HANDLE, e: CK_BYTE_PTR, el: CK_ULONG_PTR));
stub!(c_decrypt_init(s: CK_SESSION_HANDLE, m: *mut CK_MECHANISM, k: CK_OBJECT_HANDLE));
stub!(
    c_decrypt(s: CK_SESSION_HANDLE, e: CK_BYTE_PTR, el: CK_ULONG, d: CK_BYTE_PTR, dl: CK_ULONG_PTR)
);
stub!(
    c_decrypt_update(
        s: CK_SESSION_HANDLE,
        e: CK_BYTE_PTR,
        el: CK_ULONG,
        d: CK_BYTE_PTR,
        dl: CK_ULONG_PTR,
    )
);
stub!(c_decrypt_final(s: CK_SESSION_HANDLE, d: CK_BYTE_PTR, dl: CK_ULONG_PTR));
stub!(c_digest_init(s: CK_SESSION_HANDLE, m: *mut CK_MECHANISM));
stub!(
    c_digest(s: CK_SESSION_HANDLE, d: CK_BYTE_PTR, dl: CK_ULONG, o: CK_BYTE_PTR, ol: CK_ULONG_PTR)
);
stub!(c_digest_update(s: CK_SESSION_HANDLE, p: CK_BYTE_PTR, pl: CK_ULONG));
stub!(c_digest_key(s: CK_SESSION_HANDLE, k: CK_OBJECT_HANDLE));
stub!(c_digest_final(s: CK_SESSION_HANDLE, o: CK_BYTE_PTR, ol: CK_ULONG_PTR));
// Multi-part signing is not offered (CKM_ECDSA is single-part).
stub!(c_sign_update(s: CK_SESSION_HANDLE, p: CK_BYTE_PTR, pl: CK_ULONG));
stub!(c_sign_final(s: CK_SESSION_HANDLE, o: CK_BYTE_PTR, ol: CK_ULONG_PTR));
stub!(c_sign_recover_init(s: CK_SESSION_HANDLE, m: *mut CK_MECHANISM, k: CK_OBJECT_HANDLE));
stub!(
    c_sign_recover(
        s: CK_SESSION_HANDLE,
        d: CK_BYTE_PTR,
        dl: CK_ULONG,
        o: CK_BYTE_PTR,
        ol: CK_ULONG_PTR,
    )
);
stub!(c_verify_init(s: CK_SESSION_HANDLE, m: *mut CK_MECHANISM, k: CK_OBJECT_HANDLE));
stub!(c_verify(s: CK_SESSION_HANDLE, d: CK_BYTE_PTR, dl: CK_ULONG, sig: CK_BYTE_PTR, sl: CK_ULONG));
stub!(c_verify_update(s: CK_SESSION_HANDLE, p: CK_BYTE_PTR, pl: CK_ULONG));
stub!(c_verify_final(s: CK_SESSION_HANDLE, sig: CK_BYTE_PTR, sl: CK_ULONG));
stub!(c_verify_recover_init(s: CK_SESSION_HANDLE, m: *mut CK_MECHANISM, k: CK_OBJECT_HANDLE));
stub!(
    c_verify_recover(
        s: CK_SESSION_HANDLE,
        sig: CK_BYTE_PTR,
        sl: CK_ULONG,
        d: CK_BYTE_PTR,
        dl: CK_ULONG_PTR,
    )
);
stub!(
    c_digest_encrypt_update(
        s: CK_SESSION_HANDLE,
        p: CK_BYTE_PTR,
        pl: CK_ULONG,
        e: CK_BYTE_PTR,
        el: CK_ULONG_PTR,
    )
);
stub!(
    c_decrypt_digest_update(
        s: CK_SESSION_HANDLE,
        e: CK_BYTE_PTR,
        el: CK_ULONG,
        p: CK_BYTE_PTR,
        pl: CK_ULONG_PTR,
    )
);
stub!(
    c_sign_encrypt_update(
        s: CK_SESSION_HANDLE,
        p: CK_BYTE_PTR,
        pl: CK_ULONG,
        e: CK_BYTE_PTR,
        el: CK_ULONG_PTR,
    )
);
stub!(
    c_decrypt_verify_update(
        s: CK_SESSION_HANDLE,
        e: CK_BYTE_PTR,
        el: CK_ULONG,
        p: CK_BYTE_PTR,
        pl: CK_ULONG_PTR,
    )
);
stub!(
    c_generate_key(
        s: CK_SESSION_HANDLE,
        m: *mut CK_MECHANISM,
        t: *mut CK_ATTRIBUTE,
        c: CK_ULONG,
        k: CK_OBJECT_HANDLE_PTR,
    )
);
stub!(
    c_generate_key_pair(
        s: CK_SESSION_HANDLE,
        m: *mut CK_MECHANISM,
        pt: *mut CK_ATTRIBUTE,
        pc: CK_ULONG,
        vt: *mut CK_ATTRIBUTE,
        vc: CK_ULONG,
        pk: CK_OBJECT_HANDLE_PTR,
        vk: CK_OBJECT_HANDLE_PTR,
    )
);
stub!(
    c_wrap_key(
        s: CK_SESSION_HANDLE,
        m: *mut CK_MECHANISM,
        w: CK_OBJECT_HANDLE,
        k: CK_OBJECT_HANDLE,
        o: CK_BYTE_PTR,
        ol: CK_ULONG_PTR,
    )
);
stub!(
    c_unwrap_key(
        s: CK_SESSION_HANDLE,
        m: *mut CK_MECHANISM,
        u: CK_OBJECT_HANDLE,
        d: CK_BYTE_PTR,
        dl: CK_ULONG,
        t: *mut CK_ATTRIBUTE,
        c: CK_ULONG,
        k: CK_OBJECT_HANDLE_PTR,
    )
);
stub!(
    c_derive_key(
        s: CK_SESSION_HANDLE,
        m: *mut CK_MECHANISM,
        b: CK_OBJECT_HANDLE,
        t: *mut CK_ATTRIBUTE,
        c: CK_ULONG,
        k: CK_OBJECT_HANDLE_PTR,
    )
);
stub!(c_seed_random(s: CK_SESSION_HANDLE, d: CK_BYTE_PTR, dl: CK_ULONG));
stub!(c_generate_random(s: CK_SESSION_HANDLE, d: CK_BYTE_PTR, dl: CK_ULONG));
// v2.40 legacy functions: always CKR_FUNCTION_NOT_PARALLEL.
stub!(CKR_FUNCTION_NOT_PARALLEL; c_get_function_status(s: CK_SESSION_HANDLE));
stub!(CKR_FUNCTION_NOT_PARALLEL; c_cancel_function(s: CK_SESSION_HANDLE));
stub!(c_wait_for_slot_event(flags: CK_FLAGS, slot: *mut CK_SLOT_ID, reserved: CK_VOID_PTR));
