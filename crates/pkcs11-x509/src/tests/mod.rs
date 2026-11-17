//! Tests that call the module through its function list, as an application would.
//!
//! `unit` needs nothing but the process. `mock` needs AF_UNIX and
//! tests/mock_x509_sa.py (python3 + cryptography); those tests are
//! `#[ignore]`d and run with `cargo test -p pkcs11-x509 -- --include-ignored`.
//!
//! The module's state is global, so every test holds TEST_LOCK via `Fixture`.

mod mock;
mod unit;

use crate::objects::parse_list;
use crate::types::*;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::{json, Value};
use std::ptr::null_mut;
use std::sync::{Mutex, MutexGuard};

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Alice's key as in doc/x509/service.md:52 (the e2e key).
pub const ALICE_POINT_B64: &str =
    "BLmbYNUB+MRBCDl3n76hmdh7g91nX/ulMiNSmt/Q8FrIPBma3aS3t6qtUK/T7UsjA2HmzlbqeHkHB8t9hKgaKoE=";
pub const ALICE_ID_B64: &str = "aEjYq+QB/j5mEbD87z6V2wzWw2yTgrsjaZ0hE6BhjIw=";
pub const ALICE_LABEL: &str = "alice@atlanta.com tls-client";
pub const ALICE_PATH: &str = "m/44'/1240'/1955269225'/196866'/0'";

pub const FIXTURE_CERT: &[u8] = include_bytes!("../../tests/fixtures/fixture-cert.der");
pub const FIXTURE_SUBJECT: &[u8] = include_bytes!("../../tests/fixtures/fixture-subject.der");
pub const FIXTURE_ISSUER: &[u8] = include_bytes!("../../tests/fixtures/fixture-issuer.der");
pub const FIXTURE_SERIAL: &[u8] = include_bytes!("../../tests/fixtures/fixture-serial.der");

pub fn fl() -> &'static CK_FUNCTION_LIST {
    let mut p = null_mut();
    assert_eq!(unsafe { crate::C_GetFunctionList(&mut p) }, CKR_OK);
    unsafe { &*p }
}

/// Holds the test lock; the module is initialized (unless `bare`) and
/// finalized again on drop. X509_SA_SOCK points at a path where nothing listens.
pub struct Fixture {
    _guard: MutexGuard<'static, ()>,
}

impl Fixture {
    pub fn bare() -> Fixture {
        let guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { (fl().c_finalize.unwrap())(null_mut()) };
        *crate::client::client() = crate::client::Client::new_for_tests();
        crate::client::set_read_timeout_for_tests(0);
        crate::objects::set_max_cache_age_for_tests(0);
        std::env::set_var(
            "X509_SA_SOCK",
            std::env::temp_dir().join("km-p11-nobody-listens.sock"),
        );
        Fixture { _guard: guard }
    }

    pub fn new() -> Fixture {
        let f = Fixture::bare();
        assert_eq!(unsafe { (fl().c_initialize.unwrap())(null_mut()) }, CKR_OK);
        f
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe { (fl().c_finalize.unwrap())(null_mut()) };
        *crate::client::client() = crate::client::Client::new_for_tests();
    }
}

pub fn connect_attempts() -> u64 {
    crate::client::CONNECT_ATTEMPTS.load(std::sync::atomic::Ordering::Relaxed)
}

// --- list fixtures --------------------------------------------------------

pub fn key_json(
    point_b64: &str,
    id_b64: &str,
    label: &str,
    path: &str,
    cert: Option<&[u8]>,
) -> Value {
    let mut k = json!({"label": label, "path": path, "public_key": point_b64, "id": id_b64});
    if let Some(der) = cert {
        k["cert"] = json!(BASE64.encode(der));
    }
    k
}

pub fn alice(cert: Option<&[u8]>) -> Value {
    key_json(ALICE_POINT_B64, ALICE_ID_B64, ALICE_LABEL, ALICE_PATH, cert)
}

/// A second key; the module never checks the point is on the curve.
pub fn bob(cert: Option<&[u8]>) -> Value {
    let mut point = [0x22u8; 65];
    point[0] = 0x04;
    key_json(
        &BASE64.encode(point),
        &BASE64.encode([0xB0u8; 32]),
        "bob tls-client",
        "m/bob",
        cert,
    )
}

/// Put a list result straight into the cache (fresh, so no refresh happens).
pub fn load_cache(keys: Vec<Value>) {
    let parsed = parse_list(&json!({ "keys": keys })).expect("valid list");
    crate::session::lock()
        .as_mut()
        .expect("initialized")
        .store
        .replace(parsed);
}

pub fn b64(s: &str) -> Vec<u8> {
    BASE64.decode(s).unwrap()
}

pub fn ul(v: CK_ULONG) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

// --- thin wrappers over the function list ---------------------------------

pub fn open(rw: bool) -> CK_SESSION_HANDLE {
    let mut h = 0;
    let flags = CKF_SERIAL_SESSION | if rw { CKF_RW_SESSION } else { 0 };
    assert_eq!(
        unsafe { (fl().c_open_session.unwrap())(0, flags, null_mut(), None, &mut h) },
        CKR_OK
    );
    h
}

/// Two-call read of one attribute: (rv of the second call, value).
pub fn attr(
    s: CK_SESSION_HANDLE,
    obj: CK_OBJECT_HANDLE,
    t: CK_ATTRIBUTE_TYPE,
) -> (CK_RV, Option<Vec<u8>>) {
    let get = fl().c_get_attribute_value.unwrap();
    let mut a = CK_ATTRIBUTE {
        attr_type: t,
        p_value: null_mut(),
        value_len: 0,
    };
    let rv = unsafe { get(s, obj, &mut a, 1) };
    if rv != CKR_OK {
        return (rv, None);
    }
    let mut buf = vec![0u8; a.value_len as usize];
    a.p_value = buf.as_mut_ptr().cast();
    let rv = unsafe { get(s, obj, &mut a, 1) };
    (rv, Some(buf))
}

pub fn attr_ok(s: CK_SESSION_HANDLE, obj: CK_OBJECT_HANDLE, t: CK_ATTRIBUTE_TYPE) -> Vec<u8> {
    let (rv, v) = attr(s, obj, t);
    assert_eq!(rv, CKR_OK, "attribute {:#x}", t);
    v.unwrap()
}

/// Build a CK_ATTRIBUTE array over owned values (kept alive by the caller).
pub fn template(values: &mut [(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> Vec<CK_ATTRIBUTE> {
    values
        .iter_mut()
        .map(|(t, v)| CK_ATTRIBUTE {
            attr_type: *t,
            p_value: if v.is_empty() {
                null_mut()
            } else {
                v.as_mut_ptr().cast()
            },
            value_len: v.len() as CK_ULONG,
        })
        .collect()
}

pub fn find_rv(
    s: CK_SESSION_HANDLE,
    values: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<Vec<CK_OBJECT_HANDLE>, CK_RV> {
    let mut owned = values.to_vec();
    let mut t = template(&mut owned);
    let rv = unsafe { (fl().c_find_objects_init.unwrap())(s, t.as_mut_ptr(), t.len() as CK_ULONG) };
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = Vec::new();
    loop {
        let mut page = [0 as CK_OBJECT_HANDLE; 2]; // small pages exercise paging
        let mut n = 0;
        assert_eq!(
            unsafe { (fl().c_find_objects.unwrap())(s, page.as_mut_ptr(), 2, &mut n) },
            CKR_OK
        );
        if n == 0 {
            break;
        }
        out.extend_from_slice(&page[..n as usize]);
    }
    assert_eq!(unsafe { (fl().c_find_objects_final.unwrap())(s) }, CKR_OK);
    Ok(out)
}

pub fn find(
    s: CK_SESSION_HANDLE,
    values: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Vec<CK_OBJECT_HANDLE> {
    find_rv(s, values).expect("C_FindObjectsInit")
}

pub fn find_class(s: CK_SESSION_HANDLE, class: CK_OBJECT_CLASS) -> Vec<CK_OBJECT_HANDLE> {
    find(s, &[(CKA_CLASS, ul(class))])
}

pub fn sign_init(s: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> CK_RV {
    let mut m = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        p_parameter: null_mut(),
        parameter_len: 0,
    };
    unsafe { (fl().c_sign_init.unwrap())(s, &mut m, key) }
}

/// C_Sign with a 64-byte buffer: (rv, signature).
pub fn sign(s: CK_SESSION_HANDLE, data: &[u8]) -> (CK_RV, Vec<u8>) {
    let mut sig = vec![0u8; 64];
    let mut len: CK_ULONG = 64;
    let rv = unsafe {
        (fl().c_sign.unwrap())(
            s,
            data.as_ptr() as *mut u8,
            data.len() as CK_ULONG,
            sig.as_mut_ptr(),
            &mut len,
        )
    };
    sig.truncate(len as usize);
    (rv, sig)
}

pub fn create(
    s: CK_SESSION_HANDLE,
    values: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> (CK_RV, CK_OBJECT_HANDLE) {
    let mut owned = values.to_vec();
    let mut t = template(&mut owned);
    let mut h = 0;
    let rv =
        unsafe { (fl().c_create_object.unwrap())(s, t.as_mut_ptr(), t.len() as CK_ULONG, &mut h) };
    (rv, h)
}

/// The usual certificate template for C_CreateObject.
pub fn cert_template(der: &[u8]) -> Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> {
    vec![
        (CKA_CLASS, ul(CKO_CERTIFICATE)),
        (CKA_CERTIFICATE_TYPE, ul(CKC_X_509)),
        (CKA_TOKEN, vec![CK_TRUE]),
        (CKA_VALUE, der.to_vec()),
    ]
}
