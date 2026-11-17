//! Tests that need no socket. Named after the DoD items in doc/x509/pkcs11-module.md.

use super::*;
use crate::client::{map_error, resolve_socket_path, RpcError};
use crate::objects::{get_attr, parse_cert, Attr, Class};
use std::collections::HashMap;

// ===========================================================================
// D1  every constant matches the installed header
// ===========================================================================

/// Evaluate the header's value syntax: `(0x1041UL)`, `(1UL << 20)`,
/// `((unsigned long)-1L)`, `1`.
fn eval_c(value: &str) -> Option<u64> {
    let mut v = value.trim();
    while v.starts_with('(') && v.ends_with(')') {
        v = v[1..v.len() - 1].trim();
    }
    if v == "(unsigned long)-1L" || v == "(unsigned long) -1L" {
        return Some(u64::MAX);
    }
    if let Some((a, b)) = v.split_once("<<") {
        return Some(eval_c(a)? << eval_c(b)?);
    }
    let digits = v.trim_end_matches(['U', 'L', 'u', 'l']);
    match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => digits.parse().ok(),
    }
}

#[test]
fn d1_types_match_installed_header() {
    let path = "/usr/include/p11-kit-1/p11-kit/pkcs11.h";
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("skipped: {} is not installed", path);
        return;
    };
    let mut defs: HashMap<&str, &str> = HashMap::new();
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("#define ") {
            if let Some((name, value)) = rest.split_once(char::is_whitespace) {
                defs.entry(name).or_insert(value.trim());
            }
        }
    }
    let mut checked = 0;
    for (name, ours) in ALL_CONSTANTS {
        let value = defs
            .get(name)
            .unwrap_or_else(|| panic!("{} not in {}", name, path));
        let theirs =
            eval_c(value).unwrap_or_else(|| panic!("cannot evaluate {} = {}", name, value));
        assert_eq!(
            theirs, *ours,
            "{}: header says {}, types.rs says {:#x}",
            name, value, ours
        );
        checked += 1;
    }
    assert!(checked > 90, "only {} constants checked", checked);
    // The v2.40 name and the 3.x name are the same bit.
    assert_eq!(eval_c(defs["CKF_EC_OID"]), Some(CKF_EC_NAMEDCURVE));
}

// ===========================================================================
// D2  function list
// ===========================================================================

#[test]
fn d2_function_list_version_and_no_null_entries() {
    let _f = Fixture::bare();
    assert_eq!(
        unsafe { crate::C_GetFunctionList(null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    let list = fl();
    assert_eq!((list.version.major, list.version.minor), (2, 40));
    let start = std::mem::offset_of!(CK_FUNCTION_LIST, c_initialize);
    let n = (std::mem::size_of::<CK_FUNCTION_LIST>() - start) / std::mem::size_of::<usize>();
    assert_eq!(n, 68, "v2.40 has 68 functions");
    let base = (list as *const CK_FUNCTION_LIST).cast::<u8>();
    for i in 0..n {
        let p = unsafe { *(base.add(start + i * std::mem::size_of::<usize>()) as *const usize) };
        assert_ne!(p, 0, "function list entry {} is NULL", i);
    }
}

// ===========================================================================
// D3  C_Initialize arguments
// ===========================================================================

unsafe extern "C" fn create_mutex(_: *mut CK_VOID_PTR) -> CK_RV {
    CKR_OK
}
unsafe extern "C" fn other_mutex(_: CK_VOID_PTR) -> CK_RV {
    CKR_OK
}

fn init_args(mutexes: usize, flags: CK_FLAGS, reserved: bool) -> CK_C_INITIALIZE_ARGS {
    CK_C_INITIALIZE_ARGS {
        create_mutex: (mutexes >= 1).then_some(create_mutex as _),
        destroy_mutex: (mutexes >= 2).then_some(other_mutex as _),
        lock_mutex: (mutexes >= 3).then_some(other_mutex as _),
        unlock_mutex: (mutexes >= 4).then_some(other_mutex as _),
        flags,
        reserved: if reserved {
            1usize as CK_VOID_PTR
        } else {
            null_mut()
        },
    }
}

fn init_with(args: &mut CK_C_INITIALIZE_ARGS) -> CK_RV {
    unsafe { (fl().c_initialize.unwrap())((args as *mut CK_C_INITIALIZE_ARGS).cast()) }
}

#[test]
fn d3_init_null_ok_and_twice_already_initialized() {
    let _f = Fixture::new();
    assert_eq!(
        unsafe { (fl().c_initialize.unwrap())(null_mut()) },
        CKR_CRYPTOKI_ALREADY_INITIALIZED
    );
}

#[test]
fn d3_init_args_rules() {
    let _f = Fixture::bare();
    let finalize = || unsafe { (fl().c_finalize.unwrap())(null_mut()) };
    assert_eq!(
        init_with(&mut init_args(0, 0, true)),
        CKR_ARGUMENTS_BAD,
        "reserved must be NULL"
    );
    assert_eq!(
        init_with(&mut init_args(2, CKF_OS_LOCKING_OK, false)),
        CKR_ARGUMENTS_BAD,
        "some mutex fns"
    );
    assert_eq!(
        init_with(&mut init_args(4, 0, false)),
        CKR_CANT_LOCK,
        "app mutexes only"
    );
    assert_eq!(
        init_with(&mut init_args(4, CKF_OS_LOCKING_OK, false)),
        CKR_OK
    );
    assert_eq!(finalize(), CKR_OK);
    assert_eq!(
        init_with(&mut init_args(0, CKF_OS_LOCKING_OK, false)),
        CKR_OK
    );
    assert_eq!(finalize(), CKR_OK);
    assert_eq!(
        init_with(&mut init_args(0, CKF_LIBRARY_CANT_CREATE_OS_THREADS, false)),
        CKR_OK
    );
}

// ===========================================================================
// D4  no socket I/O before a search, sign or import
// ===========================================================================

#[test]
fn d4_no_io_in_init_info_slot_token_mechanisms_sessions_login() {
    let _f = Fixture::bare();
    let before = connect_attempts();
    unsafe {
        let f = fl();
        assert_eq!((f.c_initialize.unwrap())(null_mut()), CKR_OK);
        let mut info = std::mem::zeroed::<CK_INFO>();
        assert_eq!((f.c_get_info.unwrap())(&mut info), CKR_OK);
        let mut n = 0;
        assert_eq!(
            (f.c_get_slot_list.unwrap())(CK_TRUE, null_mut(), &mut n),
            CKR_OK
        );
        let mut slot = std::mem::zeroed::<CK_SLOT_INFO>();
        assert_eq!((f.c_get_slot_info.unwrap())(0, &mut slot), CKR_OK);
        let mut token = std::mem::zeroed::<CK_TOKEN_INFO>();
        assert_eq!((f.c_get_token_info.unwrap())(0, &mut token), CKR_OK);
        assert_eq!(
            (f.c_get_mechanism_list.unwrap())(0, null_mut(), &mut n),
            CKR_OK
        );
        let mut mi = std::mem::zeroed::<CK_MECHANISM_INFO>();
        assert_eq!(
            (f.c_get_mechanism_info.unwrap())(0, CKM_ECDSA, &mut mi),
            CKR_OK
        );
        let s = open(true);
        let mut si = std::mem::zeroed::<CK_SESSION_INFO>();
        assert_eq!((f.c_get_session_info.unwrap())(s, &mut si), CKR_OK);
        assert_eq!((f.c_login.unwrap())(s, CKU_USER, null_mut(), 0), CKR_OK);
        assert_eq!((f.c_logout.unwrap())(s), CKR_OK);
        assert_eq!((f.c_close_session.unwrap())(s), CKR_OK);
    }
    assert_eq!(
        connect_attempts(),
        before,
        "nothing above may touch the socket"
    );
}

// ===========================================================================
// D5  slot and token
// ===========================================================================

fn trimmed(field: &[u8]) -> String {
    String::from_utf8_lossy(field).trim_end().to_string()
}

#[test]
fn d5_info_slot_token_strings_and_flags() {
    let _f = Fixture::new();
    unsafe {
        let f = fl();
        let mut info = std::mem::zeroed::<CK_INFO>();
        assert_eq!((f.c_get_info.unwrap())(&mut info), CKR_OK);
        assert_eq!(
            (info.cryptoki_version.major, info.cryptoki_version.minor),
            (2, 40)
        );
        assert_eq!(trimmed(&info.manufacturer_id), "DWDC");
        assert_eq!(
            trimmed(&info.library_description),
            "KeyMaster X.509 PKCS#11"
        );

        let mut slots = [99 as CK_SLOT_ID; 2];
        let mut n: CK_ULONG = 0;
        assert_eq!(
            (f.c_get_slot_list.unwrap())(CK_FALSE, slots.as_mut_ptr(), &mut n),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(n, 1);
        n = 2;
        assert_eq!(
            (f.c_get_slot_list.unwrap())(CK_FALSE, slots.as_mut_ptr(), &mut n),
            CKR_OK
        );
        assert_eq!((n, slots[0]), (1, 0));

        let mut slot = std::mem::zeroed::<CK_SLOT_INFO>();
        assert_eq!((f.c_get_slot_info.unwrap())(0, &mut slot), CKR_OK);
        assert_eq!(slot.flags, CKF_TOKEN_PRESENT);
        assert_eq!(trimmed(&slot.manufacturer_id), "DWDC");

        let rw = open(true);
        let _ro = open(false);
        let mut t = std::mem::zeroed::<CK_TOKEN_INFO>();
        assert_eq!((f.c_get_token_info.unwrap())(0, &mut t), CKR_OK);
        assert_eq!(trimmed(&t.label), "KeyMaster X.509");
        assert_eq!(trimmed(&t.manufacturer_id), "DWDC");
        assert_eq!(trimmed(&t.model), "KeyMaster");
        assert_eq!(trimmed(&t.serial_number), "0000000000000001");
        assert_eq!(
            t.flags, CKF_TOKEN_INITIALIZED,
            "no LOGIN_REQUIRED, no WRITE_PROTECTED"
        );
        assert_eq!(t.max_session_count, CK_EFFECTIVELY_INFINITE);
        assert_eq!(t.max_rw_session_count, CK_EFFECTIVELY_INFINITE);
        assert_eq!((t.session_count, t.rw_session_count), (2, 1));
        assert_eq!((f.c_close_session.unwrap())(rw), CKR_OK);
    }
}

#[test]
fn d5_slot_id_invalid_is_0x3() {
    let _f = Fixture::new();
    assert_eq!(CKR_SLOT_ID_INVALID, 0x3);
    unsafe {
        let mut slot = std::mem::zeroed::<CK_SLOT_INFO>();
        assert_eq!(
            (fl().c_get_slot_info.unwrap())(1, &mut slot),
            CKR_SLOT_ID_INVALID
        );
        let mut h = 0;
        assert_eq!(
            (fl().c_open_session.unwrap())(7, CKF_SERIAL_SESSION, null_mut(), None, &mut h),
            CKR_SLOT_ID_INVALID
        );
    }
}

// ===========================================================================
// D6  mechanisms
// ===========================================================================

#[test]
fn d6_mechanisms_ecdsa_only() {
    let _f = Fixture::new();
    unsafe {
        let f = fl();
        let mut list = [0 as CK_MECHANISM_TYPE; 4];
        let mut n: CK_ULONG = 4;
        assert_eq!(
            (f.c_get_mechanism_list.unwrap())(0, list.as_mut_ptr(), &mut n),
            CKR_OK
        );
        assert_eq!(&list[..n as usize], &[CKM_ECDSA]);

        let mut info = std::mem::zeroed::<CK_MECHANISM_INFO>();
        assert_eq!(
            (f.c_get_mechanism_info.unwrap())(0, CKM_ECDSA, &mut info),
            CKR_OK
        );
        assert_eq!((info.min_key_size, info.max_key_size), (256, 256));
        assert_eq!(
            info.flags,
            CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS
        );
        assert_eq!(info.flags, 0x0180_0800 | 0x0010_0000);
        const CKM_ECDSA_SHA256: CK_MECHANISM_TYPE = 0x1044;
        assert_eq!(
            (f.c_get_mechanism_info.unwrap())(0, CKM_ECDSA_SHA256, &mut info),
            CKR_MECHANISM_INVALID
        );
    }
}

// ===========================================================================
// D7  sessions and login
// ===========================================================================

fn session_info(s: CK_SESSION_HANDLE) -> CK_SESSION_INFO {
    let mut si = unsafe { std::mem::zeroed::<CK_SESSION_INFO>() };
    assert_eq!(
        unsafe { (fl().c_get_session_info.unwrap())(s, &mut si) },
        CKR_OK
    );
    si
}

#[test]
fn d7_open_without_serial_is_parallel_not_supported() {
    let _f = Fixture::new();
    let mut h = 0;
    let rv = unsafe { (fl().c_open_session.unwrap())(0, CKF_RW_SESSION, null_mut(), None, &mut h) };
    assert_eq!(rv, CKR_SESSION_PARALLEL_NOT_SUPPORTED);
}

#[test]
fn d7_session_handles_never_reused() {
    let _f = Fixture::new();
    let a = open(false);
    assert_eq!(unsafe { (fl().c_close_session.unwrap())(a) }, CKR_OK);
    let b = open(false);
    assert_ne!(a, b);
    assert_eq!(
        unsafe { (fl().c_close_session.unwrap())(a) },
        CKR_SESSION_HANDLE_INVALID
    );
}

#[test]
fn d7_session_states_and_module_wide_login() {
    let _f = Fixture::new();
    let f = fl();
    let ro = open(false);
    let rw = open(true);
    assert_eq!(session_info(ro).state, CKS_RO_PUBLIC_SESSION);
    assert_eq!(session_info(rw).state, CKS_RW_PUBLIC_SESSION);
    assert_eq!(session_info(ro).flags, CKF_SERIAL_SESSION);
    assert_eq!(session_info(rw).flags, CKF_SERIAL_SESSION | CKF_RW_SESSION);

    unsafe {
        assert_eq!((f.c_logout.unwrap())(ro), CKR_USER_NOT_LOGGED_IN);
        assert_eq!(
            (f.c_login.unwrap())(ro, CKU_SO, null_mut(), 0),
            CKR_USER_TYPE_INVALID
        );
        assert_eq!(
            (f.c_login.unwrap())(ro, CKU_CONTEXT_SPECIFIC, null_mut(), 0),
            CKR_OPERATION_NOT_INITIALIZED
        );
        let mut pin = *b"any pin";
        assert_eq!(
            (f.c_login.unwrap())(ro, CKU_USER, pin.as_mut_ptr(), 7),
            CKR_OK
        );
        // Login on one session makes every session a user session.
        assert_eq!(session_info(ro).state, CKS_RO_USER_FUNCTIONS);
        assert_eq!(session_info(rw).state, CKS_RW_USER_FUNCTIONS);
        let late = open(true);
        assert_eq!(session_info(late).state, CKS_RW_USER_FUNCTIONS);
        assert_eq!(
            (f.c_login.unwrap())(rw, CKU_USER, null_mut(), 0),
            CKR_USER_ALREADY_LOGGED_IN
        );
        // Logout on another session logs all of them out.
        assert_eq!((f.c_logout.unwrap())(rw), CKR_OK);
        assert_eq!(session_info(ro).state, CKS_RO_PUBLIC_SESSION);

        // Closing the last session ends the login.
        assert_eq!((f.c_login.unwrap())(ro, CKU_USER, null_mut(), 0), CKR_OK);
        assert_eq!((f.c_close_session.unwrap())(ro), CKR_OK);
        assert_eq!((f.c_close_session.unwrap())(late), CKR_OK);
        assert_eq!(
            session_info(rw).state,
            CKS_RW_USER_FUNCTIONS,
            "one session still open"
        );
        assert_eq!((f.c_close_session.unwrap())(rw), CKR_OK);
        let again = open(false);
        assert_eq!(session_info(again).state, CKS_RO_PUBLIC_SESSION);
        // C_CloseAllSessions also logs out.
        assert_eq!((f.c_login.unwrap())(again, CKU_USER, null_mut(), 0), CKR_OK);
        assert_eq!((f.c_close_all_sessions.unwrap())(0), CKR_OK);
        let fresh = open(false);
        assert_eq!(session_info(fresh).state, CKS_RO_PUBLIC_SESSION);
        assert_eq!((f.c_close_all_sessions.unwrap())(5), CKR_SLOT_ID_INVALID);
    }
}

#[test]
fn d7_sessions_have_independent_find_and_sign_operations() {
    let _f = Fixture::new();
    load_cache(vec![alice(None)]);
    let a = open(false);
    let b = open(false);
    let f = fl();
    unsafe {
        let mut t = template(&mut Vec::new());
        assert_eq!(
            (f.c_find_objects_init.unwrap())(a, t.as_mut_ptr(), 0),
            CKR_OK
        );
        assert_eq!(
            (f.c_find_objects_init.unwrap())(a, t.as_mut_ptr(), 0),
            CKR_OPERATION_ACTIVE
        );
        // b has no search of its own.
        let mut out = [0; 4];
        let mut n = 0;
        assert_eq!(
            (f.c_find_objects.unwrap())(b, out.as_mut_ptr(), 4, &mut n),
            CKR_OPERATION_NOT_INITIALIZED
        );
        assert_eq!(
            (f.c_find_objects.unwrap())(a, out.as_mut_ptr(), 4, &mut n),
            CKR_OK
        );
        assert_eq!(n, 2);
        assert_eq!((f.c_find_objects_final.unwrap())(a), CKR_OK);
        assert_eq!(
            (f.c_find_objects_final.unwrap())(a),
            CKR_OPERATION_NOT_INITIALIZED
        );
    }
    let key = find_class(a, CKO_PRIVATE_KEY)[0];
    assert_eq!(sign_init(a, key), CKR_OK);
    assert_eq!(sign_init(a, key), CKR_OPERATION_ACTIVE);
    assert_eq!(sign(b, &[0u8; 32]).0, CKR_OPERATION_NOT_INITIALIZED);
    assert_eq!(sign_init(b, key), CKR_OK);
}

// ===========================================================================
// D8  objects from the list
// ===========================================================================

#[test]
fn d8_two_objects_without_cert_three_with() {
    let _f = Fixture::new();
    let s = open(false);
    load_cache(vec![alice(None)]);
    assert_eq!(find(s, &[]).len(), 2, "no placeholder certificate");
    assert!(find_class(s, CKO_CERTIFICATE).is_empty());

    load_cache(vec![alice(Some(FIXTURE_CERT))]);
    let all = find(s, &[]);
    assert_eq!(all.len(), 3);
    let id = b64(ALICE_ID_B64);
    for h in all {
        assert_eq!(attr_ok(s, h, CKA_ID), id, "all three share CKA_ID");
        assert_eq!(attr_ok(s, h, CKA_LABEL), ALICE_LABEL.as_bytes());
    }
}

#[test]
fn d8_parse_list_skips_bad_entries() {
    use crate::objects::parse_list;
    let mut short = alice(None);
    short["public_key"] = json!(BASE64.encode([4u8; 33]));
    let mut no_label = bob(None);
    no_label["label"] = json!("");
    let bad_cert = key_json(
        &BASE64.encode({
            let mut p = [0x33u8; 65];
            p[0] = 4;
            p
        }),
        &BASE64.encode([0xC0u8; 32]),
        "carol",
        "m/c",
        Some(b"not a certificate"),
    );
    let parsed =
        parse_list(&json!({"keys": [short, no_label, alice(None), alice(None), bad_cert]}))
            .unwrap();
    assert_eq!(
        parsed.len(),
        2,
        "short point and empty label skipped, duplicate id skipped"
    );
    assert_eq!(parsed[0].label, ALICE_LABEL);
    assert!(
        parsed[1].cert.is_none(),
        "an unparsable cert hides only the cert object"
    );
    assert!(matches!(
        parse_list(&json!({"certs": []})),
        Err(RpcError::BadResult(_))
    ));
}

// ===========================================================================
// D9  attribute table
// ===========================================================================

fn key_entry(cert: bool) -> crate::objects::KeyEntry {
    crate::objects::parse_list(&json!({"keys": [alice(cert.then_some(FIXTURE_CERT))]}))
        .unwrap()
        .remove(0)
}

fn value(a: Attr) -> Vec<u8> {
    match a {
        Attr::Value(v) => v.into_owned(),
        other => panic!("expected a value, got {:?}", other),
    }
}

const T: &[u8] = &[CK_TRUE];
const F: &[u8] = &[CK_FALSE];

#[test]
fn d9_private_key_attributes() {
    let k = key_entry(false);
    let g = |t| get_attr(&k, Class::Private, t);
    assert_eq!(value(g(CKA_CLASS)), ul(CKO_PRIVATE_KEY));
    assert_eq!(value(g(CKA_KEY_TYPE)), ul(CKK_EC));
    for (a, want) in [
        (CKA_TOKEN, T),
        (CKA_PRIVATE, F),
        (CKA_SIGN, T),
        (CKA_SENSITIVE, T),
        (CKA_ALWAYS_SENSITIVE, T),
        (CKA_NEVER_EXTRACTABLE, T),
        (CKA_EXTRACTABLE, F),
        (CKA_DECRYPT, F),
        (CKA_DERIVE, F),
        (CKA_UNWRAP, F),
        (CKA_ALWAYS_AUTHENTICATE, F),
        (CKA_MODIFIABLE, F),
        (CKA_COPYABLE, F),
        (CKA_DESTROYABLE, F),
    ] {
        assert_eq!(value(g(a)), want, "attribute {:#x}", a);
    }
    assert_eq!(
        value(g(CKA_EC_PARAMS)),
        [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
    );
    assert_eq!(value(g(CKA_ID)), b64(ALICE_ID_B64));
    assert_eq!(g(CKA_VALUE), Attr::Sensitive);
    for a in [
        CKA_EC_POINT,
        CKA_VERIFY,
        CKA_CERTIFICATE_TYPE,
        CKA_SUBJECT,
        CKA_TRUSTED,
    ] {
        assert_eq!(g(a), Attr::Invalid, "attribute {:#x}", a);
    }
}

#[test]
fn d9_public_key_attributes() {
    let k = key_entry(false);
    let g = |t| get_attr(&k, Class::Public, t);
    assert_eq!(value(g(CKA_CLASS)), ul(CKO_PUBLIC_KEY));
    assert_eq!(value(g(CKA_KEY_TYPE)), ul(CKK_EC));
    assert_eq!(value(g(CKA_VERIFY)), T);
    assert_eq!(value(g(CKA_PRIVATE)), F);
    assert_eq!(value(g(CKA_MODIFIABLE)), F);
    // DER OCTET STRING wrapping the 65-byte point.
    let point = b64(ALICE_POINT_B64);
    let mut want = vec![0x04, 0x41];
    want.extend_from_slice(&point);
    assert_eq!(value(g(CKA_EC_POINT)), want);
    assert_eq!(&value(g(CKA_EC_POINT))[..3], &[0x04, 0x41, 0x04]);
    for a in [
        CKA_SIGN,
        CKA_SENSITIVE,
        CKA_VALUE,
        CKA_ALWAYS_AUTHENTICATE,
        CKA_CERTIFICATE_TYPE,
    ] {
        assert_eq!(g(a), Attr::Invalid, "attribute {:#x}", a);
    }
}

#[test]
fn d9_certificate_attributes() {
    let k = key_entry(true);
    let g = |t| get_attr(&k, Class::Cert, t);
    assert_eq!(value(g(CKA_CLASS)), ul(CKO_CERTIFICATE));
    assert_eq!(value(g(CKA_CERTIFICATE_TYPE)), ul(CKC_X_509));
    assert_eq!(value(g(CKA_VALUE)), FIXTURE_CERT);
    // Expected values were cut out of the DER with `openssl asn1parse`.
    assert_eq!(value(g(CKA_SUBJECT)), FIXTURE_SUBJECT);
    assert_eq!(value(g(CKA_ISSUER)), FIXTURE_ISSUER);
    assert_eq!(value(g(CKA_SERIAL_NUMBER)), FIXTURE_SERIAL);
    assert_eq!(
        FIXTURE_SERIAL,
        [0x02, 0x06, 0x00, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5],
        "full DER INTEGER"
    );
    assert_eq!(value(g(CKA_CERTIFICATE_CATEGORY)), ul(1));
    assert_eq!(value(g(CKA_TRUSTED)), F);
    assert_eq!(value(g(CKA_TOKEN)), T);
    assert_eq!(value(g(CKA_ID)), b64(ALICE_ID_B64));
    for a in [
        CKA_KEY_TYPE,
        CKA_EC_PARAMS,
        CKA_EC_POINT,
        CKA_SIGN,
        CKA_SENSITIVE,
    ] {
        assert_eq!(g(a), Attr::Invalid, "attribute {:#x}", a);
    }
    // Without a certificate the certificate object has nothing.
    assert_eq!(
        get_attr(&key_entry(false), Class::Cert, CKA_VALUE),
        Attr::Invalid
    );
}

#[test]
fn d9_parse_cert_rejects_non_certificates() {
    assert!(parse_cert(FIXTURE_CERT).is_some());
    assert!(parse_cert(&FIXTURE_CERT[..FIXTURE_CERT.len() - 1]).is_none());
    assert!(parse_cert(b"").is_none());
}

// ===========================================================================
// D10 CKA_ID is SHA-256 of the DER SPKI, as delivered by `list`
// ===========================================================================

#[test]
fn d10_id_is_sha256_of_spki() {
    use sha2::{Digest, Sha256};
    let prefix = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let mut spki = prefix.to_vec();
    spki.extend_from_slice(&b64(ALICE_POINT_B64));
    assert_eq!(Sha256::digest(&spki).to_vec(), b64(ALICE_ID_B64));
    // And CKA_ID is that value, taken from `list.id`, not rebuilt from CKA_EC_POINT.
    assert_eq!(
        value(get_attr(&key_entry(false), Class::Public, CKA_ID)),
        b64(ALICE_ID_B64)
    );
}

// ===========================================================================
// D11 two-pass C_GetAttributeValue
// ===========================================================================

#[test]
fn d11_two_pass_rules() {
    let _f = Fixture::new();
    load_cache(vec![alice(None)]);
    let s = open(false);
    let private = find_class(s, CKO_PRIVATE_KEY)[0];
    let get = fl().c_get_attribute_value.unwrap();

    // Pass 1: sizes; an unknown attribute and a sensitive one in the middle.
    let mut t = [
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: null_mut(),
            value_len: 0,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_EC_POINT,
            p_value: null_mut(),
            value_len: 0,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ID,
            p_value: null_mut(),
            value_len: 0,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE,
            p_value: null_mut(),
            value_len: 0,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: null_mut(),
            value_len: 0,
        },
    ];
    let rv = unsafe { get(s, private, t.as_mut_ptr(), 5) };
    assert_eq!(rv, CKR_ATTRIBUTE_SENSITIVE, "the last error set wins");
    assert_eq!(t[0].value_len, ALICE_LABEL.len() as CK_ULONG);
    assert_eq!(
        t[1].value_len, CK_UNAVAILABLE_INFORMATION,
        "private key has no EC_POINT"
    );
    assert_eq!(t[2].value_len, 32, "processing continued after an error");
    assert_eq!(t[3].value_len, CK_UNAVAILABLE_INFORMATION, "sensitive");
    assert_eq!(
        t[4].value_len, 10,
        "processing continued after the sensitive one"
    );

    // Pass 2: one buffer too small, one right.
    let mut small = [0u8; 4];
    let mut id = [0u8; 32];
    let mut t = [
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: small.as_mut_ptr().cast(),
            value_len: 4,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ID,
            p_value: id.as_mut_ptr().cast(),
            value_len: 32,
        },
    ];
    assert_eq!(
        unsafe { get(s, private, t.as_mut_ptr(), 2) },
        CKR_BUFFER_TOO_SMALL
    );
    assert_eq!(t[0].value_len, CK_UNAVAILABLE_INFORMATION);
    assert_eq!((t[1].value_len, id.to_vec()), (32, b64(ALICE_ID_B64)));

    // An unknown attribute alone; a bad handle; a NULL template.
    let mut t = [CK_ATTRIBUTE {
        attr_type: 0xdead,
        p_value: null_mut(),
        value_len: 0,
    }];
    assert_eq!(
        unsafe { get(s, private, t.as_mut_ptr(), 1) },
        CKR_ATTRIBUTE_TYPE_INVALID
    );
    assert_eq!(t[0].value_len, CK_UNAVAILABLE_INFORMATION);
    assert_eq!(
        unsafe { get(s, 9999, t.as_mut_ptr(), 1) },
        CKR_OBJECT_HANDLE_INVALID
    );
    assert_eq!(unsafe { get(s, private, null_mut(), 1) }, CKR_ARGUMENTS_BAD);
    assert_eq!(
        unsafe { get(9999, private, t.as_mut_ptr(), 1) },
        CKR_SESSION_HANDLE_INVALID
    );
}

// ===========================================================================
// D12 the search filter uses the same getter
// ===========================================================================

#[test]
fn d12_find_matches_exactly_with_the_same_getter() {
    let _f = Fixture::new();
    load_cache(vec![alice(Some(FIXTURE_CERT)), bob(None)]);
    let s = open(false);
    let all = find(s, &[]);
    assert_eq!(all.len(), 5, "empty template finds everything");

    let alice_id = b64(ALICE_ID_B64);
    assert_eq!(find(s, &[(CKA_ID, alice_id.clone())]).len(), 3);
    assert_eq!(
        find(s, &[(CKA_ID, alice_id[..31].to_vec())]).len(),
        0,
        "prefix does not match"
    );
    assert_eq!(
        find(s, &[(CKA_LABEL, b"alice".to_vec())]).len(),
        0,
        "substring does not match"
    );
    assert_eq!(
        find(s, &[(CKA_LABEL, ALICE_LABEL.as_bytes().to_vec())]).len(),
        3
    );
    assert_eq!(
        find(
            s,
            &[(CKA_CLASS, ul(CKO_PRIVATE_KEY)), (CKA_ID, alice_id.clone())]
        )
        .len(),
        1
    );
    assert_eq!(
        find(s, &[(CKA_SIGN, vec![CK_TRUE])]).len(),
        2,
        "only private keys have CKA_SIGN"
    );
    assert_eq!(
        find(s, &[(CKA_EC_POINT, vec![])]).len(),
        0,
        "empty value matches no point"
    );
    assert_eq!(
        find(s, &[(CKA_VALUE, FIXTURE_CERT.to_vec())]).len(),
        1,
        "the certificate"
    );
    assert_eq!(
        find(s, &[(0xdead, vec![1])]).len(),
        0,
        "an attribute nobody has"
    );
    assert_eq!(
        find(s, &[(CKA_CLASS, 3u32.to_ne_bytes().to_vec())]).len(),
        0,
        "a 4-byte class is not equal"
    );

    // A sensitive attribute never matches, even with the "right" bytes.
    assert_eq!(
        find(s, &[(CKA_CLASS, ul(CKO_PRIVATE_KEY)), (CKA_VALUE, vec![])]).len(),
        0
    );

    // For every object and every readable attribute: find({a: get(a)}) contains it.
    let types = [
        CKA_CLASS,
        CKA_TOKEN,
        CKA_PRIVATE,
        CKA_ID,
        CKA_LABEL,
        CKA_KEY_TYPE,
        CKA_EC_PARAMS,
        CKA_EC_POINT,
        CKA_SIGN,
        CKA_VERIFY,
        CKA_SENSITIVE,
        CKA_EXTRACTABLE,
        CKA_MODIFIABLE,
        CKA_CERTIFICATE_TYPE,
        CKA_VALUE,
        CKA_SUBJECT,
        CKA_ISSUER,
        CKA_SERIAL_NUMBER,
        CKA_CERTIFICATE_CATEGORY,
        CKA_TRUSTED,
    ];
    for &obj in &all {
        for &t in &types {
            if let (CKR_OK, Some(v)) = attr(s, obj, t) {
                assert!(
                    find(s, &[(t, v)]).contains(&obj),
                    "object {} attribute {:#x}",
                    obj,
                    t
                );
            }
        }
    }

    // NULL pValue with a length is an argument error.
    let mut t = [CK_ATTRIBUTE {
        attr_type: CKA_ID,
        p_value: null_mut(),
        value_len: 4,
    }];
    assert_eq!(
        unsafe { (fl().c_find_objects_init.unwrap())(s, t.as_mut_ptr(), 1) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(
        unsafe { (fl().c_find_objects_init.unwrap())(s, null_mut(), 1) },
        CKR_ARGUMENTS_BAD
    );
}

// ===========================================================================
// D13 handles: stable per (CKA_ID, class), never reused
// ===========================================================================

#[test]
fn d13_handles_stable_across_refresh_and_reorder() {
    let _f = Fixture::new();
    let s = open(false);
    load_cache(vec![alice(None), bob(None)]);
    let alice_id = b64(ALICE_ID_B64);
    let alice_priv = find(
        s,
        &[(CKA_CLASS, ul(CKO_PRIVATE_KEY)), (CKA_ID, alice_id.clone())],
    )[0];
    let before: Vec<_> = find(s, &[]);

    load_cache(vec![bob(None), alice(None)]); // reordered
    let mut after = find(s, &[]);
    after.sort();
    let mut sorted = before.clone();
    sorted.sort();
    assert_eq!(after, sorted, "same objects, same handles");
    assert_eq!(
        attr_ok(s, alice_priv, CKA_ID),
        alice_id,
        "the handle still names Alice's key"
    );

    load_cache(vec![bob(None)]); // Alice gone
    assert_eq!(attr(s, alice_priv, CKA_LABEL).0, CKR_OBJECT_HANDLE_INVALID);
    assert_eq!(sign_init(s, alice_priv), CKR_KEY_HANDLE_INVALID);

    // A new key gets new numbers, never one used before.
    let mut carol_point = [0x44u8; 65];
    carol_point[0] = 4;
    load_cache(vec![
        bob(None),
        key_json(
            &BASE64.encode(carol_point),
            &BASE64.encode([0xCAu8; 32]),
            "carol",
            "m/c",
            None,
        ),
    ]);
    let carol = find(s, &[(CKA_ID, vec![0xCA; 32])]);
    assert_eq!(carol.len(), 2);
    assert!(carol.iter().all(|h| !before.contains(h)));

    // Alice coming back is the same identity, so the same handle.
    load_cache(vec![alice(None), bob(None)]);
    assert_eq!(attr_ok(s, alice_priv, CKA_ID), alice_id);

    // A certificate object vanishes with its certificate.
    load_cache(vec![alice(Some(FIXTURE_CERT))]);
    let cert = find_class(s, CKO_CERTIFICATE)[0];
    load_cache(vec![alice(None)]);
    assert_eq!(attr(s, cert, CKA_VALUE).0, CKR_OBJECT_HANDLE_INVALID);
}

// ===========================================================================
// D14 refresh failure without a cache
// ===========================================================================

#[test]
fn d14_find_without_cache_is_device_error() {
    let _f = Fixture::new();
    let s = open(false);
    assert_eq!(find_rv(s, &[]), Err(CKR_DEVICE_ERROR));
    // The failed search did not leave an operation behind.
    load_cache(vec![alice(None)]);
    assert_eq!(find(s, &[]).len(), 2);
}

// ===========================================================================
// D15 signing without the socket: two-call convention, length, init errors
// ===========================================================================

#[test]
fn d15_sign_two_call_convention_keeps_the_operation() {
    let _f = Fixture::new();
    load_cache(vec![alice(None)]);
    let s = open(false);
    let key = find_class(s, CKO_PRIVATE_KEY)[0];
    let c_sign = fl().c_sign.unwrap();
    let digest = [7u8; 32];
    assert_eq!(sign_init(s, key), CKR_OK);
    unsafe {
        let mut len: CK_ULONG = 0;
        assert_eq!(
            c_sign(s, digest.as_ptr() as *mut u8, 32, null_mut(), &mut len),
            CKR_OK
        );
        assert_eq!(len, 64);
        let mut small = [0u8; 10];
        len = 10;
        assert_eq!(
            c_sign(
                s,
                digest.as_ptr() as *mut u8,
                32,
                small.as_mut_ptr(),
                &mut len
            ),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(len, 64);
    }
    // Still active: a third call gets past the two-call cases (and hits the absent socket).
    let before = connect_attempts();
    assert_eq!(sign(s, &digest).0, CKR_DEVICE_ERROR);
    assert!(
        connect_attempts() > before,
        "the real call went to the socket"
    );
    // That error ended the operation.
    assert_eq!(sign(s, &digest).0, CKR_OPERATION_NOT_INITIALIZED);
}

#[test]
fn d15_sign_requires_exactly_32_bytes() {
    let _f = Fixture::new();
    load_cache(vec![alice(None)]);
    let s = open(false);
    let key = find_class(s, CKO_PRIVATE_KEY)[0];
    let before = connect_attempts();
    for len in [0usize, 20, 31, 33, 48, 64] {
        assert_eq!(sign_init(s, key), CKR_OK);
        assert_eq!(
            sign(s, &vec![1u8; len]).0,
            CKR_DATA_LEN_RANGE,
            "length {}",
            len
        );
        assert_eq!(
            sign(s, &[1u8; 32]).0,
            CKR_OPERATION_NOT_INITIALIZED,
            "DATA_LEN_RANGE ends the op"
        );
    }
    assert_eq!(connect_attempts(), before, "nothing was sent");
}

#[test]
fn d15_sign_init_errors() {
    let _f = Fixture::new();
    load_cache(vec![alice(Some(FIXTURE_CERT))]);
    let s = open(false);
    let private = find_class(s, CKO_PRIVATE_KEY)[0];
    let public = find_class(s, CKO_PUBLIC_KEY)[0];
    let cert = find_class(s, CKO_CERTIFICATE)[0];
    let init = fl().c_sign_init.unwrap();
    unsafe {
        assert_eq!(init(s, null_mut(), private), CKR_ARGUMENTS_BAD);
        let mut m = CK_MECHANISM {
            mechanism: 0x1044,
            p_parameter: null_mut(),
            parameter_len: 0,
        };
        assert_eq!(
            init(s, &mut m, private),
            CKR_MECHANISM_INVALID,
            "no CKM_ECDSA_SHA256"
        );
        let mut param = 0u8;
        let mut m = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            p_parameter: (&mut param as *mut u8).cast(),
            parameter_len: 1,
        };
        assert_eq!(init(s, &mut m, private), CKR_MECHANISM_PARAM_INVALID);
    }
    assert_eq!(sign_init(s, public), CKR_KEY_FUNCTION_NOT_PERMITTED);
    assert_eq!(sign_init(s, cert), CKR_KEY_HANDLE_INVALID);
    assert_eq!(sign_init(s, 4242), CKR_KEY_HANDLE_INVALID);
    assert_eq!(sign_init(9999, private), CKR_SESSION_HANDLE_INVALID);
    assert_eq!(sign(s, &[0; 32]).0, CKR_OPERATION_NOT_INITIALIZED);
    assert_eq!(sign_init(s, private), CKR_OK);
    assert_eq!(sign_init(s, private), CKR_OPERATION_ACTIVE);
    // pulSignatureLen NULL: ARGUMENTS_BAD, and the operation ends.
    let data = [0u8; 32];
    assert_eq!(
        unsafe { (fl().c_sign.unwrap())(s, data.as_ptr() as *mut u8, 32, null_mut(), null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(sign_init(s, private), CKR_OK);
}

// ===========================================================================
// D16 error mapping
// ===========================================================================

#[test]
fn d16_map_error_table() {
    let rpc = |code, m: &str| RpcError::Rpc {
        code,
        message: m.into(),
    };
    let cases = [
        (rpc(-32603, "avatar unavailable"), CKR_DEVICE_ERROR),
        (
            rpc(-32001, "no service channel available"),
            CKR_DEVICE_ERROR,
        ),
        (rpc(-32002, "failed to send request"), CKR_DEVICE_ERROR),
        (rpc(-32003, "timeout"), CKR_DEVICE_ERROR),
        (rpc(-32603, "request denied by user"), CKR_FUNCTION_REJECTED),
        (rpc(-32603, "unknown-path"), CKR_KEY_HANDLE_INVALID),
        (rpc(-32603, "invalid-digest"), CKR_DATA_LEN_RANGE),
        (rpc(-32603, "unsupported"), CKR_FUNCTION_NOT_SUPPORTED),
        (rpc(-32700, "parse error"), CKR_GENERAL_ERROR),
        (rpc(-32600, "invalid request"), CKR_GENERAL_ERROR),
        (rpc(-32601, "method not found"), CKR_GENERAL_ERROR),
        (
            rpc(-32602, "'digest' must decode to exactly 32 bytes"),
            CKR_GENERAL_ERROR,
        ),
        (rpc(-32004, "response channel dropped"), CKR_FUNCTION_FAILED),
        (rpc(-32603, "sign failed: status=3"), CKR_FUNCTION_FAILED),
        (rpc(-32603, "unknown method: x"), CKR_FUNCTION_FAILED),
        (rpc(-32000, "request denied by user"), CKR_FUNCTION_FAILED), // message only counts under -32603
        (RpcError::Transport("timeout".into()), CKR_DEVICE_ERROR),
        (
            RpcError::Transport("reply id mismatch".into()),
            CKR_DEVICE_ERROR,
        ),
        (
            RpcError::BadResult("no signature".into()),
            CKR_FUNCTION_FAILED,
        ),
    ];
    for (err, want) in cases {
        assert_eq!(map_error(&err), want, "{:?}", err);
    }
}

#[test]
fn d16_socket_path_resolution() {
    use std::ffi::OsString;
    let s = |v: &str| Some(OsString::from(v));
    assert_eq!(
        resolve_socket_path(s("/x/sa.sock"), s("/run/user/5"), 5),
        std::path::Path::new("/x/sa.sock")
    );
    assert_eq!(
        resolve_socket_path(None, s("/run/user/5"), 5),
        std::path::Path::new("/run/user/5/keymaster-x509-sa.sock")
    );
    assert_eq!(
        resolve_socket_path(s(""), s(""), 1000),
        std::path::Path::new("/run/user/1000/keymaster-x509-sa.sock"),
        "empty values count as unset"
    );
}

// ===========================================================================
// D19 C_CreateObject template rules (nothing reaches the socket)
// ===========================================================================

#[test]
fn d19_create_template_rules() {
    let _f = Fixture::new();
    let rw = open(true);
    let ro = open(false);
    let before = connect_attempts();
    let good = cert_template(FIXTURE_CERT);
    let without = |a| {
        good.iter()
            .filter(|(t, _)| *t != a)
            .cloned()
            .collect::<Vec<_>>()
    };
    let with = |a, v: Vec<u8>| {
        let mut t = without(a);
        t.push((a, v));
        t
    };

    assert_eq!(create(ro, &good).0, CKR_SESSION_READ_ONLY);
    assert_eq!(create(rw, &without(CKA_CLASS)).0, CKR_TEMPLATE_INCOMPLETE);
    assert_eq!(
        create(rw, &with(CKA_CLASS, vec![1])).0,
        CKR_ATTRIBUTE_VALUE_INVALID
    );
    assert_eq!(
        create(rw, &without(CKA_CERTIFICATE_TYPE)).0,
        CKR_TEMPLATE_INCOMPLETE
    );
    assert_eq!(
        create(rw, &with(CKA_CERTIFICATE_TYPE, ul(1))).0,
        CKR_ATTRIBUTE_VALUE_INVALID
    );
    assert_eq!(create(rw, &without(CKA_VALUE)).0, CKR_TEMPLATE_INCOMPLETE);
    assert_eq!(
        create(rw, &with(CKA_TOKEN, vec![CK_FALSE])).0,
        CKR_TEMPLATE_INCONSISTENT
    );
    assert_eq!(
        create(rw, &with(CKA_TRUSTED, vec![CK_TRUE])).0,
        CKR_ATTRIBUTE_READ_ONLY
    );
    assert_eq!(
        create(rw, &with(CKA_VALUE, b"not DER".to_vec())).0,
        CKR_ATTRIBUTE_VALUE_INVALID
    );
    assert_eq!(
        create(rw, &with(CKA_SUBJECT, b"other".to_vec())).0,
        CKR_TEMPLATE_INCONSISTENT
    );
    assert_eq!(
        create(rw, &with(CKA_SERIAL_NUMBER, vec![2, 1, 1])).0,
        CKR_TEMPLATE_INCONSISTENT
    );
    assert_eq!(
        unsafe { (fl().c_create_object.unwrap())(rw, null_mut(), 0, &mut 0) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(
        connect_attempts(),
        before,
        "no invalid template reaches the socket"
    );

    // Matching subject/issuer/serial and an ignored CKA_ID/CKA_LABEL pass the
    // checks; with nobody listening the import then fails with DEVICE_ERROR.
    let mut full = good.clone();
    full.extend([
        (CKA_SUBJECT, FIXTURE_SUBJECT.to_vec()),
        (CKA_ISSUER, FIXTURE_ISSUER.to_vec()),
        (CKA_SERIAL_NUMBER, FIXTURE_SERIAL.to_vec()),
        (CKA_ID, vec![0x99; 20]),
        (CKA_LABEL, b"my label".to_vec()),
    ]);
    assert_eq!(create(rw, &full).0, CKR_DEVICE_ERROR);
    assert!(connect_attempts() > before);
}

// ===========================================================================
// D20 key creation and object changes are refused
// ===========================================================================

#[test]
fn d20_key_creation_and_object_changes_refused() {
    let _f = Fixture::new();
    load_cache(vec![alice(None)]);
    let rw = open(true);
    let key = find_class(rw, CKO_PRIVATE_KEY)[0];
    let f = fl();
    for class in [CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY] {
        let t = vec![(CKA_CLASS, ul(class)), (CKA_KEY_TYPE, ul(CKK_EC))];
        assert_eq!(
            create(rw, &t).0,
            CKR_TEMPLATE_INCONSISTENT,
            "class {}",
            class
        );
    }
    unsafe {
        let mut t = template(&mut Vec::new());
        let mut new = 0;
        assert_eq!(
            (f.c_copy_object.unwrap())(rw, key, t.as_mut_ptr(), 0, &mut new),
            CKR_ACTION_PROHIBITED
        );
        assert_eq!(
            (f.c_set_attribute_value.unwrap())(rw, key, t.as_mut_ptr(), 0),
            CKR_ACTION_PROHIBITED
        );
        assert_eq!(
            (f.c_destroy_object.unwrap())(rw, key),
            CKR_ACTION_PROHIBITED
        );
        assert_eq!(
            (f.c_destroy_object.unwrap())(rw, 4242),
            CKR_OBJECT_HANDLE_INVALID
        );
        let mut size = 0;
        assert_eq!((f.c_get_object_size.unwrap())(rw, key, &mut size), CKR_OK);
        assert_eq!(size, CK_UNAVAILABLE_INFORMATION);
        let mut m = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            p_parameter: null_mut(),
            parameter_len: 0,
        };
        let (mut a, mut b) = (0, 0);
        assert_eq!(
            (f.c_generate_key_pair.unwrap())(
                rw,
                &mut m,
                null_mut(),
                0,
                null_mut(),
                0,
                &mut a,
                &mut b
            ),
            CKR_FUNCTION_NOT_SUPPORTED
        );
        assert_eq!(
            (f.c_sign_update.unwrap())(rw, null_mut(), 0),
            CKR_FUNCTION_NOT_SUPPORTED
        );
        assert_eq!(
            (f.c_sign_final.unwrap())(rw, null_mut(), null_mut()),
            CKR_FUNCTION_NOT_SUPPORTED
        );
        assert_eq!(
            (f.c_verify_init.unwrap())(rw, &mut m, key),
            CKR_FUNCTION_NOT_SUPPORTED
        );
        assert_eq!(
            (f.c_get_function_status.unwrap())(rw),
            CKR_FUNCTION_NOT_PARALLEL
        );
        assert_eq!(
            (f.c_cancel_function.unwrap())(rw),
            CKR_FUNCTION_NOT_PARALLEL
        );
        assert_eq!(
            (f.c_init_token.unwrap())(0, null_mut(), 0, null_mut()),
            CKR_FUNCTION_NOT_SUPPORTED
        );
    }
}

// ===========================================================================
// D21 C_Finalize
// ===========================================================================

#[test]
fn d21_finalize_rules_and_reinit() {
    let _f = Fixture::new();
    let f = fl();
    let s = open(true);
    unsafe {
        assert_eq!(
            (f.c_finalize.unwrap())(1usize as CK_VOID_PTR),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!((f.c_finalize.unwrap())(null_mut()), CKR_OK);
        assert_eq!(
            (f.c_finalize.unwrap())(null_mut()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
        let mut info = std::mem::zeroed::<CK_INFO>();
        assert_eq!(
            (f.c_get_info.unwrap())(&mut info),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
        assert_eq!(open_raw(), CKR_CRYPTOKI_NOT_INITIALIZED);
        assert_eq!((f.c_initialize.unwrap())(null_mut()), CKR_OK);
        let mut si = std::mem::zeroed::<CK_SESSION_INFO>();
        assert_eq!(
            (f.c_get_session_info.unwrap())(s, &mut si),
            CKR_SESSION_HANDLE_INVALID,
            "sessions gone"
        );
    }
    // The cache went too.
    let s = open(false);
    assert_eq!(find_rv(s, &[]), Err(CKR_DEVICE_ERROR));
}

fn open_raw() -> CK_RV {
    let mut h = 0;
    unsafe { (fl().c_open_session.unwrap())(0, CKF_SERIAL_SESSION, null_mut(), None, &mut h) }
}

// ===========================================================================
// D22 NULL arguments everywhere; no files created
// ===========================================================================

#[test]
fn d22_null_pointer_arguments_return_arguments_bad() {
    let _f = Fixture::new();
    load_cache(vec![alice(None)]);
    let s = open(true);
    let key = find_class(s, CKO_PRIVATE_KEY)[0];
    let f = fl();
    unsafe {
        assert_eq!((f.c_get_info.unwrap())(null_mut()), CKR_ARGUMENTS_BAD);
        assert_eq!(
            (f.c_get_slot_list.unwrap())(0, null_mut(), null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            (f.c_get_slot_info.unwrap())(0, null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            (f.c_get_token_info.unwrap())(0, null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            (f.c_get_mechanism_list.unwrap())(0, null_mut(), null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            (f.c_get_mechanism_info.unwrap())(0, CKM_ECDSA, null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            (f.c_open_session.unwrap())(0, CKF_SERIAL_SESSION, null_mut(), None, null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            (f.c_get_session_info.unwrap())(s, null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            (f.c_get_attribute_value.unwrap())(s, key, null_mut(), 3),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            (f.c_get_object_size.unwrap())(s, key, null_mut()),
            CKR_ARGUMENTS_BAD
        );
        let mut t = template(&mut Vec::new());
        assert_eq!(
            (f.c_find_objects_init.unwrap())(s, t.as_mut_ptr(), 0),
            CKR_OK
        );
        assert_eq!(
            (f.c_find_objects.unwrap())(s, null_mut(), 1, null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!((f.c_find_objects_final.unwrap())(s), CKR_OK);
        assert_eq!(
            (f.c_sign_init.unwrap())(s, null_mut(), key),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(sign_init(s, key), CKR_OK);
        assert_eq!(
            (f.c_sign.unwrap())(s, null_mut(), 32, null_mut(), null_mut()),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(
            (f.c_create_object.unwrap())(s, null_mut(), 1, null_mut()),
            CKR_ARGUMENTS_BAD
        );
    }
}

#[test]
fn d22_no_files_created() {
    let names = |dir: &std::path::Path| -> std::collections::BTreeSet<String> {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    let dirs = [std::env::temp_dir(), std::path::PathBuf::from("/tmp")];
    let before: Vec<_> = dirs.iter().map(|d| names(d)).collect();
    {
        let _f = Fixture::new();
        load_cache(vec![alice(Some(FIXTURE_CERT))]);
        let s = open(true);
        let all = find(s, &[]);
        for h in &all {
            let _ = attr(s, *h, CKA_VALUE);
        }
        assert_eq!(sign_init(s, all[0]), CKR_OK);
        let _ = sign(s, &[0u8; 32]); // fails: nobody listens
        let _ = create(s, &cert_template(FIXTURE_CERT));
    }
    for (dir, old) in dirs.iter().zip(before) {
        let new: Vec<_> = names(dir)
            .difference(&old)
            .filter(|n| n.contains("pkcs11") || n.starts_with("km") || n.starts_with("iz"))
            .cloned()
            .collect();
        assert!(
            new.is_empty(),
            "files created in {}: {:?}",
            dir.display(),
            new
        );
    }
}

#[test]
fn d22_huge_template_value_len_is_arguments_bad() {
    use crate::find::MAX_ATTR_LEN;
    let _f = Fixture::new();
    load_cache(vec![alice(None)]);
    let s = open(true);
    let before = connect_attempts();

    // A 1-byte buffer that claims CK_UNAVAILABLE_INFORMATION bytes. Reading it
    // would be UB (and in practice a crash); it must be refused unread.
    let mut one = [0x41u8; 1];
    let huge = |v: &mut [u8; 1]| CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: v.as_mut_ptr().cast(),
        value_len: CK_UNAVAILABLE_INFORMATION,
    };
    let mut t = [huge(&mut one)];
    assert_eq!(
        unsafe { (fl().c_find_objects_init.unwrap())(s, t.as_mut_ptr(), 1) },
        CKR_ARGUMENTS_BAD
    );
    // No search was started by the refused call.
    assert_eq!(find(s, &[]).len(), 2);

    // The same entry inside an otherwise valid certificate template.
    let mut good = cert_template(FIXTURE_CERT);
    let mut t = template(&mut good);
    t.push(huge(&mut one));
    let mut h = 0;
    assert_eq!(
        unsafe { (fl().c_create_object.unwrap())(s, t.as_mut_ptr(), t.len() as CK_ULONG, &mut h) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(connect_attempts(), before, "nothing was sent");

    // The limit itself: MAX_ATTR_LEN is read, one byte more is refused.
    let mut big = vec![0u8; MAX_ATTR_LEN as usize + 1];
    let mut t = [CK_ATTRIBUTE {
        attr_type: CKA_LABEL,
        p_value: big.as_mut_ptr().cast(),
        value_len: MAX_ATTR_LEN,
    }];
    assert_eq!(
        unsafe { (fl().c_find_objects_init.unwrap())(s, t.as_mut_ptr(), 1) },
        CKR_OK
    );
    assert_eq!(unsafe { (fl().c_find_objects_final.unwrap())(s) }, CKR_OK);
    t[0].value_len = MAX_ATTR_LEN + 1;
    assert_eq!(
        unsafe { (fl().c_find_objects_init.unwrap())(s, t.as_mut_ptr(), 1) },
        CKR_ARGUMENTS_BAD
    );
}
