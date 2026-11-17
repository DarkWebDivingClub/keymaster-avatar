//! C_CreateObject for X.509 certificates only, via km-x509-sa `import`.
//!
//! KeyMaster decides whether the certificate belongs to one of its keys; the
//! module only checks the template and that the DER parses. A supplied
//! CKA_ID, CKA_LABEL or CKA_PRIVATE is ignored: KeyMaster's id and label win.
//! Any other object class is refused (key creation is not offered).

use crate::client::{self, map_error};
use crate::debug_log;
use crate::find::{read_template, refresh};
use crate::guard;
use crate::objects::{parse_cert, Class};
use crate::session::{lock, with_session};
use crate::types::*;

type Template = [(CK_ATTRIBUTE_TYPE, Vec<u8>)];

fn find_attr(t: &Template, attr: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
    t.iter()
        .find(|(a, _)| *a == attr)
        .map(|(_, v)| v.as_slice())
}

fn as_ulong(v: &[u8]) -> Option<CK_ULONG> {
    Some(CK_ULONG::from_ne_bytes(v.try_into().ok()?))
}

fn as_bool(v: &[u8]) -> Option<bool> {
    match v {
        [b] => Some(*b != CK_FALSE),
        _ => None,
    }
}

/// The template rules, in order. Returns the certificate DER.
fn check_template(t: &Template) -> Result<Vec<u8>, CK_RV> {
    let class = find_attr(t, CKA_CLASS).ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let class = as_ulong(class).ok_or(CKR_ATTRIBUTE_VALUE_INVALID)?;
    if class != CKO_CERTIFICATE {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    let cert_type = find_attr(t, CKA_CERTIFICATE_TYPE).ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    if as_ulong(cert_type) != Some(CKC_X_509) {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let der = find_attr(t, CKA_VALUE).ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    if let Some(token) = find_attr(t, CKA_TOKEN) {
        match as_bool(token) {
            None => return Err(CKR_ATTRIBUTE_VALUE_INVALID),
            Some(false) => return Err(CKR_TEMPLATE_INCONSISTENT), // only token objects exist
            Some(true) => {}
        }
    }
    if let Some(trusted) = find_attr(t, CKA_TRUSTED) {
        match as_bool(trusted) {
            None => return Err(CKR_ATTRIBUTE_VALUE_INVALID),
            Some(true) => return Err(CKR_ATTRIBUTE_READ_ONLY), // only an SO may set it
            Some(false) => {}
        }
    }
    Ok(der.to_vec())
}

/// Parse the DER; supplied subject/issuer/serial must match it.
fn check_cert(t: &Template, der: &[u8]) -> Result<(), CK_RV> {
    let cert = parse_cert(der).ok_or(CKR_ATTRIBUTE_VALUE_INVALID)?;
    for (attr, have) in [
        (CKA_SUBJECT, &cert.subject),
        (CKA_ISSUER, &cert.issuer),
        (CKA_SERIAL_NUMBER, &cert.serial),
    ] {
        if find_attr(t, attr).is_some_and(|want| want != have.as_slice()) {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
    }
    Ok(())
}

pub unsafe extern "C" fn c_create_object(
    h: CK_SESSION_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
    ph_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    guard(|| {
        // 1. Validate under the lock.
        let mut job = None;
        let rv = with_session(h, |m, h| {
            if template.is_null() || ph_object.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            let t = match read_template(template, count) {
                Ok(t) => t,
                Err(rv) => return rv,
            };
            let der = match check_template(&t) {
                Ok(der) => der,
                Err(rv) => return rv,
            };
            if !m.sessions[&h].rw {
                return CKR_SESSION_READ_ONLY;
            }
            if let Err(rv) = check_cert(&t, &der) {
                return rv;
            }
            job = Some((m.instance, der));
            CKR_OK
        });
        let Some((instance, der)) = job else {
            return rv;
        };

        // 2. Import (no state lock held).
        let verdict = match client::client().import(&der) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        match verdict.as_str() {
            "ACCEPTED" => {}
            "MALFORMED" | "KEY_MISMATCH" | "EKU_MISMATCH" => {
                debug_log!("import refused: {}", verdict);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            _ => return CKR_FUNCTION_FAILED,
        }

        // 3. Refresh so the certificate shows up, and return its handle. The
        //    certificate is stored even if this fails; the next find shows it.
        if refresh(instance).is_err() {
            return CKR_DEVICE_ERROR;
        }
        let state = lock();
        let Some(m) = state.as_ref().filter(|m| m.instance == instance) else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if !m.sessions.contains_key(&h) {
            return CKR_SESSION_CLOSED;
        }
        let handle = m
            .store
            .keys()
            .iter()
            .find(|k| k.cert.as_ref().is_some_and(|c| c.der == der))
            .and_then(|k| m.store.handle_of(&k.id, Class::Cert));
        match handle {
            Some(handle) => {
                *ph_object = handle;
                CKR_OK
            }
            None => CKR_FUNCTION_FAILED,
        }
    })
}
