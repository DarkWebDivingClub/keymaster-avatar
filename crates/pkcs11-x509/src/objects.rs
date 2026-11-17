//! The object model: km-x509-sa's `list` result as PKCS#11 objects.
//!
//! Each key gives a private key and a public key object; a key with a `cert`
//! also gives a certificate object. All three share `CKA_ID` = the key's `id`
//! (SHA-256 of its DER SubjectPublicKeyInfo, as KeyMaster delivers it).
//!
//! `get_attr` is the only attribute getter. `C_GetAttributeValue` and the
//! `C_FindObjectsInit` filter both use it, so search and read cannot disagree.

use crate::client::RpcError;
use crate::debug_log;
use crate::types::*;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use x509_cert::der::{Decode, Encode};

/// DER OID prime256v1 (1.2.840.10045.3.1.7), the value of CKA_EC_PARAMS.
pub const P256_EC_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// A cached list older than this is refreshed by C_FindObjectsInit.
const MAX_CACHE_AGE: Duration = Duration::from_secs(5);
static MAX_CACHE_AGE_MS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub fn set_max_cache_age_for_tests(ms: u64) {
    MAX_CACHE_AGE_MS.store(ms, Ordering::Relaxed);
}

fn max_cache_age() -> Duration {
    match MAX_CACHE_AGE_MS.load(Ordering::Relaxed) {
        0 => MAX_CACHE_AGE,
        ms => Duration::from_millis(ms),
    }
}

/// Certificate fields, all as DER taken from the parsed certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct CertInfo {
    pub der: Vec<u8>,
    pub subject: Vec<u8>,
    pub issuer: Vec<u8>,
    /// The whole DER INTEGER (tag, length, value), as CKA_SERIAL_NUMBER requires.
    pub serial: Vec<u8>,
}

/// Parse a certificate's DER. `None` if it is not a valid DER certificate.
pub fn parse_cert(der: &[u8]) -> Option<CertInfo> {
    let cert = x509_cert::Certificate::from_der(der).ok()?;
    let tbs = &cert.tbs_certificate;
    Some(CertInfo {
        der: der.to_vec(),
        subject: tbs.subject.to_der().ok()?,
        issuer: tbs.issuer.to_der().ok()?,
        serial: tbs.serial_number.to_der().ok()?,
    })
}

/// One key from `list`.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyEntry {
    pub id: [u8; 32],
    pub label: String,
    pub path: String,
    /// 65-byte SEC1 uncompressed P-256 point.
    pub point: [u8; 65],
    pub cert: Option<CertInfo>,
}

fn b64_field(entry: &Value, key: &str) -> Option<Vec<u8>> {
    BASE64.decode(entry.get(key)?.as_str()?).ok()
}

fn parse_entry(entry: &Value) -> Option<KeyEntry> {
    let label = entry
        .get("label")?
        .as_str()
        .filter(|s| !s.is_empty())?
        .to_string();
    let path = entry
        .get("path")?
        .as_str()
        .filter(|s| !s.is_empty())?
        .to_string();
    let point: [u8; 65] = b64_field(entry, "public_key")?.try_into().ok()?;
    if point[0] != 0x04 {
        return None;
    }
    let id: [u8; 32] = b64_field(entry, "id")?.try_into().ok()?;
    let cert = match entry.get("cert") {
        None | Some(Value::Null) => None,
        Some(_) => {
            let parsed = b64_field(entry, "cert").and_then(|der| parse_cert(&der));
            if parsed.is_none() {
                debug_log!("a listed certificate is not valid DER; showing the key without it");
            }
            parsed
        }
    };
    Some(KeyEntry {
        id,
        label,
        path,
        point,
        cert,
    })
}

/// Parse a `list` result `{"keys": [...]}`. Malformed entries and duplicate
/// ids are skipped; a result without a `keys` array is an error.
pub fn parse_list(result: &Value) -> Result<Vec<KeyEntry>, RpcError> {
    let keys = result
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::BadResult("list result has no 'keys' array".into()))?;
    let mut out: Vec<KeyEntry> = Vec::new();
    for entry in keys {
        match parse_entry(entry) {
            Some(k) if out.iter().all(|o| o.id != k.id) => out.push(k),
            Some(_) => debug_log!("skipping a key with a duplicate id"),
            None => debug_log!("skipping a malformed key entry"),
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Private,
    Public,
    Cert,
}

/// The result of reading one attribute of one object.
#[derive(Debug, PartialEq)]
pub enum Attr<'a> {
    Value(Cow<'a, [u8]>),
    /// The object has the attribute but will never reveal it.
    Sensitive,
    /// The object does not have this attribute.
    Invalid,
}

fn ulong(v: CK_ULONG) -> Attr<'static> {
    Attr::Value(Cow::Owned(v.to_ne_bytes().to_vec()))
}

fn bool_attr(v: bool) -> Attr<'static> {
    Attr::Value(Cow::Owned(vec![if v { CK_TRUE } else { CK_FALSE }]))
}

/// The one attribute getter (attribute table in doc/x509/pkcs11-module.md).
pub fn get_attr(key: &KeyEntry, class: Class, attr: CK_ATTRIBUTE_TYPE) -> Attr<'_> {
    use Class::*;
    match (class, attr) {
        (Private, CKA_CLASS) => ulong(CKO_PRIVATE_KEY),
        (Public, CKA_CLASS) => ulong(CKO_PUBLIC_KEY),
        (Cert, CKA_CLASS) => ulong(CKO_CERTIFICATE),
        (_, CKA_TOKEN) => bool_attr(true),
        (_, CKA_PRIVATE) => bool_attr(false),
        (_, CKA_ID) => Attr::Value(Cow::Borrowed(&key.id)),
        (_, CKA_LABEL) => Attr::Value(Cow::Borrowed(key.label.as_bytes())),
        (_, CKA_MODIFIABLE | CKA_COPYABLE | CKA_DESTROYABLE) => bool_attr(false),

        (Private | Public, CKA_KEY_TYPE) => ulong(CKK_EC),
        (Private | Public, CKA_EC_PARAMS) => Attr::Value(Cow::Borrowed(P256_EC_PARAMS)),

        (Private, CKA_SIGN) => bool_attr(true),
        (Private, CKA_SENSITIVE | CKA_ALWAYS_SENSITIVE | CKA_NEVER_EXTRACTABLE) => bool_attr(true),
        (
            Private,
            CKA_EXTRACTABLE | CKA_DECRYPT | CKA_DERIVE | CKA_UNWRAP | CKA_ALWAYS_AUTHENTICATE,
        ) => bool_attr(false),
        (Private, CKA_VALUE) => Attr::Sensitive,

        (Public, CKA_VERIFY) => bool_attr(true),
        (Public, CKA_EC_POINT) => {
            // DER OCTET STRING wrapping the 65-byte point: 04 41 04 X Y
            let mut der = vec![0x04, 0x41];
            der.extend_from_slice(&key.point);
            Attr::Value(Cow::Owned(der))
        }

        (Cert, _) => match &key.cert {
            None => Attr::Invalid,
            Some(cert) => match attr {
                CKA_CERTIFICATE_TYPE => ulong(CKC_X_509),
                CKA_VALUE => Attr::Value(Cow::Borrowed(&cert.der)),
                CKA_SUBJECT => Attr::Value(Cow::Borrowed(&cert.subject)),
                CKA_ISSUER => Attr::Value(Cow::Borrowed(&cert.issuer)),
                CKA_SERIAL_NUMBER => Attr::Value(Cow::Borrowed(&cert.serial)),
                CKA_CERTIFICATE_CATEGORY => ulong(CK_CERTIFICATE_CATEGORY_TOKEN_USER),
                CKA_TRUSTED => bool_attr(false),
                _ => Attr::Invalid,
            },
        },

        _ => Attr::Invalid,
    }
}

/// True if every template attribute reads as a value equal byte for byte.
/// An attribute the object lacks, or a sensitive one, never matches.
pub fn matches(key: &KeyEntry, class: Class, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
    template
        .iter()
        .all(|(t, want)| match get_attr(key, class, *t) {
            Attr::Value(have) => have.as_ref() == want.as_slice(),
            Attr::Sensitive | Attr::Invalid => false,
        })
}

/// The cached list plus the handle table. Handles are allocated per
/// (CKA_ID, class) the first time an object is seen and are never reused.
#[derive(Default)]
pub struct Store {
    keys: Vec<KeyEntry>,
    fetched: Option<Instant>,
    force_refresh: bool,
    handles: HashMap<([u8; 32], Class), CK_OBJECT_HANDLE>,
    by_handle: HashMap<CK_OBJECT_HANDLE, ([u8; 32], Class)>,
    next_handle: CK_OBJECT_HANDLE,
}

impl Store {
    pub fn has_cache(&self) -> bool {
        self.fetched.is_some()
    }

    pub fn is_stale(&self) -> bool {
        self.force_refresh || self.fetched.is_none_or(|t| t.elapsed() > max_cache_age())
    }

    /// Mark the cache stale so the next C_FindObjectsInit refreshes it.
    pub fn invalidate(&mut self) {
        self.force_refresh = true;
    }

    /// Replace the cached list and give every object present a handle.
    pub fn replace(&mut self, keys: Vec<KeyEntry>) {
        self.keys = keys;
        self.fetched = Some(Instant::now());
        self.force_refresh = false;
        let objects: Vec<([u8; 32], Class)> = self.objects_unhandled().collect();
        for obj in objects {
            if !self.handles.contains_key(&obj) {
                self.next_handle += 1;
                self.handles.insert(obj, self.next_handle);
                self.by_handle.insert(self.next_handle, obj);
            }
        }
    }

    fn objects_unhandled(&self) -> impl Iterator<Item = ([u8; 32], Class)> + '_ {
        self.keys.iter().flat_map(|k| {
            let cert = k.cert.as_ref().map(|_| (k.id, Class::Cert));
            [(k.id, Class::Private), (k.id, Class::Public)]
                .into_iter()
                .chain(cert)
        })
    }

    /// All current objects as (handle, key, class), in list order.
    pub fn objects(&self) -> Vec<(CK_OBJECT_HANDLE, &KeyEntry, Class)> {
        self.keys
            .iter()
            .flat_map(|k| {
                let classes: &[Class] = if k.cert.is_some() {
                    &[Class::Private, Class::Public, Class::Cert]
                } else {
                    &[Class::Private, Class::Public]
                };
                classes.iter().map(move |c| (k, *c))
            })
            .filter_map(|(k, c)| self.handles.get(&(k.id, c)).map(|h| (*h, k, c)))
            .collect()
    }

    /// The object behind a handle, if it is still in the list.
    pub fn lookup(&self, handle: CK_OBJECT_HANDLE) -> Option<(&KeyEntry, Class)> {
        let (id, class) = self.by_handle.get(&handle)?;
        let key = self.keys.iter().find(|k| &k.id == id)?;
        if *class == Class::Cert && key.cert.is_none() {
            return None;
        }
        Some((key, *class))
    }

    pub fn handle_of(&self, id: &[u8; 32], class: Class) -> Option<CK_OBJECT_HANDLE> {
        self.handles.get(&(*id, class)).copied()
    }

    pub fn keys(&self) -> &[KeyEntry] {
        &self.keys
    }
}
