//! Object search, attribute reads, and the refused object operations.

use crate::client::{self, RpcError};
use crate::debug_log;
use crate::guard;
use crate::objects::{get_attr, matches, parse_list, Attr};
use crate::session::{lock, with_session, FindOp};
use crate::types::*;

/// Fetch `list` (no state lock held) and store it in module `instance`.
/// On failure the cache is marked stale, so the next find tries again.
pub fn refresh(instance: u64) -> Result<(), RpcError> {
    let result = client::client().list().and_then(|v| parse_list(&v));
    if let Some(m) = lock().as_mut().filter(|m| m.instance == instance) {
        match &result {
            Ok(keys) => m.store.replace(keys.clone()),
            Err(_) => m.store.invalidate(),
        }
    }
    result.map(|_| ())
}

/// Largest template value we read (1 MiB). Larger lengths, including
/// CK_UNAVAILABLE_INFORMATION, are rejected before anything is read: no
/// attribute of ours is that big (km-x509-sa lines are capped at 1 MiB).
pub const MAX_ATTR_LEN: CK_ULONG = 1024 * 1024;

/// Copy a caller's template. `pValue == NULL` with length 0 is an empty value;
/// a length over MAX_ATTR_LEN is CKR_ARGUMENTS_BAD.
pub unsafe fn read_template(
    template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> Result<Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>, CK_RV> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if template.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    std::slice::from_raw_parts(template, count as usize)
        .iter()
        .map(|a| match (a.p_value.is_null(), a.value_len) {
            (true, 0) => Ok((a.attr_type, Vec::new())),
            (true, _) => Err(CKR_ARGUMENTS_BAD),
            (false, len) if len > MAX_ATTR_LEN => Err(CKR_ARGUMENTS_BAD),
            (false, len) => Ok((
                a.attr_type,
                std::slice::from_raw_parts(a.p_value as *const u8, len as usize).to_vec(),
            )),
        })
        .collect()
}

pub unsafe extern "C" fn c_find_objects_init(
    h: CK_SESSION_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    guard(|| {
        // 1. Validate under the lock.
        let mut prepared = None;
        let rv = with_session(h, |m, h| {
            if m.sessions[&h].find.is_some() {
                return CKR_OPERATION_ACTIVE;
            }
            match read_template(template, count) {
                Ok(t) => {
                    prepared = Some((m.instance, t, m.store.is_stale()));
                    CKR_OK
                }
                Err(rv) => rv,
            }
        });
        let Some((instance, template, stale)) = prepared else {
            return rv;
        };

        // 2. Refresh the cache if it is old (socket I/O, no lock held).
        let refresh_err = if stale { refresh(instance).err() } else { None };
        if let Some(e) = &refresh_err {
            debug_log!("list refresh failed: {:?}", e);
        }

        // 3. Re-check and start the search.
        let mut state = lock();
        let Some(m) = state.as_mut().filter(|m| m.instance == instance) else {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        };
        if refresh_err.is_some() && !m.store.has_cache() {
            return CKR_DEVICE_ERROR;
        }
        let handles = m
            .store
            .objects()
            .into_iter()
            .filter(|(_, key, class)| matches(key, *class, &template))
            .map(|(handle, _, _)| handle)
            .collect();
        match m.sessions.get_mut(&h) {
            None => CKR_SESSION_CLOSED,
            Some(s) if s.find.is_some() => CKR_OPERATION_ACTIVE,
            Some(s) => {
                s.find = Some(FindOp {
                    handles,
                    position: 0,
                });
                CKR_OK
            }
        }
    })
}

pub unsafe extern "C" fn c_find_objects(
    h: CK_SESSION_HANDLE,
    objects: CK_OBJECT_HANDLE_PTR,
    max_count: CK_ULONG,
    count: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        with_session(h, |m, h| {
            if objects.is_null() || count.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            let Some(find) = m.sessions.get_mut(&h).and_then(|s| s.find.as_mut()) else {
                return CKR_OPERATION_NOT_INITIALIZED;
            };
            let remaining = &find.handles[find.position..];
            let n = remaining.len().min(max_count as usize);
            std::ptr::copy_nonoverlapping(remaining.as_ptr(), objects, n);
            find.position += n;
            *count = n as CK_ULONG;
            CKR_OK
        })
    })
}

pub unsafe extern "C" fn c_find_objects_final(h: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| {
        with_session(h, |m, h| {
            match m.sessions.get_mut(&h).and_then(|s| s.find.take()) {
                Some(_) => CKR_OK,
                None => CKR_OPERATION_NOT_INITIALIZED,
            }
        })
    })
}

/// Two-pass read (v2.40 §5.7): every entry is processed even after an error;
/// the last error set is returned.
pub unsafe extern "C" fn c_get_attribute_value(
    h: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    guard(|| {
        with_session(h, |m, _| {
            if template.is_null() && count > 0 {
                return CKR_ARGUMENTS_BAD;
            }
            let Some((key, class)) = m.store.lookup(object) else {
                return CKR_OBJECT_HANDLE_INVALID;
            };
            if count == 0 {
                return CKR_OK;
            }
            let mut rv = CKR_OK;
            for attr in std::slice::from_raw_parts_mut(template, count as usize) {
                match get_attr(key, class, attr.attr_type) {
                    Attr::Value(bytes) => {
                        let len = bytes.len() as CK_ULONG;
                        if attr.p_value.is_null() {
                            attr.value_len = len;
                        } else if attr.value_len < len {
                            attr.value_len = CK_UNAVAILABLE_INFORMATION;
                            rv = CKR_BUFFER_TOO_SMALL;
                        } else {
                            std::ptr::copy_nonoverlapping(
                                bytes.as_ptr(),
                                attr.p_value as *mut u8,
                                bytes.len(),
                            );
                            attr.value_len = len;
                        }
                    }
                    Attr::Sensitive => {
                        attr.value_len = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_ATTRIBUTE_SENSITIVE;
                    }
                    Attr::Invalid => {
                        attr.value_len = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    }
                }
            }
            rv
        })
    })
}

pub unsafe extern "C" fn c_get_object_size(
    h: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    size: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        with_session(h, |m, _| {
            if size.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            if m.store.lookup(object).is_none() {
                return CKR_OBJECT_HANDLE_INVALID;
            }
            *size = CK_UNAVAILABLE_INFORMATION;
            CKR_OK
        })
    })
}

/// All objects have CKA_MODIFIABLE / CKA_COPYABLE / CKA_DESTROYABLE = false.
fn refuse(h: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> CK_RV {
    with_session(h, |m, _| match m.store.lookup(object) {
        Some(_) => CKR_ACTION_PROHIBITED,
        None => CKR_OBJECT_HANDLE_INVALID,
    })
}

pub unsafe extern "C" fn c_copy_object(
    h: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    _template: *mut CK_ATTRIBUTE,
    _count: CK_ULONG,
    _new_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    guard(|| refuse(h, object))
}

pub unsafe extern "C" fn c_set_attribute_value(
    h: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    _template: *mut CK_ATTRIBUTE,
    _count: CK_ULONG,
) -> CK_RV {
    guard(|| refuse(h, object))
}

pub unsafe extern "C" fn c_destroy_object(h: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> CK_RV {
    guard(|| refuse(h, object))
}
