//! Allowlist + parameter validation for client requests.
//!
//! The avatar forwards whatever method a bound connection sends, so this
//! module is the real filter for the x509 service: only `list`, `sign` and
//! `import` with well-formed params are ever forwarded. Anything else is
//! answered locally with a JSON-RPC error and nothing reaches the avatar.

use avatar_protocol::{JsonRpcError, JSONRPC_INVALID_PARAMS, JSONRPC_METHOD_NOT_FOUND};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::{json, Map, Value};

/// SHA-256 digest length: `sign` only accepts a pre-computed 32-byte digest.
pub const DIGEST_LEN: usize = 32;

/// A request that passed validation and is ready to forward.
#[derive(Debug, PartialEq)]
pub struct Forward {
    /// Method name on the avatar side, e.g. "x509.sign".
    pub avatar_method: &'static str,
    /// Params rebuilt from validated fields only.
    pub params: Value,
    /// Total decoded byte length (digest or DER), for logging sizes only.
    pub payload_len: usize,
}

fn invalid_params(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: JSONRPC_INVALID_PARAMS,
        message: message.into(),
        data: None,
    }
}

fn method_not_found() -> JsonRpcError {
    JsonRpcError {
        code: JSONRPC_METHOD_NOT_FOUND,
        message: "method not found".to_string(),
        data: None,
    }
}

/// Params must be a JSON object containing exactly `keys` (no more, no fewer).
fn exact_object<'a>(params: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, JsonRpcError> {
    let obj = params
        .as_object()
        .ok_or_else(|| invalid_params("params must be an object"))?;
    if obj.len() != keys.len() || !keys.iter().all(|k| obj.contains_key(*k)) {
        return Err(invalid_params(format!("params must have exactly: {}", keys.join(", "))));
    }
    Ok(obj)
}

/// Read a field as a base64 string and decode it. Returns (original string, decoded length).
fn base64_field<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<(&'a str, usize), JsonRpcError> {
    let s = obj
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params(format!("'{}' must be a string", key)))?;
    let bytes = BASE64
        .decode(s)
        .map_err(|_| invalid_params(format!("'{}' is not valid base64", key)))?;
    Ok((s, bytes.len()))
}

/// Check a client request. `params` is `Value::Null` when absent.
pub fn validate(method: &str, params: &Value) -> Result<Forward, JsonRpcError> {
    match method {
        "list" => {
            // No params: absent, null or an empty object.
            let empty = params.is_null() || params.as_object().is_some_and(|o| o.is_empty());
            if !empty {
                return Err(invalid_params("list takes no params"));
            }
            Ok(Forward {
                avatar_method: "x509.list",
                params: json!({}),
                payload_len: 0,
            })
        }
        "sign" => {
            // Exactly {path, digest}; no "id" alternative to path.
            let obj = exact_object(params, &["path", "digest"])?;
            let path = obj
                .get("path")
                .and_then(|v| v.as_str())
                .filter(|p| !p.is_empty())
                .ok_or_else(|| invalid_params("'path' must be a non-empty string"))?;
            let (digest, len) = base64_field(obj, "digest")?;
            if len != DIGEST_LEN {
                return Err(invalid_params(format!(
                    "'digest' must decode to exactly {} bytes",
                    DIGEST_LEN
                )));
            }
            Ok(Forward {
                avatar_method: "x509.sign",
                params: json!({ "path": path, "digest": digest }),
                payload_len: len,
            })
        }
        "import" => {
            let obj = exact_object(params, &["der"])?;
            let (der, len) = base64_field(obj, "der")?;
            if len == 0 {
                return Err(invalid_params("'der' must not be empty"));
            }
            Ok(Forward {
                avatar_method: "x509.import",
                params: json!({ "der": der }),
                payload_len: len,
            })
        }
        _ => Err(method_not_found()),
    }
}
