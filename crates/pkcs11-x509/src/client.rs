//! Client for km-x509-sa's socket: newline-delimited JSON-RPC 2.0.
//!
//! One persistent connection, opened lazily and guarded by its own mutex
//! (km-x509-sa answers one request at a time anyway). The connection is
//! dropped after any timeout, read error, EOF, unparsable or oversized line,
//! or reply id mismatch, so a late reply can never be paired with the next
//! request.
//!
//! Retry rule: a request is re-sent on a fresh connection only if not one
//! byte of it was written. Before each write a non-blocking `peek` checks the
//! connection; EOF or leftover bytes mean "stale", so it is replaced before
//! anything is sent. `list` (idempotent) may also be retried once after a
//! broken connection, but not after a timeout.

use crate::debug_log;
use crate::types::*;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

/// km-x509-sa answers within about 70 s (35 s in its queue + 35 s round trip).
pub const READ_TIMEOUT: Duration = Duration::from_secs(75);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// km-x509-sa's own line limit is 1 MiB; one more byte proves a line is too long.
const MAX_LINE: u64 = 1024 * 1024 + 1;

/// Read-timeout override in milliseconds (0 = use READ_TIMEOUT). Tests only.
static READ_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub fn set_read_timeout_for_tests(ms: u64) {
    READ_TIMEOUT_MS.store(ms, Ordering::Relaxed);
}

/// Connection attempts so far; tests use it to prove a function did no I/O.
#[cfg(test)]
pub static CONNECT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

fn read_timeout() -> Duration {
    match READ_TIMEOUT_MS.load(Ordering::Relaxed) {
        0 => READ_TIMEOUT,
        ms => Duration::from_millis(ms),
    }
}

/// Why a request produced no usable result.
#[derive(Debug, Clone, PartialEq)]
pub enum RpcError {
    /// Connect, I/O, timeout, EOF, unparsable line or id mismatch.
    Transport(String),
    /// A JSON-RPC error reply.
    Rpc { code: i64, message: String },
    /// A result that does not have the expected shape.
    BadResult(String),
}

/// The fixed mapping from km-x509-sa replies to CK_RV (doc/x509/pkcs11-module.md).
pub fn map_error(err: &RpcError) -> CK_RV {
    match err {
        RpcError::Transport(_) => CKR_DEVICE_ERROR,
        RpcError::BadResult(_) => CKR_FUNCTION_FAILED,
        RpcError::Rpc { code, message } => match (*code, message.as_str()) {
            (-32603, "avatar unavailable") => CKR_DEVICE_ERROR,
            (-32603, "request denied by user") => CKR_FUNCTION_REJECTED,
            (-32603, "unknown-path") => CKR_KEY_HANDLE_INVALID,
            (-32603, "invalid-digest") => CKR_DATA_LEN_RANGE,
            (-32603, "unsupported") => CKR_FUNCTION_NOT_SUPPORTED,
            // -32001 no channel, -32002 send failed, -32003 timeout
            (-32003..=-32001, _) => CKR_DEVICE_ERROR,
            (-32700 | -32600 | -32601 | -32602, _) => CKR_GENERAL_ERROR,
            _ => CKR_FUNCTION_FAILED,
        },
    }
}

/// `X509_SA_SOCK`, else `$XDG_RUNTIME_DIR/keymaster-x509-sa.sock`, else
/// `/run/user/<uid>/keymaster-x509-sa.sock`. Empty values count as unset.
pub fn resolve_socket_path(
    x509_sa_sock: Option<std::ffi::OsString>,
    xdg_runtime_dir: Option<std::ffi::OsString>,
    uid: u32,
) -> PathBuf {
    if let Some(p) = x509_sa_sock.filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    if let Some(d) = xdg_runtime_dir.filter(|v| !v.is_empty()) {
        return PathBuf::from(d).join("keymaster-x509-sa.sock");
    }
    PathBuf::from(format!("/run/user/{}/keymaster-x509-sa.sock", uid))
}

fn socket_path() -> PathBuf {
    resolve_socket_path(
        std::env::var_os("X509_SA_SOCK"),
        std::env::var_os("XDG_RUNTIME_DIR"),
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() },
    )
}

struct Conn {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Conn {
    fn open() -> Result<Conn, RpcError> {
        #[cfg(test)]
        CONNECT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        let path = socket_path();
        let stream = UnixStream::connect(&path)
            .map_err(|e| RpcError::Transport(format!("connect: {}", e)))?;
        stream
            .set_read_timeout(Some(read_timeout()))
            .and_then(|_| stream.set_write_timeout(Some(WRITE_TIMEOUT)))
            .map_err(|e| RpcError::Transport(format!("set timeouts: {}", e)))?;
        let reader = stream
            .try_clone()
            .map_err(|e| RpcError::Transport(format!("clone: {}", e)))?;
        debug_log!("connected to km-x509-sa");
        Ok(Conn {
            writer: stream,
            reader: BufReader::new(reader),
        })
    }

    /// True if the peer is still there and nothing unread is waiting.
    fn is_alive(&self) -> bool {
        use std::os::fd::AsRawFd;
        if !self.reader.buffer().is_empty() {
            return false;
        }
        let mut byte = [0u8; 1];
        // SAFETY: a valid fd and a 1-byte buffer we own; MSG_PEEK leaves the data queued.
        let n = unsafe {
            libc::recv(
                self.writer.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        // 0 = EOF, > 0 = unsolicited bytes (stale): both mean "replace it".
        n < 0 && std::io::Error::last_os_error().kind() == ErrorKind::WouldBlock
    }

    /// Write all of `data`; on failure report how many bytes went out.
    fn write_tracked(&mut self, data: &[u8]) -> Result<(), (usize, std::io::Error)> {
        let mut written = 0;
        while written < data.len() {
            match self.writer.write(&data[written..]) {
                Ok(0) => return Err((written, ErrorKind::WriteZero.into())),
                Ok(n) => written += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err((written, e)),
            }
        }
        self.writer.flush().map_err(|e| (written, e))
    }

    /// Read one reply line and return its `result`, or the error it carries.
    fn read_reply(&mut self, id: u64) -> Result<Result<Value, RpcError>, RpcError> {
        let mut line = Vec::new();
        let n = (&mut self.reader)
            .take(MAX_LINE)
            .read_until(b'\n', &mut line)
            .map_err(|e| match e.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                    RpcError::Transport("timeout".into())
                }
                _ => RpcError::Transport(format!("read: {}", e)),
            })?;
        if n == 0 {
            return Err(RpcError::Transport("connection closed".into()));
        }
        if line.last() != Some(&b'\n') {
            return Err(RpcError::Transport(
                "reply line too long or truncated".into(),
            ));
        }
        let reply: Value = serde_json::from_slice(&line)
            .map_err(|_| RpcError::Transport("unparsable reply".into()))?;
        if reply.get("id") != Some(&json!(id)) {
            return Err(RpcError::Transport("reply id mismatch".into()));
        }
        if let Some(err) = reply.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Ok(Err(RpcError::Rpc { code, message }));
        }
        match reply.get("result") {
            Some(result) => Ok(Ok(result.clone())),
            None => Ok(Err(RpcError::BadResult(
                "reply has neither result nor error".into(),
            ))),
        }
    }
}

pub struct Client {
    conn: Option<Conn>,
    next_id: u64,
}

static CLIENT: Mutex<Client> = Mutex::new(Client {
    conn: None,
    next_id: 1,
});

/// The shared client. A poisoned lock is recovered: the connection is dropped.
pub fn client() -> MutexGuard<'static, Client> {
    CLIENT.lock().unwrap_or_else(|poisoned| {
        let mut guard = poisoned.into_inner();
        guard.conn = None;
        guard
    })
}

/// Drop the connection if no request is using it (C_Finalize must not block
/// behind a 75 s sign; an in-flight request still ends correctly paired).
pub fn drop_connection_if_idle() {
    if let Ok(mut c) = CLIENT.try_lock() {
        c.conn = None;
    }
}

impl Client {
    #[cfg(test)]
    pub fn new_for_tests() -> Client {
        Client {
            conn: None,
            next_id: 1,
        }
    }

    /// Send one request and wait for its reply. See the module doc for the
    /// connection and retry rules.
    pub fn request(
        &mut self,
        method: &str,
        params: Value,
        idempotent: bool,
    ) -> Result<Value, RpcError> {
        let mut retried = false;
        loop {
            if !self.conn.as_ref().is_some_and(Conn::is_alive) {
                self.conn = Some(Conn::open()?);
            }
            let id = self.next_id;
            self.next_id += 1;
            let mut data = serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": id, "method": method, "params": params,
            }))
            .map_err(|e| RpcError::Transport(format!("serialize: {}", e)))?;
            data.push(b'\n');

            let conn = self.conn.as_mut().expect("connected above");
            if let Err((written, e)) = conn.write_tracked(&data) {
                self.conn = None;
                if written == 0 && !retried {
                    retried = true;
                    debug_log!(
                        "{}: write failed before any byte was sent, reconnecting",
                        method
                    );
                    continue;
                }
                return Err(RpcError::Transport(format!("write: {}", e)));
            }

            match conn.read_reply(id) {
                Ok(reply) => return reply,
                Err(e) => {
                    self.conn = None;
                    let timed_out = matches!(&e, RpcError::Transport(m) if m == "timeout");
                    if idempotent && !retried && !timed_out {
                        retried = true;
                        debug_log!("{}: connection broke, retrying once", method);
                        continue;
                    }
                    debug_log!("{}: {:?}, connection dropped", method, e);
                    return Err(e);
                }
            }
        }
    }

    /// `list` → the raw `result` value; parsed by objects::parse_list.
    pub fn list(&mut self) -> Result<Value, RpcError> {
        self.request("list", json!({}), true)
    }

    /// `sign {path, digest}` → raw 64-byte r‖s.
    pub fn sign(&mut self, path: &str, digest: &[u8; 32]) -> Result<[u8; 64], RpcError> {
        let result = self.request(
            "sign",
            json!({"path": path, "digest": BASE64.encode(digest)}),
            false,
        )?;
        let sig = result
            .get("signature")
            .and_then(Value::as_str)
            .and_then(|s| BASE64.decode(s).ok())
            .ok_or_else(|| RpcError::BadResult("missing or invalid 'signature'".into()))?;
        sig.try_into().map_err(|v: Vec<u8>| {
            RpcError::BadResult(format!("signature is {} bytes, not 64", v.len()))
        })
    }

    /// `import {der}` → the verdict string (ACCEPTED, MALFORMED, …).
    pub fn import(&mut self, der: &[u8]) -> Result<String, RpcError> {
        let result = self.request("import", json!({"der": BASE64.encode(der)}), false)?;
        result
            .get("verdict")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| RpcError::BadResult("missing 'verdict'".into()))
    }
}
