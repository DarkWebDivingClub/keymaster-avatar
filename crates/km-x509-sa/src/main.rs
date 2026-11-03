//! km-x509-sa — X.509 Service Avatar.
//!
//! Listens on a client socket (default `$XDG_RUNTIME_DIR/keymaster-x509-sa.sock`,
//! mode 0600) for newline-delimited JSON-RPC 2.0 requests `list`, `sign` and
//! `import`, validates them, and forwards them to the avatar local API as
//! `x509.list` / `x509.sign` / `x509.import` over a single connection bound
//! with `connect {type: "x509"}`.
//!
//! Structure (copied from km-nostr-sa):
//!   client handlers ──mpsc──▶ one bridge task ──▶ avatar socket
//! The bridge handles one request at a time and gives each an internal id,
//! so clients' own ids never reach the avatar and can't collide.
//!
//! Every request gets exactly one reply: either the avatar's answer or
//! JSON-RPC -32603 "avatar unavailable". Nothing waits forever.

mod validate;

#[cfg(test)]
mod tests;

use anyhow::{bail, Context, Result};
use avatar_protocol::{
    read_line_message, write_line_message, JsonRpcRequest, JsonRpcResponse, JSONRPC_INTERNAL_ERROR,
    JSONRPC_INVALID_REQUEST, JSONRPC_PARSE_ERROR,
};
use clap::Parser;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// Max time a request may wait in the queue, and separately the max time
/// for one avatar round-trip. Just above the avatar's own 30 s Nostr
/// timeout, so the avatar's `-32003 timeout` normally arrives first.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);

/// Max time to wait for the avatar's answer to our `connect`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Error message for every "couldn't get an answer from the avatar" case.
const UNAVAILABLE: &str = "avatar unavailable";

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(2); // 1 is reserved for connect

fn next_request_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Parser, Debug)]
#[command(
    name = "km-x509-sa",
    version,
    about = "X.509 Service Avatar - JSON-RPC (list/sign/import) to Avatar local API bridge"
)]
struct Cli {
    /// Avatar local API socket path
    #[arg(long, default_value = "/tmp/keymaster-avatar.sock")]
    avatar_socket: PathBuf,

    /// Client listen socket path [default: $XDG_RUNTIME_DIR/keymaster-x509-sa.sock]
    #[arg(long)]
    listen_socket: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// The -32603 "avatar unavailable" reply, carrying the client's own id.
fn unavailable(client_id: Value) -> JsonRpcResponse {
    JsonRpcResponse::error(client_id, JSONRPC_INTERNAL_ERROR, UNAVAILABLE)
}

/// Pick the client socket path: the CLI flag wins, else $XDG_RUNTIME_DIR.
/// No /tmp fallback — a world-readable directory is the wrong place for it.
fn resolve_listen_socket(flag: Option<PathBuf>, xdg_runtime_dir: Option<PathBuf>) -> Result<PathBuf> {
    match (flag, xdg_runtime_dir) {
        (Some(path), _) => Ok(path),
        (None, Some(dir)) if !dir.as_os_str().is_empty() => Ok(dir.join("keymaster-x509-sa.sock")),
        _ => bail!("set XDG_RUNTIME_DIR or pass --listen-socket"),
    }
}

/// Bind the client socket. A stale file at the path is removed first
/// (same as km-nostr-sa), then the socket is restricted to the owner (0600).
fn bind_client_socket(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("removing stale socket {}", path.display()))?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding {}", path.display()))?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(listener)
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// A validated request handed from a client handler to the bridge.
struct ClientRequest {
    avatar_method: &'static str,
    params: Value,
    client_id: Value,
    /// When the request was queued, so stale requests can be dropped.
    enqueued: Instant,
    reply: oneshot::Sender<JsonRpcResponse>,
}

async fn accept_loop(listener: UnixListener, tx: mpsc::Sender<ClientRequest>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                debug!("Client connected");
                tokio::spawn(handle_client(stream, tx.clone()));
            }
            Err(e) => error!("Accept failed: {}", e),
        }
    }
}

/// Serve one client connection: read requests, validate, hand to the bridge,
/// write the reply. Requests on one connection are answered in order.
async fn handle_client(stream: UnixStream, tx: mpsc::Sender<ClientRequest>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    loop {
        let msg: Value = match read_line_message(&mut reader).await {
            Ok(msg) => msg,
            Err(e) if e.downcast_ref::<serde_json::Error>().is_some() => {
                // Bad JSON on this line: answer and keep the connection.
                let resp = JsonRpcResponse::error(Value::Null, JSONRPC_PARSE_ERROR, "parse error");
                if write_line_message(&mut writer, &resp).await.is_err() {
                    return;
                }
                continue;
            }
            Err(e) => {
                debug!("Client disconnected: {}", e);
                return;
            }
        };

        let client_id = msg.get("id").cloned().unwrap_or(Value::Null);
        let resp = match msg.get("method").and_then(|m| m.as_str()) {
            None => JsonRpcResponse::error(client_id, JSONRPC_INVALID_REQUEST, "invalid request"),
            Some(method) => {
                let params = msg.get("params").cloned().unwrap_or(Value::Null);
                process(method, &params, client_id, &tx).await
            }
        };

        if write_line_message(&mut writer, &resp).await.is_err() {
            return;
        }
    }
}

/// Validate one request and, if valid, get the avatar's answer via the bridge.
async fn process(
    method: &str,
    params: &Value,
    client_id: Value,
    tx: &mpsc::Sender<ClientRequest>,
) -> JsonRpcResponse {
    let fwd = match validate::validate(method, params) {
        Ok(fwd) => fwd,
        Err(err) => {
            // Rejected locally: nothing is forwarded.
            info!("[x509] {} rejected: {} (code {})", method, err.message, err.code);
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(err),
                id: client_id,
            };
        }
    };
    info!("[x509] {} ({} bytes)", method, fwd.payload_len);

    let (reply_tx, reply_rx) = oneshot::channel();
    let req = ClientRequest {
        avatar_method: fwd.avatar_method,
        params: fwd.params,
        client_id: client_id.clone(),
        enqueued: Instant::now(),
        reply: reply_tx,
    };
    if tx.send(req).await.is_err() {
        return unavailable(client_id);
    }
    // If the bridge ever drops the sender, the client still gets an answer.
    reply_rx.await.unwrap_or_else(|_| unavailable(client_id))
}

// ---------------------------------------------------------------------------
// Avatar side (the bridge)
// ---------------------------------------------------------------------------

/// One bound connection to the avatar local API.
struct AvatarConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

/// Connect to the avatar and bind this connection to the "x509" service.
async fn try_connect(avatar_socket: &Path) -> Result<AvatarConn> {
    let stream = UnixStream::connect(avatar_socket).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let connect_req = JsonRpcRequest::new("connect", json!({ "type": "x509" }), 1);
    write_line_message(&mut writer, &connect_req).await?;
    let resp: JsonRpcResponse = tokio::time::timeout(CONNECT_TIMEOUT, read_line_message(&mut reader))
        .await
        .context("connect handshake timed out")??;
    if let Some(err) = resp.error {
        bail!("connect rejected: {} (code {})", err.message, err.code);
    }
    Ok(AvatarConn { reader, writer })
}

/// Retry `try_connect` with exponential backoff (1 s .. 30 s) until it works.
async fn connect_with_retry(avatar_socket: &Path) -> AvatarConn {
    let mut delay = Duration::from_secs(1);
    let max_delay = Duration::from_secs(30);
    loop {
        match try_connect(avatar_socket).await {
            Ok(conn) => {
                info!("Connected to avatar, service type: x509");
                return conn;
            }
            Err(e) => {
                warn!(
                    "Avatar not available at {}: {} — retrying in {:?}",
                    avatar_socket.display(),
                    e,
                    delay
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(max_delay);
            }
        }
    }
}

/// While (re)connecting, answer every incoming request immediately with
/// "avatar unavailable" — no queueing. Returns None if all clients are gone.
async fn connect_phase(
    avatar_socket: &Path,
    rx: &mut mpsc::Receiver<ClientRequest>,
) -> Option<AvatarConn> {
    let connecting = connect_with_retry(avatar_socket);
    tokio::pin!(connecting);
    loop {
        tokio::select! {
            conn = &mut connecting => return Some(conn),
            req = rx.recv() => match req {
                Some(req) => {
                    warn!("[x509] {}: avatar not connected", req.avatar_method);
                    let _ = req.reply.send(unavailable(req.client_id));
                }
                None => return None,
            },
        }
    }
}

/// One avatar round-trip (write request, read response).
async fn send_and_receive(conn: &mut AvatarConn, req: &JsonRpcRequest) -> Result<JsonRpcResponse> {
    write_line_message(&mut conn.writer, req).await?;
    let resp: JsonRpcResponse = read_line_message(&mut conn.reader).await?;
    Ok(resp)
}

/// Why the connected phase ended.
enum ServeEnd {
    /// The avatar connection is broken or out of sync: reconnect.
    Reconnect,
    /// All clients are gone (channel closed): stop.
    Shutdown,
}

/// Forward requests one at a time over a connected avatar connection.
async fn serve(
    conn: &mut AvatarConn,
    rx: &mut mpsc::Receiver<ClientRequest>,
    request_timeout: Duration,
) -> ServeEnd {
    loop {
        // Wait for the next request, but notice if the avatar hangs up while
        // we're idle. `fill_buf` is cancel-safe; the avatar never sends
        // unsolicited data, so anything here (or EOF) means "reconnect".
        let req = tokio::select! {
            req = rx.recv() => match req {
                Some(req) => req,
                None => return ServeEnd::Shutdown,
            },
            buf = conn.reader.fill_buf() => {
                match buf {
                    Ok([]) => warn!("Avatar closed the connection"),
                    Ok(_) => warn!("Unexpected data from avatar while idle"),
                    Err(e) => warn!("Avatar connection error: {}", e),
                }
                return ServeEnd::Reconnect;
            }
        };

        // Skip requests whose client has gone, or that waited too long.
        if req.reply.is_closed() {
            debug!("[x509] {}: client gone, skipping", req.avatar_method);
            continue;
        }
        if req.enqueued.elapsed() > request_timeout {
            warn!("[x509] {}: waited too long in queue", req.avatar_method);
            let _ = req.reply.send(unavailable(req.client_id));
            continue;
        }

        // Internal id: the client's id never goes to the avatar.
        let internal_id = next_request_id();
        let rpc = JsonRpcRequest::new(req.avatar_method, req.params, internal_id);

        match tokio::time::timeout(request_timeout, send_and_receive(conn, &rpc)).await {
            Ok(Ok(resp)) if resp.id == json!(internal_id) => {
                match &resp.error {
                    None => info!("[x509] {}: ok", req.avatar_method),
                    Some(e) => info!("[x509] {}: error {} ({})", req.avatar_method, e.code, e.message),
                }
                // Same answer, with the client's own id put back.
                let _ = req.reply.send(JsonRpcResponse {
                    id: req.client_id,
                    ..resp
                });
            }
            Ok(Ok(_)) => {
                warn!("[x509] {}: response id mismatch — reconnecting", req.avatar_method);
                let _ = req.reply.send(unavailable(req.client_id));
                return ServeEnd::Reconnect;
            }
            Ok(Err(e)) => {
                warn!("[x509] {} failed: {} — reconnecting", req.avatar_method, e);
                let _ = req.reply.send(unavailable(req.client_id));
                return ServeEnd::Reconnect;
            }
            Err(_) => {
                // Drop the connection: a late reply must not be paired
                // with the next request.
                warn!("[x509] {}: no answer within {:?} — reconnecting", req.avatar_method, request_timeout);
                let _ = req.reply.send(unavailable(req.client_id));
                return ServeEnd::Reconnect;
            }
        }
    }
}

/// The bridge task: alternate between connecting and serving, forever.
async fn bridge(avatar_socket: PathBuf, mut rx: mpsc::Receiver<ClientRequest>, request_timeout: Duration) {
    loop {
        let Some(mut conn) = connect_phase(&avatar_socket, &mut rx).await else {
            return;
        };
        match serve(&mut conn, &mut rx, request_timeout).await {
            ServeEnd::Reconnect => warn!("Avatar connection lost, reconnecting..."),
            ServeEnd::Shutdown => return,
        }
    }
}

/// Bind the client socket and run until all clients are gone (in practice: forever).
async fn run(avatar_socket: PathBuf, listen_socket: PathBuf, request_timeout: Duration) -> Result<()> {
    let listener = bind_client_socket(&listen_socket)?;
    info!("X.509 SA listening on: {}", listen_socket.display());

    let (tx, rx) = mpsc::channel::<ClientRequest>(32);
    tokio::spawn(accept_loop(listener, tx));
    bridge(avatar_socket, rx, request_timeout).await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    let listen_socket = resolve_listen_socket(
        cli.listen_socket,
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
    )?;
    println!("X509_SA_SOCK={}", listen_socket.display());

    run(cli.avatar_socket, listen_socket, REQUEST_TIMEOUT).await
}
