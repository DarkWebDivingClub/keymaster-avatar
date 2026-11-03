use super::*;
use crate::validate::{validate, DIGEST_LEN};
use avatar_protocol::{JSONRPC_INVALID_PARAMS, JSONRPC_METHOD_NOT_FOUND};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::sync::{Arc, Mutex};

fn b64(len: usize) -> String {
    BASE64.encode(vec![7u8; len])
}

fn err_code(method: &str, params: Value) -> i64 {
    validate(method, &params).expect_err("expected rejection").code
}

// ===========================================================================
// No-socket tests: allowlist + validation
// ===========================================================================

#[test]
fn validate_unknown_method_is_not_found() {
    assert_eq!(err_code("gpg.sign", json!({})), JSONRPC_METHOD_NOT_FOUND);
    assert_eq!(err_code("x509.sign", json!({})), JSONRPC_METHOD_NOT_FOUND);
    assert_eq!(err_code("connect", json!({"type": "gpg"})), JSONRPC_METHOD_NOT_FOUND);
    assert_eq!(err_code("", Value::Null), JSONRPC_METHOD_NOT_FOUND);
}

#[test]
fn validate_list_accepts_no_params() {
    for params in [Value::Null, json!({})] {
        let fwd = validate("list", &params).unwrap();
        assert_eq!(fwd.avatar_method, "x509.list");
        assert_eq!(fwd.params, json!({}));
    }
}

#[test]
fn validate_list_rejects_params() {
    assert_eq!(err_code("list", json!({"x": 1})), JSONRPC_INVALID_PARAMS);
    assert_eq!(err_code("list", json!([1])), JSONRPC_INVALID_PARAMS);
    assert_eq!(err_code("list", json!("x")), JSONRPC_INVALID_PARAMS);
}

#[test]
fn validate_sign_ok_forwards_exactly_path_and_digest() {
    let digest = b64(DIGEST_LEN);
    let fwd = validate("sign", &json!({"path": "m/1/2", "digest": digest})).unwrap();
    assert_eq!(fwd.avatar_method, "x509.sign");
    assert_eq!(fwd.params, json!({"path": "m/1/2", "digest": digest}));
    assert_eq!(fwd.payload_len, 32);
}

#[test]
fn validate_sign_rejects_bad_params() {
    let good = b64(32);
    let cases = [
        json!({"path": "p", "digest": b64(31)}),       // too short
        json!({"path": "p", "digest": b64(33)}),       // too long
        json!({"path": "p", "digest": "not base64!"}), // not base64
        json!({"path": "p", "digest": 32}),            // not a string
        json!({"digest": good}),                       // missing path
        json!({"path": "", "digest": good}),           // empty path
        json!({"path": 5, "digest": good}),            // numeric path
        json!({"id": "p", "digest": good}),            // "id" instead of path
        json!({"path": "p", "id": "x", "digest": good}), // extra key
        json!(["p", good]),                            // array params
        Value::Null,                                   // no params
    ];
    for params in cases {
        assert_eq!(
            err_code("sign", params.clone()),
            JSONRPC_INVALID_PARAMS,
            "params: {}",
            params
        );
    }
}

#[test]
fn validate_import_ok() {
    let der = b64(100);
    let fwd = validate("import", &json!({"der": der})).unwrap();
    assert_eq!(fwd.avatar_method, "x509.import");
    assert_eq!(fwd.params, json!({"der": der}));
    assert_eq!(fwd.payload_len, 100);
}

#[test]
fn validate_import_rejects_bad_params() {
    let cases = [
        json!({"der": ""}),            // empty
        json!({"der": "@@@"}),         // not base64
        json!({}),                     // missing
        json!({"der": b64(4), "x": 1}), // extra key
        json!([b64(4)]),               // array params
    ];
    for params in cases {
        assert_eq!(
            err_code("import", params.clone()),
            JSONRPC_INVALID_PARAMS,
            "params: {}",
            params
        );
    }
}

#[test]
fn listen_socket_flag_wins_over_xdg() {
    let p = resolve_listen_socket(Some("/x/y.sock".into()), Some("/run/user/1".into())).unwrap();
    assert_eq!(p, PathBuf::from("/x/y.sock"));
}

#[test]
fn listen_socket_defaults_to_xdg_runtime_dir() {
    let p = resolve_listen_socket(None, Some("/run/user/1".into())).unwrap();
    assert_eq!(p, PathBuf::from("/run/user/1/keymaster-x509-sa.sock"));
}

#[test]
fn listen_socket_without_xdg_is_an_error() {
    assert!(resolve_listen_socket(None, None).is_err());
    assert!(resolve_listen_socket(None, Some(PathBuf::new())).is_err());
}

// ===========================================================================
// Socket tests (need AF_UNIX; run by the owner outside the sandbox)
// ===========================================================================

/// What the fake avatar does when it receives `x509.sign`.
#[derive(Clone, Copy)]
enum OnSign {
    /// Reply with {path, internal_id}.
    Echo,
    /// Close the connection without answering.
    Close,
    /// Never answer (keep reading).
    Ignore,
}

/// Every (method, id) the fake avatar received after `connect`.
type Seen = Arc<Mutex<Vec<(String, Value)>>>;

/// A fresh, short temp directory (Unix socket paths are limited to 108 bytes).
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kx509-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Fake avatar local API: serves one connection.
fn start_fake_avatar(path: &Path, on_sign: OnSign) -> Seen {
    let listener = UnixListener::bind(path).unwrap();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut r = BufReader::new(r);
        loop {
            let req: JsonRpcRequest = match read_line_message(&mut r).await {
                Ok(req) => req,
                Err(_) => return,
            };
            let id = req.id.clone().unwrap_or(Value::Null);
            if req.method == "connect" {
                let resp = JsonRpcResponse::success(id, json!({"npub": ""}));
                let _ = write_line_message(&mut w, &resp).await;
                continue;
            }
            seen_task.lock().unwrap().push((req.method.clone(), id.clone()));
            let result = match req.method.as_str() {
                "x509.sign" => match on_sign {
                    OnSign::Echo => json!({"path": req.params["path"], "internal_id": id}),
                    OnSign::Close => return, // drops the stream
                    OnSign::Ignore => continue,
                },
                "x509.list" => json!({"certs": []}),
                _ => json!({}),
            };
            let _ = write_line_message(&mut w, &JsonRpcResponse::success(id, result)).await;
        }
    });
    seen
}

/// Start km-x509-sa's `run()` in the background.
fn start_sa(avatar: &Path, listen: &Path, request_timeout: Duration) {
    let (a, l) = (avatar.to_path_buf(), listen.to_path_buf());
    tokio::spawn(async move {
        run(a, l, request_timeout).await.unwrap();
    });
}

struct TestClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl TestClient {
    /// Connect to the SA's client socket, waiting up to 2 s for it to appear.
    async fn connect(path: &Path) -> TestClient {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match UnixStream::connect(path).await {
                Ok(stream) => {
                    let (r, w) = stream.into_split();
                    return TestClient { reader: BufReader::new(r), writer: w };
                }
                Err(e) if Instant::now() > deadline => panic!("SA socket never came up: {}", e),
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    }

    /// Send one request and read one reply; a hang longer than 2 s fails the test.
    async fn call(&mut self, req: Value) -> Value {
        write_line_message(&mut self.writer, &req).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), read_line_message::<Value>(&mut self.reader))
            .await
            .expect("no reply within 2 s")
            .unwrap()
    }

    /// Poll `list` until the bridge is connected to the avatar (up to 5 s).
    async fn wait_connected(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let resp = self.call(json!({"jsonrpc": "2.0", "method": "list", "id": "ready"})).await;
            if resp.get("result").is_some() {
                return;
            }
            assert!(Instant::now() < deadline, "bridge never connected: {}", resp);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn sign_req(id: Value, path: &str) -> Value {
    json!({"jsonrpc": "2.0", "method": "sign", "id": id,
           "params": {"path": path, "digest": b64(32)}})
}

fn assert_unavailable(resp: &Value, id: Value) {
    assert_eq!(resp["id"], id, "reply must carry the client's id: {}", resp);
    assert_eq!(resp["error"]["code"], json!(JSONRPC_INTERNAL_ERROR), "{}", resp);
    assert_eq!(resp["error"]["message"], json!(UNAVAILABLE), "{}", resp);
}

#[tokio::test]
async fn client_socket_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("mode");
    let path = dir.join("c.sock");
    let _listener = bind_client_socket(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "mode was {:o}", mode);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn stale_socket_replaced() {
    use std::os::unix::fs::FileTypeExt;
    let dir = temp_dir("stale");
    let path = dir.join("c.sock");
    std::fs::write(&path, b"stale").unwrap();
    let _listener = bind_client_socket(&path).unwrap();
    assert!(std::fs::metadata(&path).unwrap().file_type().is_socket());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn e2e_invalid_request_not_forwarded() {
    let dir = temp_dir("inval");
    let (avatar, listen) = (dir.join("a.sock"), dir.join("c.sock"));
    let seen = start_fake_avatar(&avatar, OnSign::Echo);
    start_sa(&avatar, &listen, Duration::from_secs(5));

    let mut c = TestClient::connect(&listen).await;
    c.wait_connected().await;

    // 31-byte digest -> -32602
    let resp = c
        .call(json!({"jsonrpc": "2.0", "method": "sign", "id": 7,
                     "params": {"path": "p", "digest": b64(31)}}))
        .await;
    assert_eq!(resp["id"], json!(7));
    assert_eq!(resp["error"]["code"], json!(JSONRPC_INVALID_PARAMS));

    // Method outside the allowlist -> -32601
    let resp = c.call(json!({"jsonrpc": "2.0", "method": "gpg.sign", "id": 8})).await;
    assert_eq!(resp["error"]["code"], json!(JSONRPC_METHOD_NOT_FOUND));

    // A valid round-trip afterwards proves ordering: anything forwarded would be seen by now.
    let resp = c.call(json!({"jsonrpc": "2.0", "method": "list", "id": 9})).await;
    assert!(resp.get("result").is_some(), "{}", resp);

    let seen = seen.lock().unwrap();
    assert!(seen.iter().all(|(m, _)| m == "x509.list"), "forwarded: {:?}", *seen);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn two_clients_same_id() {
    let dir = temp_dir("conc");
    let (avatar, listen) = (dir.join("a.sock"), dir.join("c.sock"));
    let seen = start_fake_avatar(&avatar, OnSign::Echo);
    start_sa(&avatar, &listen, Duration::from_secs(5));

    let mut a = TestClient::connect(&listen).await;
    let mut b = TestClient::connect(&listen).await;
    a.wait_connected().await;

    // Both clients use id 1, at the same time.
    let (ra, rb) = tokio::join!(a.call(sign_req(json!(1), "path/a")), b.call(sign_req(json!(1), "path/b")));

    assert_eq!(ra["id"], json!(1));
    assert_eq!(rb["id"], json!(1));
    assert_eq!(ra["result"]["path"], json!("path/a"), "{}", ra);
    assert_eq!(rb["result"]["path"], json!("path/b"), "{}", rb);

    // The avatar saw two distinct internal ids, neither of them the clients' 1.
    let seen = seen.lock().unwrap();
    let sign_ids: Vec<&Value> = seen.iter().filter(|(m, _)| m == "x509.sign").map(|(_, id)| id).collect();
    assert_eq!(sign_ids.len(), 2, "{:?}", *seen);
    assert_ne!(sign_ids[0], sign_ids[1]);
    assert!(sign_ids.iter().all(|id| **id != json!(1)), "{:?}", sign_ids);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn avatar_drops_mid_request() {
    let dir = temp_dir("drop");
    let (avatar, listen) = (dir.join("a.sock"), dir.join("c.sock"));
    let _seen = start_fake_avatar(&avatar, OnSign::Close);
    start_sa(&avatar, &listen, Duration::from_secs(5));

    let mut c = TestClient::connect(&listen).await;
    c.wait_connected().await;

    // The fake avatar reads the sign line, then closes without answering.
    let resp = c.call(sign_req(json!("abc"), "p")).await;
    assert_unavailable(&resp, json!("abc"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn request_while_disconnected_immediate_error() {
    let dir = temp_dir("disc");
    let (avatar, listen) = (dir.join("a.sock"), dir.join("c.sock"));
    // No fake avatar: nothing listens on `avatar`.
    start_sa(&avatar, &listen, Duration::from_secs(5));

    let mut c = TestClient::connect(&listen).await;
    let resp = c.call(json!({"jsonrpc": "2.0", "method": "list", "id": 42})).await;
    assert_unavailable(&resp, json!(42));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn silent_avatar_times_out() {
    let dir = temp_dir("silent");
    let (avatar, listen) = (dir.join("a.sock"), dir.join("c.sock"));
    let _seen = start_fake_avatar(&avatar, OnSign::Ignore);
    start_sa(&avatar, &listen, Duration::from_millis(300));

    let mut c = TestClient::connect(&listen).await;
    c.wait_connected().await;

    // The fake avatar never answers the sign; our 300 ms timeout must fire.
    let resp = c.call(sign_req(json!("s1"), "p")).await;
    assert_unavailable(&resp, json!("s1"));
    let _ = std::fs::remove_dir_all(&dir);
}
