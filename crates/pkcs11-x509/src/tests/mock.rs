//! Tests against tests/mock_x509_sa.py. They need AF_UNIX sockets and
//! python3 with `cryptography`, so they are ignored by default:
//!
//!     cargo test -p pkcs11-x509 -- --include-ignored

use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const NEEDS: &str = "needs AF_UNIX + python3 mock (run with --include-ignored)";

/// A running mock km-x509-sa on a fresh socket; X509_SA_SOCK points at it.
struct Mock {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
}

impl Mock {
    fn start() -> Mock {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Short path: Unix socket paths are limited to 108 bytes.
        let dir = std::env::temp_dir().join(format!("kp11-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("sa.sock");
        let child = spawn(&socket);
        std::env::set_var("X509_SA_SOCK", &socket);
        Mock { child, dir, socket }
    }

    /// Kill and start again on the same path (a new key, no stored cert).
    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.child = spawn(&self.socket);
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }

    /// One control or plain request on its own connection.
    fn call(&self, method: &str, params: Value) -> Value {
        let mut s = UnixStream::connect(&self.socket).expect("connect to mock");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        s.write_all(format!("{}\n", req).as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        reply
            .get("result")
            .cloned()
            .unwrap_or_else(|| panic!("mock error: {}", reply))
    }

    fn fault(&self, method: &str, fault: &str) {
        self.call("mock.set", json!({"method": method, "next": fault}));
    }

    fn count(&self, method: &str) -> u64 {
        self.call("mock.stats", json!({}))[method].as_u64().unwrap()
    }

    fn verify(&self, digest: &[u8], sig: &[u8]) -> bool {
        let r = self.call(
            "mock.verify",
            json!({"digest": BASE64.encode(digest), "signature": BASE64.encode(sig)}),
        );
        r["valid"].as_bool().unwrap()
    }

    fn issue(&self, eku: Option<&[&str]>) -> Vec<u8> {
        b64(self.call("mock.issue", json!({ "eku": eku }))["der"]
            .as_str()
            .unwrap())
    }

    fn foreign(&self, eku: Option<&[&str]>) -> Vec<u8> {
        b64(self.call("mock.foreign", json!({ "eku": eku }))["der"]
            .as_str()
            .unwrap())
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn spawn(socket: &std::path::Path) -> Child {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/mock_x509_sa.py");
    let mut child = Command::new("python3")
        .arg(script)
        .arg("--socket")
        .arg(socket)
        .stdout(Stdio::piped())
        .spawn()
        .expect("start python3 mock");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.starts_with("READY"), "mock did not start: {:?}", line);
    child
}

const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

fn digest(n: u8) -> [u8; 32] {
    [n; 32]
}

fn private_key(s: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let keys = find_class(s, CKO_PRIVATE_KEY);
    assert_eq!(keys.len(), 1);
    keys[0]
}

/// SignInit + Sign with a fresh digest.
fn sign_digest(s: CK_SESSION_HANDLE, d: &[u8; 32]) -> (CK_RV, Vec<u8>) {
    let key = private_key(s);
    assert_eq!(sign_init(s, key), CKR_OK);
    sign(s, d)
}

// ===========================================================================
// D8/D10 objects from a real list
// ===========================================================================

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_lists_the_mock_key() {
    let _f = Fixture::new();
    let mock = Mock::start();
    let s = open(false);
    let all = find(s, &[]);
    assert_eq!(all.len(), 2);
    let entry = &mock.call("list", json!({}))["keys"][0];
    let id = b64(entry["id"].as_str().unwrap());
    let point = b64(entry["public_key"].as_str().unwrap());
    use sha2::{Digest, Sha256};
    let mut spki = hex_prefix();
    spki.extend_from_slice(&point);
    assert_eq!(
        Sha256::digest(&spki).to_vec(),
        id,
        "mock id = SHA-256(SPKI)"
    );
    for h in all {
        assert_eq!(attr_ok(s, h, CKA_ID), id);
        assert_eq!(attr_ok(s, h, CKA_LABEL), ALICE_LABEL.as_bytes());
    }
    let _ = NEEDS;
}

fn hex_prefix() -> Vec<u8> {
    let hex = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// ===========================================================================
// D14 refresh and cache fallback
// ===========================================================================

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_find_refreshes_when_the_cache_is_old() {
    let _f = Fixture::new();
    crate::objects::set_max_cache_age_for_tests(200);
    let mock = Mock::start();
    let s = open(false);
    assert_eq!(find(s, &[]).len(), 2);
    let lists = mock.count("list");
    // Import behind the module's back.
    let der = mock.issue(Some(&[CLIENT_AUTH]));
    assert_eq!(
        mock.call("import", json!({"der": BASE64.encode(&der)}))["verdict"],
        "ACCEPTED"
    );
    assert_eq!(find(s, &[]).len(), 2, "cache still fresh");
    assert_eq!(mock.count("list"), lists, "no list while fresh");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(find(s, &[]).len(), 3, "refreshed after the cache aged");
    assert_eq!(mock.count("list"), lists + 1);
}

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_find_uses_the_cache_when_the_sa_is_down() {
    let _f = Fixture::new();
    crate::objects::set_max_cache_age_for_tests(100);
    let mut mock = Mock::start();
    let s = open(false);
    let first = find(s, &[]);
    mock.stop();
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(find(s, &[]), first, "refresh failed, cached objects served");
}

// ===========================================================================
// D15 sign end to end
// ===========================================================================

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_sign_verifies_with_the_mock_key() {
    let _f = Fixture::new();
    let mock = Mock::start();
    let s = open(false);
    let d = digest(1);
    let (rv, sig) = sign_digest(s, &d);
    assert_eq!(rv, CKR_OK);
    assert_eq!(sig.len(), 64, "raw r||s, no DER");
    assert!(mock.verify(&d, &sig));
    assert!(!mock.verify(&digest(2), &sig));
    assert_eq!(
        sign(s, &d).0,
        CKR_OPERATION_NOT_INITIALIZED,
        "a successful sign ends the op"
    );
}

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_two_sessions_sign_independently() {
    let _f = Fixture::new();
    let mock = Mock::start();
    let a = open(false);
    let b = open(false);
    let key = private_key(a);
    assert_eq!(sign_init(a, key), CKR_OK);
    assert_eq!(sign_init(b, key), CKR_OK);
    let (rb, sb) = sign(b, &digest(2));
    let (ra, sa) = sign(a, &digest(1));
    assert_eq!((ra, rb), (CKR_OK, CKR_OK));
    assert!(mock.verify(&digest(1), &sa) && mock.verify(&digest(2), &sb));
}

// ===========================================================================
// D16 error mapping through the socket
// ===========================================================================

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_sign_errors_are_mapped() {
    let _f = Fixture::new();
    let mock = Mock::start();
    let s = open(false);
    for (fault, want) in [
        ("deny", CKR_FUNCTION_REJECTED),
        ("unavailable", CKR_DEVICE_ERROR),
        ("no_channel", CKR_DEVICE_ERROR),
        ("timeout_err", CKR_DEVICE_ERROR),
        ("invalid_digest", CKR_DATA_LEN_RANGE),
        ("unknown_path", CKR_KEY_HANDLE_INVALID),
    ] {
        mock.fault("sign", fault);
        assert_eq!(sign_digest(s, &digest(3)).0, want, "fault {}", fault);
        // The error ended the operation; the next sign works.
        let (rv, sig) = sign_digest(s, &digest(4));
        assert_eq!(rv, CKR_OK, "after {}", fault);
        assert!(mock.verify(&digest(4), &sig));
    }
}

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_unknown_path_refreshes_the_cache() {
    let _f = Fixture::new();
    let mock = Mock::start();
    let s = open(false);
    let key = private_key(s);
    let lists = mock.count("list");
    mock.fault("sign", "unknown_path");
    assert_eq!(sign_init(s, key), CKR_OK);
    assert_eq!(sign(s, &digest(5)).0, CKR_KEY_HANDLE_INVALID);
    assert_eq!(mock.count("list"), lists + 1, "refreshed right away");
}

// ===========================================================================
// D17 timeouts and broken replies drop the connection
// ===========================================================================

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_silent_reply_times_out_and_drops_the_connection() {
    let _f = Fixture::new();
    crate::client::set_read_timeout_for_tests(300);
    let mock = Mock::start();
    let s = open(false);
    let key = private_key(s);
    mock.fault("sign", "silent");
    assert_eq!(sign_init(s, key), CKR_OK);
    let t = Instant::now();
    assert_eq!(sign(s, &digest(6)).0, CKR_DEVICE_ERROR);
    assert!(t.elapsed() < Duration::from_secs(3), "the timeout fired");
    let (rv, sig) = sign_digest(s, &digest(7));
    assert_eq!(rv, CKR_OK);
    assert!(mock.verify(&digest(7), &sig));
}

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_late_reply_is_not_paired_with_the_next_request() {
    let _f = Fixture::new();
    crate::client::set_read_timeout_for_tests(300);
    let mock = Mock::start();
    let s = open(false);
    let key = private_key(s);
    mock.fault("sign", "late:700");
    assert_eq!(sign_init(s, key), CKR_OK);
    assert_eq!(
        sign(s, &digest(8)).0,
        CKR_DEVICE_ERROR,
        "gave up after 300 ms"
    );
    std::thread::sleep(Duration::from_millis(600)); // the late reply is sent now
                                                    // The next sign must get its own signature, over its own digest.
    let (rv, sig) = sign_digest(s, &digest(9));
    assert_eq!(rv, CKR_OK);
    assert!(
        mock.verify(&digest(9), &sig),
        "the reply belongs to this request"
    );
    assert!(!mock.verify(&digest(8), &sig));
}

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_wrong_id_and_garbage_drop_the_connection() {
    let _f = Fixture::new();
    let mock = Mock::start();
    let s = open(false);
    for fault in ["wrong_id", "garbage"] {
        mock.fault("sign", fault);
        assert_eq!(
            sign_digest(s, &digest(10)).0,
            CKR_DEVICE_ERROR,
            "fault {}",
            fault
        );
        let (rv, sig) = sign_digest(s, &digest(11));
        assert_eq!(rv, CKR_OK, "after {}", fault);
        assert!(mock.verify(&digest(11), &sig));
    }
}

// ===========================================================================
// D18 retry only if nothing was sent
// ===========================================================================

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_stale_connection_is_replaced_before_writing() {
    let _f = Fixture::new();
    let mut mock = Mock::start();
    let s = open(false);
    let key = private_key(s); // the connection is now open
    mock.restart(); // that connection is dead; the path works again
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(sign_init(s, key), CKR_OK);
    let (rv, sig) = sign(s, &digest(12));
    assert_eq!(rv, CKR_OK, "the dead connection was noticed before writing");
    assert_eq!(
        mock.count("sign"),
        1,
        "exactly one sign reached the (new) mock"
    );
    assert!(mock.verify(&digest(12), &sig));
}

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_close_after_write_is_not_resent() {
    let _f = Fixture::new();
    let mock = Mock::start();
    let s = open(false);
    let key = private_key(s);
    let before = mock.count("sign");
    mock.fault("sign", "close");
    assert_eq!(sign_init(s, key), CKR_OK);
    assert_eq!(sign(s, &digest(13)).0, CKR_DEVICE_ERROR);
    assert_eq!(
        mock.count("sign"),
        before + 1,
        "a sign that was sent is never resent"
    );
}

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_list_retries_once_after_a_broken_connection() {
    let _f = Fixture::new();
    crate::objects::set_max_cache_age_for_tests(1);
    let mock = Mock::start();
    let s = open(false);
    assert_eq!(find(s, &[]).len(), 2);
    let before = mock.count("list");
    mock.fault("list", "close");
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(find(s, &[]).len(), 2);
    assert_eq!(mock.count("list"), before + 2, "closed once, retried once");
}

// ===========================================================================
// D19 C_CreateObject end to end
// ===========================================================================

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_create_accepted_returns_the_certificate_handle() {
    let _f = Fixture::new();
    let mock = Mock::start();
    let s = open(true);
    let id = attr_ok(s, private_key(s), CKA_ID);
    let der = mock.issue(Some(&[CLIENT_AUTH]));
    let mut t = cert_template(&der);
    t.push((CKA_ID, vec![0x55; 20])); // ignored (p11tool sends its own)
    t.push((CKA_LABEL, b"ignored".to_vec()));
    let (rv, h) = create(s, &t);
    assert_eq!(rv, CKR_OK);
    assert_eq!(attr_ok(s, h, CKA_CLASS), ul(CKO_CERTIFICATE));
    assert_eq!(attr_ok(s, h, CKA_VALUE), der);
    assert_eq!(attr_ok(s, h, CKA_ID), id, "KeyMaster's id wins");
    assert_eq!(
        attr_ok(s, h, CKA_LABEL),
        ALICE_LABEL.as_bytes(),
        "KeyMaster's label wins"
    );
    assert_eq!(find(s, &[]).len(), 3, "visible immediately");
    // No EKU at all is accepted too.
    assert_eq!(create(s, &cert_template(&mock.issue(None))).0, CKR_OK);
}

#[test]
#[ignore = "needs AF_UNIX + python3 mock (run with --include-ignored)"]
fn s_create_refused_verdicts_and_errors() {
    let _f = Fixture::new();
    let mock = Mock::start();
    let s = open(true);
    assert_eq!(
        create(s, &cert_template(&mock.foreign(Some(&[CLIENT_AUTH])))).0,
        CKR_ATTRIBUTE_VALUE_INVALID
    );
    assert_eq!(
        create(
            s,
            &cert_template(&mock.issue(Some(&[CLIENT_AUTH, SERVER_AUTH])))
        )
        .0,
        CKR_ATTRIBUTE_VALUE_INVALID,
        "EKU_MISMATCH"
    );
    assert_eq!(find_class(s, CKO_CERTIFICATE).len(), 0, "nothing stored");
    mock.fault("import", "unsupported");
    assert_eq!(
        create(s, &cert_template(&mock.issue(None))).0,
        CKR_FUNCTION_NOT_SUPPORTED
    );
    mock.fault("import", "deny");
    assert_eq!(
        create(s, &cert_template(&mock.issue(None))).0,
        CKR_FUNCTION_REJECTED
    );
    // An invalid DER never reaches the SA.
    let before = mock.count("import");
    assert_eq!(
        create(s, &cert_template(b"junk")).0,
        CKR_ATTRIBUTE_VALUE_INVALID
    );
    assert_eq!(mock.count("import"), before);
}
