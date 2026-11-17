#!/usr/bin/env python3
"""Mock km-x509-sa for testing km_pkcs11_x509 without KeyMaster.

Listens on a Unix socket (mode 0600) and speaks km-x509-sa's client protocol:
newline-delimited JSON-RPC 2.0 with `list`, `sign` and `import`, the same
parameter validation and error codes as crates/km-x509-sa/src/validate.rs,
and KeyMaster's import verdict rules (X509CertCheck.java).

There is ONE fixed software P-256 key, generated at start. Its private key
lives only in this process and is never written to disk.

Mock-only control methods (never part of the real km-x509-sa):
  mock.set     {"method": "list"|"sign"|"import", "next": FAULT}
               apply FAULT to the next call of that method. FAULT is one of:
               deny, unavailable, no_channel, timeout_err, unknown_path,
               invalid_digest, unsupported, close, silent, late:<ms>,
               wrong_id, garbage, drop (forget the stored certificate)
  mock.stats   -> {"list": n, "sign": n, "import": n} requests received
  mock.issue   {"eku": [oid, ...] | null} -> {"der": b64}
               a self-signed certificate for the mock's key
  mock.foreign {"eku": [...] | null} -> {"der": b64}  same, for another key
  mock.verify  {"digest": b64, "signature": b64} -> {"valid": bool}
               checks a raw r||s signature against the mock's public key
  mock.reset   forget the certificate, faults and counters

Usage: mock_x509_sa.py --socket PATH [--pubkey-out FILE]
Prints "READY <path>" on stdout once listening. SIGTERM stops it.
"""

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import signal
import socket
import sys
import threading
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

LABEL = "alice@atlanta.com tls-client"
PATH = "m/44'/1240'/1955269225'/196866'/0'"
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
MAX_LINE = 1024 * 1024

ERRORS = {
    "deny": (-32603, "request denied by user"),
    "unavailable": (-32603, "avatar unavailable"),
    "no_channel": (-32001, "no service channel available"),
    "timeout_err": (-32003, "timeout"),
    "unknown_path": (-32603, "unknown-path"),
    "invalid_digest": (-32603, "invalid-digest"),
    "unsupported": (-32603, "unsupported"),
}


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def invalid_params(message):
    return RpcError(-32602, message)


def b64_field(params, key):
    value = params.get(key)
    if not isinstance(value, str):
        raise invalid_params(f"'{key}' must be a string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise invalid_params(f"'{key}' is not valid base64")


def exact_object(params, keys):
    if not isinstance(params, dict):
        raise invalid_params("params must be an object")
    if set(params) != set(keys):
        raise invalid_params("params must have exactly: " + ", ".join(keys))
    return params


def make_cert(key, eku):
    """A self-signed certificate for `key`, with the given EKU OIDs (or none)."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alice@atlanta.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if eku is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(o) for o in eku]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


class Mock:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        public = self.key.public_key()
        self.point = public.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.spki = public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.key_id = hashlib.sha256(self.spki).digest()
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.cert = None
            self.faults = {}
            self.stats = {"list": 0, "sign": 0, "import": 0}

    # --- the three real methods -------------------------------------------

    def do_list(self, params):
        if not (params is None or params == {}):
            raise invalid_params("list takes no params")
        entry = {
            "label": LABEL,
            "path": PATH,
            "public_key": base64.b64encode(self.point).decode(),
            "id": base64.b64encode(self.key_id).decode(),
        }
        with self.lock:
            if self.cert is not None:
                entry["cert"] = base64.b64encode(self.cert).decode()
        return {"keys": [entry]}

    def validate_sign(self, params):
        params = exact_object(params, ["path", "digest"])
        if not isinstance(params["path"], str) or not params["path"]:
            raise invalid_params("'path' must be a non-empty string")
        digest = b64_field(params, "digest")
        if len(digest) != 32:
            raise invalid_params("'digest' must decode to exactly 32 bytes")
        return params["path"], digest

    def do_sign(self, path, digest):
        if path != PATH:
            raise RpcError(*ERRORS["unknown_path"])
        der = self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return {"signature": base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()}

    def validate_import(self, params):
        params = exact_object(params, ["der"])
        der = b64_field(params, "der")
        if not der:
            raise invalid_params("'der' must not be empty")
        return der

    def do_import(self, der):
        verdict = self.check_cert(der)
        if verdict == "ACCEPTED":
            with self.lock:
                self.cert = der
        return {"verdict": verdict, "stored": verdict == "ACCEPTED"}

    def check_cert(self, der):
        """KeyMaster's rules (X509CertCheck.check / checkEku)."""
        try:
            cert = x509.load_der_x509_certificate(der)
            spki = cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            try:
                eku = [o.dotted_string for o in
                       cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
            except x509.ExtensionNotFound:
                eku = None
        except Exception:
            return "MALFORMED"
        if spki != self.spki:
            return "KEY_MISMATCH"
        if eku is None:
            return "ACCEPTED"
        if not eku:
            return "MALFORMED"
        return "ACCEPTED" if eku == [CLIENT_AUTH] else "EKU_MISMATCH"

    # --- mock-only control -------------------------------------------------

    def control(self, method, params):
        params = params or {}
        if method == "mock.set":
            with self.lock:
                self.faults[params["method"]] = params["next"]
            return {}
        if method == "mock.stats":
            with self.lock:
                return dict(self.stats)
        if method == "mock.issue":
            return {"der": base64.b64encode(make_cert(self.key, params.get("eku"))).decode()}
        if method == "mock.foreign":
            other = ec.generate_private_key(ec.SECP256R1())
            return {"der": base64.b64encode(make_cert(other, params.get("eku"))).decode()}
        if method == "mock.verify":
            digest = base64.b64decode(params["digest"])
            sig = base64.b64decode(params["signature"])
            if len(sig) != 64:
                return {"valid": False}
            der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                             int.from_bytes(sig[32:], "big"))
            try:
                self.key.public_key().verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                return {"valid": True}
            except InvalidSignature:
                return {"valid": False}
        if method == "mock.reset":
            self.reset()
            return {}
        raise RpcError(-32601, "method not found")

    def take_fault(self, method):
        with self.lock:
            return self.faults.pop(method, None)


def reply(conn, msg):
    conn.sendall(json.dumps(msg).encode() + b"\n")


def ok(req_id, result):
    return {"jsonrpc": "2.0", "result": result, "id": req_id}


def err(req_id, code, message):
    return {"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": req_id}


def handle_request(mock, conn, line):
    """Answer one line. Returns False to close the connection."""
    try:
        msg = json.loads(line)
    except ValueError:
        reply(conn, err(None, -32700, "parse error"))
        return True
    req_id = msg.get("id") if isinstance(msg, dict) else None
    method = msg.get("method") if isinstance(msg, dict) else None
    if not isinstance(method, str):
        reply(conn, err(req_id, -32600, "invalid request"))
        return True
    params = msg.get("params")

    if method.startswith("mock."):
        try:
            reply(conn, ok(req_id, mock.control(method, params)))
        except RpcError as e:
            reply(conn, err(req_id, e.code, e.message))
        except Exception as e:  # bad control params: a test bug
            reply(conn, err(req_id, -32602, f"mock: {e}"))
        return True

    if method not in ("list", "sign", "import"):
        reply(conn, err(req_id, -32601, "method not found"))
        return True
    with mock.lock:
        mock.stats[method] += 1

    try:
        # Local validation first, like km-x509-sa: faults model the avatar side.
        if method == "list":
            mock.do_list(params)
            run = lambda: mock.do_list(params)
        elif method == "sign":
            path, digest = mock.validate_sign(params)
            run = lambda: mock.do_sign(path, digest)
        else:
            der = mock.validate_import(params)
            run = lambda: mock.do_import(der)
    except RpcError as e:
        reply(conn, err(req_id, e.code, e.message))
        return True

    fault = mock.take_fault(method)
    if fault in ERRORS:
        reply(conn, err(req_id, *ERRORS[fault]))
        return True
    if fault == "close":
        return False
    if fault == "silent":
        return True  # never answer this one
    if fault == "garbage":
        conn.sendall(b"this is not json\n")
        return True
    if fault == "drop":
        with mock.lock:
            mock.cert = None
    if fault and fault.startswith("late:"):
        time.sleep(int(fault.split(":", 1)[1]) / 1000)

    try:
        result = run()
    except RpcError as e:
        reply(conn, err(req_id, e.code, e.message))
        return True
    if fault == "wrong_id":
        req_id = (req_id if isinstance(req_id, int) else 0) + 1000
    reply(conn, ok(req_id, result))
    return True


def serve_connection(mock, conn):
    with conn:
        buf = b""
        while True:
            try:
                chunk = conn.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    if not handle_request(mock, conn, line):
                        return
                except OSError:
                    return
            if len(buf) > MAX_LINE:
                return  # like km-x509-sa: an oversized line drops the connection


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--socket", required=True)
    ap.add_argument("--pubkey-out")
    args = ap.parse_args()

    mock = Mock()
    if args.pubkey_out:
        with open(args.pubkey_out, "wb") as f:
            f.write(mock.key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    if os.path.exists(args.socket):
        os.unlink(args.socket)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(args.socket)
    os.chmod(args.socket, 0o600)
    server.listen(16)

    def stop(*_):
        try:
            os.unlink(args.socket)
        except OSError:
            pass
        os._exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f"READY {args.socket}", flush=True)

    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve_connection, args=(mock, conn), daemon=True).start()


if __name__ == "__main__":
    main()
