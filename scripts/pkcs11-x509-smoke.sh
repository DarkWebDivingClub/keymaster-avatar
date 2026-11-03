#!/bin/bash
# Smoke test for km_pkcs11_x509 with real tools (GnuTLS p11tool/certtool,
# p11-kit, OpenSC pkcs11-tool, OpenSSL) against the mock km-x509-sa. No
# KeyMaster, no phone, no avatar.
#
# What it touches:
#   - a temp dir (removed at exit)
#   - ~/.config/pkcs11/modules/km-x509-dev.module (created, removed at exit;
#     refuses to run if it already exists)
# X509_SA_SOCK is exported (before the module is registered) for this script
# only, so the module talks to the mock and never to a real km-x509-sa.
#
# GnuTLS loads a private key only from an object URL (with id=/object=); a
# bare token URL with type=private opens a session and finds nothing. So the
# key URLs are taken from `p11tool --list-all-privkeys --only-urls` and (p11tool
# 3.8 has no --list-all-pubkeys) the type=public line of `--list-all --only-urls`.
#
# p11tool, pkcs11-tool and p11-kit output used for a check is kept, stderr
# included, in $T files and printed when the check fails.
#
# Usage: scripts/pkcs11-x509-smoke.sh        (from anywhere in the repo)

set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
SO="$REPO/target/release/libkm_pkcs11_x509.so"
MOCK="$REPO/crates/pkcs11-x509/tests/mock_x509_sa.py"
MODNAME=km-x509-dev
MODDIR="$HOME/.config/pkcs11/modules"
MODFILE="$MODDIR/$MODNAME.module"
PROXY=/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so
TOKEN_LABEL="KeyMaster X.509"

PASS=0
FAIL=0
SKIP=0
MOCK_PID=
CREATED_MODFILE=
T=

cleanup() {
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null && wait "$MOCK_PID" 2>/dev/null
    [ -n "$CREATED_MODFILE" ] && rm -f "$MODFILE" && echo "removed $MODFILE"
    [ -n "$T" ] && rm -rf "$T"
}
trap cleanup EXIT

pass() { echo "PASS  $1"; PASS=$((PASS + 1)); }
# fail NAME [CAPTURED-OUTPUT]: the output is printed, indented; empty output says so.
fail() {
    echo "FAIL  $1"
    if [ $# -gt 1 ]; then
        if [ -n "$2" ]; then printf '%s\n' "$2" | sed 's/^/      /'; else echo "      (no output captured)"; fi
    fi
    FAIL=$((FAIL + 1))
}
skip() { echo "SKIP  $1"; SKIP=$((SKIP + 1)); }
die() { echo "ERROR $1"; exit 2; }

# Number of objects p11tool lists; its full output (stderr too) stays in $T/count.txt.
count_objects() { p11tool --batch "$1" "$2" >"$T/count.txt" 2>&1; grep -c '^Object' "$T/count.txt"; }
# The distinct "ID:" values p11tool prints.
listed_ids() { grep -E '^[[:space:]]*ID:' "$1" | awk '{print $2}' | sort -u; }

# --- 1. build, start the mock --------------------------------------------------
cargo build --release -p pkcs11-x509 --manifest-path "$REPO/Cargo.toml" >/dev/null 2>&1 \
    || die "cargo build --release -p pkcs11-x509 failed"
[ -f "$SO" ] || die "$SO not built"
for tool in p11tool certtool p11-kit pkcs11-tool openssl python3; do
    command -v "$tool" >/dev/null || die "$tool not installed"
done

T=$(mktemp -d)
python3 "$MOCK" --socket "$T/sa.sock" --pubkey-out "$T/pub.pem" >"$T/mock.out" 2>"$T/mock.err" &
MOCK_PID=$!
for _ in $(seq 50); do grep -q READY "$T/mock.out" 2>/dev/null && break; sleep 0.1; done
grep -q READY "$T/mock.out" || die "mock did not start: $(cat "$T/mock.err")"
export X509_SA_SOCK="$T/sa.sock"
pass "1 mock km-x509-sa listening on $X509_SA_SOCK"

# Expected CKA_ID: SHA-256 of the mock key's DER SPKI (hex, and p11tool's aa:bb:… form)
openssl pkey -pubin -in "$T/pub.pem" -outform DER -out "$T/pub.der" 2>/dev/null
ID_HEX=$(sha256sum "$T/pub.der" | cut -c1-64)
ID_COLON=$(echo "$ID_HEX" | sed 's/../&:/g; s/:$//')

# --- 2. register the module for this user ------------------------------------
[ -e "$MODFILE" ] && die "$MODFILE already exists; remove it first (not overwriting)"
mkdir -p "$MODDIR"
printf 'module: %s\ncritical: no\n' "$SO" >"$MODFILE"
CREATED_MODFILE=1
pass "2 registered $MODFILE"

# --- 3. token -----------------------------------------------------------------
p11tool --list-token-urls >"$T/tokens.txt" 2>&1
URL=$(grep 'token=KeyMaster%20X.509' "$T/tokens.txt" | head -1)
if [ -n "$URL" ] && echo "$URL" | grep -q 'manufacturer=DWDC'; then
    pass "3 token found: $URL"
else
    fail "3 token '$TOKEN_LABEL' by DWDC not listed" "$(cat "$T/tokens.txt")"
    exit 1
fi

# --- 4. (DoD a) p11-kit lists the module with the token -------------------------
p11-kit list-modules >"$T/modules.txt" 2>&1
if sed -n "/^module: $MODNAME\$/,/^module: /p" "$T/modules.txt" | grep -q "token: $TOKEN_LABEL\$"; then
    pass "4 p11-kit list-modules: $MODNAME with token '$TOKEN_LABEL'"
else
    fail "4 p11-kit list-modules does not show $MODNAME / '$TOKEN_LABEL'" \
        "$(cat "$T/modules.txt")"
fi

# --- 5. two objects before enrolment, shared ID = SHA-256(SPKI) -----------------
p11tool --batch --list-all "$URL" >"$T/list1.txt" 2>&1
N=$(grep -c '^Object' "$T/list1.txt")
IDS=$(listed_ids "$T/list1.txt")
if [ "$N" = 2 ] && [ "$IDS" = "$ID_COLON" ] && grep -q 'alice@atlanta.com tls-client' "$T/list1.txt"; then
    pass "5 two objects, label ok, shared ID = SHA-256(SPKI)"
else
    fail "5 objects/ID wrong (objects=$N ids=$IDS want $ID_COLON)" "$(cat "$T/list1.txt")"
fi

# --- 6. object URLs for the key pair (exactly one each) -------------------------
p11tool --batch --list-all-privkeys --only-urls "$URL" >"$T/privurls.txt" 2>&1
p11tool --batch --list-all --only-urls "$URL" >"$T/allurls.txt" 2>&1
PRIV_URLS=$(grep 'tls-client' "$T/privurls.txt" | grep 'type=private')
PUB_URLS=$(grep 'tls-client' "$T/allurls.txt" | grep 'type=public')
if [ "$(echo "$PRIV_URLS" | grep -c .)" = 1 ] && [ "$(echo "$PUB_URLS" | grep -c .)" = 1 ]; then
    PRIV_URL=$PRIV_URLS
    PUB_URL=$PUB_URLS
    pass "6 object URLs: $PRIV_URL"
else
    fail "6 expected exactly one private and one public key URL" \
        "$(printf -- '--list-all-privkeys --only-urls:\n%s\n--list-all --only-urls:\n%s' \
            "$(cat "$T/privurls.txt")" "$(cat "$T/allurls.txt")")"
    exit 1
fi

# --- 7. (DoD b) no certificate yet --------------------------------------------
p11tool --batch --list-all-certs "$URL" >"$T/certs0.txt" 2>&1
RC=$?
N=$(grep -c '^Object' "$T/certs0.txt")
# p11tool's convention for an empty search: exit 2 and "No matching objects found".
if [ "$RC" = 0 ] && [ "$N" = 0 ]; then
    pass "7 --list-all-certs: no certificate, exit 0"
elif [ "$RC" != 0 ] && [ "$N" = 0 ] && grep -q 'No matching objects found' "$T/certs0.txt"; then
    pass "7 --list-all-certs: no certificate (exit $RC, 'No matching objects found')"
else
    fail "7 --list-all-certs (exit=$RC objects=$N)" "$(cat "$T/certs0.txt")"
fi

# --- 8. exported public key equals the mock's ---------------------------------
if p11tool --batch --export-pubkey "$PRIV_URL" >"$T/exp.pem" 2>"$T/exp.err" \
    && openssl pkey -pubin -in "$T/exp.pem" -outform DER 2>/dev/null | cmp -s - "$T/pub.der"; then
    pass "8 --export-pubkey matches the mock key (SPKI DER)"
else
    fail "8 --export-pubkey" "$(cat "$T/exp.err")"
fi

# --- 9. GnuTLS test-sign ------------------------------------------------------
if p11tool --batch --test-sign "$PRIV_URL" >"$T/ts.txt" 2>&1; then
    pass "9 p11tool --test-sign"
else
    # GnuTLS choosing a non-SHA-256 hash gives CKR_DATA_LEN_RANGE: a finding, not a script bug.
    fail "9 p11tool --test-sign (CKR_DATA_LEN_RANGE here means GnuTLS sent a non-32-byte digest)" \
        "$(cat "$T/ts.txt")"
fi

cat >"$T/tmpl" <<'EOF'
cn = "alice@atlanta.com"
serial = 1
expiration_days = 30
tls_www_client
signing_key
EOF

# --- 10. (DoD c) CSR signed by the token --------------------------------------
if certtool --generate-request --load-privkey "$PRIV_URL" --load-pubkey "$PUB_URL" \
        --template "$T/tmpl" --outfile "$T/csr.pem" >"$T/csr.txt" 2>&1 \
    && openssl req -in "$T/csr.pem" -verify -noout >"$T/csrv.txt" 2>&1; then
    CSR_ID=$(openssl req -in "$T/csr.pem" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -c1-64)
    if [ "$CSR_ID" = "$ID_HEX" ]; then
        pass "10 certtool CSR verifies (openssl req -verify), SPKI sha256 == CKA_ID"
    else
        fail "10 CSR SPKI sha256 $CSR_ID != CKA_ID $ID_HEX" "$(cat "$T/csr.txt" "$T/csr.pem")"
    fi
else
    fail "10 certtool --generate-request / openssl req -verify" \
        "$(cat "$T/csr.txt" "$T/csrv.txt" 2>&1)"
fi

# --- 11. (DoD d) pkcs11-tool: mechanisms, raw 64-byte signature, verification ----
pkcs11-tool --module "$PROXY" -L >"$T/slots.txt" 2>&1
pkcs11-tool --module "$SO" -M >"$T/mechs.txt" 2>&1
if grep -q "$TOKEN_LABEL" "$T/slots.txt" && grep -qi 'ECDSA' "$T/mechs.txt"; then
    pass "11a pkcs11-tool sees the token (proxy) and CKM_ECDSA (direct)"
else
    fail "11a pkcs11-tool -L / -M" "$(cat "$T/slots.txt" "$T/mechs.txt")"
fi
echo "keymaster x509 smoke" >"$T/msg"
openssl dgst -sha256 -binary "$T/msg" >"$T/digest.bin"
if pkcs11-tool --module "$SO" --sign -m ECDSA --id "$ID_HEX" -i "$T/digest.bin" -o "$T/sig.raw" \
        >"$T/praw.txt" 2>&1 && [ "$(stat -c %s "$T/sig.raw")" = 64 ]; then
    pass "11b pkcs11-tool ECDSA, default format: exactly 64 bytes (raw r||s)"
else
    fail "11b pkcs11-tool --sign (raw)" "$(cat "$T/praw.txt"; ls -l "$T/sig.raw" 2>&1)"
fi
if pkcs11-tool --module "$SO" --sign -m ECDSA --id "$ID_HEX" -i "$T/digest.bin" -o "$T/sig.der" \
        --signature-format openssl >"$T/pt.txt" 2>&1 \
    && openssl dgst -sha256 -verify "$T/pub.pem" -signature "$T/sig.der" "$T/msg" >/dev/null 2>&1; then
    pass "11c pkcs11-tool ECDSA signature verifies with openssl"
else
    fail "11c pkcs11-tool --sign (openssl format)" "$(cat "$T/pt.txt")"
fi

# --- 12. 48-byte input is refused -----------------------------------------------
# pkcs11-tool sends 48 bytes multi-part (C_SignUpdate), which the module does not
# offer; a single-part C_Sign would get CKR_DATA_LEN_RANGE (unit test d15).
head -c 48 /dev/zero >"$T/d48.bin"
if pkcs11-tool --module "$SO" --sign -m ECDSA --id "$ID_HEX" -i "$T/d48.bin" -o "$T/sig48" >"$T/p48.txt" 2>&1; then
    fail "12 a 48-byte input was signed" "$(cat "$T/p48.txt")"
elif grep -qE 'CKR_DATA_LEN_RANGE|CKR_FUNCTION_NOT_SUPPORTED' "$T/p48.txt"; then
    pass "12 48-byte input refused ($(grep -oE 'CKR_DATA_LEN_RANGE|CKR_FUNCTION_NOT_SUPPORTED' "$T/p48.txt" | head -1))"
else
    fail "12 48-byte input failed, but not with DATA_LEN_RANGE / FUNCTION_NOT_SUPPORTED" "$(cat "$T/p48.txt")"
fi

# --- 13. (DoD e) key creation is refused ------------------------------------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T/f.key" 2>/dev/null
BEFORE=$(count_objects --list-all "$URL")
if pkcs11-tool --module "$SO" --write-object "$T/f.key" --type privkey >"$T/wk.txt" 2>&1; then
    fail "13 a private key was written" "$(cat "$T/wk.txt")"
elif ! grep -q 'CKR_TEMPLATE_INCONSISTENT' "$T/wk.txt"; then
    # pkcs11-tool failed, but not at C_CreateObject with our refusal.
    fail "13 key write failed without CKR_TEMPLATE_INCONSISTENT" "$(cat "$T/wk.txt")"
else
    AFTER=$(count_objects --list-all "$URL")
    [ "$AFTER" = "$BEFORE" ] && pass "13 key creation refused (CKR_TEMPLATE_INCONSISTENT), still $AFTER objects" \
        || fail "13 object count changed: $BEFORE -> $AFTER" "$(cat "$T/count.txt")"
fi

# --- 14. certtool: self-signed TLS client cert with the token key ---------------
# No `certtool --verify` of the cert against itself: GnuTLS refuses a non-CA
# self-signed cert as its own trust anchor ("issuer is not a CA"). Signatures
# made through the token are already verified in steps 9 (--test-sign),
# 10 (CSR, openssl req -verify) and 11c (pkcs11-tool + openssl dgst -verify).
certtool --generate-self-signed --load-privkey "$PRIV_URL" --load-pubkey "$PUB_URL" \
    --template "$T/tmpl" --hash SHA256 --outfile "$T/cert.pem" >"$T/ct.txt" 2>&1
RC=$?
if [ "$RC" = 0 ] && [ -s "$T/cert.pem" ]; then
    openssl x509 -in "$T/cert.pem" -pubkey -noout >"$T/certpub.pem" 2>"$T/certpub.err"
    CERT_ID=$(openssl pkey -pubin -in "$T/certpub.pem" -outform DER 2>>"$T/certpub.err" | sha256sum | cut -c1-64)
    if [ "$CERT_ID" = "$ID_HEX" ]; then
        pass "14 certtool self-signed certificate made with the token key, SPKI sha256 == CKA_ID"
    else
        fail "14 certificate SPKI sha256 $CERT_ID != CKA_ID $ID_HEX" \
            "$(cat "$T/ct.txt" "$T/certpub.err" "$T/cert.pem")"
    fi
else
    fail "14 certtool --generate-self-signed (exit=$RC)" "$(cat "$T/ct.txt")"
fi

# --- 15. import as 37.1.5 will: pkcs11-tool --write-object via the p11-kit proxy ---
if [ -s "$T/cert.pem" ] && openssl x509 -in "$T/cert.pem" -outform DER -out "$T/cert.der" 2>/dev/null; then
    if pkcs11-tool --module "$PROXY" --token-label "$TOKEN_LABEL" --write-object "$T/cert.der" \
            --type cert --id "$ID_HEX" >"$T/wc.txt" 2>&1; then
        p11tool --batch --list-all "$URL" >"$T/list2.txt" 2>&1
        N=$(grep -c '^Object' "$T/list2.txt")
        IDS=$(listed_ids "$T/list2.txt")
        NC=$(count_objects --list-all-certs "$URL")
        if [ "$N" = 3 ] && [ "$IDS" = "$ID_COLON" ] && [ "$NC" = 1 ]; then
            pass "15 pkcs11-tool --write-object (proxy): three objects, one shared ID, one certificate"
        else
            fail "15 after import (objects=$N ids=$IDS certs=$NC)" "$(cat "$T/list2.txt" "$T/count.txt")"
        fi
    else
        fail "15 pkcs11-tool --write-object --type cert" "$(cat "$T/wc.txt")"
    fi
else
    fail "15 no certificate from step 14 to import" "$(cat "$T/ct.txt" 2>&1)"
fi

# --- 16. p11tool --write (only if the slot does not hold the cert yet) -----------
if [ "$(count_objects --list-all-certs "$URL")" = 1 ]; then
    skip "16 p11tool --write: the slot already holds the certificate"
elif [ -s "$T/cert.pem" ] && p11tool --batch --write --load-certificate "$T/cert.pem" --label alice "$URL" \
        >"$T/w.txt" 2>&1 && [ "$(count_objects --list-all-certs "$URL")" = 1 ]; then
    pass "16 p11tool --write imported the certificate"
else
    fail "16 p11tool --write" "$(cat "$T/w.txt" "$T/count.txt" 2>/dev/null)"
fi

# --- 17. a certificate for another key is refused --------------------------------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/f2.key" \
    -subj "/CN=foreign" -addext "extendedKeyUsage=clientAuth" -days 1 -out "$T/foreign.pem" 2>/dev/null
BEFORE=$(count_objects --list-all "$URL")
if p11tool --batch --write --load-certificate "$T/foreign.pem" --label foreign "$URL" >"$T/w2.txt" 2>&1; then
    fail "17 a foreign certificate was accepted" "$(cat "$T/w2.txt")"
else
    AFTER=$(count_objects --list-all "$URL")
    [ "$AFTER" = "$BEFORE" ] && pass "17 foreign certificate refused, still $AFTER objects" \
        || fail "17 object count changed: $BEFORE -> $AFTER" "$(cat "$T/count.txt")"
fi

# --- summary ----------------------------------------------------------------------
echo
echo "passed: $PASS  failed: $FAIL  skipped: $SKIP"
[ "$FAIL" = 0 ]
