#!/bin/bash
# X.509 enrolment through KeyMaster's PKCS#11 module (mission 37.1.5).
#
# Alice's TLS client key lives in KeyMaster. This script selects it on the
# token "KeyMaster X.509", has the token sign a CSR (certtool), lets a CA
# issue the certificate (openssl), checks the chain, deposits the
# certificate on the token (pkcs11-tool), and proves it works in a TLS
# client-auth handshake (gnutls-cli against gnutls-serv), with a negative
# control. The private key never leaves KeyMaster.
#
# Single source: doc/x509-enrolment.md quotes the commands between the
# runbook marker comments (">>> runbook NAME" ... "<<< runbook") verbatim,
# in file order, and
# keymaster-e2e-test's X509EnrolmentTest copies this file into the avatar
# container and runs its steps. Change a command here, then update the md
# (the sync check is at the end of the md).
#
# Usage:
#   x509-enrolment.sh              the real enrolment, steps in order:
#                                  check_no_cert select_key make_csr ca_issue
#                                  verify_chain deposit handshake handshake_without_cert
#   x509-enrolment.sh STEP         one step (any of the above, or make_test_pki)
#
# make_test_pki is TEST ONLY: it creates a throwaway CA and server key. In
# real use your CA does ca_issue; put its certificate at $CERT_FILE and run
# the steps from verify_chain on one at a time.
#
# Environment:
#   X509_SA_SOCK  required: km-x509-sa's socket (km-x509-sa prints
#                 X509_SA_SOCK=<path> at startup). Never defaulted here.
#   WORKDIR       required: the directory everything is read from and
#                 written to. The script cd's there itself.
#   TOKEN_LABEL   default "KeyMaster X.509"
#   TEMPLATE      default alice.tmpl    certtool template (without one certtool prompts)
#   CA_CERT       default test-ca.pem
#   CA_KEY        default test-ca.key   (ca_issue, make_test_pki)
#   CLIENT_EXT    default client.ext    the CA's TLS-client profile (ca_issue)
#   CERT_FILE     default alice.crt     ca_issue's output; verify_chain's and deposit's input
#   SERVER_CERT   default server.pem    (handshakes, make_test_pki)
#   SERVER_KEY    default server.key    (handshakes, make_test_pki)
#   SERVER_EXT    default server.ext    (make_test_pki only)
#   PORT          default 4433          gnutls-serv's port
# Relative paths are relative to $WORKDIR.
#
# Output: one line per action ("STEP: ..."), "ok   STEP: ..." per passed
# check, "FAIL STEP: ..." followed by the output (stdout and stderr) of the
# command that failed. Every checked command's output is kept in
# $WORKDIR/logs/. Key material is never printed: no key file is ever shown,
# and the logs hold only URLs, public certificates, CSRs and tool messages.
#
# Exit status: 0 all checks passed, 1 a check failed, 2 usage or setup error.

set -euo pipefail

# >>> runbook settings
TOKEN_LABEL="${TOKEN_LABEL:-KeyMaster X.509}"
TEMPLATE="${TEMPLATE:-alice.tmpl}"
CA_CERT="${CA_CERT:-test-ca.pem}"
CA_KEY="${CA_KEY:-test-ca.key}"
CLIENT_EXT="${CLIENT_EXT:-client.ext}"
CERT_FILE="${CERT_FILE:-alice.crt}"
SERVER_CERT="${SERVER_CERT:-server.pem}"
SERVER_KEY="${SERVER_KEY:-server.key}"
SERVER_EXT="${SERVER_EXT:-server.ext}"
PORT="${PORT:-4433}"
TOKEN_URL="pkcs11:token=${TOKEN_LABEL// /%20}"
DER_FILE="${CERT_FILE%.crt}.der"
# <<< runbook

ALL_STEPS="check_no_cert select_key make_csr ca_issue verify_chain deposit handshake handshake_without_cert"

STEP=setup
LOGS=
SERVER_PID=
SERVER_LOG=

# --- output -------------------------------------------------------------------

say() { printf '%s: %s\n' "$STEP" "$*"; }
ok() { printf 'ok   %s: %s\n' "$STEP" "$*"; }

# fail MESSAGE [LOGFILE...]: print the message and each file, indented; exit 1.
fail() {
    local msg=$1 f
    shift
    printf 'FAIL %s: %s\n' "$STEP" "$msg"
    for f in "$@"; do
        if [ -s "$f" ]; then
            printf '      --- %s\n' "${f#"$PWD"/}"
            sed 's/^/      /' "$f"
        else
            printf '      --- %s: (no output)\n' "${f#"$PWD"/}"
        fi
    done
    exit 1
}

# setup_error MESSAGE: wrong environment or missing input; exit 2.
setup_error() {
    printf 'ERROR %s: %s\n' "$STEP" "$*" >&2
    exit 2
}

usage() {
    cat <<EOF
usage: $(basename "$0") [STEP]
  no STEP: the real enrolment, in order: $ALL_STEPS
  STEP:    one of: make_test_pki (test only) $ALL_STEPS
  needs X509_SA_SOCK and WORKDIR; see the header of this file for the other inputs
EOF
}

# --- helpers ------------------------------------------------------------------

need_files() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || setup_error "missing input file $f (in $PWD)"
    done
}

need_token() {
    [ -S "$X509_SA_SOCK" ] \
        || setup_error "X509_SA_SOCK=$X509_SA_SOCK is not a socket: is km-x509-sa running?"
}

# A PKCS#11 URL's id= value (percent-encoded bytes) as lowercase hex.
url_id_hex() {
    local s c out=
    s=$(printf '%s\n' "$1" | sed -n 's/.*[:;]id=\([^;]*\).*/\1/p')
    while [ -n "$s" ]; do
        c=${s:0:1}
        if [ "$c" = % ]; then
            out+=${s:1:2}
            s=${s:3}
        else
            out+=$(printf '%02x' "'$c")
            s=${s:1}
        fi
    done
    printf '%s\n' "${out,,}"
}

lines() { if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | grep -c .; fi; }

# CERT_FILE's subject CN as RFC 2253, e.g. CN=alice@atlanta.com
cert_cn() {
    openssl x509 -in "$CERT_FILE" -noout -subject -nameopt RFC2253 | sed -n 's/^subject=\(CN=[^,]*\).*/\1/p'
}

# wait_for_text FILE TEXT: poll up to 5 s for a fixed string.
wait_for_text() {
    local i
    for i in $(seq 50); do
        grep -qF -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    grep -qF -- "$2" "$1" 2>/dev/null
}

# Is something listening on TCP $PORT? Read from /proc so no probe connection
# reaches gnutls-serv (its log then holds only the real client).
port_listening() {
    local hex
    hex=$(printf ':%04X' "$PORT")
    awk -v p="$hex" 'FNR > 1 && $4 == "0A" && substr($2, length($2) - 4) == p { f = 1 } END { exit !f }' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=
    fi
}

# --- steps ----------------------------------------------------------------------

# TEST ONLY. In real use your CA does ca_issue. Creates a throwaway P-256 test
# CA and a server key and certificate for gnutls-serv. Never overwrites a key.
make_test_pki() {
    local log
    need_files "$SERVER_EXT"
    [ ! -e "$CA_KEY" ] || setup_error "$CA_KEY exists; make_test_pki never overwrites a key"
    [ ! -e "$SERVER_KEY" ] || setup_error "$SERVER_KEY exists; make_test_pki never overwrites a key"
    umask 077
    log="$LOGS/make_test_pki.ca_key.txt"
    {
    # >>> runbook make_test_pki.ca_key
    openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
    # <<< runbook
    } >"$log" 2>&1 || fail "CA key generation failed" "$log"
    log="$LOGS/make_test_pki.ca_cert.txt"
    {
    # >>> runbook make_test_pki.ca_cert
    openssl req -x509 -new -key "$CA_KEY" -subj "/CN=Test CA 37.1.5" -days 7 \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$CA_CERT"
    # <<< runbook
    } >"$log" 2>&1 || fail "CA certificate failed" "$log"
    say "test CA: $CA_CERT (key $CA_KEY, not shown)"
    log="$LOGS/make_test_pki.server_key.txt"
    {
    # >>> runbook make_test_pki.server_key
    openssl ecparam -name prime256v1 -genkey -noout -out "$SERVER_KEY"
    # <<< runbook
    } >"$log" 2>&1 || fail "server key generation failed" "$log"
    log="$LOGS/make_test_pki.server_csr.txt"
    {
    # >>> runbook make_test_pki.server_csr
    openssl req -new -key "$SERVER_KEY" -subj "/CN=localhost" -out server.csr
    # <<< runbook
    } >"$log" 2>&1 || fail "server CSR failed" "$log"
    log="$LOGS/make_test_pki.server_cert.txt"
    {
    # >>> runbook make_test_pki.server_cert
    openssl x509 -req -in server.csr -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -extfile "$SERVER_EXT" -days 7 -out "$SERVER_CERT"
    # <<< runbook
    } >"$log" 2>&1 || fail "server certificate failed" "$log"
    log="$LOGS/make_test_pki.verify.txt"
    openssl verify -CAfile "$CA_CERT" "$SERVER_CERT" >"$log" 2>&1 || true
    grep -qF "$SERVER_CERT: OK" "$log" || fail "server certificate does not verify against $CA_CERT" "$log"
    ok "test CA and server certificate ($SERVER_CERT, CN=localhost) made; server certificate verifies"
}

check_no_cert() {
    local log="$LOGS/check_no_cert.p11tool.txt" rc=0 n
    need_token
    key_urls
    say "token '$TOKEN_LABEL' lists the tls-client key pair"
    {
    # >>> runbook check_no_cert
    p11tool --batch --list-all-certs "$TOKEN_URL"
    # <<< runbook
    } >"$log" 2>&1 || rc=$?
    n=$(grep -c '^Object' "$log" || true)
    if [ "$rc" = 0 ] && [ "$n" = 0 ]; then
        ok "no certificate on the token (exit 0)"
    elif [ "$rc" = 2 ] && [ "$n" = 0 ] && grep -qF 'No matching objects found' "$log"; then
        # p11tool's way of saying "none": exit 2 and this text.
        ok "no certificate on the token (p11tool exit 2, 'No matching objects found')"
    else
        fail "expected no certificate on the token (p11tool exit $rc, $n object(s))" "$log"
    fi
}

# key_urls: sets PRIV, PUB (object URLs of the tls-client key pair) and
# TOKEN_ID (their shared CKA_ID, hex), recomputed from the token every time.
# Used by every step that needs the key; select_key just reports it.
key_urls() {
    local log="$LOGS/$STEP.key_urls.txt" diag="$LOGS/$STEP.token_objects.txt"
    PRIV=
    PUB=
    {
    # >>> runbook select_key
    PRIV=$(p11tool --batch --list-all --only-urls "$TOKEN_URL" | grep 'tls-client' | grep 'type=private')
    PUB=$(p11tool --batch --list-all --only-urls "$TOKEN_URL" | grep 'tls-client' | grep 'type=public')
    # <<< runbook
    } >"$log" 2>&1 || true
    if [ "$(lines "$PRIV")" != 1 ] || [ "$(lines "$PUB")" != 1 ]; then
        p11tool --batch --list-all --only-urls "$TOKEN_URL" >"$diag" 2>&1 || true
        fail "expected exactly one tls-client private and one public key URL on '$TOKEN_LABEL' (found $(lines "$PRIV") private, $(lines "$PUB") public; no objects at all usually means X509_SA_SOCK points at the wrong socket or KeyMaster has not attached x509)" \
            "$log" "$diag"
    fi
    case "$PRIV" in *id=*object=* | *object=*id=*) ;; *) fail "private key URL lacks id= or object=: $PRIV" ;; esac
    case "$PUB" in *id=*object=* | *object=*id=*) ;; *) fail "public key URL lacks id= or object=: $PUB" ;; esac
    TOKEN_ID=$(url_id_hex "$PRIV")
    [[ $TOKEN_ID =~ ^[0-9a-f]{64}$ ]] || fail "private key URL id= is not 32 bytes: $PRIV"
    [ "$(url_id_hex "$PUB")" = "$TOKEN_ID" ] || fail "private and public key URLs carry different id="
}

select_key() {
    need_token
    key_urls
    say "private key: $PRIV"
    say "public key:  $PUB"
    ok "exactly one tls-client key pair; shared CKA_ID (SHA-256 of the SPKI) $TOKEN_ID"
}

make_csr() {
    local log
    need_token
    need_files "$TEMPLATE"
    key_urls
    log="$LOGS/make_csr.certtool.txt"
    {
    # >>> runbook make_csr
    certtool --generate-request --load-privkey "$PRIV" --load-pubkey "$PUB" --template "$TEMPLATE" --outfile alice.csr
    # <<< runbook
    } >"$log" 2>&1 || fail "certtool --generate-request failed" "$log"
    say "alice.csr written, signed by the token; $(openssl req -in alice.csr -noout -subject 2>/dev/null)"
    log="$LOGS/make_csr.verify.txt"
    {
    # >>> runbook make_csr.verify
    openssl req -in alice.csr -noout -verify
    # <<< runbook
    } >"$log" 2>&1 || true
    grep -qF 'Certificate request self-signature verify OK' "$log" \
        || fail "the CSR's signature does not verify" "$log"
    ok "CSR self-signature verifies"
    log="$LOGS/make_csr.spki.txt"
    {
    # >>> runbook make_csr.spki
    CSR_ID=$(openssl req -in alice.csr -noout -pubkey | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)
    # <<< runbook
    } >"$log" 2>&1 || fail "could not hash the CSR's public key" "$log"
    [ "$CSR_ID" = "$TOKEN_ID" ] || fail "CSR SPKI sha256 $CSR_ID != token CKA_ID $TOKEN_ID"
    ok "CSR SPKI sha256 == token CKA_ID"
}

ca_issue() {
    local log="$LOGS/ca_issue.openssl.txt"
    need_files alice.csr "$CA_CERT" "$CA_KEY" "$CLIENT_EXT"
    {
    # >>> runbook ca_issue
    openssl x509 -req -in alice.csr -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -extfile "$CLIENT_EXT" -days 365 -out "$CERT_FILE"
    # <<< runbook
    } >"$log" 2>&1 || fail "openssl x509 -req failed" "$log"
    [ -s "$CERT_FILE" ] || fail "$CERT_FILE is empty" "$log"
    say "$CERT_FILE issued by $CA_CERT with the profile in $CLIENT_EXT:"
    openssl x509 -in "$CERT_FILE" -noout -subject -issuer -ext extendedKeyUsage 2>/dev/null | sed 's/^/      /'
    ok "$CERT_FILE written"
}

verify_chain() {
    local log
    need_token
    need_files "$CERT_FILE" "$CA_CERT"
    key_urls
    log="$LOGS/verify_chain.openssl.txt"
    {
    # >>> runbook verify_chain.openssl
    openssl verify -CAfile "$CA_CERT" "$CERT_FILE"
    # <<< runbook
    } >"$log" 2>&1 || true
    grep -qF "$CERT_FILE: OK" "$log" || fail "openssl verify: $CERT_FILE does not verify against $CA_CERT" "$log"
    ok "openssl verify: $CERT_FILE: OK"
    log="$LOGS/verify_chain.certtool.txt"
    {
    # >>> runbook verify_chain.certtool
    cat "$CERT_FILE" "$CA_CERT" | certtool --verify-chain
    # <<< runbook
    } >"$log" 2>&1 || true
    grep -qF 'Chain verification output: Verified. The certificate is trusted.' "$log" \
        || fail "certtool --verify-chain did not verify the chain" "$log"
    ok "certtool --verify-chain: Verified. The certificate is trusted."
    log="$LOGS/verify_chain.spki.txt"
    {
    # >>> runbook verify_chain.spki
    CERT_ID=$(openssl x509 -in "$CERT_FILE" -noout -pubkey | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)
    # <<< runbook
    } >"$log" 2>&1 || fail "could not hash the certificate's public key" "$log"
    [ "$CERT_ID" = "$TOKEN_ID" ] || fail "certificate SPKI sha256 $CERT_ID != token CKA_ID $TOKEN_ID"
    ok "certificate SPKI sha256 == token CKA_ID"
}

# Nothing on the token changes before the write, and no check stands between
# the certificate and C_CreateObject: a certificate KeyMaster refuses (foreign
# key, wrong EKU) reaches pkcs11-tool, and its CKR_ code is printed.
deposit() {
    local log rc=0 n ids certs_rc=0 match
    need_token
    need_files "$CERT_FILE"
    key_urls
    log="$LOGS/deposit.id.txt"
    {
    # >>> runbook deposit.id
    ID=$(openssl x509 -in "$CERT_FILE" -noout -pubkey | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)
    # <<< runbook
    } >"$log" 2>&1 || fail "could not hash the certificate's public key" "$log"
    log="$LOGS/deposit.der.txt"
    {
    # >>> runbook deposit.der
    openssl x509 -in "$CERT_FILE" -outform der -out "$DER_FILE"
    # <<< runbook
    } >"$log" 2>&1 || fail "could not convert $CERT_FILE to DER" "$log"
    say "$DER_FILE written (pkcs11-tool takes DER)"
    # The one deviation from "standard tools, unmodified": on Ubuntu,
    # pkcs11-tool's default module is opensc-pkcs11.so, not p11-kit, so it
    # would never see KeyMaster's token. Through the p11-kit proxy it needs
    # --token-label, otherwise it picks the first token ("System Trust").
    # --id is passed as usual; the module ignores it, since KeyMaster pairs the
    # certificate with its key by SPKI.
    log="$LOGS/deposit.pkcs11-tool.txt"
    {
    # >>> runbook deposit.write
    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/p11-kit-proxy.so --token-label "$TOKEN_LABEL" \
        --write-object "$DER_FILE" --type cert --id "$ID"
    # <<< runbook
    } >"$log" 2>&1 || rc=$?
    if [ "$rc" != 0 ] || ! grep -q '^Created certificate:' "$log"; then
        if [ "$ID" = "$TOKEN_ID" ]; then match=yes; else match=no; fi
        fail "pkcs11-tool --write-object refused $DER_FILE (exit $rc); certificate SPKI sha256 == token CKA_ID: $match" "$log"
    fi
    say "pkcs11-tool: Created certificate"
    [ "$ID" = "$TOKEN_ID" ] || fail "deposited certificate's SPKI sha256 $ID != token CKA_ID $TOKEN_ID"
    ok "certificate SPKI sha256 == token CKA_ID: certificate and key pair"
    log="$LOGS/deposit.list.txt"
    {
    # >>> runbook deposit.list
    p11tool --batch --list-all "$TOKEN_URL"
    # <<< runbook
    } >"$log" 2>&1 || fail "p11tool --list-all failed" "$log"
    n=$(grep -c '^Object' "$log" || true)
    ids=$({ grep -E '^[[:space:]]*ID:' "$log" || true; } | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f' | sort -u)
    [ "$n" = 3 ] && [ "$ids" = "$TOKEN_ID" ] \
        || fail "expected 3 objects with one shared ID $TOKEN_ID (found $n objects, IDs: $(echo $ids))" "$log"
    ok "token lists 3 objects (private key, public key, certificate), one shared ID"
    log="$LOGS/deposit.certs.txt"
    {
    # >>> runbook deposit.certs
    NCERTS=$(p11tool --batch --list-all-certs --only-urls "$TOKEN_URL" | wc -l)
    # <<< runbook
    } >"$log" 2>&1 || certs_rc=$?
    [ "$certs_rc" = 0 ] && [ "$NCERTS" = 1 ] \
        || fail "expected exactly one certificate (p11tool exit $certs_rc, ${NCERTS:-?} line(s))" "$log"
    ok "exactly one certificate on the token"
}

# start_server LOGFILE: gnutls-serv (software key, not the token) in the
# background, output to LOGFILE; returns once the port listens. Stopped by
# stop_server at the end of each handshake step and by the EXIT trap.
start_server() {
    local i
    SERVER_LOG=$1
    need_files "$CA_CERT" "$SERVER_CERT" "$SERVER_KEY"
    ! port_listening || setup_error "port $PORT is already in use; set PORT"
    # stdbuf: gnutls-serv's stdout goes to a file, where it would be block-
    # buffered and could be lost when the server is killed.
    # >>> runbook handshake.server
    stdbuf -oL -eL gnutls-serv --http --port "$PORT" --x509keyfile "$SERVER_KEY" --x509certfile "$SERVER_CERT" \
        --x509cafile "$CA_CERT" --require-client-cert > "$SERVER_LOG" 2>&1 &
    # <<< runbook
    SERVER_PID=$!
    for i in $(seq 100); do
        port_listening && break
        kill -0 "$SERVER_PID" 2>/dev/null || { SERVER_PID=; fail "gnutls-serv exited" "$SERVER_LOG"; }
        sleep 0.1
    done
    port_listening || fail "gnutls-serv not listening on port $PORT after 10 s" "$SERVER_LOG"
    say "gnutls-serv listening on port $PORT (pid $SERVER_PID, log $SERVER_LOG)"
}

handshake() {
    local log="$LOGS/handshake.cert_url.txt" rc=0 cn
    need_token
    need_files "$CERT_FILE"
    key_urls
    {
    # >>> runbook handshake.cert
    CERT=$(p11tool --batch --list-all-certs --only-urls "$TOKEN_URL" | grep 'tls-client')
    # <<< runbook
    } >"$log" 2>&1 || true
    [ "$(lines "$CERT")" = 1 ] || fail "expected exactly one tls-client certificate URL on the token" "$log"
    say "certificate: $CERT"
    cn=$(cert_cn)
    [ -n "$cn" ] || fail "no CN in the subject of $CERT_FILE"
    start_server server-handshake.log
    {
    # >>> runbook handshake.client
    printf 'GET / HTTP/1.0\r\n\r\n' | gnutls-cli --port "$PORT" localhost --x509cafile "$CA_CERT" \
        --x509keyfile "$PRIV" --x509certfile "$CERT" > handshake.log 2>&1
    # <<< runbook
    } || rc=$?
    say "gnutls-cli with key and certificate from the token: exit $rc (log handshake.log)"
    [ "$rc" = 0 ] || fail "gnutls-cli exited $rc" handshake.log "$SERVER_LOG"
    grep -qF -- '- Successfully sent 1 certificate(s) to server.' handshake.log \
        || fail "client did not send its certificate" handshake.log
    ok "client sent 1 certificate"
    awk -v cn="$cn" '/HTTP\/1\.0 200 OK/ { s = 1 } s && index($0, cn) { f = 1 } END { exit !f }' handshake.log \
        || fail "no '$cn' after 'HTTP/1.0 200 OK' (the server's page about its peer)" handshake.log
    ok "HTTP/1.0 200 OK, and the server's page shows the peer $cn"
    wait_for_text "$SERVER_LOG" '- Client Signature: ECDSA-SECP256R1-SHA256' \
        || fail "server log lacks '- Client Signature: ECDSA-SECP256R1-SHA256'" "$SERVER_LOG"
    ok "server verified the client's ECDSA-SECP256R1-SHA256 signature (made by the token)"
    stop_server
}

handshake_without_cert() {
    local rc=0 cn
    need_files "$CERT_FILE"
    cn=$(cert_cn)
    [ -n "$cn" ] || fail "no CN in the subject of $CERT_FILE"
    start_server server-nocert.log
    {
    # >>> runbook handshake_without_cert.client
    printf 'GET / HTTP/1.0\r\n\r\n' | gnutls-cli --port "$PORT" localhost --x509cafile "$CA_CERT" \
        > handshake-nocert.log 2>&1
    # <<< runbook
    } || rc=$?
    say "gnutls-cli without a client certificate: exit $rc (log handshake-nocert.log)"
    [ "$rc" != 0 ] || fail "gnutls-cli without a certificate exited 0" handshake-nocert.log "$SERVER_LOG"
    grep -qF 'Received alert [116]: Certificate is required' handshake-nocert.log \
        || fail "no alert 116 (Certificate is required)" handshake-nocert.log
    ! grep -qF 'HTTP/1.0 200 OK' handshake-nocert.log || fail "the server served a page" handshake-nocert.log
    ! grep -qF -- "$cn" handshake-nocert.log || fail "'$cn' appears in the log" handshake-nocert.log
    # TLS 1.3: the client still prints "- Handshake was completed" before the
    # server's alert arrives, so its absence is not asserted.
    ok "refused: exit $rc, alert 116, no page"
    wait_for_text "$SERVER_LOG" 'Certificate is required' \
        || fail "server log lacks 'Certificate is required'" "$SERVER_LOG"
    ok "server log: Certificate is required"
    stop_server
}

# --- main -----------------------------------------------------------------------

main() {
    local steps s
    [ $# -le 1 ] || { usage >&2; exit 2; }
    case "${1:-}" in
        "") steps=$ALL_STEPS ;;
        -h | --help) usage; exit 0 ;;
        make_test_pki | check_no_cert | select_key | make_csr | ca_issue | verify_chain | deposit \
            | handshake | handshake_without_cert) steps=$1 ;;
        *) usage >&2; exit 2 ;;
    esac

    [ -n "${WORKDIR:-}" ] || setup_error "WORKDIR is not set: the directory to work in (never the caller's cwd)"
    [ -d "$WORKDIR" ] || setup_error "WORKDIR=$WORKDIR is not a directory"
    cd "$WORKDIR"
    if [ -z "${X509_SA_SOCK:-}" ]; then
        setup_error "X509_SA_SOCK is not set. Set it to km-x509-sa's socket (km-x509-sa prints" \
            "X509_SA_SOCK=<path> at startup; in the e2e image /tmp/keymaster-x509-sa.sock)." \
            "Not falling back: without it the module silently uses" \
            "\$XDG_RUNTIME_DIR/keymaster-x509-sa.sock and may list no objects."
    fi
    export X509_SA_SOCK
    LOGS="$PWD/logs"
    mkdir -p "$LOGS"
    trap stop_server EXIT
    trap 'exit 130' INT TERM

    for s in $steps; do
        STEP=$s
        echo "== $s"
        "$s"
    done
    STEP=done
    echo "== all checks passed: $steps"
}

main "$@"
