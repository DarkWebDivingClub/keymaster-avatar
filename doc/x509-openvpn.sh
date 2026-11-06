#!/bin/bash
# OpenVPN with a token-held key (mission 37.1.8).
#
# Alice's TLS client key lives in KeyMaster and her certificate is on the
# token "KeyMaster X.509" (enrolled by x509-enrolment.sh, mission 37.1.5).
# This script proves the OpenSSL path first (openssl s_client through
# pkcs11-provider, against a local openssl s_server with a software key, plus
# a negative control), then prepares OpenVPN: it lists the token's
# certificate with openvpn --show-pkcs11-ids, writes a test server config and
# a client config that has pkcs11-providers + pkcs11-id and NO cert and NO
# key, and, once a tunnel is up, checks that it carries traffic. The private
# key never leaves KeyMaster.
#
# Starting and stopping the OpenVPN server and client is environment-specific
# (a network namespace on a laptop, two containers in e2e), so this script
# does not do it: see doc/x509-openvpn.md.
#
# Single source: doc/x509-openvpn.md quotes the commands between the runbook
# marker comments (">>> runbook NAME" ... "<<< runbook") verbatim, in file
# order. Change a command here, then update the md (the sync check is at the
# end of the md).
#
# Usage:
#   x509-openvpn.sh              steps in order:
#                                provider_conf openssl_gate openssl_gate_without_cert
#                                show_ids write_configs
#   x509-openvpn.sh STEP         one step (any of the above, or tunnel_check)
#
# tunnel_check needs a running tunnel (started by hand or by the e2e test), so
# it runs only when named.
#
# It reuses 37.1.5's test PKI in WORKDIR (test-ca.pem, server.pem, server.key)
# and alice.crt, and never creates a key.
#
# Environment:
#   X509_SA_SOCK   required: km-x509-sa's socket (km-x509-sa prints
#                  X509_SA_SOCK=<path> at startup). Never defaulted here.
#   WORKDIR        required: the directory everything is read from and
#                  written to. The script cd's there itself.
#   TOKEN_LABEL    default "KeyMaster X.509"
#   CA_CERT        default test-ca.pem
#   SERVER_CERT    default server.pem    (s_server and the OpenVPN server)
#   SERVER_KEY     default server.key    (s_server and the OpenVPN server)
#   CERT_FILE      default alice.crt     read only for the expected CN
#   GATE_PORT      default 4434          s_server's port
#   OSSL_PKCS11    default /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
#   P11KIT_PROXY   default /usr/lib/x86_64-linux-gnu/p11-kit-proxy.so
#   OSSL_CONF_FILE default ossl-pkcs11.cnf
#   SERVER_ADDR    default 10.98.0.2     the client's "remote"
#   LOCAL_ADDR     default $SERVER_ADDR  the server's "local"; set to "" to
#                                        omit the line (server listens on all
#                                        addresses, as in e2e)
#   VPN_PORT       default 1195
#   VPN_DEV        default tunkm0
#   LOCAL_TUN      default 10.99.0.2     the client's tunnel address
#   PEER_TUN       default 10.99.0.1     the server's tunnel address
# Relative paths are relative to $WORKDIR.
#
# Output: one line per action ("STEP: ..."), "ok   STEP: ..." per passed
# check, "FAIL STEP: ..." followed by the output (stdout and stderr) of the
# command that failed. Every checked command's output is kept in
# $WORKDIR/logs/ or $WORKDIR. Key material is never printed: no key file is
# ever shown, and the TLS session secrets that openssl s_client and the
# s_server -www page print (Master-Key, Resumption PSK, the session ticket)
# are redacted in the script's log files before anything is checked or shown.
#
# Exit status: 0 all checks passed, 1 a check failed, 2 usage or setup error.

set -euo pipefail

# >>> runbook settings
TOKEN_LABEL="${TOKEN_LABEL:-KeyMaster X.509}"
CA_CERT="${CA_CERT:-test-ca.pem}"
SERVER_CERT="${SERVER_CERT:-server.pem}"
SERVER_KEY="${SERVER_KEY:-server.key}"
CERT_FILE="${CERT_FILE:-alice.crt}"
GATE_PORT="${GATE_PORT:-4434}"
OSSL_PKCS11="${OSSL_PKCS11:-/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so}"
P11KIT_PROXY="${P11KIT_PROXY:-/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so}"
OSSL_CONF_FILE="${OSSL_CONF_FILE:-ossl-pkcs11.cnf}"
SERVER_ADDR="${SERVER_ADDR:-10.98.0.2}"
# No colon: unset means $SERVER_ADDR; set to "" means no "local" line.
LOCAL_ADDR="${LOCAL_ADDR-$SERVER_ADDR}"
VPN_PORT="${VPN_PORT:-1195}"
VPN_DEV="${VPN_DEV:-tunkm0}"
LOCAL_TUN="${LOCAL_TUN:-10.99.0.2}"
PEER_TUN="${PEER_TUN:-10.99.0.1}"
TOKEN_URL="pkcs11:token=${TOKEN_LABEL// /%20}"
# <<< runbook

ALL_STEPS="provider_conf openssl_gate openssl_gate_without_cert show_ids write_configs"

STEP=setup
LOGS=
SERVER_PID=
SERVER_LOG=

# --- output -------------------------------------------------------------------

say() { printf '%s: %s\n' "$STEP" "$*"; }
ok() { printf 'ok   %s: %s\n' "$STEP" "$*"; }

# redact FILE...: blank TLS session secrets in place (idempotent). openssl
# s_client prints the session (Master-Key, Resumption PSK, the ticket as a hex
# dump) and the s_server -www page echoes the server's view of it.
redact() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        sed -i -E \
            -e 's/^([[:space:]]*(Master-Key|Resumption PSK|PSK identity|PSK identity hint):).*/\1 [redacted]/' \
            -e 's/^([[:space:]]*[0-9a-f]{4} - ).*/\1[redacted]/' "$f"
    done
}

# fail MESSAGE [LOGFILE...]: print the message and each file (redacted),
# indented; exit 1.
fail() {
    local msg=$1 f
    shift
    printf 'FAIL %s: %s\n' "$STEP" "$msg"
    for f in "$@"; do
        redact "$f"
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
  no STEP: in order: $ALL_STEPS
  STEP:    one of: $ALL_STEPS tunnel_check (needs a running tunnel)
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

need_cmds() {
    local c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || setup_error "missing tool: $c"
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

# expected_cn: sets CN from CERT_FILE, or fails.
expected_cn() {
    need_files "$CERT_FILE"
    CN=$(cert_cn)
    [ -n "$CN" ] || fail "no CN in the subject of $CERT_FILE"
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

# port_listening PORT: is something listening on TCP PORT? Read from
# /proc so no probe connection reaches s_server (its log then holds only the
# real client).
port_listening() {
    local hex
    hex=$(printf ':%04X' "$1")
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

# Writes the OpenSSL config that loads pkcs11-provider next to the default
# provider. Used only through OPENSSL_CONF by the gate's client; the system
# openssl.cnf is not touched.
provider_conf() {
    local log="$LOGS/provider_conf.list.txt" versions
    need_cmds openssl
    # >>> runbook provider_conf
    cat > "$OSSL_CONF_FILE" <<EOF
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = $OSSL_PKCS11
pkcs11-module-path = $P11KIT_PROXY
activate = 1
EOF
    # <<< runbook
    say "$OSSL_CONF_FILE written (pkcs11-provider $OSSL_PKCS11, PKCS#11 module $P11KIT_PROXY)"
    {
    # >>> runbook provider_conf.check
    OPENSSL_CONF="$OSSL_CONF_FILE" openssl list -providers
    # <<< runbook
    } >"$log" 2>&1 || fail "openssl list -providers failed" "$log"
    awk '/^  [^ ]/ { s = $1 } /status: active/ { a[s] = 1 } END { exit !(a["default"] && a["pkcs11"]) }' "$log" \
        || fail "expected providers default and pkcs11, both 'status: active'" "$log"
    versions=$(awk '/^  [^ ]/ { s = $1 } /version:/ { printf "%s%s %s", sep, s, $2; sep = ", " }' "$log")
    ok "providers active: $versions"
}

# key_urls: sets PRIV (the tls-client private key's object URL) and TOKEN_ID
# (its CKA_ID, hex), recomputed from the token every time.
key_urls() {
    local log="$LOGS/$STEP.key_urls.txt" diag="$LOGS/$STEP.token_objects.txt"
    PRIV=
    {
    # >>> runbook key_urls
    PRIV=$(p11tool --batch --list-all --only-urls "$TOKEN_URL" | grep 'tls-client' | grep 'type=private')
    # <<< runbook
    } >"$log" 2>&1 || true
    if [ "$(lines "$PRIV")" != 1 ]; then
        p11tool --batch --list-all --only-urls "$TOKEN_URL" >"$diag" 2>&1 || true
        fail "expected exactly one tls-client private key URL on '$TOKEN_LABEL' (found $(lines "$PRIV"); no objects at all usually means X509_SA_SOCK points at the wrong socket or KeyMaster has not attached x509)" \
            "$log" "$diag"
    fi
    case "$PRIV" in *id=*object=* | *object=*id=*) ;; *) fail "private key URL lacks id= or object=: $PRIV" ;; esac
    TOKEN_ID=$(url_id_hex "$PRIV")
    [[ $TOKEN_ID =~ ^[0-9a-f]{64}$ ]] || fail "private key URL id= is not 32 bytes: $PRIV"
}

# start_gate_server LOGFILE: openssl s_server (software key, not the token) in
# the background, output to LOGFILE; returns once the port listens. Stopped by
# stop_server at the end of each gate step and by the EXIT trap.
start_gate_server() {
    local i
    SERVER_LOG=$1
    need_files "$CA_CERT" "$SERVER_CERT" "$SERVER_KEY"
    ! port_listening "$GATE_PORT" || setup_error "port $GATE_PORT is already in use; set GATE_PORT"
    # stdbuf: s_server's stdout goes to a file, where it would be block-
    # buffered and could be lost when the server is killed.
    # >>> runbook openssl_gate.server
    stdbuf -oL -eL openssl s_server -accept "$GATE_PORT" -cert "$SERVER_CERT" -key "$SERVER_KEY" -CAfile "$CA_CERT" \
        -Verify 1 -verify_return_error -www > "$SERVER_LOG" 2>&1 &
    # <<< runbook
    SERVER_PID=$!
    for i in $(seq 100); do
        port_listening "$GATE_PORT" && break
        kill -0 "$SERVER_PID" 2>/dev/null || { SERVER_PID=; fail "openssl s_server exited" "$SERVER_LOG"; }
        sleep 0.1
    done
    port_listening "$GATE_PORT" || fail "openssl s_server not listening on port $GATE_PORT after 10 s" "$SERVER_LOG"
    say "openssl s_server listening on port $GATE_PORT (pid $SERVER_PID, log $SERVER_LOG)"
}

openssl_gate() {
    local log="$LOGS/openssl_gate.cert_url.txt" rc=0 sig
    need_cmds openssl p11tool stdbuf
    need_token
    [ -f "$OSSL_CONF_FILE" ] || setup_error "missing $OSSL_CONF_FILE (in $PWD): run provider_conf first"
    expected_cn
    key_urls
    {
    # >>> runbook openssl_gate.cert
    CERT=$(p11tool --batch --list-all-certs --only-urls "$TOKEN_URL" | grep 'tls-client')
    # <<< runbook
    } >"$log" 2>&1 || true
    [ "$(lines "$CERT")" = 1 ] || fail "expected exactly one tls-client certificate URL on the token" "$log"
    say "private key: $PRIV"
    say "certificate: $CERT"
    start_gate_server server-gate.log
    {
    # >>> runbook openssl_gate.client
    printf 'GET / HTTP/1.0\r\n\r\n' | OPENSSL_CONF="$OSSL_CONF_FILE" openssl s_client -connect localhost:"$GATE_PORT" \
        -CAfile "$CA_CERT" -cert "$CERT" -key "$PRIV" -verify_return_error -ign_eof > gate.log 2>&1
    # <<< runbook
    } || rc=$?
    redact gate.log
    say "openssl s_client with key and certificate from the token: exit $rc (log gate.log)"
    [ "$rc" = 0 ] || fail "openssl s_client exited $rc" gate.log "$SERVER_LOG"
    grep -qF 'Protocol: TLSv1.3' gate.log || fail "no 'Protocol: TLSv1.3'" gate.log
    ok "exit 0, Protocol: TLSv1.3"
    awk -v cn="$CN" '/Client certificate/ { s = 1 } s && index($0, cn) { f = 1 } END { exit !f }' gate.log \
        || fail "no '$CN' after 'Client certificate' (the server's page about its peer)" gate.log
    ok "the server's page shows a Client certificate section with $CN"
    sig=$(sed -n 's/^Peer signature type: *//p' gate.log | tail -n 1)
    [ -z "$sig" ] || say "server page: Peer signature type: $sig"
    wait_for_text "$SERVER_LOG" "depth=0 $CN" || fail "server log lacks 'depth=0 $CN'" "$SERVER_LOG"
    ok "s_server log: depth=0 $CN (the server verified Alice's certificate)"
    stop_server
    redact "$SERVER_LOG"
}

# Negative control. The client still prints "Verify return code: 0 (ok)" here:
# that is the client checking the SERVER's certificate, so it is no signal.
# No OPENSSL_CONF: without -cert/-key nothing needs the token (as rehearsed,
# the token is untouched).
openssl_gate_without_cert() {
    local rc=0
    need_cmds openssl p11tool stdbuf
    expected_cn
    start_gate_server server-gate-nocert.log
    {
    # >>> runbook openssl_gate_without_cert.client
    printf 'GET / HTTP/1.0\r\n\r\n' | openssl s_client -connect localhost:"$GATE_PORT" -CAfile "$CA_CERT" \
        -verify_return_error -ign_eof > gate-nocert.log 2>&1
    # <<< runbook
    } || rc=$?
    redact gate-nocert.log
    say "openssl s_client without a client certificate: exit $rc (log gate-nocert.log)"
    [ "$rc" != 0 ] || fail "openssl s_client without a certificate exited 0" gate-nocert.log "$SERVER_LOG"
    grep -qF 'certificate required' gate-nocert.log || fail "no 'certificate required' alert" gate-nocert.log
    grep -qF 'alert number 116' gate-nocert.log || fail "no 'alert number 116'" gate-nocert.log
    ! grep -qF 'Client certificate' gate-nocert.log || fail "the server served its page" gate-nocert.log
    ! grep -qF -- "$CN" gate-nocert.log || fail "'$CN' appears in the log" gate-nocert.log
    ok "refused: exit $rc, alert 116 (certificate required), no page"
    wait_for_text "$SERVER_LOG" 'peer did not return a certificate' \
        || fail "server log lacks 'peer did not return a certificate'" "$SERVER_LOG"
    ok "s_server log: peer did not return a certificate"
    stop_server
    redact "$SERVER_LOG"
}

# pkcs11-id is pkcs11-helper's serialised id, NOT a pkcs11: URI. It is taken
# from --show-pkcs11-ids on every run, never hard-coded: it contains the
# CKA_ID (SHA-256 of the key's SPKI), so it changes with the key.
show_ids() {
    local log="$LOGS/show_ids.openvpn.txt" rc=0 n dn id label hex
    need_cmds openvpn p11tool
    need_token
    expected_cn
    key_urls
    {
    # >>> runbook show_ids
    openvpn --show-pkcs11-ids "$P11KIT_PROXY" > show-pkcs11-ids.txt 2>&1
    # <<< runbook
    } || rc=$?
    cp show-pkcs11-ids.txt "$log"
    say "openvpn --show-pkcs11-ids: exit $rc (log show-pkcs11-ids.txt)"
    [ "$rc" = 0 ] || fail "openvpn --show-pkcs11-ids exited $rc" show-pkcs11-ids.txt
    n=$(grep -c '^ *Certificate *$' show-pkcs11-ids.txt || true)
    [ "$n" = 1 ] || fail "expected exactly one Certificate block (found $n)" show-pkcs11-ids.txt
    dn=$(sed -n 's/^ *DN: *//p' show-pkcs11-ids.txt)
    [ "$dn" = "$CN" ] || fail "expected DN $CN, got '$dn'" show-pkcs11-ids.txt
    ok "exactly one Certificate, DN $CN"
    {
    # >>> runbook show_ids.extract
    sed -n 's/^ *Serialized id: *//p' show-pkcs11-ids.txt > pkcs11-id
    # <<< runbook
    } || fail "could not extract the Serialized id" show-pkcs11-ids.txt
    [ "$(wc -l < pkcs11-id)" = 1 ] || fail "expected exactly one 'Serialized id:' line" show-pkcs11-ids.txt pkcs11-id
    id=$(cat pkcs11-id)
    [[ $id != *"'"* && $id != *[[:space:]]* ]] || fail "the Serialized id contains a quote or whitespace: $id"
    # manufacturer/model/serial/label/CKA_ID; pkcs11-helper escapes space and
    # dot in the label as \x20 and \x2E.
    label=${TOKEN_LABEL// /\\x20}
    label=${label//./\\x2E}
    [[ $id == "DWDC/KeyMaster/0000000000000001/$label/"* ]] \
        || fail "Serialized id does not start with DWDC/KeyMaster/0000000000000001/$label/: $id"
    hex=${id##*/}
    [[ $hex =~ ^[0-9A-F]{64}$ ]] || fail "Serialized id does not end in 64 upper-case hex digits: $id"
    [ "$hex" = "${TOKEN_ID^^}" ] || fail "Serialized id's CKA_ID $hex != the token's CKA_ID ${TOKEN_ID^^}"
    say "pkcs11-id: $id"
    ok "pkcs11-id written: token DWDC/KeyMaster/0000000000000001/$label, CKA_ID == the key's"
}

write_configs() {
    local id want got
    [ -f pkcs11-id ] || setup_error "missing pkcs11-id (in $PWD): run show_ids first"
    [ "$(wc -l < pkcs11-id)" = 1 ] || setup_error "pkcs11-id must hold exactly one line: run show_ids again"
    id=$(cat pkcs11-id)
    [[ -n $id && $id != *"'"* ]] || setup_error "pkcs11-id is empty or contains a quote: run show_ids again"
    # >>> runbook write_configs.server
    cat > server.ovpn <<EOF
dev $VPN_DEV
dev-type tun
proto udp
EOF
    [ -z "$LOCAL_ADDR" ] || printf 'local %s\n' "$LOCAL_ADDR" >> server.ovpn
    cat >> server.ovpn <<EOF
port $VPN_PORT
tls-server
ifconfig $PEER_TUN $LOCAL_TUN
ca $CA_CERT
cert $SERVER_CERT
key $SERVER_KEY
dh none
remote-cert-tls client
ping 5
verb 4
EOF
    # <<< runbook
    if [ -n "$LOCAL_ADDR" ]; then
        grep -qx "local $LOCAL_ADDR" server.ovpn || fail "server.ovpn lacks 'local $LOCAL_ADDR'" server.ovpn
        say "server.ovpn written (local $LOCAL_ADDR, port $VPN_PORT, dev $VPN_DEV)"
    else
        ! grep -q '^local ' server.ovpn || fail "LOCAL_ADDR is empty but server.ovpn has a 'local' line" server.ovpn
        say "server.ovpn written (no 'local': all addresses, port $VPN_PORT, dev $VPN_DEV)"
    fi
    # >>> runbook write_configs.client
    cat > alice-test.ovpn <<EOF
dev $VPN_DEV
dev-type tun
proto udp
remote $SERVER_ADDR $VPN_PORT
nobind
tls-client
ifconfig $LOCAL_TUN $PEER_TUN
ca $CA_CERT
remote-cert-tls server
pkcs11-providers $P11KIT_PROXY
ping 5
verb 4
EOF
    # <<< runbook
    # printf %s keeps the backslashes literally; the single quotes stop
    # OpenVPN from interpreting them.
    # >>> runbook write_configs.pkcs11_id
    printf "pkcs11-id '%s'\n" "$(cat pkcs11-id)" >> alice-test.ovpn
    # <<< runbook
    say "alice-test.ovpn written (remote $SERVER_ADDR $VPN_PORT, dev $VPN_DEV)"
    ! grep -qE '^[[:space:]]*(cert|key|pkcs12)([[:space:]]|$)' alice-test.ovpn \
        || fail "alice-test.ovpn has a cert, key or pkcs12 line" alice-test.ovpn
    ok "alice-test.ovpn has no cert, key or pkcs12 line"
    [ "$(grep -c '^pkcs11-id ' alice-test.ovpn)" = 1 ] || fail "expected exactly one pkcs11-id line" alice-test.ovpn
    want="pkcs11-id '$id'"
    got=$(grep '^pkcs11-id ' alice-test.ovpn)
    [ "$got" = "$want" ] || fail "the pkcs11-id line does not match pkcs11-id byte for byte" alice-test.ovpn pkcs11-id
    ok "exactly one pkcs11-id line, equal to pkcs11-id (backslashes intact)"
}

# Needs a running tunnel: the OpenVPN client with alice-test.ovpn on this host
# and the server reachable at SERVER_ADDR.
tunnel_check() {
    local log="$LOGS/tunnel_check.route.txt"
    need_cmds ip ping
    {
    # >>> runbook tunnel_check.route
    ip route get "$PEER_TUN"
    # <<< runbook
    } >"$log" 2>&1 || fail "ip route get $PEER_TUN failed" "$log"
    awk -v d="$VPN_DEV" '{ for (i = 1; i < NF; i++) if ($i == "dev" && $(i + 1) == d) f = 1 } END { exit !f }' "$log" \
        || fail "the route to $PEER_TUN does not go via dev $VPN_DEV (is the tunnel up?)" "$log"
    ok "route to $PEER_TUN: dev $VPN_DEV"
    log="$LOGS/tunnel_check.ping.txt"
    {
    # >>> runbook tunnel_check.ping
    ping -c3 -W2 "$PEER_TUN"
    # <<< runbook
    } >"$log" 2>&1 || fail "ping $PEER_TUN failed" "$log"
    grep -qF ' 3 received' "$log" || fail "expected 3 of 3 replies" "$log"
    ok "ping $PEER_TUN: 3/3 through the tunnel"
}

# --- main -----------------------------------------------------------------------

main() {
    local steps s
    [ $# -le 1 ] || { usage >&2; exit 2; }
    case "${1:-}" in
        "") steps=$ALL_STEPS ;;
        -h | --help) usage; exit 0 ;;
        provider_conf | openssl_gate | openssl_gate_without_cert | show_ids | write_configs | tunnel_check) steps=$1 ;;
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
