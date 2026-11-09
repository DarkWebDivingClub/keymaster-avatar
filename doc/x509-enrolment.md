# Enrolling an X.509 client certificate through KeyMaster

Status: mission 37.1.5. Test identity: Alice (`alice@atlanta.com`), desktop KeyMaster.

This runbook gives Alice a TLS client certificate issued by a CA that is **not** KeyMaster. Her
private key stays in KeyMaster throughout:

- the token signs the certificate request;
- the CA issues the certificate;
- the certificate is stored back on the token;
- a real TLS client-auth handshake proves it works.

Every tool is standard (GnuTLS, OpenSSL, OpenSC), talking to KeyMaster through the PKCS#11 module
`libkm_pkcs11_x509.so`. There is one deviation, [described below](#the-one-deviation).

**The commands are a script.** [`x509-enrolment.sh`](x509-enrolment.sh) holds every command on this
page, and the code blocks here are copied from it verbatim ([sync check](#keeping-this-page-in-sync)).
`keymaster-e2e-test`'s `X509EnrolmentTest` copies and runs **this exact script** (system property
`x509.enrolment.script`), so what you read here is what the test runs.

For how the pieces fit together, see [x509/overview.md](x509/overview.md).
For OpenVPN with this key, see [x509-openvpn.md](x509-openvpn.md).
For client authentication in a browser, see [x509-browsers.md](x509-browsers.md).

## Prerequisites

- **KeyMaster running, with Alice attached and X.509 selected** (`--also <id>:x509`). km-x509-sa
  answers -32001 until a KeyMaster attaches `x509` ([service.md §3](x509/service.md#3-client-socket-protocol)).
- **km-x509-sa running.** On startup it prints `X509_SA_SOCK=<path>`. The systemd user unit uses
  `$XDG_RUNTIME_DIR/keymaster-x509-sa.sock`; the e2e image uses `/tmp/keymaster-x509-sa.sock`.
- **The module registered with p11-kit.** The package does this with
  `/usr/share/p11-kit/modules/keymaster.module`. For development, use a user module file instead
  ([pkcs11-module.md §10](x509/pkcs11-module.md#10-registering-the-module)).
  `p11tool --list-token-urls` should show `token=KeyMaster%20X.509`.
- **`X509_SA_SOCK` exported**, set to km-x509-sa's socket. The script refuses to run without it. If
  it is unset, the module silently falls back to `$XDG_RUNTIME_DIR/keymaster-x509-sa.sock`, which can
  be the wrong socket.
- **Tools:** GnuTLS 3.8 (`p11tool`, `certtool`, `gnutls-cli`, `gnutls-serv`), OpenSSL 3, p11-kit
  0.26 and OpenSC `pkcs11-tool`. These versions were rehearsed: GnuTLS 3.8.12, OpenSSL 3.5.5,
  p11-kit 0.26.2, OpenSC 0.27.0~rc1.
- **Approval.** With policy ASK, KeyMaster asks once per signature or import request. With `auto`,
  it never asks.
  - Read from the code: `X509ServiceHandler.sign` and `importCert` each call `checkApproval` once per
    request, with default policy ASK; `list` is APPROVE.
  - *(Inferred)* that each such call shows exactly one prompt; `AbstractServiceHandler.checkApproval`
    was not read.
  - A prompt that is not answered in time ends in a timeout (km-x509-sa allows about 70 s).

## Inputs

All inputs come from the environment and default to the names below. Relative paths are relative
to `WORKDIR`. Two inputs are required: `WORKDIR` and `X509_SA_SOCK`. The script changes into `WORKDIR`
itself and never relies on the caller's current directory.

```bash
export X509_SA_SOCK=/tmp/keymaster-x509-sa.sock   # your km-x509-sa socket
export WORKDIR=$HOME/x509-enrolment               # any directory
mkdir -p "$WORKDIR" && cd "$WORKDIR"
```

The defaults, as the script sets them:

<!-- runbook settings -->
```bash
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
```

`CERT_FILE` names the issued certificate (default `alice.crt`). `DER_FILE` is derived from it. This
page uses the defaults throughout.

Three small files must be in `WORKDIR`. The e2e test's copies are in
`keymaster-e2e-test/src/test/resources/x509/`.

`alice.tmpl`, the certtool template for the request. Without a template, certtool prompts:

```text
cn = "alice@atlanta.com"
email = "alice@atlanta.com"
tls_www_client
signing_key
```

`client.ext`, the CA's profile for a TLS client certificate (mission 37's TLS-client row):

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=email:alice@atlanta.com
```

`server.ext`, used only by the test PKI for `gnutls-serv`'s certificate:

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
```

## Running it

From the repository root, with `X509_SA_SOCK` and `WORKDIR` exported. The script changes into
`WORKDIR` itself.

```bash
doc/x509-enrolment.sh make_test_pki   # test only: a throwaway CA and server key
doc/x509-enrolment.sh                 # the enrolment, all steps in order
doc/x509-enrolment.sh deposit         # or one step at a time
```

The script output works like this:

- Each step prints what it did (`STEP: …`) and one `ok   STEP: …` per passed check.
- On the first failed check it prints `FAIL STEP: …`, followed by that command's output (stdout and
  stderr).
- It exits 0 when every check passes, 1 when a check fails and 2 for a setup error (a missing variable
  or input file, or a port already in use).
- The output of every checked command is kept in `$WORKDIR/logs/`.
- Key material is never printed.

Steps run in separate processes when called one at a time. Values that pass between steps, such as
the key URLs and the ID, are therefore recomputed from the token each time, never cached.

To run the blocks below by hand instead, paste them into one shell in `WORKDIR` after the settings
block above.

## Test only: a throwaway PKI (`make_test_pki`)

> **Not part of a real enrolment.** In real use your CA does [step 3](#3-the-ca-issues-ca_issue)
> and you need no server key. This step exists so the runbook can be followed end to end and the
> e2e test runs the same file. Keys are generated at run time and never committed. The step refuses
> to overwrite an existing `$CA_KEY` or `$SERVER_KEY`.

<!-- runbook make_test_pki.ca_key -->
```bash
openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
```

<!-- runbook make_test_pki.ca_cert -->
```bash
openssl req -x509 -new -key "$CA_KEY" -subj "/CN=Test CA 37.1.5" -days 7 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$CA_CERT"
```

<!-- runbook make_test_pki.server_key -->
```bash
openssl ecparam -name prime256v1 -genkey -noout -out "$SERVER_KEY"
```

<!-- runbook make_test_pki.server_csr -->
```bash
openssl req -new -key "$SERVER_KEY" -subj "/CN=localhost" -out server.csr
```

<!-- runbook make_test_pki.server_cert -->
```bash
openssl x509 -req -in server.csr -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -extfile "$SERVER_EXT" -days 7 -out "$SERVER_CERT"
```

**Success:** `openssl verify -CAfile test-ca.pem server.pem` prints `server.pem: OK`.

The result is a P-256 test CA with `CA:TRUE` and `keyCertSign, cRLSign`, valid for 7 days, and a
`CN=localhost` server certificate it signed.

## 0. The token has no certificate yet (`check_no_cert`)

<!-- runbook check_no_cert -->
```bash
p11tool --batch --list-all-certs "$TOKEN_URL"
```

**Success:** `No matching objects found`, and p11tool **exits 2**. For p11tool that means "none", not
an error. The script also checks that the key pair is listed, so an empty answer can't come from a
token that shows nothing at all.

**Proves:** the starting state is clean. The certificate found after step 4 was put there by this
enrolment.

## 1. Select the key (`select_key`)

The token prints the object URLs. The script greps the **role** (`tls-client`), not the account.

<!-- runbook select_key -->
```bash
PRIV=$(p11tool --batch --list-all --only-urls "$TOKEN_URL" | grep 'tls-client' | grep 'type=private')
PUB=$(p11tool --batch --list-all --only-urls "$TOKEN_URL" | grep 'tls-client' | grep 'type=public')
```

**Success:**

- Exactly one line each.
- Both carry `object=alice%40atlanta.com%20tls-client` and the same `id=`. The `id=` is the
  percent-encoded SHA-256 of the key's SubjectPublicKeyInfo, which is the PKCS#11 `CKA_ID`.
- The script prints both URLs and the ID as hex.

**Proves:** KeyMaster serves Alice's TLS client key through the token. Nothing new is derived; the
key is computed from her identity (`IdentityPaths.x509`).

## 2. Request a certificate, signed by the token (`make_csr`)

<!-- runbook make_csr -->
```bash
certtool --generate-request --load-privkey "$PRIV" --load-pubkey "$PUB" --template "$TEMPLATE" --outfile alice.csr
```

Checks:

<!-- runbook make_csr.verify -->
```bash
openssl req -in alice.csr -noout -verify
```

<!-- runbook make_csr.spki -->
```bash
CSR_ID=$(openssl req -in alice.csr -noout -pubkey | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)
```

**Success:**

- `alice.csr` has subject `CN=alice@atlanta.com`; certtool puts the email in the SAN.
- `Certificate request self-signature verify OK`.
- `$CSR_ID` equals the token ID from step 1.

**Proves:** the token signed the request (`C_Sign` → km-x509-sa `sign` → KeyMaster's vault), and the
request carries exactly the key the token reports.

## 3. The CA issues (`ca_issue`)

<!-- runbook ca_issue -->
```bash
openssl x509 -req -in alice.csr -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -extfile "$CLIENT_EXT" -days 365 -out "$CERT_FILE"
```

**Success:** `alice.crt` exists. The script prints its subject (`CN=alice@atlanta.com`), its issuer
(`CN=Test CA 37.1.5`) and its EKU (`TLS Web Client Authentication`).

This is the test CA's command, signed with the CA's own key. KeyMaster is not involved. The CA
applies its own profile (`client.ext`) and ignores the extensions requested in the CSR.

**With a real external CA:** give it `alice.csr` and put the certificate it returns (PEM) at
`$WORKDIR/alice.crt`. Then run the remaining steps one at a time:
`verify_chain`, `deposit`, `handshake`, `handshake_without_cert`.

## 4. Verify the chain (`verify_chain`)

<!-- runbook verify_chain.openssl -->
```bash
openssl verify -CAfile "$CA_CERT" "$CERT_FILE"
```

<!-- runbook verify_chain.certtool -->
```bash
cat "$CERT_FILE" "$CA_CERT" | certtool --verify-chain
```

<!-- runbook verify_chain.spki -->
```bash
CERT_ID=$(openssl x509 -in "$CERT_FILE" -noout -pubkey | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)
```

**Success:**

- `alice.crt: OK`.
- `Chain verification output: Verified. The certificate is trusted.`
- `$CERT_ID` equals the token ID.

**Proves:** the certificate chains to the CA, and it was issued for the token's key and no other.

## 5. Deposit the certificate on the token (`deposit`)

<!-- runbook deposit.id -->
```bash
ID=$(openssl x509 -in "$CERT_FILE" -noout -pubkey | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)
```

<!-- runbook deposit.der -->
```bash
openssl x509 -in "$CERT_FILE" -outform der -out "$DER_FILE"
```

<!-- runbook deposit.write -->
```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/p11-kit-proxy.so --token-label "$TOKEN_LABEL" \
    --write-object "$DER_FILE" --type cert --id "$ID"
```

pkcs11-tool takes **DER**. `--id` is the standard form, but the module ignores it: KeyMaster finds
the key by matching the certificate's SubjectPublicKeyInfo.

Checks after the write:

<!-- runbook deposit.list -->
```bash
p11tool --batch --list-all "$TOKEN_URL"
```

<!-- runbook deposit.certs -->
```bash
NCERTS=$(p11tool --batch --list-all-certs --only-urls "$TOKEN_URL" | wc -l)
```

**Success:**

- pkcs11-tool prints `Created certificate:` and exits 0.
- `$ID` equals the token ID.
- The token lists **three** objects (private key, public key, X.509 certificate) with **one** shared
  ID.
- `$NCERTS` is 1.

**Proves:** KeyMaster accepted the certificate. `X509CertCheck` checks that the SPKI is the key's own
and that the EKU is absent or exactly `clientAuth`. KeyMaster then stored it in the key's
`X509CertSlot` (`x509_cert` in `key-metadata.json`), and the token now pairs certificate and key.

**If KeyMaster refuses** (a certificate for another key, or the wrong EKU such as `serverAuth` or
`clientAuth,emailProtection`):

- pkcs11-tool fails with `CKR_ATTRIBUTE_VALUE_INVALID`.
- The script exits 1 and prints pkcs11-tool's full output, plus whether the certificate's key hash
  matched the token ID.
- Nothing is stored.
- Nothing before the write touches the token, so a refusal leaves the token unchanged.

## 6. Client-auth handshake, key and certificate from the token (`handshake`)

The server uses a software key and certificate, not the token. It writes its log to a file and is
stopped at the end of the step, including on failure. In the script, `SERVER_LOG` is
`server-handshake.log`.

<!-- runbook handshake.server -->
```bash
stdbuf -oL -eL gnutls-serv --http --port "$PORT" --x509keyfile "$SERVER_KEY" --x509certfile "$SERVER_CERT" \
    --x509cafile "$CA_CERT" --require-client-cert > "$SERVER_LOG" 2>&1 &
```

The script waits until the port is listening. It polls `/proc/net/tcp`, which needs no probe
connection, for up to 10 s. `stdbuf` line-buffers the server's output, so the log is complete even
though the server is killed.

<!-- runbook handshake.cert -->
```bash
CERT=$(p11tool --batch --list-all-certs --only-urls "$TOKEN_URL" | grep 'tls-client')
```

<!-- runbook handshake.client -->
```bash
printf 'GET / HTTP/1.0\r\n\r\n' | gnutls-cli --port "$PORT" localhost --x509cafile "$CA_CERT" \
    --x509keyfile "$PRIV" --x509certfile "$CERT" > handshake.log 2>&1
```

The client sends one GET, so it exits by itself. By hand, stop the server afterwards with `kill %1`.

**Success:**

- gnutls-cli exits 0.
- `handshake.log` contains `- Server has requested a certificate.`,
  `- Successfully sent 1 certificate(s) to server.` and `- Handshake was completed`.
- After the `HTTP/1.0 200 OK` line, the log holds the server's HTML page, which contains
  `CN=alice@atlanta.com`. The script asserts that the CN appears **after** the 200 line: that is the
  server reporting the peer it verified, not the client echoing its own certificate.
- The server log contains Alice's certificate and `- Client Signature: ECDSA-SECP256R1-SHA256`.
- The session, as rehearsed: `(TLS1.3-X.509)-(ECDHE-SECP256R1)-(ECDSA-SECP256R1-SHA256)-(AES-256-GCM)`.

**Proves:**

- The certificate works.
- GnuTLS loaded key and certificate from the token.
- The token signed the TLS 1.3 CertificateVerify (one `C_Sign` of a 32-byte digest).
- The server verified Alice's certificate against the CA and accepted her signature.

## 7. Negative control: no client certificate (`handshake_without_cert`)

The script starts the same server, with `SERVER_LOG=server-nocert.log`, then runs:

<!-- runbook handshake_without_cert.client -->
```bash
printf 'GET / HTTP/1.0\r\n\r\n' | gnutls-cli --port "$PORT" localhost --x509cafile "$CA_CERT" \
    > handshake-nocert.log 2>&1
```

**Success:**

- gnutls-cli exits non-zero (1 as rehearsed).
- `*** Received alert [116]: Certificate is required`.
- No `HTTP/1.0 200 OK` and no `CN=alice@atlanta.com` in the log.
- The server log says `Error in handshake: Certificate is required.`

**Proves:** the server really requires a client certificate, so step 6's success came from Alice's
certificate.

## The one deviation

pkcs11-tool is called with
`--module /usr/lib/x86_64-linux-gnu/p11-kit-proxy.so --token-label "KeyMaster X.509"`.

- **Why `--module`:** on Ubuntu, pkcs11-tool's default module is `opensc-pkcs11.so`, not p11-kit, so
  without it pkcs11-tool never sees KeyMaster's token.
- **Why `--token-label`:** through the proxy without a label, pkcs11-tool picks the first token
  ("System Trust").

Every other tool is used unmodified. GnuTLS tools load p11-kit's registered modules by themselves.

## Troubleshooting

These come from the 37.1.4 tool findings ([pkcs11-module.md §8](x509/pkcs11-module.md#tool-findings)) and the hand rehearsal.

| Symptom | Cause and fix |
|---|---|
| `select_key`: no URLs; the token lists no objects | `X509_SA_SOCK` is unset or points at the wrong socket (the module then falls back silently), or no KeyMaster has attached `x509` yet. Check km-x509-sa's startup line and KeyMaster's attach. |
| certtool or gnutls-cli: "requested data were not available" | A token URL was used for the key. GnuTLS needs the **object** URL with `id=`/`object=` that `select_key` prints; `pkcs11:token=…;type=private` alone is not enough. |
| pkcs11-tool does not see the token, or writes to "System Trust" | Missing `--module …/p11-kit-proxy.so` or `--token-label`; see [the deviation](#the-one-deviation). |
| `p11tool --list-all-certs` exits 2 | That is how p11tool reports an empty search (`No matching objects found`). Before deposit, it is the expected answer. |
| `p11tool --list-all-pubkeys` is unknown | p11tool 3.8 does not have it. Use `--list-all --only-urls` and take the `type=public` line. |
| `certtool --verify` refuses a self-signed test certificate | GnuTLS will not use a non-CA self-signed certificate as its own trust anchor ("issuer is not a CA"). Issue from a real CA and use `--verify-chain`, as here. |
| Negative control prints `- Handshake was completed` | That is normal with TLS 1.3: the client prints it before the server's alert arrives. Judge by exit code, alert 116 and the missing page. |
| certtool waits for input | `TEMPLATE` is missing; without a template certtool prompts. |
| openssl: `test-ca.srl` not found | A fresh `WORKDIR` has no serial file; `-CAcreateserial` creates it next to `$CA_CERT`. |
| gnutls-cli cannot read the CA file | Wrong current directory. The script changes into `WORKDIR` itself; by hand, `cd "$WORKDIR"`. |
| `deposit`: `CKR_ATTRIBUTE_VALUE_INVALID` | KeyMaster's import verdict was `KEY_MISMATCH` (the certificate is for another key) or `EKU_MISMATCH` (an EKU other than exactly `clientAuth`). Nothing was stored. |
| `check_no_cert` fails: a certificate is already there | This run is a first enrolment. A token that already holds a certificate is a renewal, which this run does not cover; KeyMaster's import replaces the stored certificate. |
| `deposit` or a signature times out | An ASK prompt was not answered in time (about 70 s). |
| `port 4433 is already in use` | Another server is running there; set `PORT`. |

## Keeping this page in sync

Each block on this page that is preceded by a `<!-- runbook NAME -->` comment is a copy of the lines
between `# >>> runbook NAME` and `# <<< runbook` in `x509-enrolment.sh`, without the function's
4-space indent. Run this from the repository root; it prints nothing but `runbook in sync` when the
two match:

```bash
diff <(awk '/^ *# >>> runbook /{n=$NF;p=1;next} /^ *# <<< runbook/{p=0} p{sub(/^    /,"");print n": "$0}' doc/x509-enrolment.sh) \
     <(awk '/^<!-- runbook /{n=$3;f=1;next} f&&/^```bash$/{p=1;next} p&&/^```$/{p=f=0;next} p{print n": "$0}' doc/x509-enrolment.md) \
  && echo "runbook in sync"
```
