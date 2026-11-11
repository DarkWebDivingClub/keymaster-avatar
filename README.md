# KeyMaster Avatar

The Avatar is the desktop-side component of KeyMaster. It bridges SSH,
GPG and Nostr signing to your phone over Bluetooth. Desktop
applications talk to local service avatars, which forward cryptographic
operations through a local Nostr relay to the KeyMaster app on your
phone, where the private keys live. **Your keys never leave the
phone** — the desktop only ever sends things to be signed and receives
signatures back.

A fourth service avatar, `km-x509-sa`, gives PKCS#11 software access to
X.509 keys through the token "KeyMaster X.509". X.509 keys are not on the
phone yet; they arrive with mission 37.2, and until then the token lists
no keys.

```
 +-----------+     +----------------+     +-----------+
 | Desktop   |     | Service        |     | km-avatar |
 | apps      |---->| avatars        |---->| (system   |
 | ssh / gpg |     | km-ssh-sa      |     |  service) |
 | / nostr   |     | km-gpg-sa      |     +-----+-----+
 | / pkcs11  |     | km-nostr-sa    |           | websocket
 +-----------+     | km-x509-sa     |           |
                   +----------------+           v
                                          +-----------+
                                          |  strfry   |
                                          |   relay   |
                                          |   :7777   |
                                          +-----------+
                                                ^ websocket
                                                |
                                       +--------------------+
                                       |   rfcomm-relay     |
                                       +--------------------+
                                                ^ RFCOMM, Bluetooth
                                                |   channel 3
                                       +--------------------+
                                       | KeyMaster Android  |
                                       |  (private keys)    |
                                       +--------------------+
```

The phone reaches the desktop over **RFCOMM**, a raw serial stream over
Bluetooth Classic — no IP, no DHCP, no Wi-Fi. `rfcomm-relay` accepts
that connection and bridges it to the local relay over a WebSocket;
`km-avatar` is a WebSocket client of the same relay. The avatar
advertises which adapter and channel to dial in
`/run/keymaster-avatar/descriptor.json`, which the phone reads from the
attach QR code.

Bluetooth PAN (`bt-nap`) was the earlier transport and is being
retired — it is a `Suggests`, not a dependency, and carries no KeyMaster
traffic.

## Components

| Component | Type | Description |
|-----------|------|-------------|
| strfry | System service | Nostr relay on port 7777 — the hub both sides connect to |
| rfcomm-relay | System service | Accepts the phone's RFCOMM connection, bridges it to the relay |
| km-avatar | System service | Avatar daemon, per-user API sockets |
| km-ssh-sa | User service | SSH agent bridged to Avatar |
| km-gpg-sa | User service | GPG agent bridged to Avatar |
| km-nostr-sa | User service | Nostr signing bridged to Avatar |
| km-x509-sa | User service | X.509 keys for PKCS#11 software, bridged to Avatar (on the phone from mission 37.2) |

## Getting Started

- **[Getting Started — Newbie](getting-started-newbi.md)** —
  Install, configure, connect your phone, and verify everything
  works. Start here.
- **[Getting Started — Developer](getting-started-developer.md)** —
  Build from source, crate structure, packaging.
- **[Reconnect Guide](doc/RECONNECT.md)** — Diagnose and fix
  broken connections after sleep, travel, or network changes.
- **[KeyMaster Android](https://github.com/DarkWebDivingClub/keymaster-android)** —
  The phone app (needed for the phone-as-signer setup).

## License

This project is licensed under the GNU General Public License v3.0
only (`GPL-3.0-only`).
