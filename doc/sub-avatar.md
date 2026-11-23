# Sub-avatars: a container that sees only some of your keys

A **sub-avatar** is a second `keymaster-avatar` on the same host, attached
to the phone as a **realm of its own**. A realm serves only the identities
you choose when you attach it. Bind the sub-avatar's socket directory into
a container instead of the host avatar's, and software in that container
can use only those identities.

Typical use: a development container where an agent runs. It should sign
with your work key, and never see your private one.

```
phone (KeyMaster)
 ├── realm "laptop"     alice@atlanta.com, alice@home.net
 │     └── km-avatar                   → /run/keymaster-avatar/api-1000.sock   (host)
 └── realm "dc01-dn50"  alice@atlanta.com
       └── km-avatar@dc01-dn50         → /run/keymaster-sub/dc01-dn50/api-1000.sock
                                            bind-mounted at /host/sa in the container
```

Both avatars share one Bluetooth link to the phone. That needs
KeyMaster for Android **0.6.1 or newer**. Per-realm **Detach**, which
the steps below use, needs **0.6.2**.

## The example

| | |
|---|---|
| Host user | `alice`, uid 1000 |
| Container | `dc01-dn50`, an unprivileged user LXC |
| Identities on the phone | `alice@atlanta.com` (work), `alice@home.net` (private) |
| Goal | the container sees only `alice@atlanta.com`; the host still sees both |

Replace these with your own names. Every path below that contains
`dc01-dn50` is per instance: one sub-avatar per container.

## Before you start

- The host avatar works: `km-avatar`, `rfcomm-relay` and `strfry` run, the
  phone is attached, and `ssh-add -l` on the host lists your keys.
- The container has `keymaster-avatar` installed, with `km-avatar`,
  `strfry` and `rfcomm-relay` **masked** inside it. The container runs only
  the service avatars (`km-ssh-sa`, `km-gpg-sa`, `km-nostr-sa`,
  `km-x509-sa`).
- `qrencode` on the host (`sudo apt install qrencode`).
- In the container, `SSH_AUTH_SOCK` and `GNUPGHOME` come from the
  package's `/etc/profile.d/keymaster.sh` at login, as on the host.

## 1. The systemd template (host)

The package does not ship a template yet, so create it by hand. It is
`km-avatar.service` with every path moved under the instance name `%i`.

`/etc/systemd/system/km-avatar@.service`:

```ini
[Unit]
Description=KeyMaster sub-avatar %i
After=network-online.target strfry.service km-avatar.service
Wants=network-online.target

[Service]
Type=simple
User=km-avatar
AmbientCapabilities=CAP_CHOWN CAP_SETUID CAP_SETGID
ExecStart=/usr/bin/keymaster-avatar --config /etc/keymaster-avatar/%i/avatar.toml
Restart=on-failure
RestartSec=5
RuntimeDirectory=keymaster-sub/%i
RuntimeDirectoryPreserve=yes
StateDirectory=keymaster-sub/%i

[Install]
WantedBy=multi-user.target
```

| Per instance | Path |
|---|---|
| Config | `/etc/keymaster-avatar/<name>/avatar.toml`, `users.toml` |
| Sockets (bind this into the container) | `/run/keymaster-sub/<name>/` |
| Seed (created on first start) | `/var/lib/keymaster-sub/<name>/seed` |

## 2. The instance config (host)

`/etc/keymaster-avatar/dc01-dn50/avatar.toml`. Copy `relay`, `bt_addr`
and `rfcomm_channel` from the host avatar's
`/etc/keymaster-avatar/avatar.toml`. The sub-avatar uses the same relay and
the same phone link.

```toml
# Sub-avatar for the dc01-dn50 container. Realm: alice@atlanta.com.
relay = "ws://localhost:7777"
bt_addr = "AA:BB:CC:DD:EE:FF"
rfcomm_channel = 5
log_level = "info"
seed_file = "/var/lib/keymaster-sub/dc01-dn50/seed"
local_api_socket = "/run/keymaster-sub/dc01-dn50"
users_file = "/etc/keymaster-avatar/dc01-dn50/users.toml"
descriptor_path = "/run/keymaster-sub/dc01-dn50/descriptor.json"
service_avatar_dir = "/usr/lib/keymaster-avatar/bin"
```

Create an empty `users.toml` for now. Its one entry is only known after the
attach (step 4).

```sh
sudo touch /etc/keymaster-avatar/dc01-dn50/users.toml
sudo systemctl daemon-reload
sudo systemctl enable --now km-avatar@dc01-dn50
```

## 3. Attach it as a new realm (phone)

```sh
qrencode -t UTF8 < /run/keymaster-sub/dc01-dn50/descriptor.json
```

In the app, open the page of the identity the container should use
(`alice@atlanta.com`), press **+ Attach** and scan the QR.

- If that identity has no realm yet, the new realm is created with it as
  the main identity. Leave every **additional identity** unticked.
- If it already has a realm (for example the host's), pick **New realm…**,
  name it `dc01-dn50`, and again tick no additional identities.

Do not add the QR to an existing realm: the container would then see
everything that realm serves.

## 4. Map the realm to the host user (host)

The realm's identity is a 64-character hex key, and it appears in the log
at the attach:

```sh
journalctl -u km-avatar@dc01-dn50 | grep "No user mapping"
# WARN keymaster_avatar: No user mapping for identity 4ed849f7…1fe5 — no per-user API socket
```

Put it in `/etc/keymaster-avatar/dc01-dn50/users.toml` with the host user
whose uid the container uses:

```toml
[[user]]
npub = "4ed849f7719e542dee664bbb9b0f0befa0bfebc2eac81d5d57199557aa991fe5"
unix_user = "alice"
```

The avatar reads `users.toml` only at start-up, so restart it:

```sh
sudo systemctl restart km-avatar@dc01-dn50
```

The phone does not re-attach a restarted avatar by itself yet. In the app,
press **Detach** on the `dc01-dn50` realm only, not "Detach all…". Then
scan the QR from step 3 again into that identity's new realm. Check:

```sh
sudo ls -l /run/keymaster-sub/dc01-dn50/
# srwx------ 1 alice alice 0 … api-1000.sock
```

## 5. Point the container at the sub-avatar

**Bind mount.** In the container's LXC config
(`~/.local/share/lxc/dc01-dn50/config`), bind the sub-avatar's directory,
not `/run/keymaster-avatar`:

```
lxc.mount.entry = /run/keymaster-sub/dc01-dn50 host/sa none bind,create=dir
```

**uid mapping.** The socket is owned by host uid 1000 with mode `0700`.
In an unprivileged container, map that uid straight through, or the
container user cannot open it:

```
lxc.idmap = u 0 100000 1000
lxc.idmap = u 1000 1000 1
lxc.idmap = u 1001 101001 64535
lxc.idmap = g 0 100000 1000
lxc.idmap = g 1000 1000 1
lxc.idmap = g 1001 101001 64535
```

(The host also needs `alice:1000:1` in `/etc/subuid` and `/etc/subgid`.)

**Service avatars in the container.** They must use `/host/sa`. Put one
drop-in per service avatar, for all users, in
`/etc/systemd/user/<unit>.d/override.conf` inside the container:

```ini
# /etc/systemd/user/km-ssh-sa.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/lib/keymaster-avatar/bin/km-ssh-sa --avatar-socket /host/sa/api-%U.sock --agent-socket %t/keymaster-ssh-agent.sock
```

```ini
# /etc/systemd/user/km-gpg-sa.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/lib/keymaster-avatar/bin/km-gpg-sa --avatar-socket /host/sa/api-%U.sock --gnupg-home %t/gnupg-keymaster
```

```ini
# /etc/systemd/user/km-nostr-sa.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/lib/keymaster-avatar/bin/km-nostr-sa --avatar-socket /host/sa/api-%U.sock --listen-socket %t/keymaster-nostr-sa.sock
```

```ini
# /etc/systemd/user/km-x509-sa.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/lib/keymaster-avatar/bin/km-x509-sa --avatar-socket /host/sa/api-%U.sock --listen-socket %t/keymaster-x509-sa.sock
```

Restart the container so that the new bind takes effect, then, as `alice`
inside it:

```sh
systemctl --user daemon-reload
systemctl --user restart km-ssh-sa km-gpg-sa km-nostr-sa km-x509-sa
```

A container whose network interface is wired by hand loses it on restart.
Wire it again before you test anything that needs the network.

## 6. Check it

| Where | Command | Expect |
|---|---|---|
| Container | `ssh-add -L` | only `alice@atlanta.com` |
| Host | `ssh-add -L` | `alice@atlanta.com` and `alice@home.net` |
| Container | `gpg -K` | only the `alice@atlanta.com` key |
| Container | `git commit -S …` then `git log --show-signature -1` | signed by `alice@atlanta.com` |
| Host | `sudo systemctl restart km-avatar@dc01-dn50`, then `ssh-add -l` | the host still works |
| Container | after `sudo systemctl restart km-avatar` on the host, `ssh-add -l` | the container still works |

Each restart in the last two rows needs a re-attach of that avatar on the
phone (Detach that realm, rescan), as in step 4.

The container now has only `alice@atlanta.com`. Any server it logs in to
or pushes to, such as a git host, must know that key. A key that was
registered only for `alice@home.net` no longer works from the container.

## Troubleshooting

| Symptom | Cause |
|---|---|
| No `api-<uid>.sock` under `/run/keymaster-sub/<name>/` | `users.toml` has no entry for the realm identity, or the avatar was not restarted after you added it |
| `ssh-add -l` in the container: "Could not open a connection" | the service avatars still point at `/run/keymaster-avatar`, or the uid is not mapped through |
| The container lists the host's keys | the bind still mounts `/run/keymaster-avatar`; check `ls -l /host/sa` in the container |
| The container lists `alice@home.net` | the QR was added to an existing realm, or `alice@home.net` was ticked as an additional identity; detach that realm and attach again |
| One avatar works, the other is never attached again | it was restarted, and the phone does not re-attach restarted avatars by itself yet; Detach that realm and rescan |
