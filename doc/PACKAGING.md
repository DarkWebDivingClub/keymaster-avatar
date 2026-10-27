# Packaging — System-Level Patches

The keymaster-avatar .deb installs several system-level configuration
files beyond the application binaries and systemd units. This document
explains what each one does and why it exists.

## NetworkManager: bt-nap-unmanaged.conf

**Installed to:** `/etc/NetworkManager/conf.d/bt-nap-unmanaged.conf`

Tells NetworkManager to leave the BT PAN bridge and BNEP interfaces
unmanaged:

```ini
[keyfile]
unmanaged-devices=interface-name:bt-nap-br;interface-name:bnep*
```

**Why:** Without this, NetworkManager detects bt-nap-br as an
externally-managed bridge and takes ownership. After sleep/wake it
strips the bridge's static IP (10.44.0.1/24), which breaks dnsmasq
DHCP — the phone can't get an address and BT PAN connectivity is
lost.

**History:** Initially installed to `/usr/lib/NetworkManager/conf.d/`
(0.6.0-2) but that path isn't read on all Ubuntu installations. Moved
to `/etc/NetworkManager/conf.d/` in 0.6.0-4.

An earlier version also included `interface-name:enx*` to cover
udev-renamed BNEP interfaces, but that inadvertently unmanaged wired
ethernet adapters whose altnames matched the pattern. Removed in
0.6.0-3.

## systemd sleep hook: km-avatar-resume

**Installed to:** `/usr/lib/systemd/system-sleep/km-avatar-resume`

Restarts bt-nap and dnsmasq on system wake:

```bash
case "$1" in
    post)
        systemctl restart bt-nap.service || true
        sleep 2
        systemctl restart dnsmasq.service || true
        ;;
esac
```

**Why:** After sleep, the Bluetooth subsystem resets and the BNEP
connection is torn down. bt-nap needs to re-register its BlueZ NAP
profile so the phone can reconnect. dnsmasq is restarted after a short
delay to ensure the bridge is ready to serve DHCP on the fresh
connection.

**Note:** The phone must still toggle "Internet access" off and on to
re-establish the BT PAN link from its side. This hook only ensures the
host side is ready.

## udev: 70-bnep.link

**Installed to:** `/etc/systemd/network/70-bnep.link`

Prevents udev from renaming BNEP interfaces (e.g., `bnep0` →
`enxf46d3f28644f`):

```ini
[Match]
OriginalName=bnep*

[Link]
NamePolicy=keep
```

**Why:** systemd applies predictable interface naming based on MAC
address. For persistent NICs this provides stable names across
reboots. BNEP interfaces are ephemeral (appear on BT PAN connect,
vanish on disconnect) so stable naming adds no value. Worse, the
rename breaks the BNEP data path — DHCP (broadcast) still works but
unicast IP traffic stops flowing, leaving the connection
non-functional.
