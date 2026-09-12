#!/usr/bin/env bash
# Build a stock Debian rootfs for an iso guest into a directory.
#
# The host does not care what runs inside a VM: it provides the kernel, the
# block device, a TAP, a vsock and the boot arguments. This produces a plain
# Debian userland that fits that contract, so agents get the apt and file
# layout they expect. `isoctl bake --distro debian` runs it against the
# mounted template volume; the live test runs it into a directory and packs
# that with `mkfs.ext4 -d`.
#
# Needs root (or a user namespace: see MODE) and `mmdebstrap` on PATH — on a
# Debian or Ubuntu host `apt install mmdebstrap`.
#
# Environment:
#   ROOTFS_DIR        target directory (required)
#   AGENT_BIN         static iso-guest-agent binary (required)
#   AUTHORIZED_KEYS   file of ssh public keys for the coder user (optional)
#   CA_CERT           the host's egress-proxy CA to trust (optional)
#   SUITE             Debian suite (default: bookworm)
#   MIRROR            apt mirror; https, since the egress proxy passes only TLS
#                     (default: https://deb.debian.org/debian)
#   SNAPSHOT          a snapshot.debian.org timestamp such as 20260901T000000Z;
#                     when set, pins the mirror to it for reproducible bytes
#   EXTRA_PACKAGES    comma-separated packages on top of the base set
#   MODE              mmdebstrap --mode (default: root; `unshare` for unprivileged)
set -euo pipefail

: "${ROOTFS_DIR:?ROOTFS_DIR is required}"
: "${AGENT_BIN:?AGENT_BIN is required}"
SUITE="${SUITE:-bookworm}"
MODE="${MODE:-root}"
MIRROR="${MIRROR:-https://deb.debian.org/debian}"
SECURITY_MIRROR="https://security.debian.org/debian-security"
if [ -n "${SNAPSHOT:-}" ]; then
  MIRROR="https://snapshot.debian.org/archive/debian/${SNAPSHOT}/"
  SECURITY_MIRROR="https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/"
fi
command -v mmdebstrap >/dev/null || { echo "build-rootfs: mmdebstrap not found on PATH" >&2; exit 1; }
[ -x "$AGENT_BIN" ] || { echo "build-rootfs: AGENT_BIN $AGENT_BIN is not executable" >&2; exit 1; }

# The base set: an init, a shell, ssh, sudo, TLS roots, and the tools an agent
# reaches for first. Everything else is a `sudo apt install` away.
PACKAGES="systemd,systemd-sysv,udev,dbus,openssh-server,sudo,ca-certificates,curl,wget,git,gnupg,less,vim,nano,procps,psmisc,iproute2,iputils-ping,netbase,locales,file,xz-utils,unzip,build-essential,python3,python3-venv,python3-pip,jq,ripgrep,fd-find"
if [ -n "${EXTRA_PACKAGES:-}" ]; then
  PACKAGES="$PACKAGES,$EXTRA_PACKAGES"
fi

APTOPTS=()
if [ -n "${SNAPSHOT:-}" ]; then
  # Snapshot Release files are old by design.
  APTOPTS+=(--aptopt='Acquire::Check-Valid-Until "false"')
fi

echo "build-rootfs: mmdebstrap $SUITE from $MIRROR into $ROOTFS_DIR" >&2
mmdebstrap --mode="$MODE" --variant=apt --format=directory \
  --include="$PACKAGES" \
  "${APTOPTS[@]}" \
  --components=main \
  "$SUITE" "$ROOTFS_DIR" "$MIRROR"

R="$ROOTFS_DIR"
in_chroot() { chroot "$R" "$@"; }

# --- apt sources: https only, with security ---
cat > "$R/etc/apt/sources.list" <<SRC
deb $MIRROR $SUITE main
deb $SECURITY_MIRROR $SUITE-security main
SRC
if [ -n "${SNAPSHOT:-}" ]; then
  echo 'Acquire::Check-Valid-Until "false";' > "$R/etc/apt/apt.conf.d/80snapshot"
fi

# --- the coder user: uid 1000, passwordless sudo, key-only ssh ---
in_chroot useradd --uid 1000 --user-group --create-home --shell /bin/bash --comment "iso workspace user" coder
echo 'coder ALL=(ALL) NOPASSWD: ALL' > "$R/etc/sudoers.d/coder"
chmod 0440 "$R/etc/sudoers.d/coder"
install -d -m 0700 -o 1000 -g 1000 "$R/home/coder/.ssh"
if [ -n "${AUTHORIZED_KEYS:-}" ] && [ -f "$AUTHORIZED_KEYS" ]; then
  grep -v -E '^\s*(#|$)' "$AUTHORIZED_KEYS" > "$R/home/coder/.ssh/authorized_keys" || true
  chown 1000:1000 "$R/home/coder/.ssh/authorized_keys"
  chmod 0600 "$R/home/coder/.ssh/authorized_keys"
fi
cat > "$R/etc/ssh/sshd_config.d/iso.conf" <<'SSHD'
PasswordAuthentication no
PermitRootLogin prohibit-password
SSHD
# ssh host keys are generated at first boot by ssh-keygen -A (Debian's unit
# does this when they are missing), so every clone of a template shares the
# ones the bake's boot generated — same as the NixOS image.

# --- the guest agent: static binary, a unit that runs it as coder on vsock ---
install -m 0755 "$AGENT_BIN" "$R/usr/local/bin/iso-guest-agent"
cat > "$R/etc/systemd/system/iso-guest-agent.service" <<'UNIT'
[Unit]
Description=iso guest agent (host exec and file access over vsock)
After=systemd-user-sessions.service

[Service]
ExecStart=/usr/local/bin/iso-guest-agent --port 5000
User=coder
Group=coder
WorkingDirectory=/home/coder
EnvironmentFile=-/etc/environment
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
UNIT
in_chroot systemctl enable iso-guest-agent.service ssh.service >/dev/null 2>&1

# --- network: the kernel's ip= argument configures eth0 before userspace;
#     only the resolver is ours to set ---
#
# Nothing in the guest may manage eth0. Debian's systemd presets enable
# systemd-networkd, and systemd-network-generator turns the kernel's ip=
# into /run/systemd/network/70-eth0.network, which hands eth0 to networkd.
# That is fatal here: networkd starts an LLDP client, the guest kernel has
# CONFIG_PACKET=m with no modules in this rootfs, so the AF_PACKET socket
# fails with EAFNOSUPPORT, networkd reports `eth0: Failed` and reconfigures
# in a loop, and the address the kernel already set never survives. The guest
# then answers no ARP and the bake times out waiting for sshd. Mask the three
# units and the kernel's configuration stands, as this section intends.
in_chroot systemctl mask systemd-networkd.service systemd-networkd.socket \
  systemd-network-generator.service >/dev/null 2>&1
printf 'nameserver 172.22.0.1\n' > "$R/etc/resolv.conf"
echo "iso-guest" > "$R/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 iso-guest\n' > "$R/etc/hosts"
printf '/dev/vda / ext4 defaults 0 1\n' > "$R/etc/fstab"

# --- trust the egress proxy's CA, if the host has one yet ---
if [ -n "${CA_CERT:-}" ] && [ -f "$CA_CERT" ]; then
  install -m 0644 "$CA_CERT" "$R/usr/local/share/ca-certificates/iso-egress-proxy.crt"
  in_chroot update-ca-certificates >/dev/null 2>&1 || true
fi

# --- environment agents expect: a placeholder key the proxy overrides in
#     flight, a UTF-8 locale, UTC ---
cat > "$R/etc/environment" <<'ENV'
ANTHROPIC_API_KEY=iso-proxy-injects-the-real-key
NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
LANG=C.UTF-8
ENV
echo 'LANG=C.UTF-8' > "$R/etc/default/locale"
ln -sf /usr/share/zoneinfo/UTC "$R/etc/localtime"
echo UTC > "$R/etc/timezone"

# --- notes for agents, same text the NixOS image carries ---
install -d "$R/etc/iso"
cat > "$R/etc/iso/AGENTS.md" <<'NOTES'
# Notes for agents running in this VM

This is a stock Debian system; `sudo apt install <package>` works, through
the egress proxy, when the Debian mirrors are on this VM's allow-list.

## Outbound network & credentials

Outbound HTTPS is routed through iso's egress proxy on the host. The proxy
terminates TLS and overrides credential headers in flight, so real credentials
never exist inside this VM.

Which hosts are credentialed is the host's decision, made per VM, and it can
change while you are running. Do not assume any particular service is
authenticated, and do not try to work it out from your own environment:
values like `ANTHROPIC_API_KEY` here are placeholders, not secrets.

What this means for you:

- Make requests normally. Where a client library insists on a credential,
  pass any syntactically valid placeholder — the proxy replaces it.
- Do not fetch, refresh, validate or cache tokens for these APIs, and do not
  run `gh auth login` or anything like it. There is nothing here to log in
  with, and replacing an injected header with one you obtained yourself turns
  a working request into a broken one.
- Plain HTTP is dropped; use `https://`.
- A connection that is reset means that host is not on this VM's allow-list.
  A request that completes but returns 401 or 403 means the host is allowed
  but no credential is brokered for it. Neither is fixable from in here, so
  report it rather than working around it.

## Your VM identity & service endpoints

To learn who you are and how you're reached from outside, query the metadata
service:

    curl -s http://metadata.iso.internal/ | jq

It returns your `name`, the `host` you're reachable at, and `endpoints` — one
entry per forwarded port, each with `vm_port`, `host_port`, and a ready-to-use
`endpoint`. Only ports listed there are reachable from outside the VM.
NOTES

# --- serial console: autologin root on ttyS0 for debugging, as the NixOS image does ---
install -d "$R/etc/systemd/system/serial-getty@ttyS0.service.d"
cat > "$R/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" <<'GETTY'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --keep-baud 115200,57600,38400,9600 - $TERM
GETTY

# --- Debian names fd's binary fdfind; agents (and pi's find tool) expect fd ---
ln -sf /usr/bin/fdfind "$R/usr/local/bin/fd"

# --- trim what a microVM never uses ---
rm -rf "$R/var/cache/apt/archives/"*.deb "$R/var/lib/apt/lists/"* 2>/dev/null || true

echo "build-rootfs: done ($(du -sh "$R" | cut -f1))" >&2
