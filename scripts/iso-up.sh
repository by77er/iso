#!/usr/bin/env bash
# Bring up the iso stack: control plane + egress proxy daemons, then register
# any baked templates. Idempotent — safe to run repeatedly and on every boot.
#
# Env: ISO_STATE_DIR (default <repo>/state), ISO_VG (default iso), ISO_UPLINK
# (default: controld detects the default-route interface), ISO_BIN_DIR (default
# <repo>/target/debug), ISO_TEMPLATES ("name:vcpus:mem_mib ...", default
# "base:1:512").
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="${ISO_STATE_DIR:-$REPO/state}"
SOCK="$STATE/control.sock"
BIN="${ISO_BIN_DIR:-$REPO/target/debug}"
VG="${ISO_VG:-iso}"

# privileged tooling controld shells out to, plus nix-provided firecracker.
export PATH="/usr/sbin:/sbin:$HOME/.nix-profile/bin:$PATH"

mkdir -p "$STATE"

# --- control plane (needs root: netlink, nft, lvm, firecracker, kvm) ---
if ! pgrep -f "$BIN/iso-controld" >/dev/null 2>&1; then
  echo "[iso-up] starting iso-controld"
  sudo -n setsid env "PATH=$PATH" \
    ISO_STATE_DIR="$STATE" ISO_VG="$VG" ISO_UPLINK="${ISO_UPLINK:-}" \
    "$BIN/iso-controld" >"$STATE/controld.log" 2>&1 </dev/null &
  for i in $(seq 1 150); do [ -S "$SOCK" ] && break; sleep 0.2; done
else
  echo "[iso-up] iso-controld already running"
fi
[ -S "$SOCK" ] || { echo "[iso-up] controld admin socket missing; see $STATE/controld.log"; exit 1; }

# Admin API over the root-only unix socket. (The TCP listener speaks mutual
# TLS; remote clients get a certificate from `isoctl admin issue-client`.)
api() { sudo -n curl -s --unix-socket "$SOCK" "$@"; }

# --- register baked templates (idempotent upsert by name). Each entry in
#     ISO_TEMPLATES is "name:vcpus:mem_mib"; vcpus/mem MUST match what
#     `isoctl bake --name <name>` was run with, since a Firecracker snapshot
#     only resumes with the same machine size. The rootfs LV is tpl_<name> and
#     the snapshot is state/templates/<name>; entries that aren't baked yet are
#     skipped. ---
KERNEL="$(nix build "$REPO#kernel" --no-link --print-out-paths 2>/dev/null)/vmlinux"
BOOTARGS="console=ttyS0 reboot=k panic=1 acpi=off quiet loglevel=3 root=/dev/vda rootfstype=ext4 rw ip=172.20.0.1::172.20.0.0:255.255.255.254::eth0:off init=/nix/var/nix/profiles/system/init"
for spec in ${ISO_TEMPLATES:-base:1:512}; do
  IFS=: read -r name vcpus mem <<<"$spec"
  if [ -f "$STATE/templates/$name/vmstate" ]; then
    code=$(api -o /dev/null -w '%{http_code}' \
      -H 'content-type: application/json' \
      -d "{\"name\":\"$name\",\"rootfs_template\":\"$name\",\"snapshot_mem\":\"$STATE/templates/$name/mem\",\"snapshot_vmstate\":\"$STATE/templates/$name/vmstate\",\"vcpus\":$vcpus,\"mem_mib\":$mem,\"kernel\":\"$KERNEL\",\"boot_args\":\"$BOOTARGS\"}" \
      http://x/templates)
    echo "[iso-up] template '$name' registered ($code)"
  else
    echo "[iso-up] template '$name' not baked yet (no $STATE/templates/$name/vmstate); skipping"
  fi
done

# --- egress proxy stack (root): CA minter, secret provider, MITM proxy.
#     Reads state/{ca,secrets.toml}; proxy resolves per-VM policy via the
#     control plane's identify.sock and serves the nft Proxy-mode DNAT target. ---
start_svc() { # name binary
  if ! pgrep -f "$2" >/dev/null 2>&1; then
    echo "[iso-up] starting $1"
    sudo -n setsid env "PATH=$PATH" ISO_STATE_DIR="$STATE" "$2" \
      >"$STATE/$1.log" 2>&1 </dev/null &
  fi
}
start_svc iso-cad "$BIN/iso-cad"
if [ -f "$STATE/secrets.toml" ]; then
  start_svc iso-secretsd "$BIN/iso-secretsd"
else
  echo "[iso-up] $STATE/secrets.toml missing — skipping iso-secretsd (no injection)"
fi
start_svc iso-proxyd "$BIN/iso-proxyd"

# --- Docker hole-punch: if this host runs Docker, its `ip filter FORWARD`
#     policy is drop. iso VMs forward through the root netns (host veth
#     `vm<slot>` <-> uplink), so allow-egress VMs are dropped unless we accept
#     their traffic. DOCKER-USER is the Docker-sanctioned hook for custom
#     forward rules; a single `vm*` pair covers every VM. Idempotent; tagged
#     via comment. ---
if sudo -n nft list chain ip filter DOCKER-USER >/dev/null 2>&1; then
  if ! sudo -n nft list chain ip filter DOCKER-USER 2>/dev/null | grep -q 'iso-vm-egress'; then
    sudo -n nft insert rule ip filter DOCKER-USER oifname \"vm*\" counter accept comment \"iso-vm-egress\"
    sudo -n nft insert rule ip filter DOCKER-USER iifname \"vm*\" counter accept comment \"iso-vm-egress\"
    echo "[iso-up] installed DOCKER-USER carve-out for vm* egress"
  else
    echo "[iso-up] DOCKER-USER carve-out already present"
  fi
fi
