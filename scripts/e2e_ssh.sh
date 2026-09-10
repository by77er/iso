#!/usr/bin/env bash
# End-to-end live validation of the iso system (self-contained; does NOT touch a
# running iso deployment — it uses its own state dir and volume group):
#   - bakes a NixOS rootfs into our OWN throwaway VG (isoe2e)
#   - runs iso-controld, registers the template, and creates VMs via the HTTP API
#   - SSHes into each VM and exercises Allow / Deny / Proxy egress
#   - in Proxy mode, verifies a stand-in proxy on 172.22.0.1 receives the conn
# Run as root from a `nix develop` shell after `cargo build`. Needs the guest
# ssh key at state/keys/test_ed25519 (override with ISO_SSH_KEY).
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE=/var/tmp/iso-e2e
VG=isoe2e
SOCK=$STATE/control.sock
KEY="${ISO_SSH_KEY:-$REPO/state/keys/test_ed25519}"
KERNEL=$(nix build "path:$REPO/image#kernel" --no-link --print-out-paths 2>/dev/null)/vmlinux
SYS=$(nix build "path:$REPO/image#toplevel" --no-link --print-out-paths 2>/dev/null)
NIXOS_INSTALL=$(nix build "path:$REPO/image#nixos-install-tools" --no-link --print-out-paths 2>/dev/null)/bin/nixos-install
CONTROLD=$REPO/target/debug/iso-controld
PROXY_LOG=$STATE/proxy.log
CONTROLD_LOG=$STATE/controld.log
BOOTARGS="console=ttyS0 reboot=k panic=1 acpi=off quiet loglevel=3 root=/dev/vda rootfstype=ext4 rw ip=172.20.0.1::172.20.0.0:255.255.255.254::eth0:off init=/nix/var/nix/profiles/system/init"

CONTROLD_PID=""; LISTENER_PID=""
api() { local p="$1"; shift; curl -s --unix-socket "$SOCK" "$@" "http://x$p"; }
jget() { python3 -c "import json,sys;print(json.load(sys.stdin)$1)"; }
ssh_vm() { ip netns exec "$1" ssh -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 -o LogLevel=ERROR coder@172.20.0.1 "$2"; }

cleanup() {
  [ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null
  [ -n "$CONTROLD_PID" ] && kill "$CONTROLD_PID" 2>/dev/null
  sleep 0.5
  for n in 0 1 2 3 4; do ip netns del "$(printf 'vm%04x' $n)" 2>/dev/null; done
  pkill -f "firecracker --api-sock $STATE" 2>/dev/null
  vgremove -f "$VG" 2>/dev/null
  for d in $(losetup -j "$STATE/storage.img" -O NAME --noheadings 2>/dev/null); do losetup -d "$d"; done
  ip link del dummy0 2>/dev/null
  nft flush chain ip filter DOCKER-USER 2>/dev/null
  nft add rule ip filter DOCKER-USER counter return 2>/dev/null
  rm -rf "$STATE"
}
trap cleanup EXIT
cleanup
mkdir -p "$STATE"

echo "== starting iso-controld (state=$STATE vg=$VG) =="
ISO_STATE_DIR=$STATE ISO_VG=$VG ISO_IMAGE_SIZE_GIB=16 ISO_UPLINK="${ISO_UPLINK:-}" "$CONTROLD" >"$CONTROLD_LOG" 2>&1 &
CONTROLD_PID=$!
for i in $(seq 1 150); do [ -S "$SOCK" ] && lvs "$VG/pool" >/dev/null 2>&1 && break; sleep 0.2; done
if ! lvs "$VG/pool" >/dev/null 2>&1; then echo "FAIL: controld didn't bring up the pool"; cat "$CONTROLD_LOG"; exit 1; fi
echo "controld up; services dummy: $(ip -4 -o addr show dummy0 | awk '{print $4}')"

# This host runs Docker (ip filter FORWARD policy drop). Allow-mode direct
# egress (172.21.x) isn't matched by Docker's rules, so carve our veth traffic
# into DOCKER-USER. Disjoint from docker (172.17); restored on cleanup.
# Deny/Proxy don't need this.
nft insert rule ip filter DOCKER-USER oifname "vm*" accept 2>/dev/null
nft insert rule ip filter DOCKER-USER iifname "vm*" accept 2>/dev/null

echo "== baking rootfs into $VG/tpl_base (nixos-install) =="
lvcreate -y -V 8G --thinpool pool -n tpl_base "$VG" >/dev/null
mkfs.ext4 -F -q "/dev/$VG/tpl_base"
MNT=$(mktemp -d)
mount "/dev/$VG/tpl_base" "$MNT"
if "$NIXOS_INSTALL" --root "$MNT" --system "$SYS" --no-bootloader --no-root-passwd --no-channel-copy >"$STATE/nixos-install.log" 2>&1; then
  echo "nixos-install ok"
else
  echo "FAIL: nixos-install"; tail -20 "$STATE/nixos-install.log"; umount -R "$MNT"; exit 1
fi
sync; umount -R "$MNT"; rmdir "$MNT"

echo "== registering template =="
api /templates -X POST -H 'content-type: application/json' \
  -d "{\"name\":\"sshvm\",\"rootfs_template\":\"base\",\"vcpus\":1,\"mem_mib\":512,\"kernel\":\"$KERNEL\",\"boot_args\":\"$BOOTARGS\"}" \
  -o /dev/null -w "templates -> %{http_code}\n"

test_mode() {
  local mode=$1 expect=$2
  echo "================ egress mode: $mode ================"
  local id slot ns
  id=$(api /vms -X POST -H 'content-type: application/json' -d "{\"template\":\"sshvm\",\"egress\":\"$mode\"}" | jget "['id']")
  slot=$(api /vms | jget "[0]['slot']")
  ns=$(printf 'vm%04x' "$slot")
  echo "[$mode] id=$id slot=$slot netns=$ns"

  local up=0
  for i in $(seq 1 60); do if ssh_vm "$ns" true 2>/dev/null; then up=1; break; fi; sleep 1; done
  if [ "$up" != 1 ]; then echo "[$mode] FAIL: ssh never came up"; tail -15 "$CONTROLD_LOG"; api "/vms/$id" -X DELETE >/dev/null; return; fi
  echo "[$mode] ssh up; whoami=$(ssh_vm "$ns" 'whoami' 2>/dev/null), ip=$(ssh_vm "$ns" 'ip -4 -o addr show eth0 | awk "{print \$4}"' 2>/dev/null)"

  local res
  res=$(ssh_vm "$ns" "timeout 6 bash -c 'cat </dev/null >/dev/tcp/1.1.1.1/443 && echo REACHED || echo BLOCKED'" 2>/dev/null)
  echo "[$mode] egress 1.1.1.1:443 -> ${res:-<no output>}  (expected: $expect)"

  if [ "$mode" = proxy ]; then
    sleep 0.5
    if grep -q PROXY-CONN "$PROXY_LOG" 2>/dev/null; then
      echo "[$mode] proxy RECEIVED connection: $(grep PROXY-CONN "$PROXY_LOG" | tail -1)"
    else
      echo "[$mode] proxy did NOT receive a connection"
    fi
  fi
  api "/vms/$id" -X DELETE >/dev/null && echo "[$mode] destroyed"
  sleep 1
}

test_mode allow REACHED
test_mode deny  BLOCKED

echo "== starting stand-in proxy on 172.22.0.1:3128 =="
python3 -c '
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("172.22.0.1",3128)); s.listen()
while True:
    c,a=s.accept(); print("PROXY-CONN from",a,flush=True); c.close()
' >"$PROXY_LOG" 2>&1 &
LISTENER_PID=$!
sleep 0.5
test_mode proxy REACHED

echo "== done =="
