#!/usr/bin/env bash
# Live test of the dual-horizon DNS + metadata server: boot a VM (Deny egress —
# DNS/metadata are the always-on services baseline), and from inside it resolve
# metadata.iso.internal (-> dummy) + hit the metadata server, plus a forwarded name.
# Run as root from a `nix develop` shell after `cargo build`. Needs the guest
# ssh key at state/keys/test_ed25519 (override with ISO_SSH_KEY).
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE=/var/tmp/iso-dnstest
VG=isodnstest
SOCK=$STATE/control.sock
KEY="${ISO_SSH_KEY:-$REPO/state/keys/test_ed25519}"
KERNEL=$(nix build "path:$REPO/image#kernel" --no-link --print-out-paths 2>/dev/null)/vmlinux
SYS=$(nix build "path:$REPO/image#toplevel" --no-link --print-out-paths 2>/dev/null)
NIXOS_INSTALL=$(nix build "path:$REPO/image#nixos-install-tools" --no-link --print-out-paths 2>/dev/null)/bin/nixos-install
CONTROLD=$REPO/target/debug/iso-controld
BOOTARGS="console=ttyS0 reboot=k panic=1 acpi=off quiet loglevel=3 root=/dev/vda rootfstype=ext4 rw ip=172.20.0.1::172.20.0.0:255.255.255.254::eth0:off init=/nix/var/nix/profiles/system/init"
CD=""
api(){ local p="$1"; shift; curl -s --unix-socket "$SOCK" "$@" "http://x$p"; }
ssh_vm(){ ip netns exec "$1" ssh -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 -o LogLevel=ERROR coder@172.20.0.1 "$2"; }
cleanup(){
  [ -n "$CD" ] && kill "$CD" 2>/dev/null; sleep 0.5
  pkill -f "firecracker --api-sock $STATE" 2>/dev/null
  for n in 0 1 2; do ip netns del "$(printf vm%04x $n)" 2>/dev/null; done
  lvchange -an $VG 2>/dev/null; vgremove -f $VG 2>/dev/null
  for d in $(losetup -j $STATE/storage.img -O NAME --noheadings 2>/dev/null); do losetup -d "$d"; done
  ip link del dummy0 2>/dev/null; rm -rf $STATE
}
trap cleanup EXIT
cleanup; mkdir -p $STATE

echo "== controld up (state=$STATE) =="
ISO_STATE_DIR=$STATE ISO_VG=$VG ISO_IMAGE_SIZE_GIB=16 ISO_UPLINK="${ISO_UPLINK:-}" "$CONTROLD" >$STATE/cd.log 2>&1 &
CD=$!
for i in $(seq 1 150); do [ -S "$SOCK" ] && lvs "$VG/pool" >/dev/null 2>&1 && break; sleep 0.2; done
lvs "$VG/pool" >/dev/null 2>&1 || { echo FAIL pool; cat $STATE/cd.log; exit 1; }
sleep 1
echo "dns/metadata bound? $(ss -lnup 2>/dev/null | grep -c 172.22.0.1:53) udp53 $(ss -lntp 2>/dev/null | grep -c 172.22.0.1:80) tcp80"

echo "== build rootfs (nixos-install) =="
lvcreate -y -V 8G --thinpool pool -n tpl_base $VG >/dev/null
mkfs.ext4 -F -q /dev/$VG/tpl_base
MNT=$(mktemp -d); mount /dev/$VG/tpl_base $MNT
"$NIXOS_INSTALL" --root $MNT --system "$SYS" --no-bootloader --no-root-passwd --no-channel-copy >$STATE/install.log 2>&1 || { echo FAIL install; tail -5 $STATE/install.log; exit 1; }
sync; umount -R $MNT; rmdir $MNT

api /templates -X POST -H 'content-type: application/json' -d "{\"name\":\"t\",\"rootfs_template\":\"base\",\"vcpus\":1,\"mem_mib\":512,\"kernel\":\"$KERNEL\",\"boot_args\":\"$BOOTARGS\"}" -o /dev/null -w "template -> %{http_code}\n"

id=$(api /vms -X POST -H 'content-type: application/json' -d '{"template":"t","egress":"deny"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
slot=$(api /vms | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["slot"])')
ns=$(printf vm%04x $slot)
echo "VM id=$id slot=$slot ns=$ns (egress=deny)"
for i in $(seq 1 60); do ssh_vm $ns true 2>/dev/null && break; sleep 1; done

echo "---- from inside the VM ----"
echo "resolvectl DNS    -> $(ssh_vm $ns 'resolvectl status 2>/dev/null | grep -iE "Current DNS|DNS Servers" | head -2 | tr "\n" " "' 2>/dev/null)"
echo "metadata by IP    -> $(ssh_vm $ns 'curl -s --max-time 5 http://172.22.0.1/' 2>/dev/null)"
echo "metadata.iso.internal (resolvectl) -> $(ssh_vm $ns 'resolvectl query metadata.iso.internal 2>&1 | head -1' 2>/dev/null)"
echo "metadata.iso.internal (getent)     -> $(ssh_vm $ns 'getent hosts metadata.iso.internal' 2>/dev/null)"
echo "metadata by NAME  -> $(ssh_vm $ns 'curl -s --max-time 5 http://metadata.iso.internal/' 2>/dev/null)"
echo "forwarded name    -> $(ssh_vm $ns 'getent hosts one.one.one.one' 2>/dev/null)"

api /vms/$id -X DELETE -o /dev/null -w "destroy -> %{http_code}\n"
echo "== done =="
