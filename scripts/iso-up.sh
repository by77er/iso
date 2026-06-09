#!/usr/bin/env bash
# Bring up the iso stack: control plane (root) + agentd (user). Idempotent —
# safe to run repeatedly and from ~/personalize on every boot.
set -uo pipefail

REPO="$HOME/iso"
STATE="$REPO/state"
SOCK="$STATE/control.sock"
CONTROLD="$REPO/target/debug/iso-controld"
AGENTD="$HOME/iso-agentd"

# privileged tooling controld shells out to, plus nix-provided firecracker.
export PATH="/usr/sbin:/sbin:$HOME/.local/state/nix/profiles/personal/bin:$HOME/.nix-profile/bin:$PATH"

mkdir -p "$STATE"

# --- control plane (needs root: netlink, nft, lvm, firecracker, kvm) ---
if ! pgrep -f "$CONTROLD" >/dev/null 2>&1; then
  echo "[iso-up] starting iso-controld"
  sudo -n setsid env "PATH=$PATH" \
    ISO_STATE_DIR="$STATE" ISO_VG=iso ISO_UPLINK=ens3 \
    "$CONTROLD" >"$STATE/controld.log" 2>&1 </dev/null &
  for i in $(seq 1 150); do [ -S "$SOCK" ] && break; sleep 0.2; done
else
  echo "[iso-up] iso-controld already running"
fi
[ -S "$SOCK" ] || { echo "[iso-up] controld admin socket missing; see $STATE/controld.log"; exit 1; }

# Admin API over TCP (the unix socket is root-owned; the TCP listener is bound on
# the host's reachable IP — also what agentd uses).
HOST_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+')"
ADMIN="http://${HOST_IP}:7070"

# --- register the prewarmed 'agent' template (idempotent) ---
if [ -f "$STATE/templates/agent/vmstate" ]; then
  KERNEL="$(nix build "path:$REPO/image#kernel" --no-link --print-out-paths 2>/dev/null)/vmlinux"
  BOOTARGS="console=ttyS0 reboot=k panic=1 acpi=off quiet loglevel=3 root=/dev/vda rootfstype=ext4 rw ip=172.20.0.1::172.20.0.0:255.255.255.254::eth0:off init=/nix/var/nix/profiles/system/init"
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H 'content-type: application/json' \
    -d "{\"name\":\"agent\",\"rootfs_template\":\"agent\",\"snapshot_mem\":\"$STATE/templates/agent/mem\",\"snapshot_vmstate\":\"$STATE/templates/agent/vmstate\",\"vcpus\":1,\"mem_mib\":512,\"kernel\":\"$KERNEL\",\"boot_args\":\"$BOOTARGS\"}" \
    "$ADMIN/templates")
  echo "[iso-up] template 'agent' registered ($code) via $ADMIN"
fi

# --- agentd (user). Runs even without a bot token (gateway just stays
#     down); dynamic CONTROL_PLANE_URL tracks the host IP across reboots. ---
if [ -f "$STATE/agentd.env" ] && [ -d "$AGENTD" ]; then
  export CONTROL_PLANE_URL="$ADMIN"
  export DATABASE_PATH="$STATE/agentd.db"
  export SSH_KEY="$STATE/keys/test_ed25519"
  export AGENT_TEMPLATE=agent
  set -a; . "$STATE/agentd.env"; set +a  # BOT_TOKEN + any overrides
  # liveness by its HTTP API, not pgrep (stale `mix` launchers gave false hits).
  if ! curl -s -m1 -o /dev/null "http://127.0.0.1:7700/" 2>/dev/null; then
    echo "[iso-up] starting agentd (control plane $CONTROL_PLANE_URL)"
    (
      cd "$AGENTD" || exit
      mix ecto.create --quiet 2>/dev/null
      mix ecto.migrate --quiet 2>/dev/null
      setsid mix run --no-halt >"$STATE/agentd.log" 2>&1 </dev/null &
    )
  else
    echo "[iso-up] agentd already running"
  fi
else
  echo "[iso-up] skipping agentd (no $STATE/agentd.env or $AGENTD missing)"
fi
