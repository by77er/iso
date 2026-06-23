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
# Which baked rootfs/snapshot the 'agent' template resolves to. Bump when you
# bake a new image (agent_v1 = NixOS 25.05 + monorepo tooling + pi; agent_v2
# adds the metadata-service AGENTS.md note); the LV is tpl_<AGENT_ROOTFS>, the
# snapshot is state/templates/<AGENT_ROOTFS>.
AGENT_ROOTFS="${AGENT_ROOTFS:-agent_v2}"
if [ -f "$STATE/templates/$AGENT_ROOTFS/vmstate" ]; then
  KERNEL="$(nix build "path:$REPO/image#kernel" --no-link --print-out-paths 2>/dev/null)/vmlinux"
  BOOTARGS="console=ttyS0 reboot=k panic=1 acpi=off quiet loglevel=3 root=/dev/vda rootfstype=ext4 rw ip=172.20.0.1::172.20.0.0:255.255.255.254::eth0:off init=/nix/var/nix/profiles/system/init"
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H 'content-type: application/json' \
    -d "{\"name\":\"agent\",\"rootfs_template\":\"$AGENT_ROOTFS\",\"snapshot_mem\":\"$STATE/templates/$AGENT_ROOTFS/mem\",\"snapshot_vmstate\":\"$STATE/templates/$AGENT_ROOTFS/vmstate\",\"vcpus\":1,\"mem_mib\":512,\"kernel\":\"$KERNEL\",\"boot_args\":\"$BOOTARGS\"}" \
    "$ADMIN/templates")
  echo "[iso-up] template 'agent' -> rootfs '$AGENT_ROOTFS' registered ($code) via $ADMIN"
fi

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
start_svc iso-cad "$REPO/target/debug/iso-cad"
if [ -f "$STATE/secrets.toml" ]; then
  start_svc iso-secretsd "$REPO/target/debug/iso-secretsd"
else
  echo "[iso-up] $STATE/secrets.toml missing — skipping iso-secretsd (no injection)"
fi
start_svc iso-proxyd "$REPO/target/debug/iso-proxyd"

# --- Docker hole-punch: this host runs Docker, whose `ip filter FORWARD` policy
#     is drop. iso VMs forward through the root netns (host veth `vm<slot>` <->
#     uplink), so allow-egress VMs are dropped unless we accept their traffic.
#     DOCKER-USER is the Docker-sanctioned hook for custom forward rules; a
#     single `vm*` pair covers every VM. Idempotent; tagged via comment. ---
if sudo -n nft list chain ip filter DOCKER-USER >/dev/null 2>&1; then
  if ! sudo -n nft list chain ip filter DOCKER-USER 2>/dev/null | grep -q 'iso-vm-egress'; then
    sudo -n nft insert rule ip filter DOCKER-USER oifname \"vm*\" counter accept comment \"iso-vm-egress\"
    sudo -n nft insert rule ip filter DOCKER-USER iifname \"vm*\" counter accept comment \"iso-vm-egress\"
    echo "[iso-up] installed DOCKER-USER carve-out for vm* egress"
  else
    echo "[iso-up] DOCKER-USER carve-out already present"
  fi
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
    # Run under agentd's nix flake (Elixir 1.20 + Erlang/OTP 27). nix develop
    # inherits the exported env (token, CONTROL_PLANE_URL, ...).
    (
      cd "$AGENTD" || exit
      setsid nix develop --command bash -c '
        mix deps.get >/dev/null 2>&1
        mix ecto.create --quiet 2>/dev/null
        mix ecto.migrate --quiet 2>/dev/null
        exec mix run --no-halt
      ' >"$STATE/agentd.log" 2>&1 </dev/null &
    )
  else
    echo "[iso-up] agentd already running"
  fi
else
  echo "[iso-up] skipping agentd (no $STATE/agentd.env or $AGENTD missing)"
fi
