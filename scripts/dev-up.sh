#!/usr/bin/env bash
# Bring iso up on a development machine from a checkout, end to end:
#
#   1. host packages a Debian/Ubuntu host needs (lvm2, thin tools, mmdebstrap)
#   2. the control plane, jailed, on a loop-file thin pool under ./state,
#      with the admin API on loopback over mutual TLS
#   3. the egress-proxy daemons (so proxy-mode VMs work once a CA exists)
#   4. an admin client certificate for the invoking user, in ~/.iso/creds
#   5. a Debian template baked from the flake's kernel and static agent,
#      registered with the control plane
#
# Idempotent: re-running skips what exists. Run with sudo from the repository
# after `cargo build -p iso-controld -p iso-cli -p iso-ca -p iso-secrets
# -p iso-proxy` and `nix build .#kernel .#iso-guest-agent-static` as yourself.
#
#   sudo scripts/dev-up.sh
#
# Environment: ISO_STATE_DIR (default ./state), ISO_VETH_NET (default: picks
# 172.30.0.0 when the host already lives in 172.21.0.0/16), ISO_UPLINK
# (default: the default-route interface), ISO_IMAGE_SIZE_GIB (default 30),
# ISO_TEMPLATE_NAME (default debian), DEBIAN_SUITE (default trixie).
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
USER_NAME="${SUDO_USER:?run with sudo, not as root directly}"
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="${ISO_STATE_DIR:-$REPO/state}"
BIN="$REPO/target/debug"
TEMPLATE="${ISO_TEMPLATE_NAME:-debian}"
SUITE="${DEBIAN_SUITE:-trixie}"
SOCK="$STATE/control.sock"

# Binaries the daemon shells out to, from the invoking user's profile.
export PATH="/usr/sbin:/sbin:$USER_HOME/.nix-profile/bin:$USER_HOME/.local/bin:$PATH"
for b in firecracker jailer nix nft ip; do
  command -v "$b" >/dev/null || { echo "dev-up: $b not on PATH" >&2; exit 1; }
done
for b in iso-controld isoctl iso-cad iso-secretsd iso-proxyd; do
  [ -x "$BIN/$b" ] || { echo "dev-up: $BIN/$b missing; cargo build it first" >&2; exit 1; }
done
FC="$(readlink -f "$(command -v firecracker)")"
JAILER="$(readlink -f "$(command -v jailer)")"

# --- 1. host packages ---
if command -v apt-get >/dev/null; then
  missing=()
  for p in lvm2 thin-provisioning-tools mmdebstrap; do
    dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "[dev-up] installing ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}"
  fi
fi
modprobe dm_thin_pool 2>/dev/null || true

# --- addressing: stay clear of the host's own network ---
UPLINK="${ISO_UPLINK:-$(ip -4 route show default | awk '{print $5; exit}')}"
if [ -z "${ISO_VETH_NET:-}" ]; then
  if ip -4 addr show | grep -q 'inet 172\.21\.'; then
    ISO_VETH_NET=172.30.0.0
  else
    ISO_VETH_NET=172.21.0.0
  fi
fi
export ISO_VETH_NET

mkdir -p "$STATE"
chmod 0755 "$STATE"

# --- 2. control plane ---
DAEMON_ENV=(
  "PATH=$PATH"
  "ISO_STATE_DIR=$STATE"
  "ISO_VG=iso"
  "ISO_UPLINK=$UPLINK"
  "ISO_IMAGE_SIZE_GIB=${ISO_IMAGE_SIZE_GIB:-30}"
  "ISO_VETH_NET=$ISO_VETH_NET"
  "ISO_JAILER=1"
  "ISO_JAILER_BIN=$JAILER"
  "ISO_FIRECRACKER_BIN=$FC"
  "ISO_ADMIN_TCP=127.0.0.1:7070"
)
if ! pgrep -f "$BIN/iso-controld" >/dev/null; then
  echo "[dev-up] starting iso-controld (uplink $UPLINK, veth net $ISO_VETH_NET/16, jailed)"
  setsid env "${DAEMON_ENV[@]}" "$BIN/iso-controld" >"$STATE/controld.log" 2>&1 </dev/null &
  for _ in $(seq 1 300); do [ -S "$SOCK" ] && break; sleep 0.2; done
fi
[ -S "$SOCK" ] || { echo "[dev-up] no admin socket; see $STATE/controld.log" >&2; tail -20 "$STATE/controld.log" >&2; exit 1; }
api() { curl -s --unix-socket "$SOCK" "$@"; }
echo "[dev-up] control plane: $(api http://x/stats)"

# --- 3. proxy daemons (the CA first, so the bake can trust it) ---
start_svc() {
  if ! pgrep -f "$BIN/$1" >/dev/null; then
    echo "[dev-up] starting $1"
    setsid env "PATH=$PATH" "ISO_STATE_DIR=$STATE" "$BIN/$1" >"$STATE/$1.log" 2>&1 </dev/null &
  fi
}
start_svc iso-cad
[ -f "$STATE/secrets.toml" ] || printf '# [global."api.anthropic.com"]\n# "x-api-key" = "sk-ant-..."\n' > "$STATE/secrets.toml"
start_svc iso-secretsd
start_svc iso-proxyd
for _ in $(seq 1 50); do [ -f "$STATE/ca/ca.crt" ] && break; sleep 0.1; done

# --- 4. an admin client for the user ---
CREDS="$USER_HOME/.iso/creds"
if [ ! -f "$CREDS/$USER_NAME.crt" ]; then
  echo "[dev-up] issuing admin client certificate '$USER_NAME' into $CREDS"
  "$BIN/isoctl" admin --pki-dir "$STATE/admin-pki" issue-client --name "$USER_NAME" --out "$CREDS" 2>/dev/null
  chown -R "$USER_NAME" "$USER_HOME/.iso"
fi

# --- ssh key for the guests: bake syncs the builder over it, and you can
#     `ip netns exec vmNNNN ssh -i state/keys/test_ed25519 coder@172.20.0.1` ---
if [ ! -f "$STATE/keys/test_ed25519" ]; then
  mkdir -p "$STATE/keys"
  ssh-keygen -q -t ed25519 -N '' -C "iso dev $(hostname)" -f "$STATE/keys/test_ed25519"
  chown -R "$USER_NAME" "$STATE/keys"
fi
KEYS="$STATE/keys/authorized_keys"
{ grep -v -E '^\s*(#|$)' "$REPO/image/keys/authorized_keys" 2>/dev/null || true; cat "$STATE/keys/test_ed25519.pub"; } | sort -u > "$KEYS"

# --- Docker's FORWARD policy would drop allow-mode egress; carve iso's veths out ---
if nft list chain ip filter DOCKER-USER >/dev/null 2>&1 && ! nft list chain ip filter DOCKER-USER | grep -q iso-vm-egress; then
  nft insert rule ip filter DOCKER-USER oifname "vm*" counter accept comment "iso-vm-egress"
  nft insert rule ip filter DOCKER-USER iifname "vm*" counter accept comment "iso-vm-egress"
  echo "[dev-up] installed DOCKER-USER carve-out for vm* egress"
fi

# --- 5. the Debian template ---
if [ ! -f "$STATE/templates/$TEMPLATE/template.json" ]; then
  # Nix runs as the invoking user (its store is theirs); root only bakes.
  as_user() { sudo -u "$USER_NAME" env "PATH=$PATH" "HOME=$USER_HOME" "$@"; }
  echo "[dev-up] building the kernel and the static guest agent with Nix (as $USER_NAME)"
  KERNEL="$(cd "$REPO" && as_user nix build .#kernel --no-link --print-out-paths 2>/dev/null)/vmlinux"
  AGENT="$(cd "$REPO" && as_user nix build .#iso-guest-agent-static --no-link --print-out-paths 2>/dev/null)/bin/iso-guest-agent"
  [ -f "$KERNEL" ] && [ -x "$AGENT" ] || { echo "[dev-up] nix build failed" >&2; exit 1; }
  echo "[dev-up] baking template '$TEMPLATE' (Debian $SUITE); this takes a few minutes"
  # A high slot, so the builder never collides with the allocator's first VM.
  env "${DAEMON_ENV[@]}" "$BIN/isoctl" bake --name "$TEMPLATE" --distro debian --debian-suite "$SUITE" \
    --kernel "$KERNEL" --agent-bin "$AGENT" --authorized-keys "$KEYS" \
    --flake "$REPO" --state "$STATE" --vg iso --uplink "$UPLINK" --slot 32767 \
    --vcpus 2 --mem-mib 2048 --size 16G >/dev/null
fi
code=$(api -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
  -d @"$STATE/templates/$TEMPLATE/template.json" http://x/templates)
echo "[dev-up] template '$TEMPLATE' registered ($code)"

cat <<EOF

iso is up. For pi, in your own shell:

  export ISO_SERVER=https://127.0.0.1:7070 ISO_CREDS=$CREDS ISO_CLIENT=$USER_NAME
  export ISO_TEMPLATE=$TEMPLATE ISO_EGRESS=allow
  pi

Each session creates a Debian VM on first tool use and destroys it on exit;
/iso shows it, ISO_KEEP=1 keeps it. Logs: $STATE/*.log
EOF
