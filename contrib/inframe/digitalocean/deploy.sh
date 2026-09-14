#!/usr/bin/env bash
# Turn the three droplets `inframe apply` created into a working iso fleet:
#
#   control  iso-fleetd (:7080, mTLS)     the one API clients use
#            iso-proxyd --role proxy       the tier, :3129 on the private IP
#            iso-cad, iso-secretsd         :7443 / :7444 on the private IP, mTLS
#   host-a/b iso-controld (:7070 private, mTLS, shared admin CA)
#            iso-proxyd --role edge        carries guest connections to the tier
#            one baked Debian template
#
# Run from this directory after `inframe apply --stack do`, as the user who
# built iso. Needs: the iso binaries (built here or with ISO_BIN), the guest
# kernel and static agent (Nix, or ISO_KERNEL / ISO_AGENT_BIN), ssh access
# as root to the droplets with the account key, rsync, and jq or python3. Idempotent-ish:
# rerunning reinstalls binaries and configs and skips the bake if a template
# exists.
#
#   INFRAME=/path/to/inframe   the inframe CLI (default: `inframe` on PATH)
#   ISO_REPO=../../..          this repository
#   ISO_BIN=<repo>/target/release
#   SECRETS_TOML=./secrets.example.toml
#   TEMPLATE=debian  DEBIAN_SUITE=trixie
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISO_REPO="${ISO_REPO:-$(cd "$HERE/../../.." && pwd)}"
ISO_BIN="${ISO_BIN:-$ISO_REPO/target/release}"
INFRAME="${INFRAME:-inframe}"
SECRETS_TOML="${SECRETS_TOML:-$HERE/secrets.example.toml}"
TEMPLATE="${TEMPLATE:-debian}"
SUITE="${DEBIAN_SUITE:-trixie}"
OUT="$HERE/.deploy"
mkdir -p "$OUT"
SSH=(ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes)
say() { echo "[deploy] $*"; }

# ---- what inframe made ----
outputs=$("$INFRAME" --project "$HERE/inframe.toml" output --stack do)
# jq if present, python otherwise: `val '.control_ip.value'`
val() {
  if command -v jq >/dev/null; then echo "$outputs" | jq -r "$1"; else
    echo "$outputs" | python3 -c "import json,sys; d=json.load(sys.stdin)
for k in sys.argv[1].strip('.').split('.'): d=d[k]
print(d)" "$1"; fi
}
CONTROL=$(val '.control_ip.value'); CONTROL_PRIV=$(val '.control_private_ip.value')
HOST_A=$(val '.host_ips.value.a'); HOST_A_PRIV=$(val '.host_private_ips.value.a')
HOST_B=$(val '.host_ips.value.b'); HOST_B_PRIV=$(val '.host_private_ips.value.b')
say "control $CONTROL ($CONTROL_PRIV) · host-a $HOST_A ($HOST_A_PRIV) · host-b $HOST_B ($HOST_B_PRIV)"

# ---- what we ship ----
for b in iso-controld isoctl iso-cad iso-secretsd iso-proxyd iso-fleetd; do
  [ -x "$ISO_BIN/$b" ] || { echo "missing $ISO_BIN/$b: cargo build --release -p iso-controld -p iso-cli -p iso-ca -p iso-secrets -p iso-proxy -p iso-fleet" >&2; exit 1; }
done
if [ -z "${ISO_KERNEL:-}" ]; then
  ISO_KERNEL="$(cd "$ISO_REPO" && nix build .#kernel --no-link --print-out-paths)/vmlinux"
fi
if [ -z "${ISO_AGENT_BIN:-}" ]; then
  ISO_AGENT_BIN="$(cd "$ISO_REPO" && nix build .#iso-guest-agent-static --no-link --print-out-paths)/bin/iso-guest-agent"
fi
[ -f "$ISO_KERNEL" ] && [ -x "$ISO_AGENT_BIN" ] || { echo "kernel or agent missing" >&2; exit 1; }
[ -f "$SECRETS_TOML" ] || { echo "no $SECRETS_TOML" >&2; exit 1; }

wait_cloud_init() { # ip
  for _ in $(seq 1 120); do
    "${SSH[@]}" "root@$1" test -f /var/lib/iso/.cloud-init-done 2>/dev/null && return 0
    sleep 5
  done
  echo "cloud-init never finished on $1" >&2; exit 1
}
ship_bins() { # ip
  rsync -az --rsync-path="rsync" "$ISO_BIN"/{iso-controld,isoctl,iso-cad,iso-secretsd,iso-proxyd,iso-fleetd} "root@$1:/usr/local/bin/"
}
unit() { # ip name exec [Environment lines...]
  local ip=$1 name=$2 exec=$3; shift 3
  local env=""; for e in "$@"; do env+="Environment=$e"$'\n'; done
  "${SSH[@]}" "root@$ip" "cat > /etc/systemd/system/$name.service" <<UNIT
[Unit]
Description=$name
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=$exec
Restart=always
RestartSec=2
$env
[Install]
WantedBy=multi-user.target
UNIT
  "${SSH[@]}" "root@$ip" "systemctl daemon-reload && systemctl enable --now $name >/dev/null && systemctl restart $name"
}

# ============================================================ control ====
say "control: waiting for cloud-init"; wait_cloud_init "$CONTROL"
ship_bins "$CONTROL"
rsync -az "$SECRETS_TOML" "root@$CONTROL:/var/lib/iso/secrets.toml"

# One admin CA for every host, minted on the control host, and the identities
# the control host's services present. The fleet's own API CA is separate.
"${SSH[@]}" "root@$CONTROL" bash -s "$CONTROL_PRIV" "$HOST_A_PRIV" "$HOST_B_PRIV" "$CONTROL" <<'REMOTE'
set -euo pipefail
priv=$1; a=$2; b=$3; pub=$4
P=/var/lib/iso-fleet
mkdir -p $P/hosts-pki $P/pki /etc/iso-fleet
# hosts admin CA (issue with no SANs never reissues a server cert here)
isoctl admin --pki-dir $P/hosts-pki ca >/dev/null
[ -f /etc/iso-fleet/hosts/fleet.crt ] || isoctl admin --pki-dir $P/hosts-pki issue-client --name fleet --out /etc/iso-fleet/hosts 2>/dev/null
[ -f /etc/iso-fleet/svc/control.crt ] || isoctl admin --pki-dir $P/hosts-pki issue-server --name control --san "$priv" --out /etc/iso-fleet/svc 2>/dev/null
[ -f /etc/iso-fleet/edges/host-a.crt ] || isoctl admin --pki-dir $P/hosts-pki issue-server --name host-a --san "$a" --out /etc/iso-fleet/edges 2>/dev/null
[ -f /etc/iso-fleet/edges/host-b.crt ] || isoctl admin --pki-dir $P/hosts-pki issue-server --name host-b --san "$b" --out /etc/iso-fleet/edges 2>/dev/null
# the fleet API's own CA and an operator client
isoctl admin --pki-dir $P/pki ca >/dev/null
[ -f /etc/iso-fleet/operator/operator.crt ] || isoctl admin --pki-dir $P/pki issue-client --name operator --out /etc/iso-fleet/operator 2>/dev/null

cat > /etc/iso-fleet/proxy.toml <<EOT
role = "proxy"
listen = ["$priv:3129"]
[ca]
url = "https://$priv:7443"
[secrets]
url = "https://$priv:7444"
[tls]
ca = "/etc/iso-fleet/svc/ca.crt"
cert = "/etc/iso-fleet/svc/control.crt"
key = "/etc/iso-fleet/svc/control.key"
EOT
cat > /etc/iso-fleet/fleet.toml <<EOT
listen = "0.0.0.0:7080"
db = "$P/fleet.db"
pki_dir = "$P/pki"
extra_sans = ["$pub", "$priv"]
sync_every_ms = 3000
[hosts_tls]
ca = "/etc/iso-fleet/hosts/ca.crt"
cert = "/etc/iso-fleet/hosts/fleet.crt"
key = "/etc/iso-fleet/hosts/fleet.key"
[[hosts]]
name = "host-a"
url = "https://$a:7070"
[[hosts]]
name = "host-b"
url = "https://$b:7070"
EOT
REMOTE
TLS_ENV=(ISO_TLS_CA=/etc/iso-fleet/svc/ca.crt ISO_TLS_CERT=/etc/iso-fleet/svc/control.crt ISO_TLS_KEY=/etc/iso-fleet/svc/control.key)
unit "$CONTROL" iso-cad      /usr/local/bin/iso-cad      ISO_STATE_DIR=/var/lib/iso "ISO_CA_LISTEN=$CONTROL_PRIV:7443" "${TLS_ENV[@]}"
unit "$CONTROL" iso-secretsd /usr/local/bin/iso-secretsd ISO_STATE_DIR=/var/lib/iso "ISO_SECRETS_LISTEN=$CONTROL_PRIV:7444" "${TLS_ENV[@]}"
unit "$CONTROL" iso-proxyd   /usr/local/bin/iso-proxyd   ISO_PROXY_CONFIG=/etc/iso-fleet/proxy.toml
unit "$CONTROL" iso-fleetd   "/usr/local/bin/iso-fleetd /etc/iso-fleet/fleet.toml"
# the tier CA guests must trust, the hosts admin CA hosts must hold, the edge
# identities, and the operator's fleet credentials
for _ in $(seq 1 30); do "${SSH[@]}" "root@$CONTROL" test -f /var/lib/iso/ca/ca.crt && break; sleep 1; done
rsync -az "root@$CONTROL:/var/lib/iso/ca/ca.crt" "$OUT/tier-ca.crt"
rsync -az "root@$CONTROL:/var/lib/iso-fleet/hosts-pki/ca.crt" "root@$CONTROL:/var/lib/iso-fleet/hosts-pki/ca.key" "$OUT/"
rsync -az "root@$CONTROL:/etc/iso-fleet/edges/" "$OUT/edges/"
rsync -az "root@$CONTROL:/etc/iso-fleet/operator/" "$OUT/creds/"
say "control: services up; tier CA and host CA fetched"

# ============================================================== hosts ====
host() { # name public private
  local name=$1 ip=$2 priv=$3
  say "$name: waiting for cloud-init"; wait_cloud_init "$ip"
  if "${SSH[@]}" "root@$ip" test -f /var/lib/iso-no-kvm; then
    echo "$name has no /dev/kvm; Firecracker cannot run here" >&2; exit 1
  fi
  ship_bins "$ip"
  rsync -az "$ISO_KERNEL" "root@$ip:/opt/iso/vmlinux"
  rsync -az "$ISO_AGENT_BIN" "root@$ip:/opt/iso/iso-guest-agent"
  rsync -az --delete "$ISO_REPO/image/" "root@$ip:/opt/iso/image/"
  # bake reads the CA guests must trust from the state directory, where
  # iso-cad would have put it on a single host; here it is the tier's.
  "${SSH[@]}" "root@$ip" "mkdir -p /var/lib/iso/ca"
  rsync -az "$OUT/tier-ca.crt" "root@$ip:/var/lib/iso/ca/ca.crt"
  rsync -az "$OUT/tier-ca.crt" "root@$ip:/opt/iso/image/ca.crt"
  rsync -az "$OUT/edges/$name.crt" "$OUT/edges/$name.key" "$OUT/edges/ca.crt" "root@$ip:/etc/iso/"
  # the shared admin CA, before controld's first start so it is adopted
  "${SSH[@]}" "root@$ip" "mkdir -p /var/lib/iso/admin-pki && chmod 700 /var/lib/iso/admin-pki"
  rsync -az --chmod=F600 "$OUT/ca.crt" "$OUT/ca.key" "root@$ip:/var/lib/iso/admin-pki/"
  "${SSH[@]}" "root@$ip" "ssh-keygen -q -t ed25519 -N '' -f /opt/iso/guest_ed25519 </dev/null 2>/dev/null || true; cat /opt/iso/guest_ed25519.pub > /opt/iso/authorized_keys"
  "${SSH[@]}" "root@$ip" "cat > /etc/iso/edge.toml" <<EOT
role = "edge"
listen = ["172.22.0.1:3128", "172.22.0.1:443"]
host_id = "$name"
[identify]
socket = "/var/lib/iso/identify.sock"
[tier]
addrs = ["$CONTROL_PRIV:3129"]
server_name = "$CONTROL_PRIV"
[tls]
ca = "/etc/iso/ca.crt"
cert = "/etc/iso/$name.crt"
key = "/etc/iso/$name.key"
EOT
  unit "$ip" iso-controld /usr/local/bin/iso-controld \
    ISO_STATE_DIR=/var/lib/iso ISO_VG=iso ISO_UPLINK=eth0 ISO_IMAGE_SIZE_GIB=40 \
    "ISO_ADMIN_TCP=$priv:7070" ISO_JAILER_BIN=/usr/local/bin/jailer ISO_FIRECRACKER_BIN=/usr/local/bin/firecracker \
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  for _ in $(seq 1 60); do "${SSH[@]}" "root@$ip" test -S /var/lib/iso/control.sock && break; sleep 2; done
  # the edge only needs identify.sock, which controld just created
  unit "$ip" iso-proxyd /usr/local/bin/iso-proxyd ISO_PROXY_CONFIG=/etc/iso/edge.toml
  if ! "${SSH[@]}" "root@$ip" test -f "/var/lib/iso/templates/$TEMPLATE/template.json"; then
    say "$name: baking template '$TEMPLATE' (Debian $SUITE), several minutes"
    "${SSH[@]}" "root@$ip" "cd /opt/iso && PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      ISO_JAILER_BIN=/usr/local/bin/jailer ISO_FIRECRACKER_BIN=/usr/local/bin/firecracker \
      isoctl bake --name $TEMPLATE --distro debian --debian-suite $SUITE \
        --kernel /opt/iso/vmlinux --agent-bin /opt/iso/iso-guest-agent --authorized-keys /opt/iso/authorized_keys \
        --flake /opt/iso --state /var/lib/iso --vg iso --uplink eth0 --slot 32767 --vcpus 2 --mem-mib 2048 --size 16G >/opt/iso/bake.log 2>&1"
  fi
  "${SSH[@]}" "root@$ip" "curl -s -o /dev/null -w '%{http_code}\n' --unix-socket /var/lib/iso/control.sock -H 'content-type: application/json' -d @/var/lib/iso/templates/$TEMPLATE/template.json http://x/templates"
  say "$name: controld, edge and template '$TEMPLATE' ready"
}
host host-a "$HOST_A" "$HOST_A_PRIV"
host host-b "$HOST_B" "$HOST_B_PRIV"

# ============================================================ operator ====
cat <<EOT

The fleet is up. In your shell:

  export ISO_SERVER=https://$CONTROL:7080 ISO_CREDS=$OUT/creds ISO_CLIENT=operator
  isoctl vm create --template $TEMPLATE --egress proxy --principal alice --allow api.github.com --quiet
  isoctl vm exec <id> -- curl -sS https://api.github.com/zen
  curl -s --cert \$ISO_CREDS/operator.crt --key \$ISO_CREDS/operator.key --cacert \$ISO_CREDS/ca.crt \$ISO_SERVER/hosts | jq

The guest never held a token: the request was terminated on the control host,
the header injected there, and host-a or host-b only carried bytes.
EOT
