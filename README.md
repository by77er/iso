# iso

Firecracker microVM sandboxes for coding agents and other untrusted code, on one Linux host.

Every VM gets its own kernel, its own network namespace, and a copy-on-write disk cut from a warm snapshot, so it boots in milliseconds. Egress is decided on the host, per VM: **deny** it, **allow** it, or **proxy** it through a transparent TLS-terminating proxy that enforces a domain allow-list and injects real credentials in flight. The guest only ever holds a placeholder key.

## Why

Containers share the host kernel, and agents usually run with your API keys in their environment. iso removes both problems:

- **Hardware isolation.** Each workload is a Firecracker microVM. Nothing in the guest can reach the host's routing, firewall, or the daemons that hold secrets.
- **One golden image, cloned per VM.** Every guest sees byte-identical config (same IP, same MAC, same TAP name), so a single memory snapshot resumes into any slot. Disks are LVM thin snapshots of a template volume.
- **Secrets never enter the guest.** The proxy terminates TLS on the host, swaps the placeholder `x-api-key` or `Authorization` header for the real one keyed by domain and principal, and re-originates the connection. The CA key and the secret store each live in their own process behind a Unix socket.
- **Enforcement the guest can't touch.** Routing, NAT, and nftables verdicts live in per-VM namespaces and the host root namespace. A `deny` VM has no default route at all.

## How a proxied connection flows

```text
guest 172.20.0.1 ─tap─▶ netns vm0003 ─SNAT to vp─▶ host root netns
                                                        │
                        nft: slot 3 is `proxy` ──DNAT──▶ iso-proxyd
                                                        │ src ip → slot → {principal, allow}
                                                        │ TLS? has SNI? SNI ∈ allow? :authority == SNI?
                                             iso-cad ───┤ sign a leaf cert for the SNI
                                        iso-secretsd ───┤ headers for (SNI, principal)
                                                        ▼
                                                upstream TLS ──▶ internet
```

Not TLS, or no SNI: dropped. SNI not on the allow-list: reset. Request host that doesn't match the SNI: rejected, so an injected credential can never be redirected to another host. CA down: fail closed. Secrets down: forward without injection.

## Components

| Part | Role |
| --- | --- |
| `iso-controld` | Host daemon. VM records in SQLite, slot allocator, templates, port forwards. Serves the admin HTTP API, the guest metadata service, DNS, and the identify RPC the proxy uses. |
| `iso-control-plane` | The orchestration core behind the daemon, transport-agnostic. |
| `iso-network-manager` | netlink + nftables. Every fixture (netns, veth pair, /31 addresses, NAT, egress verdict) is a pure function of a 15-bit slot ID, so provision and teardown are idempotent. |
| `iso-storage-manager` | LVM thin pool over a loop file. Templates are volumes; VM disks are thin snapshots. |
| `iso-firecracker` | Drives Firecracker over its API socket from inside the VM's netns. Snapshot and resume for warm starts. |
| `iso-proxy` / `iso-ca` / `iso-secrets` | The `proxy` egress mode: `iso-proxyd` (data plane), `iso-cad` (sign-only CA), `iso-secretsd` (TOML-backed header store, hot-reloaded). |
| `iso-dns-server` | Dual-horizon resolver on the services address: `metadata.iso.internal` locally, everything else forwarded. |
| `iso-cli` | `isoctl bake`: build the NixOS image, install it onto a template volume, boot it once, snapshot it. |
| `image/` | Nix flake for the guest: a stripped Firecracker kernel and a minimal NixOS rootfs with sshd and a `coder` user. |

Design notes with the full reasoning: [`crates/iso-network-manager/DESIGN.md`](crates/iso-network-manager/DESIGN.md) and [`crates/iso-proxy/DESIGN.md`](crates/iso-proxy/DESIGN.md).

## Egress modes

| Mode | External traffic | Host services (DNS, metadata) |
| --- | --- | --- |
| `deny` | none; the netns has no default route | reachable |
| `allow` | direct out the uplink; allow-listed domains are DNS-steered through the proxy for credential injection | reachable |
| `proxy` | everything intercepted; only allow-listed TLS destinations pass, with credentials injected | reachable |

Mode and allow-list are per VM, changeable live with `PATCH /vms/{id}/policy`, and apply to new connections.

## Quick start

You need an x86_64 Linux host with KVM, root, LVM2, nftables, and Nix with flakes. `nix develop` provides the nightly Rust toolchain and a Firecracker binary. Replace `eth0` below with your uplink interface.

```bash
nix develop
cargo build

# Guests are key-only. Put your public key in the image and keep the private
# half where bake and the e2e scripts look for it.
mkdir -p state/keys
ssh-keygen -t ed25519 -N '' -f state/keys/test_ed25519
cat state/keys/test_ed25519.pub >> image/keys/authorized_keys

# Control plane (root: netlink, nft, LVM, KVM). All state lives under ISO_STATE_DIR.
sudo ISO_STATE_DIR=$PWD/state ISO_VG=iso ISO_UPLINK=eth0 target/debug/iso-controld &

# Bake a warm template from image/ and register it.
sudo target/debug/isoctl bake --name base --flake image --state $PWD/state --vg iso --uplink eth0 \
  | sudo curl -s --unix-socket state/control.sock -H 'content-type: application/json' -d @- http://x/templates

# Boot a VM with no egress, then SSH in through its namespace.
# Every guest is 172.20.0.1 inside its own netns; the netns is vm<slot in hex>.
sudo curl -s --unix-socket state/control.sock -H 'content-type: application/json' \
  -d '{"template":"base","egress":"deny","labels":{"name":"demo"}}' http://x/vms
sudo curl -s --unix-socket state/control.sock http://x/vms
sudo ip netns exec vm0000 ssh -i state/keys/test_ed25519 coder@172.20.0.1
```

For `proxy` mode, start the three proxy daemons and bake the CA into the image so guests trust it:

```bash
sudo ISO_STATE_DIR=$PWD/state target/debug/iso-cad &        # generates state/ca/ca.crt on first run
cp state/ca/ca.crt image/ca.crt                             # then re-bake
sudo ISO_STATE_DIR=$PWD/state target/debug/iso-secretsd &   # reads state/secrets.toml
sudo ISO_STATE_DIR=$PWD/state target/debug/iso-proxyd &
```

`state/secrets.toml` maps domains to headers, globally or per principal:

```toml
[global."api.anthropic.com"]
"x-api-key" = "sk-ant-..."

[principals.alice."api.github.com"]
"authorization" = { bearer = "ghu_..." }

[principals.alice."github.com"]
"authorization" = { basic = "ghu_..." }   # git over HTTPS
```

Then create a VM as that principal:

```bash
sudo curl -s --unix-socket state/control.sock -H 'content-type: application/json' \
  -d '{"template":"base","egress":"proxy","principal":"alice","allow":["api.anthropic.com","api.github.com","github.com"]}' \
  http://x/vms
```

Inside the guest, `curl https://api.github.com/user` just works. No token in the environment, no `gh auth login`.

`scripts/iso-up.sh` brings the whole stack up idempotently and is safe to run on every boot.

## Admin API

Served on `$ISO_STATE_DIR/control.sock` and, by default, TCP port 7070 on the host's primary IP (see caveats). JSON in, JSON out.

| Endpoint | Effect |
| --- | --- |
| `POST /vms` | Create and boot. Body: `template`, plus optional `egress`, `ingress`, `labels`, `lifecycle` (`ephemeral` or `durable`), `restart`, `vcpus`, `mem_mib`, `principal`, `allow`. |
| `GET /vms`, `GET /vms/{id}` | List, inspect. |
| `POST /vms/{id}/start` · `stop` · `suspend` · `halt` | Lifecycle. |
| `DELETE /vms/{id}` | Destroy. |
| `PATCH /vms/{id}/policy` | Change `egress`, `principal`, `allow` on a running VM. |
| `POST /vms/{id}/forwards` | Open a host port to a VM port. The host port is allocated and returned. |
| `POST /templates` | Register a baked template. |
| `GET /stats` | Pool and slot usage. |

Guests can ask `http://metadata.iso.internal/` who they are: their id, name, labels, and the external `host:port` for every forwarded port. A VM sees only its own record.

## Caveats

This is a working prototype, not a hardened product.

- The admin API is unauthenticated. Set `ISO_ADMIN_TCP=127.0.0.1:7070` or front it with something that authenticates. Anyone who reaches it controls every VM.
- Firecracker runs as a direct child of root without the jailer.
- x86_64 only; the guest kernel config is Firecracker-specific.
- `isoctl bake` drives the host directly rather than through the daemon, so bake on a quiet host.

## Tests

`cargo test` covers the pure parts: slot math, network plans, storage naming, proxy policy. The integration tests in `iso-controld` and `iso-firecracker` need root and KVM and skip otherwise. `scripts/e2e_ssh.sh` and `scripts/e2e_dns.sh` bake a throwaway image into their own volume group and exercise all three egress modes over SSH.
