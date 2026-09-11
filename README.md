# iso

Firecracker microVM sandboxes for coding agents and other untrusted code, on one Linux host.

Every VM gets its own kernel, its own network namespace, and a copy-on-write disk cut from a warm snapshot, so it boots in milliseconds. Egress is decided on the host, per VM: **deny** it, **allow** it, or **proxy** it through a transparent TLS-terminating proxy that enforces a domain allow-list and injects real credentials in flight. The guest only ever holds a placeholder key. A coding agent never has to run inside the VM: the host reaches a small agent in the guest over vsock, so `exec` and file access are admin API calls, and a harness outside the VM drives them as tools.

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
| `iso-guest-agent` / `iso-guest-proto` | The service inside the guest that runs programs and moves files for the host, and its wire protocol. |
| `iso-admin-pki` | The admin API's own CA: server certificate and client certificates for mutual TLS. |
| `iso-client` | Rust client for the admin API, generated from its OpenAPI document. |
| `iso-cli` | `isoctl`: bake templates, issue admin client certificates, and drive VMs (`isoctl vm create`, `exec`, `cat`, `put`, …). |
| `image/` | The guest image, built by the repository's flake (`nix build .#toplevel`): a stripped Firecracker kernel with vsock, and a lean NixOS rootfs with sshd, a `coder` user and the guest agent. |

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

# Bake a warm template from the flake's image (nix build .#toplevel) and register it.
sudo target/debug/isoctl bake --name base --state $PWD/state --vg iso --uplink eth0 \
  | sudo curl -s --unix-socket state/control.sock -H 'content-type: application/json' -d @- http://x/templates

# Boot a VM with no egress and run something in it through the guest agent.
sudo curl -s --unix-socket state/control.sock -H 'content-type: application/json' \
  -d '{"template":"base","egress":"deny","labels":{"name":"demo"}}' http://x/vms
sudo curl -s --unix-socket state/control.sock -H 'content-type: application/json' \
  -d '{"cmd":"uname","args":["-a"]}' http://x/vms/<id>/exec

# Or SSH in through its namespace: every guest is 172.20.0.1 inside its own
# netns, and the netns is vm<slot in hex>.
sudo ip netns exec vm0000 ssh -i state/keys/test_ed25519 coder@172.20.0.1
```

From another machine, or as a non-root user, use the TCP listener with a
client certificate and the `isoctl vm` commands:

```bash
sudo target/debug/isoctl admin issue-client --name me --out ./creds   # ca.crt, me.crt, me.key
export ISO_SERVER=https://<host ip>:7070 ISO_CREDS=./creds ISO_CLIENT=me
id=$(target/debug/isoctl vm create --template base --name demo --quiet)
target/debug/isoctl vm exec "$id" -- sh -c 'echo hello from $(hostname)'
target/debug/isoctl vm put  "$id" /home/coder/hello.txt --content "hi"
target/debug/isoctl vm rm   "$id"
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

`scripts/iso-up.sh` brings the whole stack up idempotently and is safe to run on every boot. `ISO_JAILER=1` in its environment (or the daemon's) runs every VM under Firecracker's jailer.

## Admin API

Served on `$ISO_STATE_DIR/control.sock` (root only) and on TCP port 7070 of the host's primary IP with mutual TLS: the daemon keeps a CA of its own and `isoctl admin issue-client` mints certificates for it. The OpenAPI document is generated from the handlers and served at `/openapi.json`; `crates/iso-client` is generated from it, and `isoctl vm` wraps that. [docs/admin-api.md](docs/admin-api.md) has the details. JSON in, JSON out.

| Endpoint | Effect |
| --- | --- |
| `POST /vms` | Create and boot. Body: `template`, plus optional `egress`, `ingress`, `labels`, `lifecycle` (`ephemeral` or `durable`), `restart`, `vcpus`, `mem_mib`, `principal`, `allow`. |
| `GET /vms`, `GET /vms/{id}` | List, inspect. |
| `POST /vms/{id}/start` · `stop` · `suspend` · `halt` | Lifecycle. |
| `DELETE /vms/{id}` | Destroy. |
| `PATCH /vms/{id}/policy` | Change `egress`, `principal`, `allow` on a running VM. |
| `POST /vms/{id}/forwards` | Open a host port to a VM port. The host port is allocated and returned. |
| `POST /vms/{id}/exec` | Run a program inside the VM through the guest agent; output and exit status come back. |
| `GET` / `PUT` / `DELETE /vms/{id}/files?path=`, `GET /vms/{id}/dir?path=` | Read, write, remove and list files inside the VM. |
| `POST /templates` | Register a baked template. |
| `GET /stats` | Pool and slot usage. |
| `GET /openapi.json` | The API's OpenAPI 3.0 document. |

Guests can ask `http://metadata.iso.internal/` who they are: their id, name, labels, and the external `host:port` for every forwarded port. A VM sees only its own record.

## Caveats

This is a working prototype, not a hardened product.

- Any client certificate from the admin CA is a full administrator: no roles, no per-VM ownership, no revocation short of replacing the CA.
- The jailer is opt-in (`ISO_JAILER=1`); without it Firecracker runs as a direct child of root.
- Templates baked before the guest agent existed have no vsock device, so `exec` and the file operations need a re-bake with the current image.
- x86_64 only; the guest kernel config is Firecracker-specific.
- `isoctl bake` drives the host directly rather than through the daemon, so bake on a quiet host.

## Tests

`cargo test` covers the pure parts: slot math, network plans, storage naming, proxy policy. The integration tests in `iso-controld` and `iso-firecracker` need root and KVM and skip otherwise. `scripts/e2e_ssh.sh` and `scripts/e2e_dns.sh` bake a throwaway image into their own volume group and exercise all three egress modes over SSH.
