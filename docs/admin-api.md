# The admin API

`iso-controld` serves one HTTP API on two transports. The reference for every
operation, parameter and schema is the OpenAPI document the daemon generates
from its own handlers: `GET /openapi.json`, or `cargo run -p iso-controld --bin
iso-openapi`. This page covers what the document cannot: how to reach the API,
how to authenticate, the client crate, the command line, and the guest agent
behind the `exec` and file operations.

## Transports and authentication

| Transport | Where | Who |
| --- | --- | --- |
| Unix socket | `$ISO_STATE_DIR/control.sock`, mode 0600 | root on the host |
| TCP, mutual TLS | `ISO_ADMIN_TCP`, default the host's primary IPv4 on port 7070 | anyone holding a client certificate from this host's admin CA |

The admin CA lives under `ISO_ADMIN_TLS_DIR` (default `$ISO_STATE_DIR/admin-pki`)
and is created the first time the daemon starts. It is separate from the egress
proxy's CA on purpose: that one is trusted by guests and terminates hostile
traffic, and a compromise of it must not yield admin credentials. The server
certificate names `localhost`, `127.0.0.1`, the host's primary address and
hostname, plus anything in `ISO_ADMIN_SANS`; it is reissued when that set grows.

Mint a client identity on the host and copy the three files to wherever the
client runs:

```bash
sudo isoctl admin issue-client --name orchestrator --out ./creds
#   ./creds/orchestrator.crt  ./creds/orchestrator.key  ./creds/ca.crt
curl --cacert creds/ca.crt --cert creds/orchestrator.crt --key creds/orchestrator.key \
  https://10.0.0.5:7070/vms
```

The threat model is deliberately simple. Any certificate chaining to the CA is
a full administrator; there are no roles and no per-VM ownership. Certificates
are valid for two years and there is no revocation list: to revoke, delete the
`admin-pki` directory, restart the daemon, and reissue. A guest cannot reach the
TCP listener without a certificate, which closes the path an `allow`-mode VM
previously had to the unauthenticated port. `ISO_ADMIN_INSECURE=1` serves plain
HTTP instead, for a lab host on a private network.

## Clients

**Rust.** `crates/iso-client` is generated from the OpenAPI document by
[progenitor](https://github.com/oxidecomputer/progenitor); a test in
`iso-controld` fails when the checked-in document drifts from the code, and
`scripts/gen-client.sh` regenerates both. The hand-written part is the mutual
TLS setup:

```rust
let creds = iso_client::Credentials::from_dir("./creds", "orchestrator")?;
let iso = iso_client::Client::connect("https://10.0.0.5:7070", &creds)?;

let vm = iso.create()
    .body_map(|b| b.template("base").egress("proxy").principal("alice").allow(vec!["api.github.com".into()]))
    .send().await?;
let out = iso.guest_exec().id(&vm.id)
    .body_map(|b| b.cmd("sh").args(vec!["-c".into(), "git status".into()]))
    .send().await?;
println!("{}", out.stdout);
```

**Command line.** `isoctl vm …` wraps the same client. Connection settings come
from `--server`/`ISO_SERVER`, `--creds`/`ISO_CREDS` and `--client`/`ISO_CLIENT`,
or `--insecure`.

```bash
export ISO_SERVER=https://10.0.0.5:7070 ISO_CREDS=./creds ISO_CLIENT=orchestrator
id=$(isoctl vm create --template base --name build-42 --egress proxy \
       --principal alice --allow api.github.com --forward 8080 --quiet)
isoctl vm exec "$id" -- git clone https://github.com/example/repo
isoctl vm put "$id" /home/coder/repo/notes.md --content "# hi" --mkdir
isoctl vm cat "$id" /home/coder/repo/README.md
isoctl vm ls  "$id" /home/coder/repo
isoctl vm rm  "$id"
```

`exec` copies the program's stdout and stderr to ours and exits with its exit
code, so it composes with shell tooling the way `ssh host cmd` does.

## Operations

| Method and path | What it does |
| --- | --- |
| `POST /vms` | Create and boot. Body: `template`, plus optional `egress`, `ingress`, `labels`, `lifecycle`, `restart`, `vcpus`, `mem_mib`, `principal`, `allow`. |
| `GET /vms`, `GET /vms/{id}` | List, inspect. |
| `POST /vms/{id}/start` · `stop` · `suspend` · `halt` | Lifecycle transitions; `409` when not valid in the current state. |
| `DELETE /vms/{id}` | Destroy, whatever the lifecycle. |
| `PATCH /vms/{id}/policy` | Change `egress`, `principal`, `allow` on a running VM; applies to new connections. |
| `POST /vms/{id}/forwards`, `DELETE /vms/{id}/forwards/{host_port}` | Open or close an ingress forward; the host port is allocated. |
| `GET /vms/{id}/agent` | Ping the guest agent. |
| `POST /vms/{id}/exec` | Run a program inside the VM. |
| `GET` / `PUT` / `DELETE /vms/{id}/files?path=` | Read, write, remove a file inside the VM. |
| `GET /vms/{id}/dir?path=` | List a directory inside the VM. |
| `POST /templates` | Register a baked template. |
| `GET /stats` | Pool and slot usage. |
| `GET /openapi.json` | This API, as OpenAPI 3.0. |

Errors are `{"error": "…"}`. `400` is a malformed id or a request the guest
agent refused (a missing file, a program that could not be spawned), `404` an
unknown VM, template or forward, `409` a state conflict or exhausted resource,
`502` a VM whose agent could not be reached, `504` an agent that did not answer
in time.

## The guest agent

`exec` and the file operations are served by `iso-guest-agent`, a small
service the base image runs as the `coder` user on vsock port 5000. The host
reaches it through Firecracker's vsock device, so nothing about it touches the
VM's network policy: a `deny` VM is as reachable as any other. The agent speaks
length-prefixed JSON frames (`crates/iso-guest-proto`); the admin API is the
only intended client.

Semantics worth knowing:

- `exec` runs the program in its own process group with the agent's user and
  environment plus the request's `env`; `timeout_ms` (default 120 s) kills the
  whole group, and captured stdout and stderr are each capped at
  `max_output_bytes` (default 1 MiB). The response carries the exit code, or the
  signal, `timed_out` and `truncated` flags, and the duration. Passwordless
  `sudo` is available inside the guest for anything that needs root.
- File bodies travel base64 (`content_b64`); `PUT` also accepts plain `content`
  for text. `GET` reads at most `max_bytes` (default 16 MiB) and says whether it
  was cut. Listings never follow symlinks.
- A template baked before the vsock device existed has no channel: the daemon
  reports `502` with a message saying so. Re-bake with the current image.

`iso-guest-agent --listen-tcp 127.0.0.1:5000` serves the same protocol over
TCP for debugging outside a VM.

## Running VMs under the jailer

`ISO_JAILER=1` makes the daemon (and `isoctl bake`) launch every VM through
Firecracker's `jailer`: a chroot per VM under `ISO_JAIL_DIR` (default
`$ISO_STATE_DIR/jail`), the VMM dropped to `ISO_JAIL_UID`/`ISO_JAIL_GID`
(default 65534), the netns joined by the jailer, cgroup v2, and optional
`ISO_JAIL_CGROUPS` and `ISO_JAIL_RLIMITS` (comma-separated `key=value`).
Inside the jail the rootfs is a device node pointing at the VM's own volume,
the kernel and snapshot are hard links (or a per-host cached copy when the
source is on another filesystem, as the Nix store is), and every path
Firecracker sees is the same for every VM, which is what a snapshot needs.

Requirements: the jail directory must not be on a `nodev` mount, and the
`jailer` binary must match the Firecracker version. Templates baked without
the jailer still resume under it; templates baked under it record only
jail-relative paths. A VM's jail is removed on destroy.

## Metadata and DNS, briefly

Guests reach `http://metadata.iso.internal/` (the services address on port 80)
and get their own record only: id, name, labels, the host's address, and one
`endpoint` per forwarded port. The same address serves DNS: `metadata.iso.internal`
locally, everything else forwarded, with `allow`-mode VMs steered to the
proxy for the domains on their allow-list. Neither surface is authenticated;
both identify the caller by the source address the host assigned it.
