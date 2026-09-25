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

A host in a fleet holds no CA key. The control host mints its identity with
`isoctl admin issue-server`, and the host is given `ca.crt`, `server.crt` and
`server.key` with no `ca.key` beside them. It then presents that identity and
verifies clients, but refuses to issue certificates of its own, so a
compromised host cannot mint credentials. See [fleet.md](fleet.md).

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
`admin-pki` directory, restart the daemon, and reissue. A guest cannot use the
TCP listener without a certificate. `ISO_ADMIN_INSECURE=1` serves plain HTTP
instead, for a lab host on a private network.

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
| `POST /vms` | Create and boot. Body: `template`, plus optional `egress` (`proxy` or `deny`), `ingress`, `labels`, `lifecycle` (`ephemeral` or `durable`), `restart`, `vcpus`, `mem_mib`, `principal`, `allow`, `rules`. |
| `GET /vms`, `GET /vms/{id}` | List, inspect. |
| `POST /vms/{id}/start` · `stop` · `suspend` · `halt` | Lifecycle transitions; `409` when not valid in the current state. |
| `POST /vms/{id}/terminate` | Cold-stop a durable VM: discard its running and suspended state, keep its disk and forwarded ports. The next `start` boots it fresh. |
| `POST /vms/{id}/retire-suspension` | For a suspended durable VM: resume it only to shut it down cleanly, then terminate it, freeing the snapshot files. If the guest does not shut down in time the files are kept and the call fails. |
| `DELETE /vms/{id}` | Destroy, whatever the lifecycle. |
| `PATCH /vms/{id}/policy` | Change `egress`, `principal`, `allow`, `rules` on a running VM. Bumps `policy_gen`; new connections carry it and the proxy closes older ones within a second. A rule that does not parse is a `400`. |
| `POST /vms/{id}/forwards`, `DELETE /vms/{id}/forwards/{host_port}` | Open or close an ingress forward; the host port is allocated. |
| `GET /vms/{id}/agent` | Ping the guest agent. |
| `POST /vms/{id}/exec` | Run a program inside the VM. |
| `GET` / `PUT` / `DELETE /vms/{id}/files?path=` | Read, write, remove a file inside the VM. |
| `GET /vms/{id}/dir?path=` | List a directory inside the VM. |
| `GET /templates` | Registered templates, and whether each has a memory snapshot. |
| `POST /templates` | Register a template baked by `isoctl bake`. |
| `POST /templates/build` | Build a template from an OCI image: `{ "name", "image", "vcpus"?, "mem_mib"?, "size"?, "force"? }`. `202` with a build status; the host pulls the image, bakes it with the guest agent as init, and registers the template. An existing template answers `ready` unless `force` is set. One build at a time per host. `501` on a host without `ISO_BAKE_KERNEL` and `ISO_BAKE_AGENT_BIN`. |
| `GET /templates/builds` | Every build this daemon has run, newest first. |
| `GET /templates/builds/{name}` | One build: `state` is `building`, `ready` or `failed`, with `error` and the last KiB of the bake's log. |
| `GET /stats` | Slots, VM count, and storage: thin-pool usage, suspension files, and free space on the filesystem under the pool. Storage fields are `null` when the backend cannot report them. |
| `GET /openapi.json` | This API, as OpenAPI 3.0. |

A VM record carries `signed` when a fleet placed it: the fleet's signature
over the policy (`{claims, sig}`, both base64). `POST /vms` and
`PATCH /vms/{id}/policy` accept `signed`; the host stores it only when it
describes the policy the host stores, at the generation the call produces
(or the current one, for a re-signing that changes nothing), and answers
400 otherwise. A change without `signed` drops the stored signature.

Errors are `{"error": "…"}`. `400` is a malformed id, a rule that does not
parse, or a request the guest agent refused (a missing file, a program that
could not be spawned), `404` an unknown VM, template or forward, `409` a state
conflict or exhausted resource, `501` a template build on a host not configured
for it, `502` a VM whose agent could not be reached, `504` an agent that did
not answer in time.

## The guest agent

`exec` and the file operations are served by `iso-guest-agent`, a small
service on vsock port 5000 in every guest: as the `coder` user on the NixOS
and Debian images, and as PID 1 in a template built from an OCI image (see
below). The host reaches it through Firecracker's vsock device, so nothing
about it touches the VM's network policy: a `deny` VM is as reachable as any
other. The agent speaks
length-prefixed JSON frames (`crates/iso-guest-proto`); the admin API is the
only intended client.

Semantics worth knowing:

- `exec` runs the program in its own process group with the agent's user and
  environment plus the request's `env`; `timeout_ms` (default 120 s) kills the
  whole group, and captured stdout and stderr are each capped at
  `max_output_bytes` (default 1 MiB). The response carries the exit code, or the
  signal, `timed_out` and `truncated` flags, and the duration. An agent
  running as root runs the program as `user` (a name or uid) when the request
  names one, the way `docker exec --user` does; an OCI template's default is
  the image's `USER`. On the NixOS and Debian images the agent is `coder`,
  with passwordless `sudo` for anything that needs root.
- File bodies travel base64 (`content_b64`); `PUT` also accepts plain `content`
  for text. `GET` reads at most `max_bytes` (default 16 MiB) and says whether it
  was cut. Listings never follow symlinks.
- A template baked before the vsock device existed has no channel: the daemon
  reports `502` with a message saying so. Re-bake with the current image.
- After a snapshot resume the daemon tells the agent the host's wall clock
  (`set_clock`): a restored guest otherwise keeps the time it was baked at,
  since kvm-clock only seeds a fresh boot. The agent steps the clock when it
  is more than a second off; its unit grants `CAP_SYS_TIME` for that and
  nothing else. A template baked with an older agent logs a warning on the
  host at each resume and keeps its stale clock until it is re-baked.

`iso-guest-agent --listen-tcp 127.0.0.1:5000` serves the same protocol over
TCP for debugging outside a VM.

### Guest flavors

The host provides a kernel, a block device, a TAP, a vsock and boot
arguments, and nothing about it depends on the userland inside. Every flavor
gets the resolver, the proxy CA and the agent; the NixOS and Debian images
also have the `coder` user and sshd.

| Flavor | Built by | Init | For |
| --- | --- | --- | --- |
| `nixos` (default) | the flake, `nix build .#toplevel` | NixOS stage 2 | reproducible, minimal, declarative |
| `debian` | `image/debian/build-rootfs.sh` via `mmdebstrap`, at bake time | systemd | agents that expect apt and the usual file layout |
| `oci` | any OCI image: `isoctl bake --image REF` (or `--oci-tar FILE`), or `POST /templates/build` | the guest agent | running an existing container image unchanged |

An OCI image has no init, so the agent is one: as PID 1 it mounts the pseudo
filesystems, runs the agent proper with the image's environment, working
directory and user (from `/etc/iso/image.json`, written at bake time), reaps
orphans, and powers off on Ctrl-Alt-Del. The bake puts the proxy CA into every
system bundle the image has and points `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS` and `PIP_CERT` at it,
so python, node, curl and git trust the proxy without changes to the image.
`ISO_REGISTRY_AUTH=user:password` reaches a private registry; images must be
linux/amd64.

`isoctl bake --distro debian --debian-suite trixie [--debian-snapshot 20260901T000000Z] [--debian-packages a,b]`
builds the Debian one; apt mirrors are `https://` because the proxy passes only
TLS, so a VM that should install packages needs `deb.debian.org` and
`security.debian.org` on its allow-list. The static agent binary comes from
`nix build .#iso-guest-agent-static`. `bake` saves every registration as
`state/templates/<name>/template.json`, which `iso-up.sh` posts on boot.

## Running VMs under the jailer

The daemon (and `isoctl bake`) launch every VM through Firecracker's `jailer`
unless `ISO_JAILER=0`: a chroot per VM under `ISO_JAIL_DIR` (default
`$ISO_STATE_DIR/jail`), the VMM dropped to `ISO_JAIL_UID`/`ISO_JAIL_GID`
(default 65534), the netns joined by the jailer, cgroup v2, and optional
`ISO_JAIL_CGROUPS` and `ISO_JAIL_RLIMITS` (comma-separated `key=value`).
Inside the jail the rootfs is a device node pointing at the VM's own volume,
the kernel and snapshot are hard links (or a per-host cached copy when the
source is on another filesystem, as the Nix store is), and every path
Firecracker sees is the same for every VM, which is what a snapshot needs.

The daemon refuses to start if the jailer is on but its binary cannot be
found, rather than quietly running VMs unjailed.

Requirements: the jail directory must not be on a `nodev` mount (`/tmp` is
often a tmpfs mounted that way; the symptom is "Permission denied" opening
`/dev/net/tun` or `/dev/kvm` inside the jail), and the `jailer` binary must
match the Firecracker version. Jail paths run long, past the 107-byte unix
socket limit with most state directories; the daemon connects to a jailed
VM's sockets through `/proc/self/fd`, so that limit does not apply to it. Templates baked without
the jailer still resume under it; templates baked under it record only
jail-relative paths. A VM's jail is removed on destroy.

## Metadata and DNS, briefly

Guests reach `http://metadata.iso.internal/` (the services address on port 80)
and get their own record only: id, name, labels, the host's address, one
`endpoint` per forwarded port, and their egress policy (`egress`, a short
`egress_note`, `principal`, `allow`, `rules`, `policy_gen`). For each allowed
host it also lists the *names* of the headers the proxy injects, never their
values, so a guest can tell which requests will carry a credential.

The same address serves DNS: `metadata.iso.internal` locally, everything else
through the upstream resolvers. The server answers A queries itself and
remembers, per VM, which name each address came from: that is how the proxy
puts a name to a plain TCP connection and matches it against a
`tunnel tcp://host:port` rule. AAAA queries get no answer, since guests have no
IPv6 route. Neither surface is authenticated; both identify the caller by the
source address the host assigned it.
