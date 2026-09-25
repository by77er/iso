# iso — external API reference

Describes every interface `iso` exposes outside its own process boundary, as implemented today
(`iso-controld`). Three surfaces are external:

| Surface | Bound on | Consumer | Auth |
| --- | --- | --- | --- |
| **Admin API** | `$ISO_STATE_DIR/control.sock` and `ISO_ADMIN_TCP` (default `<primary_ipv4>:7070`) | operators, orchestrators, a fleet | socket file permissions (root); mutual TLS on TCP |
| **Metadata API** | `172.22.0.1:80`, reachable only from inside a VM | guests | source IP |
| **DNS** | `172.22.0.1:53` | guests | source IP |

A fourth group — `identify.sock`, `ca.sock`, `secrets.sock` and their HTTPS counterparts — is
plumbing between the iso daemons and is documented at the end as a boundary statement, not as a
supported interface.

The OpenAPI document the daemon generates from its handlers (`GET /openapi.json`) is the
authoritative schema for the admin API. [admin-api.md](admin-api.md) covers authentication, the
Rust client, `isoctl`, and the guest agent behind `exec` and the file operations.

> **Security notice.** Any client certificate that chains to the host's admin CA is a full
> administrator, and so is anyone who can open the Unix socket. There are no roles and no per-VM
> ownership: an administrator can reassign any VM's `principal` and thereby obtain another
> principal's injected credentials. `ISO_ADMIN_INSECURE=1` removes TLS from the TCP listener
> entirely; use it only on a private lab network.

All request and response bodies are JSON. Errors carry `{"error": "<message>"}`.

---

## Admin API

### Conventions

`{id}` is a VM id in canonical hyphenated UUID form or bare 32-hex; both parse. An unparseable id
returns `400 {"error":"invalid vm id"}`.

| Status | Meaning | Causes |
| --- | --- | --- |
| `400` | bad request | malformed id; a rule that does not parse; a fleet signature that does not describe the policy; a request the guest agent refused (a missing file, a program that could not be spawned) |
| `404` | no such object | unknown VM, template, forward or build |
| `409` | cannot satisfy right now | the id already exists, slots or host ports exhausted, storage pool over its watermark, VM in the wrong state for the transition |
| `501` | not configured | a template build on a host without `ISO_BAKE_KERNEL` and `ISO_BAKE_AGENT_BIN` |
| `502` | guest agent unreachable | the VM's agent could not be reached (for example, a template baked without the vsock device) |
| `504` | guest agent too slow | the agent did not answer in time |
| `500` | everything else | backend (LVM, netlink, nftables, Firecracker) failures, store errors |

**Enum parsing is lenient and silent.** `egress`, `lifecycle`, `restart`, and `proto` fall back to
a default rather than rejecting an unrecognized value: an unknown `egress` becomes `deny` (on
`PATCH /vms/{id}/policy` it leaves the mode unchanged), unknown `lifecycle` becomes `ephemeral`,
unknown `restart` becomes `never`, and any `proto` that isn't `"udp"` (case-insensitive) becomes
`tcp`. A typo such as `"egress": "prox"` yields a VM with no egress rather than an error, and so
does the removed `"allow"` mode — check `GET /vms/{id}` to confirm what was applied.

### VM object

Returned by `GET /vms` and `GET /vms/{id}`.

```json
{
  "id": "6f1c2e94-...-a1b2c3d4e5f6",
  "slot": 3,
  "template": "agent",
  "state": "running",
  "egress": "proxy",
  "lifecycle": "ephemeral",
  "restart": "never",
  "labels": { "name": "build-42" },
  "ingress": [ { "host_port": 20007, "vm_port": 8080, "proto": "tcp" } ],
  "tap": "tap0",
  "rootfs_device": "/dev/iso/vm_6f1c2e94...",
  "principal": "alice",
  "allow": [ "api.github.com", "api.anthropic.com" ],
  "rules": [ "deny https://api.github.com/user/keys" ],
  "policy_gen": 4
}
```

`slot`, `tap`, and `rootfs_device` are `null` while the VM holds no placement (state `stopped`).
`state` is one of `creating`, `running`, `suspended`, `stopped`, `failed` — note that `failed` is
defined but never currently produced, so clients should treat it as reserved. `egress` is
`proxy` or `deny`: every byte a VM sends outward goes through the proxy, where its rules decide
(`allow https://*/**` is the open policy; `tunnel tcp://host:port` carries a plain TCP connection
through as bytes). There is no direct mode. `policy_gen` is bumped by every policy change.
`signed`, the fleet's signature over the policy, is present only when a fleet placed the VM.

### `POST /vms` — create and boot a VM

Creates the record, allocates a slot and any host ports, provisions storage and network, and boots.
Returns once the VM is running.

```json
{
  "template": "agent",
  "egress": "proxy",
  "ingress": [ { "vm_port": 8080, "proto": "tcp" } ],
  "labels": { "name": "build-42" },
  "lifecycle": "ephemeral",
  "restart": "never",
  "vcpus": 2,
  "mem_mib": 2048,
  "principal": "alice",
  "allow": [ "api.github.com" ],
  "rules": [ "deny https://api.github.com/user/keys" ]
}
```

Only `template` is required. `vcpus` and `mem_mib` override the template's values when present,
which forces a cold boot instead of a snapshot resume. On `ingress` entries, `host_port` is ignored
if supplied — the control plane allocates it from `forward_ports` (default range 20000–30000) and
reports it back on subsequent reads. `id` creates the VM under a caller-chosen id (a fleet records
the id before it calls, so a retry is a `409`, never a second VM). `signed` carries a fleet's
signature over the policy; see [admin-api.md](admin-api.md).

`lifecycle` selects whether the record and its rootfs survive a stop: `ephemeral` VMs are deleted
on stop, `durable` ones return to state `stopped` and can be started again. `restart` selects
supervisor behavior on unexpected exit: `never`, `always`, or `on_failure`.

**`200 OK`** → `{"id": "<uuid>"}`.

### `GET /vms` — list all VMs

**`200 OK`** → array of VM objects. No filtering, pagination, or query parameters.

### `GET /vms/{id}` — fetch one VM

**`200 OK`** → VM object. **`404`** if unknown.

### `DELETE /vms/{id}` — destroy

Tears down runtime, network, and storage, releases the slot and ports, and deletes the record
regardless of lifecycle. **`204 No Content`**.

### Lifecycle: `POST /vms/{id}/start` · `stop` · `suspend` · `halt` · `terminate` · `retire-suspension`

All take no body and return **`204 No Content`**, or `409` when the VM is not in a state permitting
the transition.

| Action | Effect |
| --- | --- |
| `start` | Boot a `stopped` VM (re-provisions placement) or resume a `suspended` one. A resumed guest has its clock set by the host. |
| `stop` | Graceful shutdown, then a kill if the guest does not exit in time. `ephemeral` → record deleted; `durable` → state `stopped`, rootfs retained. |
| `suspend` | Pause and snapshot in place; slot and network are retained. |
| `halt` | Immediate kill, no graceful shutdown. Same record disposition as `stop`. |
| `terminate` | Durable VMs only: discard running and suspended state, keeping the disk and forwarded ports. The next `start` is a cold boot. |
| `retire-suspension` | Suspended durable VMs only: resume just long enough to shut the guest down cleanly, then `terminate`, freeing the snapshot files. If the guest does not shut down in time the files are kept and the call fails. |

### `PATCH /vms/{id}/policy` — set egress policy and identity

```json
{ "principal": "alice", "allow": ["api.github.com"], "rules": ["deny https://api.github.com/user/keys"], "egress": "proxy" }
```

All fields are optional; omitted fields are left unchanged. An `egress` value that doesn't parse is
*ignored* rather than rejected; a rule that doesn't parse is a `400`. Takes effect on a live VM
without a restart, and bumps `policy_gen`.

`principal` selects which credential set `iso-secretsd` injects for this VM's proxied requests.
`allow` is a host list, sugar for `allow https://host/**` plus `allow wss://host/**`, and `rules`
are the URI-level rules on top of it: default deny, and a matching deny wins. **There is no
ownership check**: any administrator may set any VM's principal to any string.

**`204 No Content`**.

The proxy caches identity for about a second, and re-reads the policy of every VM with live
connections on the same tick: a connection admitted under an older generation is closed, HTTP/2
sessions and WebSockets included. New connections carry the new policy.

### `POST /vms/{id}/forwards` — open an ingress port forward

```json
{ "vm_port": 8080, "proto": "tcp" }
```

**`200 OK`** → `{"host_port": 20007, "vm_port": 8080, "proto": "tcp"}`. The host port is allocated
by the control plane. Returns `409` if the port range is exhausted.

### `DELETE /vms/{id}/forwards/{host_port}` — close a forward

Optional query parameter `?proto=tcp|udp`, defaulting to `tcp` — forwards are keyed on
`(host_port, proto)`, so the protocol must match the one used to create it.

**`204 No Content`**, or `404` if no such forward exists.

### Inside the guest: `agent` · `exec` · `files` · `dir`

These go to the guest agent over vsock, so they work whatever the VM's egress.

| Endpoint | Effect |
| --- | --- |
| `GET /vms/{id}/agent` | Ping the agent: its version, hostname, uid and working directory. `409` if the VM is not running. |
| `POST /vms/{id}/exec` | Run `{cmd, args, cwd?, env?, stdin?, timeout_ms?, max_output_bytes?, user?}`; returns the exit code or signal, stdout and stderr, and `timed_out` / `truncated` flags. |
| `GET /vms/{id}/files?path=` | Read a file (`content_b64`), at most `max_bytes` (default 16 MiB). |
| `PUT /vms/{id}/files?path=` | Write `{content}` or `{content_b64}`, with optional `mode` and `mkdir`. |
| `DELETE /vms/{id}/files?path=` | Remove a path (`&recursive=true` for a directory). |
| `GET /vms/{id}/dir?path=` | List a directory, without following symlinks. |

[admin-api.md](admin-api.md) has the semantics: defaults, limits, and users.

### `GET /templates` · `POST /templates` — list and register templates

`GET /templates` → the registered templates: name, vCPUs, memory, and whether each has a memory
snapshot (so clones resume rather than boot).

`POST /templates` registers one:

```json
{
  "name": "agent",
  "rootfs_template": "agent_v2",
  "snapshot_mem": "/var/lib/iso/templates/agent/mem",
  "snapshot_vmstate": "/var/lib/iso/templates/agent/vmstate",
  "vcpus": 2,
  "mem_mib": 2048,
  "kernel": "/nix/store/...-vmlinux/vmlinux",
  "boot_args": "ro console=ttyS0 ip=172.20.0.1::172.20.0.0:255.255.255.254::eth0:off acpi=off"
}
```

`rootfs_template` names an LVM logical volume (with the manager's `tpl_` prefix applied) that VM
rootfs volumes are cut from as CoW snapshots. `snapshot_mem` and `snapshot_vmstate` are optional
and must be supplied together — supplying only one silently disables snapshot resume for the
template. When both are present, VMs created from this template resume from the snapshot (warm
start) instead of cold-booting.

All paths are host filesystem paths, taken verbatim: they are not validated for existence,
canonicalized, or constrained to any directory. Registration is upsert-style by `name`.

**`201 Created`**.

This endpoint only records a template definition. `isoctl bake` produces the LV and snapshot files
on that specific host, prints the registration body, and saves it as
`$ISO_STATE_DIR/templates/<name>/template.json`.

### `POST /templates/build` · `GET /templates/builds[/{name}]` — build from an OCI image

```json
{ "name": "py312", "image": "python:3.12-slim", "vcpus": 2, "mem_mib": 2048, "size": "16G", "force": false }
```

The daemon runs `isoctl bake --image` itself, one build at a time, and registers the template when
the bake succeeds. An existing template answers `ready` at once unless `force` is set.
**`202 Accepted`** with a build status; `501` on a host without `ISO_BAKE_KERNEL` and
`ISO_BAKE_AGENT_BIN`.

`GET /templates/builds` lists every build this daemon has run, newest first;
`GET /templates/builds/{name}` returns one, with `state` `building`, `ready` or `failed`, and on
failure `error` and the last KiB of the bake's log.

### `GET /stats` — host capacity

**`200 OK`**:

```json
{
  "storage_backend": "lvm-thin",
  "pool_capacity_bytes": 107374182400, "pool_used_bytes": 13314398618,
  "snapshot_bytes": 2147483648,
  "filesystem_capacity_bytes": 250000000000, "filesystem_available_bytes": 180000000000,
  "data_percent": 12.4, "metadata_percent": 3.1,
  "slots_used": 7, "slots_total": 32768, "vms": 7
}
```

Thin-pool data and metadata utilization, the allocated size of tracked suspension files, the
filesystem that holds the pool's backing file, slot allocator occupancy, and the VM record count.
The storage byte fields are `null` when the backend cannot report them. LVM's pool usage includes
blocks shared between templates and VMs, so it is not a sum of disk sizes, and it overlaps with
nothing else here: do not add the figures together. This is host-global and is deliberately absent
from the VM-facing metadata API.

---

## Metadata API (guest-facing)

A guest reaches this at `http://172.22.0.1/` (also `http://metadata.iso.internal/`), which is
routable from every VM in every egress mode. The caller is identified by the source IP of the TCP
connection — the VM's post-SNAT `vp` address — which is mapped back to a slot by pure arithmetic
and then to a VM record. Headers are never trusted for identity.

### `GET /`

```json
{
  "id": "6f1c2e94-...",
  "name": "build-42",
  "slot": 3,
  "template": "agent",
  "labels": { "name": "build-42" },
  "host": "10.0.0.5",
  "endpoints": [
    { "vm_port": 8080, "host_port": 20007, "proto": "tcp", "endpoint": "10.0.0.5:20007" }
  ],
  "egress": "proxy",
  "egress_note": "All egress goes through the proxy. …",
  "principal": "alice",
  "allow": [ "api.github.com" ],
  "rules": [],
  "policy_gen": 1,
  "credentials": [ { "host": "api.github.com", "headers": [ "authorization" ] } ]
}
```

A VM sees **only its own record** — no host-global state and no other VM's data. `name` is a
convenience projection of `labels["name"]` and is `null` if unset. `host` is the host's reachable
IPv4, provided so a guest can construct the externally reachable URL for a service it is running;
it and each `endpoint` are `null` if the host address could not be determined. `credentials` lists,
per literal allowed host (a wildcard has no host to describe), the *names* of the headers the proxy
injects; an empty list means the host is reachable but no credential is added. It is `null` in
`deny` mode or when the secrets service is not configured.

**This endpoint always returns HTTP 200**, including on failure — errors appear only in the body as
`{"error": "unknown caller", "src": "172.21.0.7"}` or `{"error": "unsupported source"}`. Guest
agents must inspect the body rather than relying on the status code.

The metadata service exposes no secret values and no write operations.

---

## DNS (guest-facing)

`172.22.0.1:53`, UDP and TCP, is the only resolver guests are configured with.

- Authoritative for the `iso.internal.` zone, which contains a single A record,
  `metadata.iso.internal` → `172.22.0.1`. Zone transfers (AXFR) are refused.
- Everything else is forwarded upstream (default `1.1.1.1`, `8.8.8.8`). No DNSSEC validation.
- **Every A answer is remembered**, per VM, for at least ten minutes: `(VM, address) → name`.
  A VM's traffic is intercepted at the network layer whatever DNS says, so DNS is not a security
  boundary; the memory is what puts a name to a plain TCP connection (one to a port other than 443,
  which carries no SNI) so it can be matched against `tunnel tcp://name:port` rules. An address a VM
  never resolved through this server has no name and is refused.
- AAAA queries answer NODATA: guests have no IPv6 route, and a passthrough needs the A answer the
  server saw.

---

## Internal RPC (not an external interface)

Three Unix sockets under `$ISO_STATE_DIR` carry one JSON request and one JSON response per
connection, framed by half-close (write, `shutdown()`, read to EOF) rather than by a length prefix.

| Socket | Server | Client | Purpose |
| --- | --- | --- | --- |
| `identify.sock` | `iso-controld` | `iso-proxyd` | source IP → `{found, vm, egress, principal, allow, rules, policy_gen, signed}`, plus `dst_name` for a destination the VM resolved |
| `ca.sock` | `iso-cad` | `iso-proxyd` | sign a leaf CSR under the tier's MITM root |
| `secrets.sock` | `iso-secretsd` | `iso-proxyd`, `iso-controld` (names only, for metadata) | `(domain, principal, path)` → header map, or header names |

Failure modes are asymmetric by design: the CA fails **closed** (an error yields an empty chain, so
no certificate is minted and the connection is refused), while secrets fail **open** (an error
yields an empty header map, so the request proceeds without injected credentials).

For a proxy tier on other machines, `iso-cad` and `iso-secretsd` also serve the same methods over
HTTPS with mutual TLS (`POST /sign`, `POST /headers`) when started with `ISO_CA_LISTEN` or
`ISO_SECRETS_LISTEN`, and then answer only the certificate names in `ISO_ALLOWED_CLIENTS`. The Unix
sockets carry no authentication: access control is the socket file's permissions, and anything that
can open `ca.sock` can obtain a certificate for an arbitrary name, and anything that can open
`secrets.sock` can read any principal's credentials.

Do not build external tooling against these; they are expected to change shape.
