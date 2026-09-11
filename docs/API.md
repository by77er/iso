# iso — external API reference

Describes every interface `iso` exposes outside its own process boundary, as implemented today
(`iso-controld`). Three surfaces are external:

| Surface | Bound on | Consumer | Auth |
| --- | --- | --- | --- |
| **Admin API** | `$ISO_STATE_DIR/control.sock` and `<primary_ipv4>:7070` | operators, orchestrators | **none** |
| **Metadata API** | `172.22.0.1:80`, reachable only from inside a VM | guest agents | source IP |
| **DNS** | `172.22.0.1:53` | guests | source IP |

A fourth group — `identify.sock`, `ca.sock`, `secrets.sock` — is internal plumbing between the iso
daemons and is documented at the end as a boundary statement, not as a supported interface.

> **Security notice.** The admin API is unauthenticated on both transports, and its TCP listener
> defaults to the host's routable primary IPv4, not loopback. Anyone who can reach port 7070 has
> full control of every VM on the host, including the ability to reassign any VM's `principal` and
> thereby obtain another principal's injected credentials. Treat reachability of that port as
> equivalent to root on the host until authentication lands. See `docs/` plan notes for the fix.

All request and response bodies are JSON. Errors carry `{"error": "<message>"}`.

---

## Admin API

### Conventions

`{id}` is a VM id in canonical hyphenated UUID form or bare 32-hex; both parse. An unparseable id
returns `400 {"error":"invalid vm id"}`.

Status codes are mapped centrally from the control plane's error type:

| Status | Meaning | Causes |
| --- | --- | --- |
| `400` | malformed id | `VmId::parse` failure |
| `404` | no such object | unknown VM, template, or forward |
| `409` | cannot satisfy right now | slots exhausted, host ports exhausted, storage pool over watermark, VM in the wrong state for the requested transition |
| `500` | everything else | backend (LVM, netlink, nftables, Firecracker) failures, store errors |

**Enum parsing is lenient and silent.** `egress`, `lifecycle`, `restart`, and `proto` fall back to
a default rather than rejecting an unrecognized value: an unknown `egress` becomes `deny`, unknown
`lifecycle` becomes `ephemeral`, unknown `restart` becomes `never`, and any `proto` that isn't
`"udp"` (case-insensitive) becomes `tcp`. A typo such as `"egress": "prox"` yields a VM with no
egress rather than an error — check the response body of `GET /vms/{id}` to confirm what was
actually applied.

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
  "allow": [ "api.github.com", "api.anthropic.com" ]
}
```

`slot`, `tap`, and `rootfs_device` are `null` while the VM holds no placement (state `stopped`).
`state` is one of `creating`, `running`, `suspended`, `stopped`, `failed` — note that `failed` is
defined but never currently produced, so clients should treat it as reserved. `egress` is
`allow`, `proxy`, or `deny`.

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
  "allow": [ "api.github.com" ]
}
```

Only `template` is required. `vcpus` and `mem_mib` override the template's values when present.
On `ingress` entries, `host_port` is ignored if supplied — the control plane allocates it from
`forward_ports` (default range 20000–30000) and reports it back on subsequent reads.

`lifecycle` selects whether the record and its rootfs survive a stop: `ephemeral` VMs are deleted
on stop, `durable` ones return to state `stopped` and can be started again. `restart` selects
supervisor behavior on unexpected exit: `never`, `always`, or `on_failure`.

**`200 OK`** → `{"id": "<uuid>"}`. Errors: `409` if slots/ports are exhausted or the storage pool
is above its watermark; `404` for an unknown template.

### `GET /vms` — list all VMs

**`200 OK`** → array of VM objects. No filtering, pagination, or query parameters.

### `GET /vms/{id}` — fetch one VM

**`200 OK`** → VM object. **`404`** if unknown.

### `DELETE /vms/{id}` — destroy

Tears down runtime, network, and storage, releases the slot and ports, and deletes the record
regardless of lifecycle. **`204 No Content`**.

### `POST /vms/{id}/start` · `/stop` · `/suspend` · `/halt`

All take no body and return **`204 No Content`**.

| Action | Effect |
| --- | --- |
| `start` | Boot a `stopped` VM (re-provisions placement) or resume a `suspended` one. |
| `stop` | Graceful shutdown. `ephemeral` → record deleted; `durable` → state `stopped`, rootfs retained. |
| `suspend` | Pause and snapshot to memory; slot and network are retained. |
| `halt` | Immediate kill, no graceful shutdown. Same record disposition as `stop`. |

Returns `409` when the VM is not in a state permitting the transition.

### `PATCH /vms/{id}/policy` — set egress policy and identity

```json
{ "principal": "alice", "allow": ["api.github.com"], "egress": "proxy" }
```

All three fields are optional; omitted fields are left unchanged. An `egress` value that doesn't
parse is *ignored* rather than rejected. Takes effect on a live VM without a restart.

`principal` selects which credential set `iso-secretsd` injects for this VM's proxied requests, and
`allow` is the exact-match domain allow-list the proxy enforces (default deny). **There is no
ownership check**: any caller may set any VM's principal to any string.

**`204 No Content`**.

Two staleness caveats: the proxy caches identity for ~1s, and — more significantly — it resolves
policy once per TCP connection, so a change does not apply to connections already open. Long-lived
HTTP/2 connections can outlive a revocation indefinitely.

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

### `POST /templates` — register a template

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

Note that this endpoint only records a template definition — it does not build, fetch, or install
any artifact. Producing the referenced LV and snapshot files is done out of band by
`isoctl bake` on that specific host.

### `GET /stats` — host capacity

**`200 OK`**:

```json
{ "data_percent": 12.4, "metadata_percent": 3.1, "slots_used": 7, "slots_total": 32768, "vms": 7 }
```

Thin-pool data and metadata utilization, slot allocator occupancy, and total VM record count. This
is host-global and is deliberately absent from the VM-facing metadata API.

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
  ]
}
```

A VM sees **only its own record** — no host-global state and no other VM's data. `name` is a
convenience projection of `labels["name"]` and is `null` if unset. `host` is the host's reachable
IPv4, provided so a guest can construct the externally reachable URL for a service it is running;
it and each `endpoint` are `null` if the host address could not be determined.

**This endpoint always returns HTTP 200**, including on failure — errors appear only in the body as
`{"error": "unknown caller", "src": "172.21.0.7"}` or `{"error": "unsupported source"}`. Guest
agents must inspect the body rather than relying on the status code.

The metadata service exposes no secrets, no credentials, and no write operations.

---

## DNS (guest-facing)

`172.22.0.1:53`, UDP and TCP, is the only resolver guests are configured with.

- Authoritative for the `iso.internal.` zone, which contains a single A record,
  `metadata.iso.internal` → `172.22.0.1`. Zone transfers (AXFR) are refused.
- Everything else is forwarded upstream (default `1.1.1.1`, `8.8.8.8`). No DNSSEC validation.
- **Selective redirect:** for a VM in `allow` egress mode, an A query for a name that appears
  exactly in that VM's `allow` list is answered with the proxy's address instead of the real one,
  with a 5-second TTL, so that traffic is routed through credential injection. The matching AAAA
  query returns NODATA so clients fall back to A. Matching is case-sensitive exact string equality,
  so a mixed-case query silently misses the redirect and resolves normally.
- VMs in `proxy` mode are **not** affected by this redirect: their traffic is intercepted at the
  network layer by nftables regardless of what DNS returns, so DNS is not a security boundary for
  them. For `allow`-mode VMs the redirect is a credential-injection convenience, not a restriction —
  those VMs have unrestricted direct egress either way.

---

## Internal RPC (not an external interface)

Three Unix sockets under `$ISO_STATE_DIR` carry one JSON request and one JSON response per
connection, framed by half-close (write, `shutdown()`, read to EOF) rather than by a length prefix.
They exist only between iso's own daemons and carry no versioning or authentication — access
control is entirely the socket file's permissions.

| Socket | Server | Client | Purpose |
| --- | --- | --- | --- |
| `identify.sock` | `iso-controld` | `iso-proxyd` | source IP → `{found, egress, principal, allow}` |
| `ca.sock` | `iso-cad` | `iso-proxyd` | sign a leaf CSR under the host's MITM root |
| `secrets.sock` | `iso-secretsd` | `iso-proxyd` | `(domain, principal)` → header map |

Failure modes are asymmetric by design: the CA fails **closed** (an error yields an empty chain, so
no certificate is minted and the connection is refused), while secrets fail **open** (an error
yields an empty header map, so the request proceeds without injected credentials).

Do not build external tooling against these; they are expected to change shape, and neither
`iso-cad` nor `iso-secretsd` performs any peer authentication — anything that can open `ca.sock`
can obtain a certificate for an arbitrary name, and anything that can open `secrets.sock` can read
any principal's credentials.
