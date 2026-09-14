# The fleet service

`iso-fleetd` is one API over many iso hosts. A client asks for a VM and gets
one somewhere; from then on it names the VM by id and never a host. The
fleet picks the host, remembers the choice, routes every later call to that
host's admin API, and keeps its record honest with a sync loop. Hosts run
`iso-controld` unchanged. Adding capacity is adding a host to the config.

## The one idea

The host admin API is already a host agent API: imperative, mutually
authenticated, generated into a client, and complete. So the fleet has no
host protocol of its own. Its API is the host API with the host removed, and
`isoctl vm`, the pi extension and `iso-client` work against it by changing a
URL:

```bash
export ISO_SERVER=https://fleet.example.internal:7080 ISO_CREDS=./creds ISO_CLIENT=me
isoctl vm create --template debian --egress proxy --principal alice --rule 'allow https://api.github.com/**'
isoctl vm exec <id> -- uname -a          # routed to whichever host has it
```

Two things are fleet-specific. `POST /vms` accepts `host` to pin a placement.
Every VM record carries `host` and `fleet_state`. `GET /hosts` and
`GET /stats` describe the fleet. `GET /openapi.json` is the host document.

## Placement

Hosts are filtered to the healthy ones that have the template and a free
slot, least loaded first. Capacity is enforced by the host, not the fleet:
a create that loses a race for the last slot gets a `409` from the host and
moves to the next candidate. No locks, no leader. A template that no host
has at all is a `404`; one no healthy host can take right now is a `409`.

## Consistency without a reconciler

The fleet writes the VM record with its id and chosen host **before** it
calls the host, and the host creates under that id (`409` if it exists).
So a retry after a lost reply is a conflict, never a second VM. The sync
loop then lists every host every `sync_every_ms` and settles three cases:

| The fleet has it | The host has it | Result |
| --- | --- | --- |
| yes | yes | `placed`; the host's state is recorded |
| yes | no, host reachable | `lost` (or `failed` if it was still `creating` past `create_grace_secs`) |
| no | yes | an orphan, counted on the host and logged |
| yes | host unreachable | `unreachable`; the record is kept, calls are refused with `409` |
| `deleting` | yes | the delete is retried until the host confirms |

`fleet_state` is one of `creating`, `placed`, `unreachable`, `lost`,
`deleting`, `failed`. A `lost` or `failed` record is cleared with `DELETE`.

## Policy and the proxy

Principal and rules travel through the fleet API to the host record, where
identify serves them locally and the generation is bumped as on a single
host. The fleet is the only writer, so the host's store is its cache by
fact. Whether a host runs the proxy inline (`--role single`) or only an edge
in front of a separate tier is a per-host deployment choice the fleet does
not see. Inline trusts the host with leaf keys and secret values in memory;
the separate tier is the security boundary that keeps both off the host.

## Identity

- **Clients → fleet**: mutual TLS on the fleet's own CA (`pki_dir`), minted
  with `isoctl admin --pki-dir <pki_dir> issue-client`. `insecure = true`
  serves plain HTTP for development.
- **Fleet → hosts**: one identity for every host, so every host must trust
  the same admin CA. Copy one `ca.crt` and `ca.key` into each host's
  `ISO_ADMIN_TLS_DIR` before its controld first starts; `load_or_generate`
  keeps what it finds. Mint the fleet's identity from that CA and put its
  three files in `[hosts_tls]`.

## Running more than one

Every handler is stateless over the database, and placement needs no
coordination because hosts enforce capacity. One process is enough for
hundreds of hosts; when it is not, the store moves from SQLite to a shared
database and `iso-fleetd` runs as N replicas behind a balancer, with no
change to the API or the hosts.

## Deliberately not built

Template distribution: bake on each host or copy the artifacts, and the
fleet places only where the template exists. A declarative host API and
consensus between fleet replicas: the database is the coordination.
Multi-tenant authorization: the fleet's client CA is the boundary; per-tenant
scoping is a column and a check when a second tenant arrives.

## Tests

`cargo test -p iso-fleet` runs the fleet against two real host admin APIs
(the daemon's router over mock managers, `iso-controld`'s `testing`
feature) behind gates the tests can close. They cover placement by template
and load, host-enforced capacity, pinning, policy forwarding and validation
pass-through, exec routed to the right host through the real guest agent,
delete on both sides, orphan and lost detection, a host going down and
coming back with its VMs, deferred deletes, and the create grace period.

## Signed policies

The fleet signs the policy of every VM it places or changes, for the host it
is placed on: `POST /vms` carries a signature at generation 1 for the chosen
host, `PATCH /vms/{id}/policy` is intercepted, laid over the host's current
policy exactly as the host will lay it, and signed at the next generation
(a `signed` field a client sends is ignored). The key is
`<pki_dir>/policy-signing.pkcs8`, minted on first start; its public half,
`<pki_dir>/policy-signing.pub`, is what a proxy tier is configured with
(`[fleet] policy_key_file` in `proxy.toml`). Signatures live
`policy_ttl_secs` (default a day); the sync loop re-signs a VM's policy when
a third of that is left, which changes no policy and bumps no generation.
Hosts store and serve the signature and cannot check it; the tier does, and
refuses anything else. See the proxy's `DESIGN.md`, "Signed policies".
