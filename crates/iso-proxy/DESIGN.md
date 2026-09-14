# iso-proxy — Credential-injecting, policy-enforcing egress proxy

The backend for the `Proxy` egress mode (and the injection path of `Allow`
mode). A **transparent MITM HTTPS proxy** that (a) lets through *only* TLS,
(b) enforces per-VM **URI-level rules** (default-deny, deny wins), (c) injects
credential headers based on the VM's **principal**, and (d) tunnels WebSocket
upgrades. One binary, three roles, so the same code runs on one host or as a
stateless tier serving many.

## Guiding principles

- **Guest-tamper-proof.** Enforcement lives in the host root netns + this proxy;
  the guest cannot reach or reconfigure either. The VM only ever sees a CA it
  trusts and a transparent redirect.
- **TLS or nothing.** A connection that isn't a TLS `ClientHello` has no SNI,
  hence no routable destination, hence is dropped.
- **MITM everything.** Every allowed TLS connection is terminated and
  re-originated. The upstream leg is HTTPS only and webpki-validated (plus any
  operator-added roots); no code path can originate plaintext.
- **Secrets never touch the guest, the CA key never touches the proxy.** Both
  live behind RPC boundaries in their own processes.
- **Policy travels with the connection.** Nothing in the data plane looks
  policy up mid-flight; the thing that admits a connection also owns its
  lifetime and ends it when policy changes.

## Roles

```text
single   nft DNAT ─▶ iso-proxyd ─┬─ identify.sock (controld)      today's deployment:
                                 ├─ ca.sock (iso-cad)             everything on the host
                                 └─ secrets.sock (iso-secretsd)

edge     nft DNAT ─▶ iso-proxyd --role edge ─▶ mTLS + PROXY v2 {vm, principal, rules, gen} ─▶ tier
                       └─ identify.sock (controld)

proxy    edges ─mTLS─▶ iso-proxyd --role proxy ─┬─ https://…/sign     (iso-cad, mTLS)
                                                 └─ https://…/headers  (iso-secretsd, mTLS)
```

- **single**: accept the connections nftables steers to the services address,
  name each one through the host's identify RPC, serve it here. This is what
  `iso-up.sh` runs; nothing about it changed.
- **edge**: the half that stays on a host. Name the connection, refuse what
  should never be proxied (unknown source, deny-mode VM), and carry the raw
  bytes to a replica over mutual TLS (admin PKI) with the connection's
  identity **and whole policy** in one custom PROXY protocol v2 TLV
  (`0xE5`, JSON `WirePolicy`). Round-robins over the tier's addresses. Nothing
  is terminated at the edge.
- **proxy**: a stateless replica. Require a client certificate from the admin
  CA, read the header, serve the connection with the policy it carries. It
  has no state directory, no policy lookup, no cache and no watch; the only
  services it calls are the CA and the secrets store, over HTTPS with mutual
  TLS. Its one cache is leaf certificates, until their `not_after`.

The **registry** (edge and single roles) records every live connection under
its source address and policy generation, tunnels included. A watcher
re-reads each VM's policy every `watch_every` (1 s) and closes everything held
at an older generation, or by a VM that became unknown or deny-mode. That is
how an h2 session or a WebSocket outlives a `PATCH /policy` by at most one
tick, and the tier never learns it happened.

## Data flow (serving a connection, `single` and `proxy`)

```text
   1. accept; policy ← identify(src ip) [single] or the PROXY header [proxy]
   2. egress == deny? ──▶ DROP (a deny VM has no egress; reaching the services
      address is not a licence to proxy for it)
   3. peek TLS ClientHello  ── not TLS / no SNI? ──▶ DROP
   4. host phase: some allow rule names the SNI? ── no ──▶ DROP (never terminated,
      no certificate minted)
   5. CertAuthority.sign(SNI, csr) ──▶ leaf (cached until not_after − 10 min);
      complete TLS to VM (ALPN h2, http/1.1)
   6. per request/stream:
        :authority/Host == SNI                       ── else 421
        URI phase: rules.evaluate(https|wss, host, path)  ── deny ──▶ 403 JSON
        hdrs = SecretProvider.headers(SNI, principal, path); set/override
        Upgrade: websocket?  ── yes ──▶ forward over http/1.1; on 101 bridge both
                                        upgraded streams, bytes only, no timer
                             ── no  ──▶ forward (h2 or http/1.1), stream body
```

## Rules

Grammar and semantics live in `iso-policy` (pure, tested). In short:

```text
rule    := ("allow" | "deny") pattern
pattern := scheme "://" host [":" port] path
scheme  := "https" | "wss"        wss matches only Upgrade requests
host    := exact | "*." suffix    one or more leading labels, never the apex
path    := "/" segments           "*" = one segment, "**" = the rest (last only)
```

- Default deny. Explicit deny wins regardless of order. Query strings are
  never matched.
- Host phase at SNI time uses only allow rules' hosts; a host with deny rules
  only is never terminated.
- URI phase runs after the authority check and before injection, so a denied
  path never carries a credential. The guest gets `403` with
  `{"error":"denied by policy","request":…,"rule":…|null}` and
  `x-iso-denied: policy`, because at that point a reset would look like a
  network fault.
- The legacy `allow: [host]` list is sugar for `allow https://host/**` plus
  `allow wss://host/**`. Records and clients that only know `allow` keep
  working; the effective policy is `allow` expanded plus `rules`.
- Consumers: both proxy phases, the DNS steer for Allow mode (host phase, so
  `*.example.com` steers), control-plane validation (`400` on a bad rule),
  and the metadata description (literal allow hosts only).

## Identity, policy & principal

| Thing | Owner | How set |
| --- | --- | --- |
| src ip → vm | control plane (`identify`) | — |
| `principal`, `allow`, `rules` | VM record | `POST /vms`, `PATCH /vms/{id}/policy`, `isoctl vm create/policy --rule` |
| `policy_gen` | VM record | bumped by every policy change |
| secrets (headers) | secret provider | adapter: TOML, exec, … |

`IdentifyResponse` now carries `vm`, `rules` (effective, expanded) and
`policy_gen` beside `allow`, `principal` and `egress`. A proxy that predates
`rules` still works from `allow`.

## RPC boundaries (`iso-rpc`)

Every side service speaks two transports from one handler: **Unix** (one
half-close framed JSON request per connection, root-only socket under
`state/`) and **HTTPS** (`POST /<method>`, JSON body, mutual TLS on the admin
PKI). A service identity comes from `isoctl admin issue-server`, and is read
from `ISO_TLS_CA`, `ISO_TLS_CERT`, `ISO_TLS_KEY`.

### SecretProvider — `secrets.sock` · `POST /headers`
```
headers(domain, principal, path, names_only) -> { headers } | { names }
```
Fail-open: down or empty ⇒ inject nothing. Backends are adapters behind
`iso_secrets::SecretProvider` (`headers` may mint; `names` must not): TOML,
`exec` (an operator program: `prog headers|names <domain> <principal|-> <path|->`),
`chain`.

### CertAuthority — `ca.sock` · `POST /sign`
```
sign(domain, csr_pem) -> { chain_der_b64: [leaf, ca], not_after }
```
Sign-only; leaves live 24 h; empty chain ⇒ refusal, proxy fails closed.

## CA trust bootstrap

One CA per **tier** (a single host is a tier of one), generated into
`state/ca/`, private key only ever in `iso-cad`. Guests must trust `ca.crt`,
baked into the template before the snapshot. Serving it from metadata at boot
(so one template serves many hosts) is the next step, not this one.

## Configuration (`iso-proxyd`)

No config file ⇒ today's behaviour: `single` on `ISO_PROXY_LISTEN` with the
three sockets under `ISO_STATE_DIR`. Otherwise `ISO_PROXY_CONFIG=file.toml`:

```toml
role = "edge"                          # single | edge | proxy
listen = ["172.22.0.1:3128", "172.22.0.1:443"]
[identify]  socket = "/var/lib/iso/identify.sock"   ttl_ms = 1000
[tier]      addrs = ["10.0.0.9:3129"]  server_name = "proxy-1"
[tls]       ca = "creds/ca.crt"  cert = "creds/edge.crt"  key = "creds/edge.key"
```

```toml
role = "proxy"
listen = ["0.0.0.0:3129"]
[ca]        url = "https://10.0.0.7:7443"
[secrets]   url = "https://10.0.0.7:7444"
[tls]       ca = "creds/ca.crt"  cert = "creds/proxy-1.crt"  key = "creds/proxy-1.key"
[upstream]  extra_roots = ["/etc/ssl/corp-ca.pem"]  pins = { "api.internal" = "10.0.0.5:8443" }
```

`iso-cad` and `iso-secretsd` add the HTTPS listener with `ISO_CA_LISTEN` /
`ISO_SECRETS_LISTEN` plus the `ISO_TLS_*` identity.

## Failure modes

- Not TLS / no SNI ⇒ drop. No allow rule for the host ⇒ drop before minting.
- `:authority != SNI` ⇒ 421. URI rule deny ⇒ 403.
- Unknown source / deny-mode VM ⇒ refused at the edge.
- SecretProvider down or empty ⇒ forward without injection (fail-open).
- CertAuthority down ⇒ block (fail-closed). Tier unreachable ⇒ the edge
  closes the guest connection.
- Policy changed ⇒ the edge closes that VM's connections within one watch
  tick; new ones carry the new generation.

## Tests

`cargo test -p iso-proxy` runs both configurations in-process on loopback,
no root and no network: `tests/single_host.rs` (one process, Unix sockets)
and `tests/multi_host.rs` (two edges, one replica, HTTPS mTLS to the CA and
secrets services). They cover injection, the host and URI phases, deny-mode
refusal, WebSocket tunnels with injection on the handshake, close-on-policy-
change in both roles, the tier refusing non-admin-CA edges, and a replica
with a stranger identity failing closed at the CA. `tests/e2e.rs` is the
`#[ignore]`d real-network check against an external echo service.
