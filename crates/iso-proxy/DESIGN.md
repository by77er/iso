# iso-proxy — Credential-injecting, policy-enforcing egress proxy

The one path out of a VM: every TCP connection a VM makes is intercepted
and lands here (the other egress mode is `deny`). A **transparent MITM
HTTPS proxy** that (a) terminates TLS only for hosts an allow rule names,
(b) enforces per-VM **URI-level rules** (default-deny, deny wins), (c)
injects credential headers based on the VM's **principal**, (d) tunnels
WebSocket upgrades, and (e) carries a connection through as bytes, never
terminated, where a `tunnel tcp://host:port` rule says so. One binary, three
roles, so the same code runs on one host or as a stateless tier serving many.

## Guiding principles

- **Guest-tamper-proof.** Enforcement lives in the host root netns + this proxy;
  the guest cannot reach or reconfigure either. The VM only ever sees a CA it
  trusts and a transparent redirect.
- **A name or nothing.** On port 443 the ClientHello's SNI names the host; a
  connection that isn't TLS has no SNI, hence no routable destination, hence
  is dropped. On any other port the name is what the VM resolved the
  address from through the host's DNS (the only resolver it can reach); an
  address it never resolved has no name and is refused. Rules name hosts,
  never addresses.
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

edge     nft DNAT ─▶ iso-proxyd --role edge ─▶ pooled mTLS HTTP/2 tunnel, one CONNECT ─▶ tier
                       └─ identify.sock (controld)      stream per guest connection, policy in headers

proxy    edges ─mTLS─▶ iso-proxyd --role proxy ─┬─ https://…/sign     (iso-cad, mTLS)
                                                 └─ https://…/headers  (iso-secretsd, mTLS)
```

- **single**: accept the connections nftables steers to the services address,
  name each one through the host's identify RPC, serve it here. This is what
  `iso-up.sh` runs; nothing about it changed.
- **edge**: the half that stays on a host. Name the connection, refuse what
  should never be proxied (unknown source, deny-mode VM), and carry the raw
  bytes to a replica as one **HTTP/2 CONNECT stream** on a long-lived
  mutual-TLS tunnel (admin PKI), the way Envoy tunnels TCP. The stream's
  headers carry the connection's identity **and whole policy**
  (`x-iso-policy`: base64 JSON `WirePolicy`; `x-iso-src`). The edge keeps a
  small pool of tunnels per replica (`tier_pool_size`, default 2) and spreads
  streams over replicas and pools round-robin; a new guest connection costs
  a stream open, not a handshake. PINGs every 10 s notice a dead replica.
  Nothing is terminated at the edge.
- **proxy**: a stateless replica. Require a client certificate from the admin
  CA, speak HTTP/2, and serve every CONNECT stream as one guest connection
  with the policy its headers carry (anything but CONNECT is 405, a stream
  without the policy header is 400). It has no state directory, no policy
  lookup, no cache and no watch; the only services it calls are the CA and
  the secrets store, over HTTPS with mutual TLS. Its one cache is leaf
  certificates, until their `not_after`.

The **registry** (edge and single roles) records every live connection under
its source address and policy generation, tunnels included. A watcher
re-reads each VM's policy every `watch_every` (1 s) and closes everything held
at an older generation, or by a VM that became unknown or deny-mode. That is
how an h2 session or a WebSocket outlives a `PATCH /policy` by at most one
tick: at the edge it is a RST_STREAM on the tunnel, and the tier never learns
why.

## Data flow (serving a connection, `single` and `proxy`)

```text
   1. accept; policy ← identify(src ip) [single] or the CONNECT headers [proxy]
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

## Signed policies

In the split, the tier learns a connection's policy from the edge. Left
there, the tier trusts the host: root on a VM host could present any
principal and any rule set and have credentials injected for it. So the
fleet signs what it places or changes (`iso_policy::signed`): the claims
`{host, vm, egress, principal, rules, policy_gen, expires}` as canonical
JSON under an ed25519 key only the fleet holds. The host stores the
signature beside the policy (and refuses one that does not describe the
policy it stores), `identify` serves it, the edge relays it in
`x-iso-policy`, and a tier configured with the fleet's public key (`[fleet]
policy_key_file`) accepts a stream only when the signature verifies, the
claims have not expired, and the `host` claimed is the name on the edge's
certificate. The policy the tier enforces is then the signed claims; the
rest of the wire policy is not read. A host can present only policies the
fleet issued to it, for VMs placed on it, until they expire (the fleet
re-signs at a third of the life left, without a generation bump). The
CA and secrets services likewise answer only the tier's certificate name
(`ISO_ALLOWED_CLIENTS`), and no host holds the admin CA key.

## Access log

Every request the proxy terminates (`single` and `proxy` roles) leaves one
`tracing` event under the target `iso_proxy::access`, and every tunnel it
closes (a WebSocket after its 101) leaves one more. The request event
carries who (`src`, `edge`, `vm`, `principal`), what (`method`, `scheme`,
`host`, `path`), the decision (`decision`, `rule`), the *names* of the
headers injected (`injected`), and the outcome (`status`, `latency_ms`,
`upgrade`); a ClientHello dropped at SNI time leaves a `phase = sni` event.
The tunnel event carries `kind`, `host`, `path`, `bytes_up`, `bytes_down`
and `duration_ms`. Never a query string, a header value or a body: this
log is meant to be shipped. `iso-proxyd --log-format json` (or
`ISO_LOG_FORMAT=json`) writes each line as one JSON object;
`RUST_LOG=iso_proxy::access=info` keeps the access log alone. On the tier
`edge` is the name on the edge's certificate, so a line names the host a
request came through even when the host lies.

## Passthrough (`tunnel tcp://host:port`)

The nftables intercept redirects every TCP port a VM dials to the proxy's
listener; the kernel's conntrack keeps the original destination
(`SO_ORIGINAL_DST`), which the edge or single-role proxy reads on accept.
Port 443 goes through the ClientHello peek (`sni.rs`, which keeps the bytes
so they can be replayed to whichever side reads next): a `tunnel
tcp://host:443` rule for the SNI carries the TLS session through untouched,
the guest sees the upstream's own certificate and nothing is injected;
otherwise an allow rule terminates as before. Any other port asks the
host's DNS memory (`identify` with `dst`) for the name the VM resolved the
address from, and a `tunnel tcp://name:port` rule carries the connection
to `name:port`, dialled by name on the proxy's side (pins apply). In the
split, the edge puts the destination and its name in the CONNECT headers
(`x-iso-dst`, `x-iso-dst-name`) and the tier does the rest, so the tier
still needs no lookup. Every tunnel leaves one access event with the bytes
each way; a refused connection leaves a `phase = tcp` event saying why.

## Failure modes

- Not TLS / no SNI ⇒ drop. No allow rule for the host ⇒ drop before minting.
- `:authority != SNI` ⇒ 421. URI rule deny ⇒ 403.
- Unknown source / deny-mode VM ⇒ refused at the edge.
- Tier with a fleet key: unsigned, expired, badly signed, or signed for
  another host ⇒ the CONNECT is answered 403 and the guest's connection is
  closed before any TLS.
- SecretProvider down or empty ⇒ forward without injection (fail-open).
- CertAuthority down ⇒ block (fail-closed). Every replica unreachable ⇒ the
  edge closes the guest connection; one replica down ⇒ the next is used.
- Policy changed ⇒ the edge closes that VM's connections within one watch
  tick; new ones carry the new generation.

## Tests

`cargo test -p iso-proxy` runs both configurations in-process on loopback,
no root and no network: `tests/single_host.rs` (one process, Unix sockets)
and `tests/multi_host.rs` (two edges, one replica, HTTPS mTLS to the CA and
secrets services). They cover injection, the host and URI phases, deny-mode
refusal, WebSocket tunnels with injection on the handshake, close-on-policy-
change in both roles, the tier refusing non-admin-CA edges, a replica with a
stranger identity failing closed at the CA, and twenty guest connections
sharing at most two tunnels. `tests/e2e.rs` is the
`#[ignore]`d real-network check against an external echo service.
