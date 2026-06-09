# iso-proxy — Credential-injecting, policy-enforcing egress proxy

The backend for the `Proxy` egress mode. A **transparent MITM HTTPS proxy** on
the host that (a) lets through *only* TLS, (b) enforces a per-VM domain
allow-list (default-deny), and (c) injects/overrides credential headers based on
the VM's **principal** and **global** secrets.

## Guiding principles

- **Guest-tamper-proof.** Enforcement lives in the host root netns + this proxy;
  the guest cannot reach or reconfigure either. The VM only ever sees a CA it
  trusts and a transparent redirect.
- **TLS or nothing.** A connection that isn't a TLS `ClientHello` has no SNI,
  hence no routable destination, hence is dropped. "Only TLS" and "transparent
  routing needs a destination" are the same requirement.
- **MITM everything (for now).** Every allowed TLS connection is terminated and
  re-originated. Splicing un-injected domains is a later perf optimization that
  slots in behind the same boundaries — nothing here precludes it.
- **Secrets never touch the guest, the CA key never touches the proxy.** Both
  live behind RPC boundaries in their own processes.

## Topology & data flow

`Proxy`-mode VMs have their egress steered (nftables, host root netns) to the
proxy on the services address `172.22.0.1`. The VM's `vp` source IP is preserved,
so the proxy identifies the VM the same way the metadata server does
(`address_to_slot`).

```
VM (172.20.0.1) ──tap──vp(172.21.x)──▶ nft redirect ──▶ iso-proxyd @172.22.0.1:PORT
                                                          │
   1. accept; src_ip ──▶ control-plane identify ──▶ {vm, principal, allow}
   2. peek TLS ClientHello  ── not TLS? ──▶ DROP
   3. SNI = client_hello.server_name   ── no SNI? ──▶ DROP
   4. SNI ∈ allow?           ── no ──▶ RESET
   5. CertAuthority.sign(SNI, csr) ──▶ leaf cert (cached); complete TLS to VM
   6. dial upstream TLS to resolve(SNI) (webpki-validated); ALPN h2/h1.1
   7. per request/stream:
        require :authority/Host == SNI            ── else 421/RESET
        hdrs = SecretProvider.headers(SNI, principal); set/override; forward
   8. stream bodies both ways (SSE/chunked safe)
```

nftables (Proxy mode), root netns, per slot:
- redirect VM egress **TCP** (any port) → `172.22.0.1:PROXY_PORT` (DNAT, src kept);
- VM **DNS** (udp/tcp 53) → the iso resolver (`172.22.0.1:53`);
- **drop everything else** out of the netns (other UDP incl. QUIC/:443-udp, so
  clients fall back to TCP TLS).

## Identity, policy & principal

| Thing | Owner | How set (now) | How set (later) |
| --- | --- | --- | --- |
| src_ip → vm | control plane (`identify`) | — | — |
| `principal` (current user) | control-plane VM record | `isoctl policy set` | orchestrator push |
| `allow` (domain list) | control-plane VM record | `isoctl policy set` | orchestrator push |
| secrets (headers) | secret provider TOML | edit `state/secrets.toml` | secret store |

The VM record gains `principal: Option<String>` and `allow: Vec<String>`
(exact-match domains). `principal` is **deliberately mutable** at runtime; the
proxy re-resolves it per request through a short-TTL (~1s) `identify` cache, so
a change takes effect within the TTL without a lookup storm.

## RPC boundaries

Both are unix-domain-socket servers under `state/`, framed as length-prefixed
(u32 BE) JSON request→response. Realized in Rust as traits with (a) in-process
impls for tests and (b) RPC client/server impls for deployment.

### SecretProvider — `state/secrets.sock`
```
headers(domain: String, principal: Option<String>) -> Map<String,String>
```
Returns the **effective** headers to set/override: the provider merges **global
OVER per-principal** internally. Empty ⇒ inject nothing (fail-open: an allowed
domain with no secrets is forwarded verbatim). "override" = set the value (add if
absent, replace if present).

Backing TOML (`state/secrets.toml`):
```toml
# Injected for every principal (override per-principal). Keyed by domain.
[global."api.anthropic.com"]
"x-api-key"         = "sk-ant-..."
"anthropic-version" = "2023-06-01"

# Per-principal. One test principal "default".
[principals.default."api.github.com"]
"authorization" = "Bearer ghp_..."
```

### CertAuthority — `state/ca.sock`
```
sign(domain: String, csr_der: Bytes) -> { chain_der: [Bytes], not_after }
```
**Sign-only**: the proxy generates a disposable leaf keypair and CSR; the CA only
signs. The CA private key never leaves the minter. Proxy caches leaf certs per
domain (short lifetime, e.g. 24h; SAN = domain).

## CA trust bootstrap

A single CA is generated once into `state/ca/` (`ca.crt`, `ca.key`). The minter
loads its key; the proxy trusts nothing extra (it validates upstream with webpki
roots). The **VM must trust `ca.crt`**, baked into the template trust store
(`security.pki.certificateFiles`, or via `isoctl bake --inject`) **before the
snapshot** — warm-resume freezes the trust store, so post-snapshot trust changes
are invisible. For e2e we can shortcut with `curl --cacert` to validate the data
path without rebaking.

## HTTP — hyper end-to-end

We do **not** hand-roll `h2`. rustls terminates TLS (server side, ALPN
`["h2","http/1.1"]`, cert resolved per-SNI via the minter using
`LazyConfigAcceptor` to read the ClientHello first); hyper serves whatever ALPN
negotiated. A hyper client re-originates upstream (prefer h2, webpki-validated),
one upstream connection per client connection (same SNI; h2 multiplexes). We
operate at the `http::Request`/`Response` header level and stream bodies. SNI is
per-connection but `:authority` is per-stream, so `:authority == SNI` is checked
per request — both a correctness (one upstream per SNI) and anti-fronting
guarantee. This is *especially* important on injected flows: it prevents a
crafted `:authority` from redirecting the injected credential to another host.

## Failure modes

- Not TLS / no SNI ⇒ drop. SNI ∉ allow ⇒ reset.
- `:authority != SNI` ⇒ reject (421).
- SecretProvider down or empty ⇒ **forward without injection** (fail-open;
  the domain is already allow-listed).
- CertAuthority down ⇒ **block** (fail-closed; we can't terminate).
- Upstream TLS/DNS failure ⇒ 502 to the VM.

## Crate layout

- `iso-proxy` — data plane (`iso-proxyd`); `SecretProvider`/`CertAuthority`
  traits + their RPC client impls; `identify` client.
- `iso-secrets` — `TomlSecretProvider` + `iso-secretsd` (RPC server).
- `iso-ca` — CA (generate/load, sign CSR) + `iso-cad` (RPC server).
- control plane / `iso-controld` — `principal`+`allow` on the VM record; an
  `identify` endpoint (for the proxy) and a policy-set endpoint (for the CLI).
- `iso-cli` — `isoctl policy set <vm> --principal <p> --allow <domain>...`.

## e2e test plan

1. Generate CA into `state/ca`; start `iso-cad`, `iso-secretsd` (with a test
   `secrets.toml` injecting a recognizable header for an echo domain), `iso-proxyd`.
2. Create a `Proxy`-mode VM; `isoctl policy set` it to `principal=default`,
   `allow=[<echo-domain>]`.
3. From the VM (trusting the CA via `--cacert`):
   - `curl https://<echo>/headers` ⇒ response reflects the injected header ✓
     (proves MITM + injection + CA trust + h2).
   - `curl https://example.com` ⇒ blocked (not in allow-list) ✓.
   - `curl http://<echo>` ⇒ blocked (non-TLS) ✓.
