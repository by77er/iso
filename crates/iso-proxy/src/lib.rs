//! iso-proxy — credential-injecting, policy-enforcing transparent MITM HTTPS
//! proxy. The backend for the `Proxy` egress mode. See `DESIGN.md`.
//!
//! One binary, three roles:
//!
//! - **single**: today's deployment. Accept the connections nftables steers
//!   to the services address, name each one through the host's identify RPC,
//!   and serve it here. The CA and secrets services are Unix sockets.
//! - **edge**: the half that stays on a host. Name the connection, then carry
//!   it to a proxy replica as one CONNECT stream on a long-lived mutual-TLS
//!   HTTP/2 tunnel, with the policy in the stream's headers. Nothing is
//!   terminated here.
//! - **proxy**: a stateless replica anywhere. Accept mutual TLS HTTP/2 from
//!   edges, and serve each CONNECT stream as a guest connection with the
//!   policy it carries. The CA and secrets services are reached over HTTPS
//!   with mutual TLS.
//!
//! Serving a connection is the same in `single` and `proxy`: peek the
//! ClientHello for the SNI, refuse it unless some allow rule names that host,
//! mint a leaf, terminate, and per request check the authority, evaluate the
//! URI rules, inject credentials, and forward or tunnel.

pub mod access;
pub mod dst;
pub mod sni;
pub mod ca;
pub mod edge;
pub mod policy;
pub mod tunnel;
pub mod ws;

pub use policy::{Policy, PolicyResolver, RpcResolver, StaticResolver, WirePolicy};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::HOST;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use hyper_util::rt::{TokioExecutor, TokioIo};
use iso_policy::{Decision, Scheme};
use rustls_pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::LazyConfigAcceptor;

use ca::CaClient;
use edge::Registry;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Resp = Response<BoxBody<Bytes, BoxError>>;
pub type UpstreamClient = Client<HttpsConnector<HttpConnector<PinResolver>>, Incoming>;

/// DNS for upstreams: pinned hosts answer from the table, everything else
/// goes to the system resolver. A pinned address keeps its port when the
/// request names none, which is how a test upstream on an ephemeral port is
/// reached as `https://host/`.
#[derive(Clone)]
pub struct PinResolver {
    pins: Arc<std::collections::HashMap<String, SocketAddr>>,
    gai: GaiResolver,
}

impl tower_service::Service<Name> for PinResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = BoxError;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        tower_service::Service::poll_ready(&mut self.gai, cx).map_err(|e| Box::new(e) as BoxError)
    }

    fn call(&mut self, name: Name) -> Self::Future {
        if let Some(addr) = self.pins.get(name.as_str()).copied() {
            return Box::pin(async move { Ok(vec![addr].into_iter()) });
        }
        let fut = tower_service::Service::call(&mut self.gai, name);
        Box::pin(async move {
            let addrs = fut.await.map_err(|e| Box::new(e) as BoxError)?;
            Ok(addrs.collect::<Vec<_>>().into_iter())
        })
    }
}

/// Which half of the proxy this process is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Single,
    Edge,
    Proxy,
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "single" => Ok(Role::Single),
            "edge" => Ok(Role::Edge),
            "proxy" => Ok(Role::Proxy),
            other => Err(format!("unknown role {other:?} (single | edge | proxy)")),
        }
    }
}

/// Proxy configuration. Which fields matter depends on `role`; the
/// constructors below fill in the right ones.
pub struct ProxyConfig {
    pub role: Role,
    /// Addresses to accept on: the nft intercept target, every TCP port a
    /// VM dials lands there (`single`, `edge`), or the address edges dial
    /// (`proxy`).
    pub listen: Vec<SocketAddr>,
    /// This host's name in the tunnel headers (`edge`) and in logs.
    pub host_id: String,
    /// Resolves a connection's source IP to its VM's policy (`single`, `edge`).
    pub resolver: Option<Arc<dyn PolicyResolver>>,
    /// How often the edge re-reads the policy of VMs with live connections.
    pub watch_every: Duration,
    /// The CA and secrets services (`single`, `proxy`).
    pub ca: Option<iso_rpc::Endpoint>,
    pub secrets: Option<iso_rpc::Endpoint>,
    /// The tier to carry connections to (`edge`).
    pub tier: Vec<SocketAddr>,
    pub tier_server_name: Option<String>,
    pub tier_tls: Option<Arc<rustls::ClientConfig>>,
    /// Long-lived HTTP/2 connections per replica. More than one spreads
    /// guest streams over several TCP connections, which is what keeps one
    /// lossy connection's head-of-line blocking from stalling every stream.
    pub tier_pool_size: usize,
    /// Counters for the edge's tunnels; readable while running.
    pub metrics: Arc<edge::Metrics>,
    /// Mutual TLS the replica requires from edges (`proxy`).
    pub accept_tls: Option<Arc<rustls::ServerConfig>>,
    /// The fleet's policy signing key (`proxy`). With it, a stream is served
    /// only under a policy the fleet signed for the edge presenting it, and
    /// nothing else the edge says about the policy is read. Without it the
    /// edge's word is taken, which is only right where there is no fleet.
    pub policy_verifier: Option<iso_policy::signed::Verifier>,
    /// Roots trusted for upstreams on top of the public webpki set: a private
    /// CA in front of an internal API, or a test upstream.
    pub extra_upstream_roots: Vec<CertificateDer<'static>>,
    /// Upstream hosts dialled at a fixed address instead of what DNS says,
    /// like `curl --resolve`: an internal API on a private address, or a
    /// test upstream on an ephemeral port. The TLS name and the certificate
    /// check are still the host's.
    pub upstream_pins: std::collections::HashMap<String, SocketAddr>,
    pub handshake_timeout: Duration,
    /// How a guest connection's original destination is learned (`single`,
    /// `edge`): the kernel's conntrack record by default.
    pub dst_lookup: dst::DstLookup,
}

impl ProxyConfig {
    fn base(role: Role, listen: Vec<SocketAddr>) -> Self {
        Self {
            role,
            listen,
            host_id: hostname(),
            resolver: None,
            watch_every: Duration::from_secs(1),
            ca: None,
            secrets: None,
            tier: Vec::new(),
            tier_server_name: None,
            tier_tls: None,
            tier_pool_size: 2,
            metrics: Arc::new(edge::Metrics::default()),
            accept_tls: None,
            policy_verifier: None,
            extra_upstream_roots: Vec::new(),
            upstream_pins: std::collections::HashMap::new(),
            handshake_timeout: Duration::from_secs(10),
            dst_lookup: dst::kernel_lookup(),
        }
    }

    /// Today's deployment: everything in one process on the host.
    pub fn single(
        listen: Vec<SocketAddr>,
        resolver: Arc<dyn PolicyResolver>,
        ca: iso_rpc::Endpoint,
        secrets: iso_rpc::Endpoint,
    ) -> Self {
        Self {
            resolver: Some(resolver),
            ca: Some(ca),
            secrets: Some(secrets),
            ..Self::base(Role::Single, listen)
        }
    }

    /// The on-host half of the split.
    pub fn edge(
        listen: Vec<SocketAddr>,
        resolver: Arc<dyn PolicyResolver>,
        tier: Vec<SocketAddr>,
        tier_tls: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            resolver: Some(resolver),
            tier,
            tier_tls: Some(tier_tls),
            ..Self::base(Role::Edge, listen)
        }
    }

    /// A replica of the tier. Edges speak HTTP/2 to it, so that is what it
    /// offers in ALPN; nothing else is served on this listener.
    pub fn proxy(
        listen: Vec<SocketAddr>,
        accept_tls: Arc<rustls::ServerConfig>,
        ca: iso_rpc::Endpoint,
        secrets: iso_rpc::Endpoint,
    ) -> Self {
        let mut accept = (*accept_tls).clone();
        accept.alpn_protocols = vec![b"h2".to_vec()];
        Self {
            accept_tls: Some(Arc::new(accept)),
            ca: Some(ca),
            secrets: Some(secrets),
            ..Self::base(Role::Proxy, listen)
        }
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "iso".to_string())
}

/// Registers a task spawned on behalf of a connection (a WebSocket tunnel)
/// with whatever owns that connection's lifetime, so a policy change ends it
/// too. `None` where nothing local owns lifetime: on a tier replica, the
/// edge's TCP close does it.
pub type OnTask = Arc<dyn Fn(tokio::task::AbortHandle) -> edge::Registration + Send + Sync>;

/// Shared, cheap-to-clone context for serving connections.
#[derive(Clone)]
struct Ctx {
    ca: Arc<CaClient>,
    secrets: Arc<iso_secrets::Client>,
    /// Upstream client that negotiates h2 or http/1.1.
    client: UpstreamClient,
    /// Upstream client pinned to http/1.1, for upgrades.
    client_h1: UpstreamClient,
    handshake_timeout: Duration,
    /// Hosts dialled at a fixed address, for passthroughs as for requests.
    pins: Arc<std::collections::HashMap<String, SocketAddr>>,
}

/// Everything a running proxy holds, for whichever role.
struct Runtime {
    cfg: Arc<ProxyConfig>,
    ctx: Option<Ctx>,
    registry: Arc<Registry>,
    tier: Option<Arc<edge::Tier>>,
}

/// Run the proxy, binding every address in `cfg.listen`. Never returns
/// unless a listener fails.
pub async fn run(cfg: ProxyConfig) -> std::io::Result<()> {
    let mut listeners = Vec::new();
    for addr in &cfg.listen {
        let l = TcpListener::bind(addr).await?;
        tracing::info!("iso-proxy ({:?}) listening on {addr}", cfg.role);
    if cfg.role == Role::Proxy {
        match &cfg.policy_verifier {
            Some(_) => tracing::info!("proxy: fleet-signed policies required from edges"),
            None => tracing::warn!("proxy: no fleet policy key configured; policies from edges are taken on faith"),
        }
    }
        listeners.push(l);
    }
    run_with_listeners(listeners, cfg).await
}

/// Run on already-bound listeners (tests bind `:0`).
pub async fn run_with_listeners(
    listeners: Vec<TcpListener>,
    cfg: ProxyConfig,
) -> std::io::Result<()> {
    let rt = Arc::new(build_runtime(cfg)?);
    if let (Some(resolver), true) = (
        &rt.cfg.resolver,
        matches!(rt.cfg.role, Role::Single | Role::Edge),
    ) {
        tokio::spawn(edge::watch(
            rt.registry.clone(),
            resolver.clone(),
            rt.cfg.watch_every,
        ));
    }
    let mut handles = Vec::new();
    for listener in listeners {
        let rt = rt.clone();
        handles.push(tokio::spawn(accept_loop(listener, rt)));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

fn build_runtime(cfg: ProxyConfig) -> std::io::Result<Runtime> {
    let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, m.to_string());
    let ctx = match cfg.role {
        Role::Single | Role::Proxy => {
            let ca = cfg
                .ca
                .clone()
                .ok_or_else(|| invalid("this role needs a CA endpoint"))?;
            let secrets = cfg
                .secrets
                .clone()
                .ok_or_else(|| invalid("this role needs a secrets endpoint"))?;
            let (client, client_h1) =
                upstream_clients(&cfg.extra_upstream_roots, &cfg.upstream_pins);
            Some(Ctx {
                ca: Arc::new(CaClient::new(ca).map_err(|e| std::io::Error::other(e.to_string()))?),
                secrets: Arc::new(iso_secrets::Client::from_endpoint(secrets)),
                client,
                client_h1,
                handshake_timeout: cfg.handshake_timeout,
                pins: Arc::new(cfg.upstream_pins.clone()),
            })
        }
        Role::Edge => None,
    };
    if matches!(cfg.role, Role::Single | Role::Edge) && cfg.resolver.is_none() {
        return Err(invalid("this role needs a policy resolver"));
    }
    let tier = match cfg.role {
        Role::Edge => Some(Arc::new(edge::Tier::new(
            cfg.tier.clone(),
            cfg.tier_server_name.clone(),
            cfg.tier_tls
                .clone()
                .ok_or_else(|| invalid("edge needs a TLS client config for the tier"))?,
            cfg.host_id.clone(),
            cfg.tier_pool_size,
            cfg.metrics.clone(),
        )?)),
        _ => None,
    };
    if cfg.role == Role::Proxy && cfg.accept_tls.is_none() {
        return Err(invalid("proxy needs a TLS server config to accept edges"));
    }
    Ok(Runtime {
        cfg: Arc::new(cfg),
        ctx,
        registry: Registry::new(),
        tier,
    })
}

/// Two upstream clients over one root store: one that negotiates h2 or
/// http/1.1, one pinned to http/1.1 for upgrades. Both are https-only, so no
/// code path can ever originate plaintext.
fn upstream_clients(
    extra_roots: &[CertificateDer<'static>],
    pins: &std::collections::HashMap<String, SocketAddr>,
) -> (UpstreamClient, UpstreamClient) {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for r in extra_roots {
        let _ = roots.add(r.clone());
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let resolver = PinResolver {
        pins: Arc::new(pins.clone()),
        gai: GaiResolver::new(),
    };
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    let both = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls.clone())
        .https_only()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http.clone());
    let h1 = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .wrap_connector(http);
    (
        Client::builder(TokioExecutor::new()).build(both),
        Client::builder(TokioExecutor::new()).build(h1),
    )
}

async fn accept_loop(listener: TcpListener, rt: Arc<Runtime>) -> std::io::Result<()> {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let rt = rt.clone();
        match rt.cfg.role {
            Role::Single => tokio::spawn(single_conn(tcp, peer, rt)),
            Role::Edge => tokio::spawn(edge_conn(tcp, peer, rt)),
            Role::Proxy => tokio::spawn(proxy_conn(tcp, peer, rt)),
        };
    }
}

/// `single`: name the connection, register it, serve it here.
async fn single_conn(tcp: TcpStream, peer: SocketAddr, rt: Arc<Runtime>) {
    let resolver = rt.cfg.resolver.as_ref().expect("single has a resolver");
    let policy = match edge::admit(&**resolver, peer.ip()).await {
        Ok(p) => p,
        Err(why) => {
            tracing::info!("refuse {peer}: {why:?}");
            return;
        }
    };
    let ctx = rt.ctx.clone().expect("single has a ctx");
    let registry = rt.registry.clone();
    let policy_for_reg = policy.clone();
    // Anything the connection spawns (a tunnel) is registered beside it.
    let on_task: OnTask = {
        let registry = registry.clone();
        let policy = policy.clone();
        let ip = peer.ip();
        Arc::new(move |h| registry.register(ip, &policy, h))
    };
    let conn = access::Conn::new(peer.ip(), &rt.cfg.host_id, &policy);
    let dst = lookup_dst(&rt, &tcp, peer.ip()).await;
    let task = tokio::spawn(async move {
        if let Err(e) = serve_conn(tcp, conn, policy, ctx, Some(on_task), dst).await {
            tracing::debug!("conn {peer} ended: {e}");
        }
    });
    // Registering after spawn is fine: the handle aborts a task at any point.
    let _reg = registry.register(peer.ip(), &policy_for_reg, task.abort_handle());
    let _ = task.await;
}

/// `edge`: name the connection, carry it to a replica, register it.
async fn edge_conn(tcp: TcpStream, peer: SocketAddr, rt: Arc<Runtime>) {
    let resolver = rt.cfg.resolver.as_ref().expect("edge has a resolver");
    let policy = match edge::admit(&**resolver, peer.ip()).await {
        Ok(p) => p,
        Err(why) => {
            tracing::info!("refuse {peer}: {why:?}");
            return;
        }
    };
    let tier = rt.tier.clone().expect("edge has a tier");
    let registry = rt.registry.clone();
    let policy_for_reg = policy.clone();
    let dst = lookup_dst(&rt, &tcp, peer.ip()).await;
    let task = tokio::spawn(async move {
        let mut upstream = match tier.open(peer, &policy, &dst).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("edge: tier unreachable for {peer}: {e}");
                return;
            }
        };
        let mut tcp = tcp;
        match tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await {
            Ok((a, b)) => tracing::debug!("edge: {peer} done, {a} up {b} down"),
            Err(e) => tracing::debug!("edge: {peer} ended: {e}"),
        }
    });
    let _reg = registry.register(peer.ip(), &policy_for_reg, task.abort_handle());
    let _ = task.await;
}

/// `proxy`: mutual TLS from an edge, then an HTTP/2 connection whose every
/// CONNECT stream is one guest connection with its policy in the headers.
async fn proxy_conn(tcp: TcpStream, peer: SocketAddr, rt: Arc<Runtime>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(rt.cfg.accept_tls.clone().expect("proxy has accept tls"));
    let tls = match tokio::time::timeout(rt.cfg.handshake_timeout, acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::info!("proxy: edge {peer} failed mTLS: {e}");
            return;
        }
        Err(_) => {
            tracing::info!("proxy: edge {peer} handshake timed out");
            return;
        }
    };
    // The name the edge's certificate was issued under: what a signed
    // policy's `host` must equal.
    let edge_name: Arc<str> = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(iso_admin_pki::peer_common_name)
        .unwrap_or_default()
        .into();
    tracing::info!("proxy: tunnel from edge {peer} ({edge_name}) open");
    let ctx = rt.ctx.clone().expect("proxy has a ctx");
    let verifier = rt.cfg.policy_verifier.clone().map(Arc::new);
    let service = service_fn(move |req: Request<Incoming>| {
        let ctx = ctx.clone();
        let edge_name = edge_name.clone();
        let verifier = verifier.clone();
        async move { Ok::<_, std::convert::Infallible>(accept_stream(req, peer, &edge_name, verifier.as_deref(), ctx)) }
    });
    let served = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .keep_alive_timeout(Duration::from_secs(20))
        .max_concurrent_streams(Some(4096))
        .serve_connection(TokioIo::new(tls), service)
        .await;
    match served {
        Ok(()) => tracing::info!("proxy: tunnel from edge {peer} closed"),
        Err(e) => tracing::info!("proxy: tunnel from edge {peer} ended: {e}"),
    }
}

/// One CONNECT on a tunnel: validate the identity it carries, answer 200,
/// and serve the stream as the guest's connection. Anything else on the
/// tunnel is refused. With a verifier, the policy is the fleet's signed
/// claims and nothing else: unsigned, badly signed, expired, or signed for
/// another host than the one this edge is, and the stream is refused.
fn accept_stream(
    mut req: Request<Incoming>,
    edge: SocketAddr,
    edge_name: &str,
    verifier: Option<&iso_policy::signed::Verifier>,
    ctx: Ctx,
) -> Resp {
    if req.method() != http::Method::CONNECT {
        return simple(405, "the tier speaks CONNECT only");
    }
    let decoded = match tunnel::decode(req.headers()) {
        Ok(d) => d,
        Err(e) => {
            tracing::info!("proxy: edge {edge} sent an unusable stream: {e}");
            return simple(400, "bad tunnel headers");
        }
    };
    let src = decoded.src.map(|s| s.ip()).unwrap_or(edge.ip());
    let dst = decoded.dst.clone();
    let policy = match verifier {
        Some(v) => {
            let Some(signed) = decoded.policy.signed else {
                tracing::warn!("proxy: edge {edge_name} ({edge}) sent an unsigned policy for {src}; refused");
                return simple(403, "unsigned policy");
            };
            let claims = match v.verify(&signed) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("proxy: edge {edge_name} ({edge}) sent a policy that does not verify for {src}: {e}");
                    return simple(403, "policy does not verify");
                }
            };
            if claims.host != edge_name {
                tracing::warn!(
                    "proxy: edge {edge_name} ({edge}) presented a policy signed for host {:?} (vm {}); refused",
                    claims.host,
                    claims.vm
                );
                return simple(403, "policy is for another host");
            }
            match Policy::from_claims(claims, signed) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("proxy: signed policy from {edge_name} has an unparsable rule: {e}");
                    return simple(400, "bad policy");
                }
            }
        }
        None => match decoded.policy.into_policy() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("proxy: edge {edge} sent an unparsable policy: {e}");
                return simple(400, "bad policy");
            }
        },
    };
    if policy.is_deny_mode() {
        tracing::info!("proxy: refusing deny-mode connection from {src} via {edge}");
        return simple(403, "deny-mode vm");
    }
    let on_upgrade = hyper::upgrade::on(&mut req);
    let conn = access::Conn::new(src, edge_name, &policy);
    tokio::spawn(async move {
        let stream = match on_upgrade.await {
            Ok(u) => TokioIo::new(u),
            Err(e) => {
                tracing::debug!("proxy: stream from {src} via {edge} never opened: {e}");
                return;
            }
        };
        if let Err(e) = serve_conn(stream, conn, policy, ctx, None, dst).await {
            tracing::debug!("conn {src} via {edge} ended: {e}");
        }
    });
    Response::builder()
        .status(200)
        .body(http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}).boxed())
        .unwrap()
}

/// The destination a guest connection was dialling and, for a port that
/// carries no SNI, the name the VM resolved it from.
async fn lookup_dst(rt: &Runtime, tcp: &TcpStream, src: std::net::IpAddr) -> dst::Dst {
    let addr = (rt.cfg.dst_lookup)(tcp);
    let mut d = dst::Dst { addr, name: None };
    if let Some(a) = addr
        && a.port() != 443
        && let Some(resolver) = &rt.cfg.resolver
    {
        d.name = resolver.resolve_dst(src, *a.ip()).await;
    }
    d
}

/// Carry a connection through as bytes: dial `host:port` (a pin first, then
/// DNS), replay what was peeked, copy both ways until either side is done,
/// and log the tunnel. Nothing is terminated and nothing is injected.
async fn passthrough<S>(
    stream: S,
    prefix: Vec<u8>,
    conn: &access::Conn,
    ctx: &Ctx,
    host: &str,
    port: u16,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering::Relaxed;
    let started = std::time::Instant::now();
    let addr = match ctx.pins.get(host) {
        Some(a) => *a,
        None => match tokio::net::lookup_host((host, port)).await.ok().and_then(|mut it| it.next()) {
            Some(a) => a,
            None => {
                conn.tcp_denied(host, port, "does not resolve");
                return Ok(());
            }
        },
    };
    let mut upstream = match tokio::time::timeout(ctx.handshake_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => ws::Metered::new(s),
        _ => {
            conn.tcp_denied(host, port, "unreachable");
            return Ok(());
        }
    };
    let mut guest = ws::Metered::new(sni::Prefixed::new(prefix, stream));
    let (to_guest, to_upstream) = (guest.written(), upstream.written());
    if let Err(e) = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await {
        tracing::debug!("tcp tunnel to {host}:{port} ended: {e}");
    }
    conn.tunnel_closed("tcp", host, port, "", to_upstream.load(Relaxed), to_guest.load(Relaxed), started.elapsed());
    Ok(())
}

/// Serve one guest connection. A port with no SNI is a passthrough or
/// nothing; on 443 the ClientHello's SNI decides between a passthrough
/// (`tunnel tcp://host:443`), terminating (an allow rule names the host)
/// and dropping.
async fn serve_conn<S>(
    mut stream: S,
    conn: access::Conn,
    policy: Policy,
    ctx: Ctx,
    on_task: Option<OnTask>,
    dst: dst::Dst,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let port = dst.port();
    if port != 443 {
        let Some(host) = dst.name.clone() else {
            conn.tcp_denied(&dst.label(), port, "no name: the address was not resolved through the host");
            return Ok(());
        };
        if !policy.rules.tunnel_allowed(&host, port) {
            conn.tcp_denied(&host, port, "no tunnel rule");
            return Ok(());
        }
        return passthrough(stream, Vec::new(), &conn, &ctx, &host, port).await;
    }

    // Peek the ClientHello: non-TLS never produces one → dropped here.
    let peeked = match sni::peek(&mut stream, ctx.handshake_timeout).await {
        Ok(p) => p,
        Err(_) => return Ok(()), // never sent a ClientHello
    };
    let sni = match (peeked.is_tls, peeked.sni.clone()) {
        (true, Some(s)) => s,
        _ => return Ok(()), // not TLS, or no SNI → unroutable
    };

    // A tunnel rule for the host carries the TLS session through untouched.
    if policy.rules.tunnel_allowed(&sni, 443) {
        return passthrough(stream, peeked.bytes, &conn, &ctx, &sni, 443).await;
    }

    // Host phase: is there any allow rule this host could satisfy? A host
    // with no allow rule is never terminated and never gets a certificate.
    if !policy.rules.host_allowed(&sni) {
        conn.sni_denied(&sni);
        return Ok(());
    }

    let stream = sni::Prefixed::new(peeked.bytes, stream);
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let handshake = match tokio::time::timeout(ctx.handshake_timeout, acceptor).await {
        Ok(Ok(h)) => h,
        Ok(Err(_)) => return Ok(()),
        Err(_) => return Ok(()),
    };

    // Mint (fail-closed) and terminate.
    let server_cfg = match ctx.ca.server_config(&sni).await {
        Some(c) => c,
        None => {
            tracing::error!("cert mint failed for {sni}");
            return Ok(());
        }
    };
    let tls = match tokio::time::timeout(ctx.handshake_timeout, handshake.into_stream(server_cfg))
        .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()),
    };

    let sni = Arc::new(sni);
    let policy = Arc::new(policy);
    let service = service_fn(move |req| {
        handle(
            req,
            sni.clone(),
            policy.clone(),
            ctx.clone(),
            on_task.clone(),
            conn.clone(),
        )
    });

    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(tls), service)
        .await
}

async fn handle(
    req: Request<Incoming>,
    sni: Arc<String>,
    policy: Arc<Policy>,
    ctx: Ctx,
    on_task: Option<OnTask>,
    conn: access::Conn,
) -> Result<Resp, BoxError> {
    let started = std::time::Instant::now();
    let method = req.method().clone();
    // Anti-fronting: the request authority must equal the SNI we terminated.
    let authority = req.uri().host().map(str::to_string).or_else(|| {
        req.headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
    });
    if authority.as_deref() != Some(sni.as_str()) {
        tracing::warn!("authority {authority:?} != sni {sni}");
        conn.request(&access::RequestOutcome {
            method: &method,
            scheme: "https",
            host: &sni,
            path: req.uri().path(),
            decision: "deny",
            rule: Some("authority"),
            injected: &[],
            status: 421,
            latency: started.elapsed(),
            upgrade: false,
        });
        return Ok(simple(421, "authority does not match TLS SNI"));
    }

    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let uri: http::Uri = match format!("https://{sni}{pq}").parse() {
        Ok(u) => u,
        Err(_) => return Ok(simple(400, "bad request target")),
    };

    // URI phase, before anything is injected: a denied path never carries a
    // credential. An upgrade request is judged under `wss`.
    let upgrade = ws::is_websocket_upgrade(req.headers());
    let scheme = if upgrade { Scheme::Wss } else { Scheme::Https };
    let path = uri.path().to_string();
    if let Decision::Deny(rule) = policy.rules.evaluate(scheme, &sni, None, &path) {
        conn.request(&access::RequestOutcome {
            method: &method,
            scheme: scheme.as_str(),
            host: &sni,
            path: &path,
            decision: "deny",
            rule: Some(rule.as_deref().unwrap_or("default")),
            injected: &[],
            status: 403,
            latency: started.elapsed(),
            upgrade,
        });
        return Ok(denied(&sni, scheme, &path, rule.as_deref()));
    }

    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    parts.headers.remove(HOST); // re-derived from the authority by the client

    // The provider sees the path (never the query string) so it can apply
    // path-scoped rules — a credential that must not reach a vendor's OAuth
    // routes, say — instead of deciding host-wide.
    let mut injected = Vec::new();
    for (k, v) in ctx
        .secrets
        .headers(&sni, policy.principal.as_deref(), Some(&path))
        .await
    {
        if let (Ok(name), Ok(val)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::header::HeaderValue::from_str(&v),
        ) {
            injected.push(name.as_str().to_string());
            parts.headers.insert(name, val); // override
        }
    }
    injected.sort();

    let upstream = Request::from_parts(parts, body);
    let outcome = |status: u16, latency: Duration| access::RequestOutcome {
        method: &method,
        scheme: scheme.as_str(),
        host: &sni,
        path: &path,
        decision: "allow",
        rule: None,
        injected: &injected,
        status,
        latency,
        upgrade,
    };
    if upgrade {
        let result = ws::proxy_upgrade(upstream, &ctx.client_h1, on_task, conn.clone(), sni.to_string(), path.clone()).await;
        return match result {
            Ok(resp) => {
                conn.request(&outcome(resp.status().as_u16(), started.elapsed()));
                Ok(resp)
            }
            Err(e) => {
                conn.request(&outcome(502, started.elapsed()));
                Ok(simple(502, &format!("upstream error: {e}")))
            }
        };
    }
    match ctx.client.request(upstream).await {
        Ok(resp) => {
            conn.request(&outcome(resp.status().as_u16(), started.elapsed()));
            Ok(resp.map(|b| b.map_err(|e| Box::new(e) as BoxError).boxed()))
        }
        Err(e) => {
            conn.request(&outcome(502, started.elapsed()));
            Ok(simple(502, &format!("upstream error: {e}")))
        }
    }
}

fn simple(status: u16, msg: &str) -> Resp {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from(msg.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// The URI phase's answer to the guest: a 403 that says which rule, so an
/// agent can tell a policy decision from a broken network.
fn denied(host: &str, scheme: Scheme, path: &str, rule: Option<&str>) -> Resp {
    let body = serde_json::json!({
        "error": "denied by policy",
        "request": format!("{}://{host}{path}", scheme.as_str()),
        "rule": rule,
    });
    Response::builder()
        .status(403)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header("x-iso-denied", "policy")
        .body(
            Full::new(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}
