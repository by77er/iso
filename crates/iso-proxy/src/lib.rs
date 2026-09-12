//! iso-proxy — credential-injecting, policy-enforcing transparent MITM HTTPS
//! proxy. The backend for the `Proxy` egress mode. See `DESIGN.md`.

mod policy;
mod rpc;

pub use policy::{Policy, PolicyResolver, RpcResolver, StaticResolver};

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

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
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::LazyConfigAcceptor;

use rpc::CaClient;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Resp = Response<BoxBody<Bytes, BoxError>>;
type UpstreamClient = Client<HttpsConnector<HttpConnector>, Incoming>;

/// Proxy configuration.
pub struct ProxyConfig {
    /// Addresses to accept redirected egress on: the nft Proxy-mode DNAT target
    /// (`:3128`) and the DNS-redirect target for Allow mode (`:443`).
    pub listen: Vec<SocketAddr>,
    pub ca_sock: PathBuf,
    pub secrets_sock: PathBuf,
    /// Resolves a connection's source IP to its VM's egress policy.
    pub resolver: Arc<dyn PolicyResolver>,
}

/// Shared, cheap-to-clone request context.
#[derive(Clone)]
struct Ctx {
    ca: Arc<CaClient>,
    secrets: Arc<iso_secrets::Client>,
    client: UpstreamClient,
    resolver: Arc<dyn PolicyResolver>,
}

/// Run the proxy, binding every address in `cfg.listen`.
pub async fn run(cfg: ProxyConfig) -> std::io::Result<()> {
    let ctx = build_ctx(&cfg.ca_sock, &cfg.secrets_sock, cfg.resolver.clone())?;
    let mut handles = Vec::new();
    for addr in cfg.listen {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("iso-proxy listening on {addr}");
        let ctx = ctx.clone();
        handles.push(tokio::spawn(accept_loop(listener, ctx)));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

/// Run the proxy on an already-bound listener (used by tests that need `:0`).
pub async fn run_with_listener(listener: TcpListener, cfg: ProxyConfig) -> std::io::Result<()> {
    let ctx = build_ctx(&cfg.ca_sock, &cfg.secrets_sock, cfg.resolver)?;
    accept_loop(listener, ctx).await
}

fn build_ctx(
    ca_sock: &std::path::Path,
    secrets_sock: &std::path::Path,
    resolver: Arc<dyn PolicyResolver>,
) -> std::io::Result<Ctx> {
    let ca = Arc::new(
        CaClient::new(ca_sock.to_path_buf()).map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let secrets = Arc::new(iso_secrets::Client::new(secrets_sock));
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: UpstreamClient = Client::builder(TokioExecutor::new()).build(https);
    Ok(Ctx {
        ca,
        secrets,
        client,
        resolver,
    })
}

async fn accept_loop(listener: TcpListener, ctx: Ctx) -> std::io::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(tcp, peer.ip(), ctx).await {
                tracing::debug!("conn {peer} ended: {e}");
            }
        });
    }
}

async fn serve_conn(tcp: TcpStream, peer: IpAddr, ctx: Ctx) -> Result<(), BoxError> {
    // Peek the ClientHello: non-TLS never produces one → dropped here.
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp);
    let handshake = match acceptor.await {
        Ok(h) => h,
        Err(_) => return Ok(()), // not TLS
    };

    let sni = match handshake.client_hello().server_name() {
        Some(s) => s.to_string(),
        None => return Ok(()), // no SNI → unroutable
    };

    // Resolve this VM's current policy by source IP; default-deny.
    let policy = match ctx.resolver.resolve(peer).await {
        Some(p) => p,
        None => {
            tracing::info!("deny {sni}: unknown source {peer}");
            return Ok(());
        }
    };
    if !policy.allow.contains(&sni) {
        tracing::info!("deny {sni} for {peer} (not in allow-list)");
        return Ok(());
    }
    let principal = policy.principal.clone();

    // Mint (fail-closed) and terminate.
    let server_cfg = match ctx.ca.server_config(&sni).await {
        Some(c) => c,
        None => {
            tracing::error!("cert mint failed for {sni}");
            return Ok(());
        }
    };
    let tls = handshake.into_stream(server_cfg).await?;

    let sni2 = sni.clone();
    let ctx2 = ctx.clone();
    let service = service_fn(move |req| {
        handle(req, sni2.clone(), principal.clone(), ctx2.clone())
    });

    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls), service)
        .await
}

async fn handle(
    req: Request<Incoming>,
    sni: String,
    principal: Option<String>,
    ctx: Ctx,
) -> Result<Resp, BoxError> {
    // Anti-fronting: the request authority must equal the SNI we terminated.
    let authority = req
        .uri()
        .host()
        .map(str::to_string)
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
        });
    if authority.as_deref() != Some(sni.as_str()) {
        tracing::warn!("authority {authority:?} != sni {sni}");
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

    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    parts.headers.remove(HOST); // re-derived from the authority by the client

    // The provider sees the path (never the query string) so it can apply
    // path-scoped rules — a credential that must not reach a vendor's OAuth
    // routes, say — instead of deciding host-wide.
    let path = parts.uri.path().to_string();
    for (k, v) in ctx
        .secrets
        .headers(&sni, principal.as_deref(), Some(&path))
        .await
    {
        if let (Ok(name), Ok(val)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::header::HeaderValue::from_str(&v),
        ) {
            parts.headers.insert(name, val); // override
        }
    }

    let upstream = Request::from_parts(parts, body);
    match ctx.client.request(upstream).await {
        Ok(resp) => Ok(resp.map(|b| b.map_err(|e| Box::new(e) as BoxError).boxed())),
        Err(e) => Ok(simple(502, &format!("upstream error: {e}"))),
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
