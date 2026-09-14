//! iso-rpc — the two transports iso's side services (the CA, the secrets
//! provider, identify) speak, so each daemon and each client has one place
//! to get them from.
//!
//! - **Unix**: one JSON request per connection, half-close framed: the client
//!   writes the body and shuts down its write side, the server answers and
//!   closes. Root-only sockets under the state directory. The single-host
//!   form.
//! - **HTTPS**: `POST <base>/<method>` with a JSON body, mutual TLS on the
//!   admin PKI (`iso-admin-pki`). The form a service takes when the caller is
//!   on another machine, or is a proxy replica that must not be on this one.
//!
//! Both carry the same bodies; a service serves either or both from one
//! handler, and a client picks by [`Endpoint`].

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio_rustls::TlsAcceptor;

/// How long a peer gets to finish a TLS handshake, and how long one RPC may
/// take end to end.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// A request handler: the method name (the last path segment over HTTPS;
/// the caller's declared method over Unix, see [`serve_unix`]) and the raw
/// JSON body, to a raw JSON reply.
pub trait Handler: Send + Sync + 'static {
    fn call(&self, method: &str, body: Vec<u8>) -> impl Future<Output = Vec<u8>> + Send;
}

impl<F, Fut> Handler for F
where
    F: Fn(&str, Vec<u8>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Vec<u8>> + Send,
{
    fn call(&self, method: &str, body: Vec<u8>) -> impl Future<Output = Vec<u8>> + Send {
        (self)(method, body)
    }
}

// ---------------------------------------------------------------- unix ----

/// Serve `handler` on a Unix socket. Every connection is one request. The
/// method is fixed per socket (a socket serves one thing), so it is passed
/// in rather than parsed.
pub async fn serve_unix<H: Handler>(
    sock: &Path,
    method: &'static str,
    handler: Arc<H>,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock)?;
    loop {
        let (mut conn, _) = listener.accept().await?;
        let handler = handler.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            if tokio::time::timeout(CALL_TIMEOUT, conn.read_to_end(&mut buf))
                .await
                .is_err()
            {
                return;
            }
            let resp = handler.call(method, buf).await;
            let _ = conn.write_all(&resp).await;
            let _ = conn.shutdown().await;
        });
    }
}

/// One half-close framed call over a Unix socket.
pub async fn call_unix<Req: Serialize, Resp: DeserializeOwned>(
    sock: &Path,
    req: &Req,
) -> std::io::Result<Resp> {
    let fut = async {
        let mut conn = UnixStream::connect(sock).await?;
        conn.write_all(&serde_json::to_vec(req)?).await?;
        conn.shutdown().await?;
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await?;
        Ok::<_, std::io::Error>(serde_json::from_slice(&buf)?)
    };
    tokio::time::timeout(CALL_TIMEOUT, fut)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "rpc timed out"))?
}

// --------------------------------------------------------------- https ----

/// Serve `handler` over HTTPS with mutual TLS. `POST /<method>` with a JSON
/// body; anything else is 404. `cfg` comes from `iso_admin_pki::Creds::server_config`.
pub async fn serve_https<H: Handler>(
    listener: TcpListener,
    cfg: Arc<rustls::ServerConfig>,
    handler: Arc<H>,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(cfg);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!("rpc tls handshake from {peer} failed: {e}");
                    return;
                }
                Err(_) => return,
            };
            let svc = service_fn(move |req: Request<Incoming>| {
                let handler = handler.clone();
                async move {
                    if req.method() != hyper::Method::POST {
                        return Ok::<_, hyper::Error>(status(StatusCode::METHOD_NOT_ALLOWED));
                    }
                    let method = req.uri().path().trim_matches('/').to_string();
                    let body = match req.into_body().collect().await {
                        Ok(b) => b.to_bytes().to_vec(),
                        Err(_) => return Ok(status(StatusCode::BAD_REQUEST)),
                    };
                    let out = handler.call(&method, body).await;
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(out)))
                        .unwrap())
                }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), svc)
                .await
            {
                tracing::debug!("rpc connection from {peer}: {e}");
            }
        });
    }
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// An HTTPS RPC client bound to one base URL and one mutual-TLS identity.
#[derive(Clone)]
pub struct HttpsClient {
    base: String,
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl HttpsClient {
    /// `base` like `https://10.0.0.7:7443`; `cfg` from
    /// `iso_admin_pki::Creds::client_config`.
    pub fn new(base: &str, cfg: Arc<rustls::ClientConfig>) -> Self {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config((*cfg).clone())
            .https_only()
            .enable_http1()
            .build();
        Self {
            base: base.trim_end_matches('/').to_string(),
            client: Client::builder(TokioExecutor::new()).build(https),
        }
    }

    pub async fn call<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        method: &str,
        req: &Req,
    ) -> std::io::Result<Resp> {
        let uri: http::Uri = format!("{}/{}", self.base, method).parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("bad rpc url: {e}"),
            )
        })?;
        let request = Request::builder()
            .method(hyper::Method::POST)
            .uri(uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(serde_json::to_vec(req)?)))
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let fut = async {
            let resp = self
                .client
                .request(request)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            if resp.status() != StatusCode::OK {
                return Err(std::io::Error::other(format!(
                    "rpc {method}: http {}",
                    resp.status()
                )));
            }
            let body = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .to_bytes();
            Ok::<_, std::io::Error>(serde_json::from_slice(&body)?)
        };
        tokio::time::timeout(CALL_TIMEOUT, fut)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "rpc timed out"))?
    }
}

// ------------------------------------------------------------ endpoint ----

/// Where a side service is, from a client's point of view.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // one per service, cloned rarely
pub enum Endpoint {
    /// A Unix socket on this host. `method` is implied by the socket.
    Unix(PathBuf),
    /// An HTTPS base URL, mutual TLS.
    Https(HttpsClient),
}

impl Endpoint {
    pub fn unix(sock: impl Into<PathBuf>) -> Self {
        Endpoint::Unix(sock.into())
    }

    pub fn https(base: &str, cfg: Arc<rustls::ClientConfig>) -> Self {
        Endpoint::Https(HttpsClient::new(base, cfg))
    }

    pub async fn call<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        method: &str,
        req: &Req,
    ) -> std::io::Result<Resp> {
        match self {
            Endpoint::Unix(sock) => call_unix(sock, req).await,
            Endpoint::Https(c) => c.call(method, req).await,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Endpoint::Unix(p) => p.display().to_string(),
            Endpoint::Https(c) => c.base.clone(),
        }
    }
}

/// `addr` parsed as a socket address, for `ISO_*_LISTEN` style settings.
pub fn parse_listen(s: &str) -> std::io::Result<SocketAddr> {
    s.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("bad listen address {s:?}: {e}"),
        )
    })
}
