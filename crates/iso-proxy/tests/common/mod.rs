//! Shared harness for the proxy's integration tests. Nothing here needs
//! root, a VM, or the network: the CA, the secrets service, the upstream and
//! the proxy all run in-process on loopback.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use iso_admin_pki::{AdminPki, Creds};
use iso_ca::Ca;
use iso_policy::RuleSet;
use iso_proxy::{Policy, PolicyResolver};
use iso_secrets::TomlSecretProvider;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The host every test speaks to through the proxy. It exists only in the
/// proxy's pin table and in the upstream's certificate.
pub const UPSTREAM_HOST: &str = "api.example.test";

pub fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // JSON lines into a buffer the tests can read back (the access log is
    // asserted on), and to the test writer for a failing test's output.
    use tracing_subscriber::fmt::writer::MakeWriterExt as _;
    let capture = Capture(CAPTURE.get_or_init(Default::default).clone());
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .flatten_event(true)
        .with_writer(capture.and(tracing_subscriber::fmt::TestWriter::new()))
        .try_init();
}

static CAPTURE: std::sync::OnceLock<Arc<Mutex<Vec<u8>>>> = std::sync::OnceLock::new();

/// Everything the subscriber wrote, as bytes, shared by every test in the
/// process: tests pick their own events out by a unique path or size.
#[derive(Clone)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

/// The access log so far: every `iso_proxy::access` event as the JSON
/// object the subscriber wrote.
pub fn access_events() -> Vec<serde_json::Value> {
    let bytes = CAPTURE.get().map(|c| c.lock().unwrap().clone()).unwrap_or_default();
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["target"] == iso_proxy::access::TARGET)
        .collect()
}

/// A path no other test uses.
pub fn unique_path(prefix: &str) -> String {
    format!("{prefix}/{}", nanos())
}

pub fn tempdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "iso-proxy-{tag}-{}-{}",
        std::process::id(),
        nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// A policy the tests can change while connections are open, and the
/// names it remembers VMs resolving (what the host's DNS memory answers).
pub struct TestResolver {
    inner: Mutex<Option<Policy>>,
    dst: Mutex<std::collections::HashMap<(IpAddr, std::net::Ipv4Addr), String>>,
}

impl TestResolver {
    pub fn new(policy: Policy) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(policy)),
            dst: Mutex::new(Default::default()),
        })
    }
    pub fn set(&self, policy: Option<Policy>) {
        *self.inner.lock().unwrap() = policy;
    }
    /// Remember that the VM at `src` resolved `dst` from `name`.
    pub fn name_dst(&self, src: IpAddr, dst: std::net::Ipv4Addr, name: &str) {
        self.dst.lock().unwrap().insert((src, dst), name.to_string());
    }
    /// A new generation with the same rules: what a `PATCH /policy` does.
    pub fn bump(&self) {
        let mut g = self.inner.lock().unwrap();
        if let Some(p) = g.as_mut() {
            p.policy_gen += 1;
        }
    }
}

#[async_trait]
impl PolicyResolver for TestResolver {
    async fn resolve(&self, _ip: IpAddr) -> Option<Policy> {
        self.inner.lock().unwrap().clone()
    }
    async fn resolve_dst(&self, ip: IpAddr, dst: std::net::Ipv4Addr) -> Option<String> {
        self.dst.lock().unwrap().get(&(ip, dst)).cloned()
    }
}

/// A destination lookup that answers the same address for every connection:
/// what the kernel's conntrack would say had the connection been redirected.
pub fn fixed_dst(addr: &str) -> iso_proxy::dst::DstLookup {
    let a: std::net::SocketAddrV4 = addr.parse().unwrap();
    Arc::new(move |_| Some(a))
}

/// A raw TCP echo server on an ephemeral port: what a `tunnel tcp://`
/// rule reaches, standing in for a database or an ssh server.
pub struct TestTcpEcho {
    pub addr: SocketAddr,
}

impl TestTcpEcho {
    pub async fn start() -> Self {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { break };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        Self { addr }
    }
}

pub fn policy(egress: &str, principal: Option<&str>, rules: &[&str]) -> Policy {
    Policy {
        egress: egress.into(),
        principal: principal.map(str::to_string),
        rules: Arc::new(RuleSet::parse(rules).unwrap()),
        policy_gen: 1,
        vm: Some("vm-test".into()),
        signed: None,
    }
}

/// The tier CA (what guests trust) served on a Unix socket and over HTTPS.
pub struct TestCa {
    pub ca: Arc<Ca>,
    pub sock: PathBuf,
    pub https: Option<SocketAddr>,
    pub cert_pem: String,
}

impl TestCa {
    pub async fn start(dir: &Path, https: Option<Arc<rustls::ServerConfig>>) -> Self {
        let ca = Arc::new(Ca::load_or_generate(&dir.join("ca")).unwrap());
        let sock = dir.join("ca.sock");
        {
            let ca = ca.clone();
            let sock = sock.clone();
            tokio::spawn(async move { iso_ca::serve_unix(ca, &sock).await });
        }
        let https = match https {
            Some(cfg) => {
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = l.local_addr().unwrap();
                let ca = ca.clone();
                tokio::spawn(async move { iso_ca::serve_https(ca, l, cfg, iso_rpc::ClientAllow::AnyFromCa).await });
                Some(addr)
            }
            None => None,
        };
        wait_for(&sock).await;
        Self {
            ca,
            sock,
            https,
            cert_pem: std::fs::read_to_string(dir.join("ca/ca.crt")).unwrap(),
        }
    }
}

/// The secrets service, TOML-backed, on a Unix socket and over HTTPS.
pub struct TestSecrets {
    pub sock: PathBuf,
    pub https: Option<SocketAddr>,
}

impl TestSecrets {
    pub async fn start(dir: &Path, https: Option<Arc<rustls::ServerConfig>>) -> Self {
        let toml = format!(
            "[global.\"{UPSTREAM_HOST}\"]\n\"x-iso-injected\" = \"hello-from-iso\"\n\n\
             [principals.alice.\"{UPSTREAM_HOST}\"]\n\"authorization\" = {{ bearer = \"alice-token\" }}\n"
        );
        let provider = Arc::new(TomlSecretProvider::from_toml(&toml).unwrap());
        let sock = dir.join("secrets.sock");
        {
            let provider = provider.clone();
            let sock = sock.clone();
            tokio::spawn(async move { iso_secrets::serve_unix(provider, &sock).await });
        }
        let https = match https {
            Some(cfg) => {
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = l.local_addr().unwrap();
                tokio::spawn(async move { iso_secrets::serve_https(provider, l, cfg, iso_rpc::ClientAllow::AnyFromCa).await });
                Some(addr)
            }
            None => None,
        };
        wait_for(&sock).await;
        Self { sock, https }
    }
}

async fn wait_for(sock: &Path) {
    for _ in 0..200 {
        if sock.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("{} never appeared", sock.display());
}

/// A TLS upstream for `UPSTREAM_HOST` on an ephemeral port, with its own
/// CA that the proxy is told to trust. Serves:
/// - `GET /get`, `/repos/…`, `/anything` → 200 JSON `{ "path", "headers" }`
/// - `GET /user/keys` → 200 `secret keys` (what a deny rule protects)
/// - `GET /ws` with `Upgrade: websocket` → 101, then echoes bytes
pub struct TestUpstream {
    pub addr: SocketAddr,
    pub ca_der: rustls_pki_types::CertificateDer<'static>,
    /// The same CA as PEM, for a guest that must trust the upstream itself
    /// (a passthrough shows the guest the upstream's certificate).
    pub ca_pem: String,
    pub hits: Arc<Mutex<Vec<String>>>,
}

impl TestUpstream {
    pub async fn start(dir: &Path) -> Self {
        // Its own CA, distinct from the tier CA: the proxy must verify
        // upstreams against something the guest never sees.
        let up_ca = Ca::load_or_generate(&dir.join("upstream-ca")).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![UPSTREAM_HOST.to_string()]).unwrap();
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        let signed = up_ca.sign(&csr).unwrap();
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> = signed
            .chain_der
            .into_iter()
            .map(rustls_pki_types::CertificateDer::from)
            .collect();
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key_der)
            .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let hits2 = hits.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let hits = hits2.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let hits = hits.clone();
                        async move { upstream_handler(req, hits).await }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection_with_upgrades(TokioIo::new(tls), svc)
                    .await;
                });
            }
        });
        Self {
            addr,
            ca_der: rustls_pki_types::CertificateDer::from(up_ca.ca_cert_der().to_vec()),
            ca_pem: {
                use base64::Engine as _;
                let b64 = base64::engine::general_purpose::STANDARD.encode(up_ca.ca_cert_der());
                let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
                format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
            },
            hits,
        }
    }

    pub fn hit_paths(&self) -> Vec<String> {
        self.hits.lock().unwrap().clone()
    }
}

type UpResp = Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>;

async fn upstream_handler(
    mut req: Request<Incoming>,
    hits: Arc<Mutex<Vec<String>>>,
) -> Result<UpResp, hyper::Error> {
    let path = req.uri().path().to_string();
    hits.lock().unwrap().push(path.clone());
    let full = |status: StatusCode, body: Vec<u8>| -> UpResp {
        Response::builder()
            .status(status)
            .body(
                Full::new(Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    };
    if path == "/ws" {
        let is_upgrade = req
            .headers()
            .get(http::header::UPGRADE)
            .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
            .unwrap_or(false);
        if !is_upgrade {
            return Ok(full(StatusCode::BAD_REQUEST, b"not an upgrade".to_vec()));
        }
        let injected = req.headers().get("x-iso-injected").cloned();
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let Ok(up) = on_upgrade.await else { return };
            let mut io = TokioIo::new(up);
            let mut buf = [0u8; 1024];
            loop {
                let n = match io.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if io.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        let mut resp = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::CONNECTION, "Upgrade")
            .header("sec-websocket-accept", "test-accept")
            .header("x-ws-upstream", "echo");
        if let Some(v) = injected {
            resp = resp.header("x-ws-saw-injected", v);
        }
        return Ok(resp
            .body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap());
    }
    if path == "/user/keys" {
        return Ok(full(StatusCode::OK, b"secret keys".to_vec()));
    }
    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("?").to_string(),
            )
        })
        .collect();
    let body = serde_json::json!({ "path": path, "headers": headers, "version": format!("{:?}", req.version()) });
    Ok(full(StatusCode::OK, serde_json::to_vec(&body).unwrap()))
}

/// A guest-like client: trusts the tier CA, and "resolves" `UPSTREAM_HOST`
/// to the proxy, which is what nftables DNAT does to a real guest.
pub fn guest_client(proxy: SocketAddr, tier_ca_pem: &str, http1_only: bool) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(tier_ca_pem.as_bytes()).unwrap())
        .resolve(UPSTREAM_HOST, proxy)
        .no_proxy()
        .timeout(Duration::from_secs(10));
    if http1_only {
        b = b.http1_only();
    }
    b.build().unwrap()
}

pub fn url(path: &str) -> String {
    format!("https://{UPSTREAM_HOST}{path}")
}

/// Open a WebSocket-style upgrade through the proxy and return the raw
/// upgraded stream plus the 101 response's headers.
pub async fn open_ws(
    client: &reqwest::Client,
    path: &str,
) -> Result<(reqwest::Upgraded, http::HeaderMap), reqwest::Error> {
    let resp = client
        .get(url(path))
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await?;
    let headers = resp.headers().clone();
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(resp.error_for_status().unwrap_err());
    }
    let up = resp.upgrade().await?;
    Ok((up, headers))
}

/// The admin PKI with service identities for every role, for the split.
pub struct TestPki {
    pub pki: AdminPki,
    pub edge: Creds,
    pub proxy: Creds,
    pub ca_svc: Creds,
    pub secrets_svc: Creds,
    pub stranger: Creds,
}

impl TestPki {
    pub fn new(dir: &Path) -> Self {
        let sans = vec!["127.0.0.1".to_string(), "localhost".to_string()];
        let pki = AdminPki::load_or_generate(&dir.join("admin-pki"), &sans).unwrap();
        let creds = |name: &str| Creds {
            ca_pem: pki.ca_cert_pem().to_string(),
            identity: pki.issue_server(name, &sans).unwrap(),
        };
        let other = AdminPki::load_or_generate(&dir.join("other-pki"), &sans).unwrap();
        let stranger = Creds {
            ca_pem: pki.ca_cert_pem().to_string(),
            identity: other.issue_server("stranger", &sans).unwrap(),
        };
        Self {
            edge: creds("edge-hostA"),
            proxy: creds("proxy-1"),
            ca_svc: creds("iso-cad"),
            secrets_svc: creds("iso-secretsd"),
            stranger,
            pki,
        }
    }
}

/// Wait until `f` is true, or fail after `for_`.
pub async fn eventually<F: FnMut() -> bool>(mut f: F, for_: Duration, what: &str) {
    let start = std::time::Instant::now();
    while start.elapsed() < for_ {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for: {what}");
}
