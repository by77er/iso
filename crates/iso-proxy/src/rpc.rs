//! RPC clients for the two boundaries: the CertAuthority (`iso-cad`) and the
//! SecretProvider (`iso-secretsd`). Each call is one connection: write JSON,
//! half-close, read the JSON reply (see `iso-proxy/DESIGN.md`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use iso_ca::{SignRequest, SignResponse};
use iso_secrets::{HeadersRequest, HeadersResponse};

pub(crate) async fn call<Req: Serialize, Resp: DeserializeOwned>(
    sock: &Path,
    req: &Req,
) -> std::io::Result<Resp> {
    let mut conn = UnixStream::connect(sock).await?;
    let body = serde_json::to_vec(req)?;
    conn.write_all(&body).await?;
    conn.shutdown().await?; // half-close: signals end-of-request to the server
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

/// SecretProvider RPC client. Fail-open: any error ⇒ inject nothing.
pub struct SecretsClient {
    sock: PathBuf,
}

impl SecretsClient {
    pub fn new(sock: PathBuf) -> Self {
        Self { sock }
    }

    pub async fn headers(&self, domain: &str, principal: Option<&str>) -> HashMap<String, String> {
        let req = HeadersRequest {
            domain: domain.to_string(),
            principal: principal.map(str::to_string),
        };
        match call::<_, HeadersResponse>(&self.sock, &req).await {
            Ok(r) => r.headers,
            Err(e) => {
                tracing::warn!("secrets rpc failed, injecting nothing: {e}");
                HashMap::new()
            }
        }
    }
}

/// CertAuthority RPC client. Holds one disposable leaf key shared across all
/// minted certs (CA only signs); caches a ready `ServerConfig` per domain.
pub struct CaClient {
    sock: PathBuf,
    leaf_key_pem: String,
    leaf_key_der: Vec<u8>,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CaClient {
    pub fn new(sock: PathBuf) -> Result<Self, rcgen::Error> {
        let key = KeyPair::generate()?;
        Ok(Self {
            sock,
            leaf_key_pem: key.serialize_pem(),
            leaf_key_der: key.serialize_der(),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// A rustls `ServerConfig` presenting a freshly-minted (cached) cert for
    /// `domain`, ALPN h2 + http/1.1. `None` ⇒ minting failed (fail-closed).
    pub async fn server_config(&self, domain: &str) -> Option<Arc<ServerConfig>> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cfg) = cache.get(domain) {
                return Some(cfg.clone());
            }
        }

        let key = KeyPair::from_pem(&self.leaf_key_pem).ok()?;
        let params = CertificateParams::new(vec![domain.to_string()]).ok()?;
        let csr_pem = params.serialize_request(&key).ok()?.pem().ok()?;

        let resp: SignResponse = call(
            &self.sock,
            &SignRequest {
                domain: domain.to_string(),
                csr_pem,
            },
        )
        .await
        .ok()?;
        if resp.chain_der_b64.is_empty() {
            return None;
        }

        let certs: Vec<CertificateDer<'static>> = resp
            .chain_der_b64
            .iter()
            .filter_map(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            .map(CertificateDer::from)
            .collect();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key_der.clone()));

        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key_der)
            .ok()?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);

        self.cache
            .lock()
            .unwrap()
            .insert(domain.to_string(), cfg.clone());
        Some(cfg)
    }
}
