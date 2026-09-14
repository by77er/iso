//! The CertAuthority client: a disposable leaf key, CSRs signed by `iso-cad`
//! over either transport, and a per-domain cache of ready `ServerConfig`s
//! that evicts at the leaf's expiry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use iso_ca::{SignRequest, SignResponse};
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Re-mint this long before a leaf expires, so a client never sees one that
/// is about to.
const RENEW_MARGIN: Duration = Duration::from_secs(10 * 60);
/// A CA that does not say when a leaf expires gets this long.
const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);

struct Cached {
    cfg: Arc<ServerConfig>,
    /// Unix seconds after which the entry is not used.
    renew_at: u64,
}

/// CertAuthority RPC client. Holds one disposable leaf key shared across all
/// minted certs (CA only signs); caches a ready `ServerConfig` per domain
/// until shortly before its leaf expires.
pub struct CaClient {
    endpoint: iso_rpc::Endpoint,
    leaf_key_pem: String,
    leaf_key_der: Vec<u8>,
    cache: Mutex<HashMap<String, Cached>>,
}

impl CaClient {
    pub fn new(endpoint: iso_rpc::Endpoint) -> Result<Self, rcgen::Error> {
        let key = KeyPair::generate()?;
        Ok(Self {
            endpoint,
            leaf_key_pem: key.serialize_pem(),
            leaf_key_der: key.serialize_der(),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// A rustls `ServerConfig` presenting a fresh (or cached, unexpired) cert
    /// for `domain`, ALPN h2 + http/1.1. `None` ⇒ minting failed (fail-closed).
    pub async fn server_config(&self, domain: &str) -> Option<Arc<ServerConfig>> {
        let now = unix_now();
        {
            let mut cache = self.cache.lock().unwrap();
            match cache.get(domain) {
                Some(c) if c.renew_at > now => return Some(c.cfg.clone()),
                Some(_) => {
                    cache.remove(domain);
                }
                None => {}
            }
        }

        let key = KeyPair::from_pem(&self.leaf_key_pem).ok()?;
        let params = CertificateParams::new(vec![domain.to_string()]).ok()?;
        let csr_pem = params.serialize_request(&key).ok()?.pem().ok()?;

        let resp: SignResponse = match self
            .endpoint
            .call(
                iso_ca::METHOD,
                &SignRequest {
                    domain: domain.to_string(),
                    csr_pem,
                },
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("ca rpc failed for {domain}: {e}");
                return None;
            }
        };
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

        let not_after = resp.not_after.unwrap_or(now + DEFAULT_TTL.as_secs());
        let renew_at = not_after
            .saturating_sub(RENEW_MARGIN.as_secs())
            .max(now + 1);
        self.cache.lock().unwrap().insert(
            domain.to_string(),
            Cached {
                cfg: cfg.clone(),
                renew_at,
            },
        );
        Some(cfg)
    }

    /// Cached domains and when each will be re-minted (unix seconds). For
    /// tests and diagnostics.
    pub fn cache_state(&self) -> Vec<(String, u64)> {
        self.cache
            .lock()
            .unwrap()
            .iter()
            .map(|(d, c)| (d.clone(), c.renew_at))
            .collect()
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
