//! iso-ca — the egress proxy's certificate authority (sign-only minter).
//!
//! Holds the CA private key in its own process and only ever **signs** leaf
//! CSRs the proxy submits — the proxy generates the disposable leaf key, the
//! CA key never crosses the RPC boundary. See `iso-proxy/DESIGN.md`.
//!
//! Leaves are short-lived ([`LEAF_TTL`]); the response says when each one
//! expires so the proxy can evict it and ask again. The service answers on a
//! Unix socket (single host) and, when given a service identity, over HTTPS
//! with mutual TLS (a proxy tier on other machines).

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams, DnType,
    IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("pem: {0}")]
    Pem(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// How long a signed leaf is good for. Short: a leaf key that leaks is worth
/// at most this long, and the proxy re-mints on expiry with no operator step.
pub const LEAF_TTL: time::Duration = time::Duration::hours(24);

/// How far into the past a leaf is valid from. A guest resumed from a
/// snapshot keeps the wall clock it was baked with until something in it
/// sets the time, so a leaf minted "now" would be not-yet-valid to any guest
/// whose template is older than the skew allowed here. Back-dating costs
/// nothing: the leaf is ours, and its expiry is what bounds exposure.
pub const LEAF_BACKDATE: time::Duration = time::Duration::days(30);

/// The RPC method name, over both transports.
pub const METHOD: &str = "sign";

/// Request to sign a leaf CSR (PEM).
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub domain: String,
    pub csr_pem: String,
}

/// Signed chain (leaf first, then CA), each entry base64 (DER). An empty
/// chain means the CA refused; the proxy fails closed on it.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SignResponse {
    pub chain_der_b64: Vec<String>,
    /// When the leaf expires, seconds since the Unix epoch. Absent from a CA
    /// that predates expiry; callers treat that as "soon".
    #[serde(default)]
    pub not_after: Option<u64>,
}

/// A signed leaf, in memory.
pub struct Signed {
    /// Leaf DER first, then the CA DER.
    pub chain_der: Vec<Vec<u8>>,
    pub not_after: u64,
}

/// A loaded certificate authority.
pub struct Ca {
    // A self-signed cert rebuilt from the stored CA params: only its `params`
    // (issuer DN, key-id method, key usages) are read by `signed_by`. The chain
    // we actually serve uses the *stored* CA DER below, which the VM trusts.
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert_der: Vec<u8>,
}

impl Ca {
    /// Load `dir/ca.crt` + `dir/ca.key`, generating a fresh CA if either is absent.
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let crt = dir.join("ca.crt");
        let key = dir.join("ca.key");
        if !crt.exists() || !key.exists() {
            let (cert_pem, key_pem) = generate()?;
            std::fs::write(&crt, &cert_pem)?;
            write_private(&key, key_pem.as_bytes())?;
        }
        let cert_pem = std::fs::read_to_string(&crt)?;
        let key_pem = std::fs::read_to_string(&key)?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Build from in-memory PEM (cert + key).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let ca_key = KeyPair::from_pem(key_pem)?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem)?;
        let ca_cert = params.self_signed(&ca_key)?;
        let ca_cert_der = pem_to_der(cert_pem)?;
        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_der,
        })
    }

    /// CA certificate in DER.
    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// Sign a leaf CSR (PEM) for [`LEAF_TTL`]. Returns the chain (leaf DER
    /// first, then CA DER) and the leaf's expiry.
    pub fn sign(&self, csr_pem: &str) -> Result<Signed> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
        let now = time::OffsetDateTime::now_utc();
        let not_after = now + LEAF_TTL;
        csr.params.not_before = now - LEAF_BACKDATE;
        csr.params.not_after = not_after;
        let leaf = csr.signed_by(&self.ca_cert, &self.ca_key)?;
        Ok(Signed {
            chain_der: vec![leaf.der().to_vec(), self.ca_cert_der.clone()],
            not_after: not_after.unix_timestamp().max(0) as u64,
        })
    }

    /// The RPC handler: a JSON [`SignRequest`] in, a JSON [`SignResponse`] out.
    /// Any failure answers with an empty chain, which the proxy treats as a
    /// refusal (fail-closed).
    pub fn handle(&self, body: &[u8]) -> Vec<u8> {
        let out = (|| -> std::result::Result<SignResponse, String> {
            let req: SignRequest = serde_json::from_slice(body).map_err(|e| e.to_string())?;
            let signed = self.sign(&req.csr_pem).map_err(|e| e.to_string())?;
            Ok(SignResponse {
                chain_der_b64: signed
                    .chain_der
                    .iter()
                    .map(|d| base64::engine::general_purpose::STANDARD.encode(d))
                    .collect(),
                not_after: Some(signed.not_after),
            })
        })();
        match out {
            Ok(resp) => serde_json::to_vec(&resp).unwrap_or_default(),
            Err(e) => {
                tracing::error!("iso-ca sign failed: {e}");
                serde_json::to_vec(&SignResponse::default()).unwrap_or_default()
            }
        }
    }
}

/// Generate a fresh CA, returning `(cert_pem, key_pem)`.
fn generate() -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "iso egress proxy CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// Serve the CertAuthority RPC on a Unix socket (one request per connection,
/// JSON, half-close delimited). Runs until the listener errors.
pub async fn serve_unix(ca: Arc<Ca>, sock: &Path) -> std::io::Result<()> {
    iso_rpc::serve_unix(
        sock,
        METHOD,
        Arc::new(move |_m: &str, body: Vec<u8>| {
            let ca = ca.clone();
            async move { ca.handle(&body) }
        }),
    )
    .await
}

/// Serve the CertAuthority RPC over HTTPS with mutual TLS: `POST /sign`.
pub async fn serve_https(
    ca: Arc<Ca>,
    listener: tokio::net::TcpListener,
    cfg: Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
    iso_rpc::serve_https(
        listener,
        cfg,
        Arc::new(move |m: &str, body: Vec<u8>| {
            let ca = ca.clone();
            let ok = m == METHOD;
            async move {
                if ok {
                    ca.handle(&body)
                } else {
                    serde_json::to_vec(&SignResponse::default()).unwrap_or_default()
                }
            }
        }),
    )
    .await
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| Error::Pem(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A leaf CSR for `domain`, plus its (discarded here) private key.
    fn csr_for(domain: &str) -> String {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    #[test]
    fn signs_csr_under_ca_with_a_short_lifetime() {
        let dir = tempdir();
        let ca = Ca::load_or_generate(&dir).unwrap();
        let signed = ca.sign(&csr_for("api.anthropic.com")).unwrap();
        assert_eq!(signed.chain_der.len(), 2);

        // leaf parses, carries the SAN, is issued by our CA, and expires soon.
        let (_, leaf) = x509_parser::parse_x509_certificate(&signed.chain_der[0]).unwrap();
        let (_, ca_x) = x509_parser::parse_x509_certificate(&signed.chain_der[1]).unwrap();
        assert_eq!(leaf.issuer(), ca_x.subject());
        let sans: Vec<_> = leaf
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                x509_parser::extensions::GeneralName::DNSName(d) => Some(*d),
                _ => None,
            })
            .collect();
        assert!(sans.contains(&"api.anthropic.com"));
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        assert!(signed.not_after > now + 23 * 3600 && signed.not_after <= now + 24 * 3600 + 5);
        assert_eq!(
            leaf.validity().not_after.timestamp() as u64,
            signed.not_after
        );
        // Valid to a guest whose clock froze at bake time weeks ago.
        let not_before = leaf.validity().not_before.timestamp() as u64;
        assert!(not_before <= now - 29 * 86_400, "leaf is not back-dated");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handler_reports_expiry_and_refuses_garbage() {
        let dir = tempdir();
        let ca = Ca::load_or_generate(&dir).unwrap();
        let req = serde_json::to_vec(&SignRequest {
            domain: "x.test".into(),
            csr_pem: csr_for("x.test"),
        })
        .unwrap();
        let resp: SignResponse = serde_json::from_slice(&ca.handle(&req)).unwrap();
        assert_eq!(resp.chain_der_b64.len(), 2);
        assert!(resp.not_after.is_some());
        let bad: SignResponse = serde_json::from_slice(&ca.handle(b"nonsense")).unwrap();
        assert!(bad.chain_der_b64.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("iso-ca-test-{}-{}", std::process::id(), rand()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }
    fn rand() -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut h);
        h.finish()
    }
}
