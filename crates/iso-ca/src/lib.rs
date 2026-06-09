//! iso-ca — the egress proxy's certificate authority (sign-only minter).
//!
//! Holds the CA private key in its own process and only ever **signs** leaf CSRs
//! the proxy submits — the proxy generates the disposable leaf key, the CA key
//! never crosses the RPC boundary. See `iso-proxy/DESIGN.md`.

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams, DnType, IsCa,
    KeyPair, KeyUsagePurpose,
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

/// Request to sign a leaf CSR (PEM).
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub domain: String,
    pub csr_pem: String,
}

/// Signed chain (leaf first, then CA), each entry base64 (DER).
#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub chain_der_b64: Vec<String>,
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
            std::fs::write(&key, &key_pem)?;
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

    /// Sign a leaf CSR (PEM). Returns the chain (leaf DER first, then CA DER).
    pub fn sign(&self, csr_pem: &str) -> Result<Vec<Vec<u8>>> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
        let leaf = csr.signed_by(&self.ca_cert, &self.ca_key)?;
        Ok(vec![leaf.der().to_vec(), self.ca_cert_der.clone()])
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

/// Serve the CertAuthority RPC on `sock` (one request/response per connection,
/// JSON, half-close delimited). Runs until the listener errors.
pub async fn serve_unix(ca: Arc<Ca>, sock: &Path) -> std::io::Result<()> {
    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock)?;
    loop {
        let (mut conn, _) = listener.accept().await?;
        let ca = ca.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            if conn.read_to_end(&mut buf).await.is_err() {
                return;
            }
            let resp = handle(&ca, &buf);
            let _ = conn.write_all(&resp).await;
            let _ = conn.shutdown().await;
        });
    }
}

fn handle(ca: &Ca, req: &[u8]) -> Vec<u8> {
    let out = (|| -> std::result::Result<SignResponse, String> {
        let req: SignRequest = serde_json::from_slice(req).map_err(|e| e.to_string())?;
        let chain = ca.sign(&req.csr_pem).map_err(|e| e.to_string())?;
        let chain_der_b64 = chain
            .iter()
            .map(|d| base64::engine::general_purpose::STANDARD.encode(d))
            .collect();
        Ok(SignResponse { chain_der_b64 })
    })();
    match out {
        Ok(resp) => serde_json::to_vec(&resp).unwrap_or_default(),
        Err(e) => {
            tracing::error!("iso-ca sign failed: {e}");
            // Empty chain signals failure (proxy fails closed on certs).
            serde_json::to_vec(&SignResponse {
                chain_der_b64: Vec::new(),
            })
            .unwrap_or_default()
        }
    }
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
    fn signs_csr_under_ca() {
        let dir = tempdir();
        let ca = Ca::load_or_generate(&dir).unwrap();
        let chain = ca.sign(&csr_for("api.anthropic.com")).unwrap();
        assert_eq!(chain.len(), 2);

        // leaf parses, carries the SAN, and is issued by our CA.
        let (_, leaf) = x509_parser::parse_x509_certificate(&chain[0]).unwrap();
        let (_, ca_x) = x509_parser::parse_x509_certificate(&chain[1]).unwrap();
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
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("iso-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }
}
