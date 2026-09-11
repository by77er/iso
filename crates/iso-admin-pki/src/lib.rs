//! iso-admin-pki — mutual TLS for the admin API, with a CA of its own.
//!
//! One CA per host, generated on first use under the daemon's state
//! directory. It signs the daemon's server certificate and every client
//! certificate an operator mints with `isoctl admin issue-client`. A client
//! that presents a certificate chaining to this CA is an administrator; there
//! is no finer authorization and no revocation short of replacing the CA.
//!
//! This is deliberately **not** the egress proxy's CA (`iso-ca`). That one
//! is trusted by guests and terminates hostile traffic; sharing a trust root
//! with it would hand a compromised proxy admin credentials.

use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("pem: {0}")]
    Pem(String),
    #[error("invalid name {0:?}: {1}")]
    Name(String, String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// How long the CA and the certificates it issues are good for. Long, on
/// purpose: rotation is "delete the directory and re-issue", and a host's
/// admin API is not a public endpoint.
const CA_DAYS: i64 = 365 * 10;
const LEAF_DAYS: i64 = 365 * 2;

/// A PEM certificate and private key pair.
#[derive(Clone, Debug)]
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
}

impl Identity {
    /// The certificate in DER, for a rustls config.
    pub fn cert_der(&self) -> Result<CertificateDer<'static>> {
        Ok(CertificateDer::from(pem_to_der(&self.cert_pem)?))
    }
    /// The key in DER (PKCS#8), for a rustls config.
    pub fn key_der(&self) -> Result<PrivateKeyDer<'static>> {
        Ok(PrivateKeyDer::Pkcs8(pem_to_der(&self.key_pem)?.into()))
    }
}

/// The admin CA plus this host's server identity, on disk under one directory:
/// `ca.crt`, `ca.key`, `server.crt`, `server.key` (keys are mode 0600).
pub struct AdminPki {
    dir: PathBuf,
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert_pem: String,
}

impl AdminPki {
    /// Load the CA from `dir`, generating a fresh one if it is absent. The
    /// server certificate is (re)issued whenever it is missing or `server_sans`
    /// names something the existing one does not cover.
    pub fn load_or_generate(dir: &Path, server_sans: &[String]) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        let ca_crt = dir.join("ca.crt");
        let ca_key = dir.join("ca.key");
        if !ca_crt.exists() || !ca_key.exists() {
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params.distinguished_name.push(DnType::CommonName, "iso admin CA");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::hours(1);
            params.not_after = now + time::Duration::days(CA_DAYS);
            let cert = params.self_signed(&key)?;
            write_private(&ca_key, key.serialize_pem().as_bytes())?;
            std::fs::write(&ca_crt, cert.pem())?;
        }
        let ca_cert_pem = std::fs::read_to_string(&ca_crt)?;
        let ca_key = KeyPair::from_pem(&std::fs::read_to_string(&ca_key)?)?;
        // Rebuild the issuer from the stored params; only its DN and key ids are
        // read when signing, the served chain uses the stored PEM.
        let ca_cert = CertificateParams::from_ca_cert_pem(&ca_cert_pem)?.self_signed(&ca_key)?;
        let pki = Self { dir: dir.to_path_buf(), ca_cert, ca_key, ca_cert_pem };

        let server_crt = dir.join("server.crt");
        let server_key = dir.join("server.key");
        let stale = match std::fs::read_to_string(&server_crt) {
            Ok(pem) => !sans_covered(&pem, server_sans),
            Err(_) => true,
        };
        if stale || !server_key.exists() {
            let id = pki.issue("iso-controld", server_sans, ExtendedKeyUsagePurpose::ServerAuth)?;
            write_private(&server_key, id.key_pem.as_bytes())?;
            std::fs::write(&server_crt, id.cert_pem)?;
        }
        Ok(pki)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The CA certificate, PEM. Clients pin this.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_cert_der(&self) -> Result<CertificateDer<'static>> {
        Ok(CertificateDer::from(pem_to_der(&self.ca_cert_pem)?))
    }

    /// This host's server identity, as stored.
    pub fn server_identity(&self) -> Result<Identity> {
        Ok(Identity {
            cert_pem: std::fs::read_to_string(self.dir.join("server.crt"))?,
            key_pem: std::fs::read_to_string(self.dir.join("server.key"))?,
        })
    }

    /// Mint a client certificate whose common name is `name`. The key never
    /// touches disk here; the caller decides where it goes.
    pub fn issue_client(&self, name: &str) -> Result<Identity> {
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@')) {
            return Err(Error::Name(name.into(), "use letters, digits, '-', '_', '.', '@'".into()));
        }
        self.issue(name, &[], ExtendedKeyUsagePurpose::ClientAuth)
    }

    fn issue(&self, cn: &str, sans: &[String], eku: ExtendedKeyUsagePurpose) -> Result<Identity> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![eku];
        params.subject_alt_names = sans.iter().map(|s| san(s)).collect::<Result<Vec<_>>>()?;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(LEAF_DAYS);
        let cert = params.signed_by(&key, &self.ca_cert, &self.ca_key)?;
        Ok(Identity { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
    }
}

fn san(s: &str) -> Result<SanType> {
    Ok(match s.parse::<IpAddr>() {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => SanType::DnsName(s.try_into().map_err(|e: rcgen::Error| Error::Name(s.into(), e.to_string()))?),
    })
}

/// Whether a stored server certificate already names every SAN we want. The
/// PEM is parsed back through rcgen, which keeps the SAN list on its params.
fn sans_covered(cert_pem: &str, wanted: &[String]) -> bool {
    let Ok(params) = CertificateParams::from_ca_cert_pem(cert_pem) else {
        return false;
    };
    let have: Vec<String> = params
        .subject_alt_names
        .iter()
        .map(|s| match s {
            SanType::DnsName(d) => d.as_str().to_string(),
            SanType::IpAddress(ip) => ip.to_string(),
            other => format!("{other:?}"),
        })
        .collect();
    wanted.iter().all(|w| have.contains(w))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// Strip PEM armor and decode the base64 body of the first block.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN") {
            inside = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if inside {
            body.push_str(line.trim());
        }
    }
    if body.is_empty() {
        return Err(Error::Pem("no PEM block found".into()));
    }
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| Error::Pem(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!("iso-admin-pki-{}-{}", std::process::id(), rand_suffix()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }
    fn rand_suffix() -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut h);
        h.finish()
    }

    #[test]
    fn generates_once_and_reloads() {
        let dir = tempdir();
        let sans = vec!["localhost".to_string(), "10.0.0.5".to_string()];
        let a = AdminPki::load_or_generate(&dir, &sans).unwrap();
        let b = AdminPki::load_or_generate(&dir, &sans).unwrap();
        assert_eq!(a.ca_cert_pem(), b.ca_cert_pem(), "same CA on reload");
        let s1 = a.server_identity().unwrap();
        let s2 = b.server_identity().unwrap();
        assert_eq!(s1.cert_pem, s2.cert_pem, "server cert kept when SANs are covered");
        assert_eq!(std::fs::metadata(dir.join("ca.key")).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_san_reissues_the_server_cert() {
        let dir = tempdir();
        let a = AdminPki::load_or_generate(&dir, &["localhost".into()]).unwrap();
        let first = a.server_identity().unwrap().cert_pem;
        let b = AdminPki::load_or_generate(&dir, &["localhost".into(), "192.168.1.9".into()]).unwrap();
        let second = b.server_identity().unwrap().cert_pem;
        assert_ne!(first, second);
        assert!(sans_covered(&second, &["192.168.1.9".into(), "localhost".into()]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn client_certs_chain_to_the_ca_and_are_client_auth() {
        let dir = tempdir();
        let pki = AdminPki::load_or_generate(&dir, &["localhost".into()]).unwrap();
        let id = pki.issue_client("orchestrator").unwrap();
        let der = id.cert_der().unwrap();
        let params = CertificateParams::from_ca_cert_pem(&id.cert_pem).unwrap();
        assert_eq!(params.extended_key_usages, vec![ExtendedKeyUsagePurpose::ClientAuth]);
        assert!(!der.is_empty());
        assert!(id.key_der().is_ok());
        assert!(pki.issue_client("bad name!").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
