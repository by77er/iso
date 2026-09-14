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
//!
//! A host in a fleet does not hold the CA key at all: the control host mints
//! its identity (`isoctl admin issue-server`) and the host loads `ca.crt`,
//! `server.crt` and `server.key` with no `ca.key` beside them. Such a host
//! can present its identity and verify clients but can issue nothing, which
//! is the point: a compromised host cannot mint a credential the other
//! services would accept.

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
    #[error("{0}")]
    NoCaKey(String),
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
/// `ca.crt`, `ca.key`, `server.crt`, `server.key` (keys are mode 0600). With
/// `ca.crt` but no `ca.key`, the identity was issued elsewhere and this
/// process can verify and present but not issue.
pub struct AdminPki {
    dir: PathBuf,
    /// The issuer, when the key is here.
    signer: Option<(Certificate, KeyPair)>,
    ca_cert_pem: String,
}

impl AdminPki {
    /// Load the CA from `dir`, generating a fresh one if it is absent. The
    /// server certificate is (re)issued whenever it is missing or `server_sans`
    /// names something the existing one does not cover.
    ///
    /// A directory holding `ca.crt` without `ca.key` is an identity issued
    /// elsewhere: `server.crt` and `server.key` must be there. Names in
    /// `server_sans` the certificate does not carry cannot be added here;
    /// [`Self::uncovered_server_sans`] says which, for the caller to report.
    pub fn load_or_generate(dir: &Path, server_sans: &[String]) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        let ca_crt = dir.join("ca.crt");
        let ca_key = dir.join("ca.key");
        if ca_crt.exists() && !ca_key.exists() {
            return Self::load_issued_elsewhere(dir, server_sans);
        }
        if !ca_crt.exists() {
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
        let pki = Self { dir: dir.to_path_buf(), signer: Some((ca_cert, ca_key)), ca_cert_pem };

        let server_crt = dir.join("server.crt");
        let server_key = dir.join("server.key");
        let stale = match std::fs::read_to_string(&server_crt) {
            Ok(pem) => !sans_covered(&pem, server_sans),
            Err(_) => true,
        };
        if stale || !server_key.exists() {
            let id = pki.issue("iso-controld", server_sans, &[ExtendedKeyUsagePurpose::ServerAuth])?;
            write_private(&server_key, id.key_pem.as_bytes())?;
            std::fs::write(&server_crt, id.cert_pem)?;
        }
        Ok(pki)
    }

    fn load_issued_elsewhere(dir: &Path, server_sans: &[String]) -> Result<Self> {
        let ca_cert_pem = std::fs::read_to_string(dir.join("ca.crt"))?;
        let server_crt = dir.join("server.crt");
        let server_key = dir.join("server.key");
        let how = "issue one on the control host with `isoctl admin issue-server --name <host> --san <ip>` \
                   and install it as server.crt and server.key, or add ca.key to let this host issue its own";
        std::fs::read_to_string(&server_crt).map_err(|e| {
            Error::NoCaKey(format!("{}: {e}; this host has no ca.key, so {how}", server_crt.display()))
        })?;
        if !server_key.exists() {
            return Err(Error::NoCaKey(format!("{} is missing; {how}", server_key.display())));
        }
        let _ = server_sans;
        Ok(Self { dir: dir.to_path_buf(), signer: None, ca_cert_pem })
    }

    /// The names in `wanted` the stored server certificate does not carry.
    /// Empty after a load that could reissue; for an identity issued
    /// elsewhere, what the issuer left out, which clients cannot dial by.
    pub fn uncovered_server_sans(&self, wanted: &[String]) -> Vec<String> {
        let Ok(pem) = std::fs::read_to_string(self.dir.join("server.crt")) else {
            return wanted.to_vec();
        };
        wanted
            .iter()
            .filter(|w| !sans_covered(&pem, std::slice::from_ref(w)))
            .cloned()
            .collect()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether the CA key is here, so certificates can be issued.
    pub fn can_issue(&self) -> bool {
        self.signer.is_some()
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
        check_name(name)?;
        self.issue(name, &[], &[ExtendedKeyUsagePurpose::ClientAuth])
    }

    /// Mint a service identity: a certificate good as a TLS **server** for
    /// `sans` and as a TLS **client** to the other services. One identity per
    /// process is enough: a proxy replica presents it to edges and to the CA
    /// and secrets services alike.
    pub fn issue_server(&self, name: &str, sans: &[String]) -> Result<Identity> {
        check_name(name)?;
        self.issue(
            name,
            sans,
            &[ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
        )
    }

    fn issue(&self, cn: &str, sans: &[String], eku: &[ExtendedKeyUsagePurpose]) -> Result<Identity> {
        let Some((ca_cert, ca_key)) = &self.signer else {
            return Err(Error::NoCaKey(format!(
                "cannot issue {cn:?}: {} holds no ca.key (this identity was issued elsewhere)",
                self.dir.display()
            )));
        };
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = eku.to_vec();
        params.subject_alt_names = sans.iter().map(|s| san(s)).collect::<Result<Vec<_>>>()?;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(LEAF_DAYS);
        let cert = params.signed_by(&key, ca_cert, ca_key)?;
        Ok(Identity { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
    }
}

/// The common name of the first certificate a TLS peer presented: the name
/// an identity was issued under. `None` when there is no certificate or it
/// carries no common name.
pub fn peer_common_name(chain: &[CertificateDer<'_>]) -> Option<String> {
    let leaf = chain.first()?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}

fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@')) {
        return Err(Error::Name(name.into(), "use letters, digits, '-', '_', '.', '@'".into()));
    }
    Ok(())
}

/// The CA to trust plus the identity to present: what a service loads from
/// disk to talk mutual TLS with the others. Written by `isoctl admin
/// issue-server --out DIR` as `ca.crt`, `<name>.crt` and `<name>.key`.
#[derive(Clone, Debug)]
pub struct Creds {
    pub ca_pem: String,
    pub identity: Identity,
}

impl Creds {
    pub fn from_dir(dir: &Path, name: &str) -> Result<Self> {
        Ok(Self {
            ca_pem: std::fs::read_to_string(dir.join("ca.crt"))?,
            identity: Identity {
                cert_pem: std::fs::read_to_string(dir.join(format!("{name}.crt")))?,
                key_pem: std::fs::read_to_string(dir.join(format!("{name}.key")))?,
            },
        })
    }

    /// From three files.
    pub fn from_files(ca: &Path, cert: &Path, key: &Path) -> Result<Self> {
        Ok(Self {
            ca_pem: std::fs::read_to_string(ca)?,
            identity: Identity {
                cert_pem: std::fs::read_to_string(cert)?,
                key_pem: std::fs::read_to_string(key)?,
            },
        })
    }

    /// From `ISO_TLS_CA`, `ISO_TLS_CERT`, `ISO_TLS_KEY` (file paths). `None`
    /// when none of the three is set; an error when only some are.
    pub fn from_env() -> Result<Option<Self>> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        match (get("ISO_TLS_CA"), get("ISO_TLS_CERT"), get("ISO_TLS_KEY")) {
            (None, None, None) => Ok(None),
            (Some(ca), Some(cert), Some(key)) => {
                Self::from_files(Path::new(&ca), Path::new(&cert), Path::new(&key)).map(Some)
            }
            _ => Err(Error::Pem("set all of ISO_TLS_CA, ISO_TLS_CERT and ISO_TLS_KEY, or none".into())),
        }
    }

    /// A rustls server config that presents this identity and requires a
    /// client certificate from the CA.
    pub fn server_config(&self) -> Result<std::sync::Arc<rustls::ServerConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(pem_to_der(&self.ca_pem)?)).map_err(|e| Error::Pem(e.to_string()))?;
        let verifier = rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(roots))
            .build()
            .map_err(|e| Error::Pem(e.to_string()))?;
        let cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![self.identity.cert_der()?], self.identity.key_der()?)
            .map_err(|e| Error::Pem(e.to_string()))?;
        Ok(std::sync::Arc::new(cfg))
    }

    /// A rustls client config that trusts only the CA and presents this
    /// identity.
    pub fn client_config(&self) -> Result<std::sync::Arc<rustls::ClientConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(pem_to_der(&self.ca_pem)?)).map_err(|e| Error::Pem(e.to_string()))?;
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![self.identity.cert_der()?], self.identity.key_der()?)
            .map_err(|e| Error::Pem(e.to_string()))?;
        Ok(std::sync::Arc::new(cfg))
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
    fn an_identity_issued_elsewhere_loads_without_the_ca_key_and_cannot_issue() {
        let control = tempdir();
        let issuer = AdminPki::load_or_generate(&control, &["localhost".into()]).unwrap();
        let id = issuer.issue_server("host-a", &["10.0.0.4".into()]).unwrap();

        let host = tempdir();
        std::fs::create_dir_all(&host).unwrap();
        std::fs::write(host.join("ca.crt"), issuer.ca_cert_pem()).unwrap();
        std::fs::write(host.join("server.crt"), &id.cert_pem).unwrap();
        std::fs::write(host.join("server.key"), &id.key_pem).unwrap();

        let pki = AdminPki::load_or_generate(&host, &["10.0.0.4".into()]).unwrap();
        assert!(!pki.can_issue());
        assert_eq!(pki.ca_cert_pem(), issuer.ca_cert_pem());
        assert_eq!(pki.server_identity().unwrap().cert_pem, id.cert_pem, "kept as issued");
        let err = pki.issue_client("anyone").unwrap_err().to_string();
        assert!(err.contains("no ca.key"), "{err}");
        assert!(!host.join("ca.key").exists());

        // A name the issued certificate does not carry cannot be added here;
        // the load says which so the daemon can warn.
        let pki = AdminPki::load_or_generate(&host, &["10.0.0.4".into(), "10.9.9.9".into()]).unwrap();
        assert_eq!(pki.uncovered_server_sans(&["10.0.0.4".into(), "10.9.9.9".into()]), vec!["10.9.9.9".to_string()]);
        assert!(issuer.uncovered_server_sans(&["localhost".into()]).is_empty());

        // Without a server identity at all there is nothing to serve.
        let bare = tempdir();
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::write(bare.join("ca.crt"), issuer.ca_cert_pem()).unwrap();
        let err = AdminPki::load_or_generate(&bare, &[]).err().expect("nothing to serve").to_string();
        assert!(err.contains("server.crt"), "{err}");
        let _ = std::fs::remove_dir_all(&control);
        let _ = std::fs::remove_dir_all(&host);
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[test]
    fn peer_common_name_reads_the_name_an_identity_was_issued_under() {
        let dir = tempdir();
        let pki = AdminPki::load_or_generate(&dir, &["localhost".into()]).unwrap();
        let client = pki.issue_client("fleet").unwrap();
        let der = client.cert_der().unwrap();
        assert_eq!(peer_common_name(&[der]).as_deref(), Some("fleet"));
        let server = pki.issue_server("control", &["10.0.0.2".into()]).unwrap();
        assert_eq!(peer_common_name(&[server.cert_der().unwrap()]).as_deref(), Some("control"));
        assert_eq!(peer_common_name(&[]), None);
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
