//! iso-client — a Rust client for the iso admin API.
//!
//! Everything under [`types`] and the [`Client`] itself are generated from the
//! daemon's OpenAPI document by [progenitor](https://github.com/oxidecomputer/progenitor)
//! (`scripts/gen-client.sh`); the daemon has a test that fails when the
//! checked-in document drifts from its code. This file adds what the generator
//! cannot know: how to authenticate.
//!
//! The daemon's TCP listener speaks mutual TLS with a CA of its own. A client
//! needs that CA certificate and a client identity issued by it, both written
//! by `isoctl admin issue-client --name NAME --out DIR` as `ca.crt`, `NAME.crt`
//! and `NAME.key`.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let client = iso_client::Client::connect(
//!     "https://10.0.0.5:7070",
//!     &iso_client::Credentials::from_dir("./creds", "orchestrator")?,
//! )?;
//! let vms = client.list().send().await?;
//! println!("{} vms", vms.len());
//! # Ok(()) }
//! ```

mod generated;

pub use generated::*;

use std::path::{Path, PathBuf};

/// The CA to trust and the identity to present, as PEM.
#[derive(Clone, Debug)]
pub struct Credentials {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// A configuration problem, as opposed to an API error.
#[derive(Debug)]
pub enum SetupError {
    Io(PathBuf, std::io::Error),
    Env(&'static str),
    Tls(String),
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetupError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            SetupError::Env(v) => write!(f, "{v} is not set"),
            SetupError::Tls(m) => write!(f, "tls: {m}"),
        }
    }
}

impl std::error::Error for SetupError {}

fn read(path: &Path) -> Result<String, SetupError> {
    std::fs::read_to_string(path).map_err(|e| SetupError::Io(path.to_path_buf(), e))
}

impl Credentials {
    /// `ca.crt`, `<name>.crt` and `<name>.key` from `dir`, as `isoctl admin
    /// issue-client --out dir` writes them.
    pub fn from_dir(dir: impl AsRef<Path>, name: &str) -> Result<Self, SetupError> {
        let dir = dir.as_ref();
        Ok(Self {
            ca_pem: read(&dir.join("ca.crt"))?,
            cert_pem: read(&dir.join(format!("{name}.crt")))?,
            key_pem: read(&dir.join(format!("{name}.key")))?,
        })
    }

    /// Three explicit files.
    pub fn from_files(ca: impl AsRef<Path>, cert: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<Self, SetupError> {
        Ok(Self {
            ca_pem: read(ca.as_ref())?,
            cert_pem: read(cert.as_ref())?,
            key_pem: read(key.as_ref())?,
        })
    }

    /// From `ISO_CA`, `ISO_CLIENT_CERT` and `ISO_CLIENT_KEY` (file paths).
    pub fn from_env() -> Result<Self, SetupError> {
        let var = |k: &'static str| std::env::var(k).map_err(|_| SetupError::Env(k));
        Self::from_files(var("ISO_CA")?, var("ISO_CLIENT_CERT")?, var("ISO_CLIENT_KEY")?)
    }
}

impl Client {
    /// A client for `base_url` (e.g. `https://10.0.0.5:7070`) that trusts only
    /// the admin CA in `creds` and presents its identity.
    pub fn connect(base_url: &str, creds: &Credentials) -> Result<Self, SetupError> {
        // reqwest is built without a provider so it does not drag in aws-lc;
        // ring is what the rest of iso uses. Installing twice is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = reqwest::Certificate::from_pem(creds.ca_pem.as_bytes()).map_err(|e| SetupError::Tls(e.to_string()))?;
        let pem = format!("{}{}", creds.cert_pem, creds.key_pem);
        let identity = reqwest::Identity::from_pem(pem.as_bytes()).map_err(|e| SetupError::Tls(e.to_string()))?;
        let http = reqwest::Client::builder()
            // Trust the admin CA and nothing else.
            .tls_certs_only([ca])
            .identity(identity)
            .build()
            .map_err(|e| SetupError::Tls(e.to_string()))?;
        Ok(Self::new_with_client(base_url.trim_end_matches('/'), http))
    }

    /// A client for a daemon started with `ISO_ADMIN_INSECURE=1`, or for
    /// anything else that already speaks plain HTTP to it.
    pub fn insecure(base_url: &str) -> Self {
        Self::new(base_url.trim_end_matches('/'))
    }
}
