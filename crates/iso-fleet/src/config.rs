//! `iso-fleetd` configuration: a TOML file.
//!
//! ```toml
//! listen = "0.0.0.0:7080"
//! db = "/var/lib/iso-fleet/fleet.db"
//! pki_dir = "/var/lib/iso-fleet/pki"     # the fleet's own admin CA for API clients,
//!                                        # and its policy signing key (policy-signing.pkcs8 / .pub)
//! sync_every_ms = 3000
//! create_grace_secs = 60
//! policy_ttl_secs = 86400                # how long a signed policy is good for; re-signed at a third left
//!
//! [hosts_tls]                            # the identity the fleet presents to hosts:
//! ca = "/etc/iso-fleet/hosts/ca.crt"     # one admin CA shared by every host
//! cert = "/etc/iso-fleet/hosts/fleet.crt"
//! key = "/etc/iso-fleet/hosts/fleet.key"
//!
//! [[hosts]]
//! name = "hostA"
//! url = "https://10.0.0.5:7070"
//! [[hosts]]
//! name = "hostB"
//! url = "https://10.0.0.6:7070"
//! ```
//!
//! `insecure = true` serves plain HTTP and speaks plain HTTP to hosts, for
//! development and tests only.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_db")]
    pub db: PathBuf,
    /// Plain HTTP in and out. Never in production.
    #[serde(default)]
    pub insecure: bool,
    /// The fleet's own CA: server certificate for `listen`, client
    /// certificates minted with `isoctl admin --pki-dir <pki_dir> issue-client`.
    #[serde(default = "default_pki")]
    pub pki_dir: PathBuf,
    /// Extra names for the server certificate.
    #[serde(default)]
    pub extra_sans: Vec<String>,
    #[serde(default = "default_sync")]
    pub sync_every_ms: u64,
    /// How long a VM may sit in `creating` without the host knowing it before
    /// it is written off as failed.
    #[serde(default = "default_grace")]
    pub create_grace_secs: u64,
    /// How long a policy the fleet signs stays valid at the proxy tier. The
    /// sync loop re-signs a VM's policy when a third of this is left, so a
    /// running VM never lapses; a host that stops hearing from the fleet
    /// loses its ability to present policies after this long.
    #[serde(default = "default_policy_ttl")]
    pub policy_ttl_secs: u64,
    /// The identity presented to hosts.
    #[serde(default)]
    pub hosts_tls: Option<TlsFiles>,
    #[serde(default)]
    pub hosts: Vec<HostConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HostConfig {
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsFiles {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:7080".parse().unwrap()
}
fn default_db() -> PathBuf {
    PathBuf::from("/var/lib/iso-fleet/fleet.db")
}
fn default_pki() -> PathBuf {
    PathBuf::from("/var/lib/iso-fleet/pki")
}
fn default_sync() -> u64 {
    3000
}
fn default_grace() -> u64 {
    60
}
fn default_policy_ttl() -> u64 {
    86_400
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if cfg.hosts.is_empty() {
            return Err("no [[hosts]] configured".into());
        }
        if !cfg.insecure && cfg.hosts_tls.is_none() {
            return Err("[hosts_tls] is required unless insecure = true".into());
        }
        Ok(cfg)
    }

    /// A configuration for tests: plain HTTP, an in-memory database, a
    /// signing key in a fresh temporary directory.
    pub fn dev(hosts: Vec<HostConfig>) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let pki_dir = std::env::temp_dir().join(format!(
            "iso-fleet-dev-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        Self {
            listen: "127.0.0.1:0".parse().unwrap(),
            db: PathBuf::from(":memory:"),
            insecure: true,
            pki_dir,
            extra_sans: Vec::new(),
            sync_every_ms: 100,
            create_grace_secs: 2,
            policy_ttl_secs: 86_400,
            hosts_tls: None,
            hosts,
        }
    }
}
