//! iso-fleet — one API over many iso hosts.
//!
//! A client asks for a VM and gets one somewhere; from then on it names the
//! VM by id and never a host. `iso-fleetd` picks the host, remembers the
//! choice in a database, routes every later call to that host's admin API,
//! and keeps its record honest with a sync loop. Hosts run `iso-controld`
//! unchanged; adding capacity is adding a host to the config.
//!
//! The fleet API is the host API minus the host, so `isoctl vm`, the pi
//! extension and the generated client work against it by changing a URL.
//!
//! The fleet also signs every policy it places or changes (see
//! [`iso_policy::signed`]): the host stores the signature, the edge relays
//! it, and a proxy tier verifies it against the fleet's public key
//! (`<pki_dir>/policy-signing.pub`) before it trusts a word the host says
//! about a VM.

pub mod api;
pub mod config;
pub mod hosts;
pub mod placement;
pub mod store;
pub mod sync;
pub mod tls;

use std::collections::HashMap;
use std::sync::Arc;

pub use config::{Config, HostConfig};
use hosts::HostClient;
use store::Store;

pub struct Fleet {
    pub cfg: Config,
    pub store: Store,
    pub hosts: HashMap<String, HostClient>,
    /// The policy signing key, from `<pki_dir>/policy-signing.pkcs8`.
    pub signer: iso_policy::signed::Signer,
    /// The public half, to recognise this fleet's own signatures.
    pub verifier: iso_policy::signed::Verifier,
}

impl Fleet {
    pub fn new(cfg: Config) -> Result<Arc<Self>, String> {
        let store = Store::open(&cfg.db).map_err(|e| format!("open {}: {e}", cfg.db.display()))?;
        let mut hosts = HashMap::new();
        for h in &cfg.hosts {
            store
                .upsert_host(&h.name, &h.url)
                .map_err(|e| e.to_string())?;
            hosts.insert(h.name.clone(), HostClient::new(h, cfg.hosts_tls.as_ref())?);
        }
        let names: Vec<String> = cfg.hosts.iter().map(|h| h.name.clone()).collect();
        store.retain_hosts(&names).map_err(|e| e.to_string())?;
        let signer = load_or_generate_signer(&cfg.pki_dir)?;
        let verifier = iso_policy::signed::Verifier::from_b64(&signer.public_key_b64()).map_err(|e| e.to_string())?;
        Ok(Arc::new(Self { cfg, store, hosts, signer, verifier }))
    }

    /// The claims this fleet signed on a host's record of a VM, if the record
    /// carries a signature and it is this fleet's. Expiry is not checked:
    /// the caller is deciding whether to renew.
    pub fn own_claims(&self, view: &serde_json::Value) -> Option<iso_policy::signed::PolicyClaims> {
        let signed: iso_policy::signed::SignedPolicy = serde_json::from_value(view.get("signed")?.clone()).ok()?;
        self.verifier.verify_ignoring_expiry(&signed).ok()
    }

    /// Sign `claims` afresh with a new expiry: a renewal, nothing else changed.
    pub fn resign(&self, claims: &iso_policy::signed::PolicyClaims) -> iso_policy::signed::SignedPolicy {
        let renewed = iso_policy::signed::PolicyClaims {
            expires: iso_policy::signed::now() + self.cfg.policy_ttl_secs,
            ..claims.clone()
        };
        self.signer.sign(&renewed)
    }

    /// Sign the policy a VM on `host` runs under. `allow` and `rules` are
    /// as the client gave them; what is signed is the effective rule set,
    /// expanded the way the host serves it, so the tier and the host agree
    /// byte for byte.
    pub fn sign_policy(
        &self,
        host: &str,
        vm: &str,
        egress: &str,
        principal: Option<&str>,
        allow: &[String],
        rules: &[String],
        policy_gen: u64,
    ) -> Result<iso_policy::signed::SignedPolicy, iso_policy::ParseError> {
        let effective = iso_policy::RuleSet::from_record(allow, rules)?.to_strings();
        let claims = iso_policy::signed::PolicyClaims {
            host: host.to_string(),
            vm: vm.to_string(),
            egress: egress.to_string(),
            principal: principal.map(str::to_string),
            rules: effective,
            policy_gen,
            expires: iso_policy::signed::now() + self.cfg.policy_ttl_secs,
        };
        Ok(self.signer.sign(&claims))
    }

    pub fn host(&self, name: &str) -> Option<&HostClient> {
        self.hosts.get(name)
    }

    /// A fresh VM id, in the host's canonical hyphenated form.
    pub fn new_id(&self) -> String {
        use std::io::Read;
        let mut b = [0u8; 16];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut b);
        }
        iso_common::VmId::from_u128(u128::from_be_bytes(b)).to_string()
    }
}

/// The router for `fleet`.
pub fn router(fleet: Arc<Fleet>) -> axum::Router {
    api::router(fleet)
}

/// The signing key under `dir`, generated on first use. The public key is
/// written beside it as base64 (`policy-signing.pub`): what a proxy tier is
/// configured with.
fn load_or_generate_signer(dir: &std::path::Path) -> Result<iso_policy::signed::Signer, String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let key = dir.join("policy-signing.pkcs8");
    let pub_ = dir.join("policy-signing.pub");
    if let Ok(doc) = std::fs::read(&key) {
        let signer = iso_policy::signed::Signer::from_pkcs8(&doc)
            .map_err(|e| format!("{}: not an ed25519 pkcs8 key: {e}", key.display()))?;
        if !pub_.exists() {
            std::fs::write(&pub_, signer.public_key_b64()).map_err(|e| format!("{}: {e}", pub_.display()))?;
        }
        return Ok(signer);
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (signer, doc) = iso_policy::signed::Signer::generate().map_err(|_| "cannot generate a signing key".to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key)
        .map_err(|e| format!("{}: {e}", key.display()))?;
    f.write_all(&doc).map_err(|e| format!("{}: {e}", key.display()))?;
    std::fs::write(&pub_, signer.public_key_b64()).map_err(|e| format!("{}: {e}", pub_.display()))?;
    tracing::info!("iso-fleetd: new policy signing key; public key at {}", pub_.display());
    Ok(signer)
}
