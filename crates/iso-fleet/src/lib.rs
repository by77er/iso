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
        Ok(Arc::new(Self { cfg, store, hosts }))
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
