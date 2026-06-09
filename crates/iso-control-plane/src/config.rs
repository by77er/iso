//! Control-plane configuration.

use std::path::PathBuf;
use std::time::Duration;

use iso_common::SlotId;

#[derive(Clone, Debug)]
pub struct Config {
    /// SQLite database path (the durable source of truth). `:memory:` for tests.
    pub db_path: PathBuf,
    /// vcpus/mem used when a template doesn't specify and the request doesn't override.
    pub default_vcpus: u32,
    pub default_mem_mib: u32,
    /// Refuse to provision once the pool's data or metadata usage reaches this.
    pub pool_watermark_percent: f64,
    /// How long to wait for graceful guest shutdown before forcing.
    pub graceful_stop: Duration,
    /// Number of placement slots (also bounds the network's `/16`).
    pub slot_capacity: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("/var/lib/iso/control.db"),
            default_vcpus: 1,
            default_mem_mib: 512,
            pool_watermark_percent: 90.0,
            graceful_stop: Duration::from_secs(30),
            slot_capacity: SlotId::MAX as usize + 1,
        }
    }
}
