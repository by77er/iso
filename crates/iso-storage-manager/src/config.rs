//! Configuration for the LVM-thin-pool storage backend.

use std::path::PathBuf;

/// Tunable storage configuration.
///
/// The backend is: a sparse flat file → loop device → LVM PV → VG → thin pool.
/// Templates are thin volumes in the pool; provisioning a VM is a thin
/// (copy-on-write) snapshot of a template.
#[derive(Clone, Debug)]
pub struct Config {
    /// Sparse flat file backing the whole pool.
    pub image_path: PathBuf,
    /// Size the sparse file is grown to (bytes). Sparse, so it consumes only
    /// what the pool actually writes.
    pub image_size: u64,
    /// Volume group name created on the loop device.
    pub vg: String,
    /// Thin-pool LV name within the VG.
    pub thin_pool: String,
    /// LV-name prefix for template volumes (`<prefix><template>`).
    pub template_prefix: String,
    /// LV-name prefix for per-VM volumes (`<prefix><vm-uuid>`).
    pub volume_prefix: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            image_path: PathBuf::from("/var/lib/iso/storage.img"),
            image_size: 100 * 1024 * 1024 * 1024, // 100 GiB sparse
            vg: "iso".to_string(),
            thin_pool: "pool".to_string(),
            template_prefix: "tpl_".to_string(),
            volume_prefix: "vm_".to_string(),
        }
    }
}
