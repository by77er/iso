//! Storage manager contract.
//!
//! Unlike the network manager, storage is keyed on [`VmId`] (**identity**), not
//! [`SlotId`]: a VM's volumes are durable and can outlive any single per-host
//! placement. This is the case where identity legitimately crosses the boundary.
//!
//! This contract is intentionally minimal for now — the storage design is not
//! yet fleshed out. Expect [`VolumeSpec`] / [`StorageHandle`] to grow (read-only
//! layers, snapshots, sizing overrides, …).

use std::future::Future;
use std::path::PathBuf;

use crate::error::Result;
use crate::ids::VmId;

/// What to provision for a VM. Placeholder shape; will expand.
#[derive(Clone, Debug)]
pub struct VolumeSpec {
    /// Name of the storage template to instantiate this VM's volume from. The
    /// template defines the base image and any sizing/layout; the manager
    /// resolves it to concrete storage.
    pub template: String,
}

/// A provisioned volume ready to be attached to a Firecracker block device.
#[derive(Clone, Debug)]
pub struct StorageHandle {
    /// Identity this storage belongs to.
    pub vm: VmId,
    /// Host path of the block device / image to hand to Firecracker.
    pub device_path: PathBuf,
}

/// Backing-pool utilisation, for monitoring. A thin pool that fills up fails
/// writes and wedges every VM, so this is watched and gated on.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PoolStats {
    /// Percent of the pool's data space in use (0..=100).
    pub data_percent: f64,
    /// Percent of the pool's metadata space in use (0..=100).
    pub metadata_percent: f64,
}

/// Manages durable per-VM storage on a single host.
///
/// Keyed on [`VmId`] so volumes survive re-placement onto a different slot.
/// Methods are expected to be **idempotent**.
pub trait StorageManager {
    /// One-time host storage setup (sparse file → loop → PV → VG → thin pool).
    /// Idempotent.
    fn init(&self) -> impl Future<Output = Result<()>> + Send;

    /// Provision storage for `vm` per `spec`. Idempotent: re-provisioning an
    /// existing VM returns its existing handle.
    fn provision(
        &self,
        vm: VmId,
        spec: &VolumeSpec,
    ) -> impl Future<Output = Result<StorageHandle>> + Send;

    /// Tear down all storage for `vm`. Idempotent: tearing down absent storage
    /// succeeds.
    fn teardown(&self, vm: VmId) -> impl Future<Output = Result<()>> + Send;

    /// Current backing-pool utilisation.
    fn pool_stats(&self) -> impl Future<Output = Result<PoolStats>> + Send;
}
