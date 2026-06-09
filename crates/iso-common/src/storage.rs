//! Storage manager contract.
//!
//! Unlike the network manager, storage is keyed on [`VmId`] (**identity**), not
//! [`SlotId`]: a VM's volumes are durable and can outlive any single per-host
//! placement. This is the case where identity legitimately crosses the boundary.
//!
//! This contract is intentionally minimal for now — the storage design is not
//! yet fleshed out. Expect [`VolumeSpec`] / [`StorageHandle`] to grow (read-only
//! layers, snapshots, sizing overrides, …).

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

/// Manages durable per-VM storage on a single host.
///
/// Keyed on [`VmId`] so volumes survive re-placement onto a different slot.
/// Methods are expected to be **idempotent**.
pub trait StorageManager {
    /// Provision storage for `vm` per `spec`. Idempotent: re-provisioning an
    /// existing VM returns its existing handle.
    async fn provision(&self, vm: VmId, spec: &VolumeSpec) -> Result<StorageHandle>;

    /// Tear down all storage for `vm`. Idempotent: tearing down absent storage
    /// succeeds.
    async fn teardown(&self, vm: VmId) -> Result<()>;
}
