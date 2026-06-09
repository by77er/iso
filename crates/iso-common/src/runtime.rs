//! Virtual machine monitor (VMM) contract.
//!
//! Abstracts the VMM so the control plane is agnostic to the backend
//! (Firecracker today; jailer-wrapped Firecracker or cloud-hypervisor later).
//! The spec is VMM-neutral; backend-specific configuration lives in the backend
//! crate, not here.

use std::future::Future;
use std::path::PathBuf;

use crate::error::Result;
use crate::ids::VmId;
use crate::network::MacAddr;

/// A resume point: a VMM memory snapshot plus saved device/vCPU state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRef {
    /// Guest memory file (mapped copy-on-write per clone).
    pub mem_file: PathBuf,
    /// Saved microVM (device + vCPU) state.
    pub vmstate: PathBuf,
}

/// VMM-neutral definition of an instance, built by the control plane from the
/// network fixture, storage handle, and template/config.
#[derive(Clone, Debug)]
pub struct InstanceSpec {
    pub vm: VmId,
    /// Network namespace to run the VMM in.
    pub netns: String,
    /// TAP device (inside the netns) backing the guest NIC.
    pub tap: String,
    /// Guest MAC.
    pub mac: MacAddr,
    /// Host path of the writable rootfs block device.
    pub rootfs_device: PathBuf,
    pub vcpus: u32,
    pub mem_mib: u32,
    /// Guest kernel (used for a fresh boot).
    pub kernel: PathBuf,
    /// Kernel boot args (fresh boot).
    pub boot_args: String,
    /// If set, resume from this snapshot instead of a fresh boot. (Resuming
    /// pins vcpus/mem to the snapshot's values.)
    pub resume_from: Option<SnapshotRef>,
}

/// Observed instance state from the VMM's perspective. Polled by the supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmStatus {
    /// No instance exists for this id.
    Absent,
    /// Defined / snapshot loaded, but not executing.
    Created,
    /// Executing.
    Running,
    /// Paused (and possibly snapshotted).
    Suspended,
    /// Exited.
    Stopped,
}

/// A VMM backend managing instances on a single host.
///
/// Implementations spawn detached VMM processes with deterministic socket/state
/// paths derived from `(config, VmId)`, so the control plane can re-adopt them
/// after a restart by calling [`VmRuntime::status`].
pub trait VmRuntime {
    /// Define the instance: spawn the VMM and load config or a snapshot. Not
    /// yet executing.
    fn create(&self, spec: &InstanceSpec) -> impl Future<Output = Result<()>> + Send;

    /// Begin or resume execution.
    fn start(&self, vm: VmId) -> impl Future<Output = Result<()>> + Send;

    /// Pause execution (and snapshot to disk for a later resume).
    fn suspend(&self, vm: VmId) -> impl Future<Output = Result<()>> + Send;

    /// Request graceful in-guest shutdown.
    fn stop(&self, vm: VmId) -> impl Future<Output = Result<()>> + Send;

    /// Forcefully terminate the instance.
    fn halt(&self, vm: VmId) -> impl Future<Output = Result<()>> + Send;

    /// Remove the instance and its VMM artifacts.
    fn destroy(&self, vm: VmId) -> impl Future<Output = Result<()>> + Send;

    /// Current observed status.
    fn status(&self, vm: VmId) -> impl Future<Output = Result<VmStatus>> + Send;
}
