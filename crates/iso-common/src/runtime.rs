//! Virtual machine monitor (VMM) contract.
//!
//! Abstracts the VMM so the control plane is agnostic to the backend
//! (Firecracker today; jailer-wrapped Firecracker or cloud-hypervisor later).
//! The spec is VMM-neutral; backend-specific configuration lives in the backend
//! crate, not here.

use std::future::Future;
use std::os::fd::OwnedFd;
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
    /// On resume, the rootfs `path_on_host` baked into the snapshot (the
    /// template's base device). Firecracker reopens that baked path, so the
    /// runtime bind-mounts `rootfs_device` (this VM's CoW volume) over it inside
    /// a private mount namespace — otherwise every clone would write the shared
    /// template. `None` for a fresh boot, where `rootfs_device` is used directly.
    pub rootfs_backing: Option<PathBuf>,
    /// Attach a vsock device with this guest CID, so the host can open
    /// [`VmRuntime::guest_channel`]s to an agent inside the VM. Only consulted on
    /// a fresh boot: a snapshot carries (or lacks) the device it was taken with.
    /// CIDs need not be unique across VMs — the host side of a Firecracker vsock
    /// is a per-VM socket, and clones of one snapshot share their CID anyway.
    pub vsock_cid: Option<u32>,
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

    /// Open a stream to `port` on the guest's vsock, for talking to an agent
    /// inside the VM. Returns a connected stream socket; the caller wraps it in
    /// whatever async I/O type it likes. Backends that cannot reach into the
    /// guest keep the default, which reports that.
    fn guest_channel(&self, vm: VmId, port: u32) -> impl Future<Output = Result<OwnedFd>> + Send {
        let _ = (vm, port);
        async { Err(crate::error::Error::Backend("this VMM backend has no guest channel".into())) }
    }
}
