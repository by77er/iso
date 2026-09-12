//! Control-plane domain types (also the durable record shapes).

use std::collections::HashMap;
use std::path::PathBuf;

use iso_common::{EgressMode, PortForward, SlotId, SnapshotRef, VmId};

/// Free-form key/value labels attached to a VM.
pub type Labels = HashMap<String, String>;

/// Whether a stopped VM's resources are reclaimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    /// On stop/exit, everything (storage + placement) is torn down.
    Ephemeral,
    /// On stop/exit, storage persists; only placement (slot/network) is freed.
    Durable,
}

/// What to do when a VM exits unexpectedly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPolicy {
    Never,
    OnFailure,
    Always,
}

/// Lifecycle state of a VM record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmState {
    Creating,
    Running,
    Suspended,
    Stopped,
    Failed,
}

macro_rules! str_enum {
    ($ty:ty { $($variant:path => $s:literal),+ $(,)? }) => {
        impl $ty {
            pub fn as_str(self) -> &'static str {
                match self { $($variant => $s),+ }
            }
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($s => Some($variant),)+ _ => None }
            }
        }
    };
}

str_enum!(Lifecycle { Lifecycle::Ephemeral => "ephemeral", Lifecycle::Durable => "durable" });
str_enum!(RestartPolicy {
    RestartPolicy::Never => "never",
    RestartPolicy::OnFailure => "on_failure",
    RestartPolicy::Always => "always",
});
str_enum!(VmState {
    VmState::Creating => "creating",
    VmState::Running => "running",
    VmState::Suspended => "suspended",
    VmState::Stopped => "stopped",
    VmState::Failed => "failed",
});

/// Map an [`EgressMode`] to/from its stored string.
pub fn egress_str(e: EgressMode) -> &'static str {
    match e {
        EgressMode::Allow => "allow",
        EgressMode::Proxy => "proxy",
        EgressMode::Deny => "deny",
    }
}
pub fn egress_parse(s: &str) -> Option<EgressMode> {
    match s {
        "allow" => Some(EgressMode::Allow),
        "proxy" => Some(EgressMode::Proxy),
        "deny" => Some(EgressMode::Deny),
        _ => None,
    }
}

/// A registered template: the resume point (disk + optional snapshot) plus the
/// machine config it was baked with.
#[derive(Clone, Debug, PartialEq)]
pub struct TemplateDef {
    pub name: String,
    /// Storage template (LV) name to snapshot for each VM's rootfs.
    pub rootfs_template: String,
    /// Firecracker memory+vmstate snapshot; `None` means fresh-boot only.
    pub snapshot: Option<SnapshotRef>,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub kernel: PathBuf,
    pub boot_args: String,
}

/// Durable per-VM record.
#[derive(Clone, Debug)]
pub struct VmRecord {
    pub id: VmId,
    /// Placement slot; `None` when a durable VM is stopped.
    pub slot: Option<SlotId>,
    pub template: String,
    pub egress: EgressMode,
    pub ingress: Vec<PortForward>,
    pub labels: Labels,
    pub lifecycle: Lifecycle,
    pub restart: RestartPolicy,
    /// Per-VM machine-config overrides (forces a fresh boot when set).
    pub vcpus: Option<u32>,
    pub mem_mib: Option<u32>,
    pub state: VmState,
    pub rootfs_device: Option<PathBuf>,
    pub tap: Option<String>,
    /// Security principal the VM acts as (selects per-principal injected creds).
    /// Deliberately mutable at runtime.
    pub principal: Option<String>,
    /// Domains routed through the egress proxy (intercept for policy +
    /// credential injection). In `Allow` mode the rest go direct; in `Proxy`
    /// mode the rest are denied.
    pub allow: Vec<String>,
    /// This VM's own snapshot, from the last successful suspend. Preferred over
    /// the template's on resume — the template's is where every clone *starts*,
    /// this is where this one left off. Cleared when the VM is destroyed (the
    /// runtime removes the files with the rest of its state dir).
    pub snapshot: Option<SnapshotRef>,
}

/// Request to create a VM.
#[derive(Clone, Debug)]
pub struct CreateVm {
    pub template: String,
    pub egress: EgressMode,
    pub ingress: Vec<PortForward>,
    pub labels: Labels,
    pub lifecycle: Lifecycle,
    pub restart: RestartPolicy,
    pub vcpus: Option<u32>,
    pub mem_mib: Option<u32>,
    pub principal: Option<String>,
    pub allow: Vec<String>,
}

impl CreateVm {
    /// Minimal request for `template` with safe defaults (ephemeral, deny, no
    /// restart, template machine-config).
    pub fn new(template: impl Into<String>) -> Self {
        Self {
            template: template.into(),
            egress: EgressMode::Deny,
            ingress: Vec::new(),
            labels: Labels::new(),
            lifecycle: Lifecycle::Ephemeral,
            restart: RestartPolicy::Never,
            vcpus: None,
            mem_mib: None,
            principal: None,
            allow: Vec::new(),
        }
    }
}

/// Aggregate host statistics (admin-only; never exposed to guests).
#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub pool: iso_common::PoolStats,
    pub slots_used: usize,
    pub slots_total: usize,
    pub vms: usize,
}
