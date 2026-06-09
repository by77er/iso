//! `iso-common` — shared contracts for iso components.
//!
//! This crate holds the *interfaces* (traits) and the *domain types* that cross
//! component boundaries. Concrete crates (`iso-network-manager`,
//! `iso-storage-manager`, …) implement these traits; the control plane depends
//! only on the abstractions here.
//!
//! Keep this crate to **types + traits + errors**. Do not let implementation
//! details (netlink, nftables, LVM, …) or unrelated utilities leak in — that is
//! what turns a shared crate into a recompile bottleneck and dependency-cycle
//! magnet.
//!
//! ## Identity vs. placement
//!
//! Two deliberately separate keys flow across these boundaries:
//!
//! - [`VmId`] — durable, global **identity**. Owned by the control plane.
//! - [`SlotId`] — per-host, recyclable **placement**. Drives all deterministic
//!   network fixtures.
//!
//! The split is reflected in the traits: [`network::NetworkManager`] is keyed on
//! [`SlotId`] (placement — it never sees identity), while
//! [`storage::StorageManager`] is keyed on [`VmId`] (storage is identity-tied and
//! may outlive any one placement).

// Public async fns in public traits don't return `Send` futures by default and
// aren't `dyn`-compatible. Implementations are expected to produce `Send`
// futures so they can run on a multi-threaded executor; callers use static
// dispatch (generics). We accept the lint rather than box every call.
#![allow(async_fn_in_trait)]

pub mod error;
pub mod identify;
pub mod ids;
pub mod network;
pub mod runtime;
pub mod storage;

pub use error::{Error, Result};
pub use ids::{SlotId, VmId};
pub use runtime::{InstanceSpec, SnapshotRef, VmRuntime, VmStatus};
pub use network::{
    EgressMode, HostNetwork, MacAddr, NetworkFixture, NetworkManager, NetworkPolicy, PortForward,
    Protocol,
};
pub use storage::{PoolStats, StorageHandle, StorageManager, VolumeSpec};
