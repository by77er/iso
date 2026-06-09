//! iso-control-plane: orchestrates the network manager, storage manager, and a
//! VMM behind a VM lifecycle state machine, with SQLite as the durable source
//! of truth.
//!
//! The [`ControlPlane`] is transport-agnostic; an axum HTTP layer (admin API)
//! wraps it. The VMM is abstracted by [`iso_common::VmRuntime`], so Firecracker
//! (today) or other backends are pluggable.

#![allow(async_fn_in_trait)]

pub mod config;
pub mod control;
pub mod error;
pub mod slot;
pub mod store;
pub mod types;

pub use config::Config;
pub use control::ControlPlane;
pub use error::{Error, Result};
pub use types::{
    CreateVm, Labels, Lifecycle, RestartPolicy, Stats, TemplateDef, VmRecord, VmState,
};
