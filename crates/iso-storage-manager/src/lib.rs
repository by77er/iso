//! iso-storage-manager: implements [`iso_common::StorageManager`] over an LVM
//! thin pool backed by a sparse loop-mounted file.
//!
//! Provisioning a VM is a thin copy-on-write **snapshot** of a named template
//! volume. The backing file, loop device, VG, thin pool and naming are all
//! configurable via [`Config`].

pub mod command;
pub mod config;
pub mod manager;

pub use config::Config;
pub use manager::Manager;
