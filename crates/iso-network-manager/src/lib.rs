//! iso-network-manager: native (netlink + nftables) implementation of
//! [`iso_common::NetworkManager`].
//!
//! - [`config`] — tunable addressing/interface configuration.
//! - [`fixture`] — pure slot → fixture derivation.
//! - [`plan`] — pure, declarative description of the desired network state.
//! - [`nft`] / [`netlink`] — render and apply the plan against the kernel.
//! - [`Manager`] — wires it together behind the `NetworkManager` trait.

pub mod config;
pub mod fixture;
pub mod manager;
pub mod netlink;
pub mod nft;
pub mod plan;

pub use config::Config;
pub use manager::Manager;
