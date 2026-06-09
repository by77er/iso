//! Host-level configuration for the network manager.
//!
//! Every address here is a *default*, not a constant — see `DESIGN.md`:
//! `172.21.0.0/16` lives inside RFC 1918 `172.16.0.0/12` and can collide with a
//! host LAN/VPC, so the prefixes are configurable.

use std::net::Ipv4Addr;

use iso_common::MacAddr;

/// Tunable addressing and interface configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Base of the `/16` from which per-slot veth `/31`s are carved.
    pub veth_net: Ipv4Addr,
    /// Constant TAP / VM-gateway address (the `/31` base inside every netns).
    pub inner_tap: Ipv4Addr,
    /// Constant VM address (identical for every VM).
    pub inner_vm: Ipv4Addr,
    /// Host-local services address (DNS, proxy) on the dummy interface.
    pub services: Ipv4Addr,
    /// Port the proxy listens on at `services` for `Proxy`-level intercept.
    pub proxy_port: u16,
    /// Host uplink interface used for masquerade and inbound forwards.
    pub uplink: String,
    /// Host primary IP for host-local hairpin to forwarded ports. `None`
    /// disables the OUTPUT-chain hairpin (external forwards still work).
    pub host_addr: Option<std::net::Ipv4Addr>,
    /// Constant guest MAC (routed datapath, never bridged).
    pub mac: MacAddr,
    /// TAP interface name inside every VM's netns. Constant (not slot-derived):
    /// the netns is isolated, so an identical name in each makes the Firecracker
    /// snapshot's frozen network config valid for every clone without override.
    pub tap_name: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            veth_net: Ipv4Addr::new(172, 21, 0, 0),
            inner_tap: Ipv4Addr::new(172, 20, 0, 0),
            inner_vm: Ipv4Addr::new(172, 20, 0, 1),
            services: Ipv4Addr::new(172, 22, 0, 1),
            proxy_port: 3128,
            uplink: "eth0".to_string(),
            host_addr: None,
            mac: MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            tap_name: "tap0".to_string(),
        }
    }
}
