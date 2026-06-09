//! Pure, deterministic derivation of a slot's network fixtures.
//!
//! Everything a slot needs is a function of the [`SlotId`] alone — no state, no
//! allocation. This is the heart of the "slot *is* the allocation" design.

use std::net::Ipv4Addr;

use iso_common::{NetworkFixture, SlotId};

use crate::config::Config;

/// Derive the [`NetworkFixture`] for `slot` under `cfg`.
///
/// veth interface names use a compact hex scheme (`vm7fff`, `vp7fff`) so the top
/// of the slot range stays within the 15-char `IFNAMSIZ` limit. The TAP name is
/// **constant** (`cfg.tap_name`) across all netns — they're isolated, so an
/// identical name keeps the Firecracker snapshot valid for every clone. The
/// veth `/31` base is `veth_net + slot*2`; the netns side is `+1`.
pub fn derive(slot: SlotId, cfg: &Config) -> NetworkFixture {
    let s = slot.get() as u32;
    let base = cfg.veth_net.to_bits();
    let vh_ip = Ipv4Addr::from_bits(base + s * 2);
    let vp_ip = Ipv4Addr::from_bits(base + s * 2 + 1);

    NetworkFixture {
        slot,
        netns: format!("vm{s:04x}"),
        tap: cfg.tap_name.clone(),
        veth_host: format!("vm{s:04x}"),
        veth_netns: format!("vp{s:04x}"),
        vh_ip,
        vp_ip,
        mac: cfg.mac,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(slot: u16) -> NetworkFixture {
        derive(SlotId::new(slot).unwrap(), &Config::default())
    }

    #[test]
    fn slot_zero() {
        let f = fx(0);
        assert_eq!(f.netns, "vm0000");
        assert_eq!(f.veth_netns, "vp0000");
        assert_eq!(f.tap, "tap0"); // constant across slots
        assert_eq!(f.vh_ip, Ipv4Addr::new(172, 21, 0, 0));
        assert_eq!(f.vp_ip, Ipv4Addr::new(172, 21, 0, 1));
    }

    #[test]
    fn slot_max_fills_the_16() {
        let f = fx(SlotId::MAX);
        assert_eq!(f.netns, "vm7fff");
        // 32767*2 = 65534 -> 172.21.255.254 / .255
        assert_eq!(f.vh_ip, Ipv4Addr::new(172, 21, 255, 254));
        assert_eq!(f.vp_ip, Ipv4Addr::new(172, 21, 255, 255));
        assert_eq!(f.tap, "tap0"); // constant regardless of slot
        // names stay within IFNAMSIZ (15).
        assert!(f.netns.len() <= 15 && f.veth_netns.len() <= 15 && f.tap.len() <= 15);
    }

    #[test]
    fn pairs_are_31_aligned_and_disjoint() {
        // adjacent slots must not overlap their /31s.
        let a = fx(1);
        let b = fx(2);
        assert_eq!(a.vh_ip, Ipv4Addr::new(172, 21, 0, 2));
        assert_eq!(a.vp_ip, Ipv4Addr::new(172, 21, 0, 3));
        assert_eq!(b.vh_ip, Ipv4Addr::new(172, 21, 0, 4));
    }
}
