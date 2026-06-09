//! Network manager contract.
//!
//! See `crates/iso-network-manager/DESIGN.md` for the full topology, NAT, and
//! firewall design that backs this interface.

use std::fmt;
use std::future::Future;
use std::net::Ipv4Addr;

use crate::error::Result;
use crate::ids::SlotId;

/// L4 protocol selector for port forwards / policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        })
    }
}

/// A 48-bit Ethernet MAC address.
///
/// Identical across all VMs by design — the datapath is routed, never bridged.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

/// Host-wide network facts produced by [`NetworkManager::init`].
///
/// Callers that bind to the services dummy (the DNS server, the proxy) need to
/// know where it lives; `init` hands that back rather than each component
/// re-deriving it from config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostNetwork {
    /// Address of the host-local services dummy interface (DNS, proxy bind to it).
    pub services_addr: Ipv4Addr,
    /// Port on `services_addr` where `Proxy`-level egress is intercepted.
    pub proxy_port: u16,
}

/// The slot-derived network resources for a single VM.
///
/// Everything here is a deterministic function of the [`SlotId`]. The constant
/// inner addressing (the VM and its gateway) is *not* included — it is identical
/// for every VM and lives as a constant in the implementation.
#[derive(Clone, Debug)]
pub struct NetworkFixture {
    /// The slot these resources derive from.
    pub slot: SlotId,
    /// Network namespace name, e.g. `vm7fff`.
    pub netns: String,
    /// TAP device name inside the namespace.
    pub tap: String,
    /// Host-side veth interface name.
    pub veth_host: String,
    /// Namespace-side veth interface name.
    pub veth_netns: String,
    /// Host-side veth address (the `/31` base).
    pub vh_ip: Ipv4Addr,
    /// Namespace-side veth address (`vh_ip + 1`). The host-unique identity of
    /// the VM after the in-netns SNAT.
    pub vp_ip: Ipv4Addr,
    /// Guest MAC (constant across VMs; routed datapath).
    pub mac: MacAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_renders_colon_hex() {
        assert_eq!(
            MacAddr([0x02, 0, 0, 0, 0x7f, 0xff]).to_string(),
            "02:00:00:00:7f:ff"
        );
    }
}

/// The three egress levels governing a VM's **external** traffic.
///
/// Access to the host's internal services (DNS, …) on the services dummy address
/// is a baseline available in every mode; these levels only govern egress
/// *beyond* it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressMode {
    /// Direct internet egress, **bypassing the proxy** (masqueraded out the
    /// uplink).
    Allow,
    /// Internet egress is **transparently intercepted by the proxy**. The proxy
    /// listen endpoint is manager configuration, not per-VM policy.
    Proxy,
    /// **No external egress.**
    Deny,
}

/// A host port exposed to the internet that DNATs through to a VM port.
///
/// The pair `(host_port, proto)` is the identity of a forward within a policy and
/// must be unique across the policy's [`NetworkPolicy::ingress`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortForward {
    /// Port opened on the host uplink.
    pub host_port: u16,
    /// Destination port on the VM's constant inner address.
    pub vm_port: u16,
    /// Protocol the forward applies to.
    pub proto: Protocol,
}

/// The **complete desired network state** for a slot.
///
/// This is declarative: callers describe the end state they want, not the steps
/// to get there. [`NetworkManager::apply`] diffs this against reality and
/// converges. Re-applying an identical policy is a no-op; applying a changed
/// policy reconciles only the difference.
///
/// The default is **deny-by-default**: [`EgressMode::Deny`] with no ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkPolicy {
    /// How VM-initiated egress is treated.
    pub egress: EgressMode,
    /// The full set of host port forwards that should exist. Anything not listed
    /// is removed; `(host_port, proto)` must be unique within the set.
    pub ingress: Vec<PortForward>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            egress: EgressMode::Deny,
            ingress: Vec::new(),
        }
    }
}

/// Manages per-VM network resources on a single host.
///
/// Keyed entirely on [`SlotId`] (**placement**) — implementations never see the
/// VM's identity. The interface is **declarative and idempotent**: the control
/// plane states the desired end state and re-drives it to converge
/// (reconciliation / crash recovery). For log correlation, attach the `VmId` to
/// the tracing span at the call site rather than threading it through these
/// signatures.
pub trait NetworkManager {
    /// One-time host network setup (IP forwarding, RPF, the services dummy
    /// interface, …). Idempotent. Returns the host-wide facts callers need to
    /// bind services.
    fn init(&self) -> impl Future<Output = Result<HostNetwork>> + Send;

    /// Converge `slot` to `policy`, creating the network fixtures if they do not
    /// yet exist. Idempotent: applying the same policy twice changes nothing,
    /// and applying a changed policy reconciles only the diff (egress mode and
    /// the ingress set). Returns the (slot-derived) fixture.
    ///
    /// A `policy.ingress` containing duplicate `(host_port, proto)` pairs is
    /// rejected with [`crate::Error::DuplicatePortForward`].
    fn apply(
        &self,
        slot: SlotId,
        policy: &NetworkPolicy,
    ) -> impl Future<Output = Result<NetworkFixture>> + Send;

    /// Converge `slot` to absent — tear down all network resources. Idempotent:
    /// tearing down an absent slot succeeds.
    fn teardown(&self, slot: SlotId) -> impl Future<Output = Result<()>> + Send;

    /// Reverse of the fixture derivation: map a host-side veth address (a VM's
    /// post-SNAT `vp` source, as seen by services bound to the dummy) back to
    /// its slot. Pure; `None` if the address is outside the managed range.
    ///
    /// Used by the metadata endpoint to identify a caller by its source IP.
    fn address_to_slot(&self, addr: Ipv4Addr) -> Option<SlotId>;
}
