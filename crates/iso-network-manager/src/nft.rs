//! Renders an abstract [`Ruleset`] into `rustables` (nftables-over-netlink) and
//! applies it. No `nft` binary, no shelling out.
//!
//! Each table is reset atomically with the add-before-delete-before-add idiom
//! so `apply` is declarative: the table always ends up exactly as described.

use std::net::{IpAddr, Ipv4Addr};

use ipnetwork::{IpNetwork, Ipv4Network};
use iso_common::{Error, Protocol, Result};
use rustables::expr::{
    Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, HighLevelPayload,
    IPv4HeaderField, Immediate, Nat, NatType, NetworkHeaderField, Register,
};
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol as NftProto,
    ProtocolFamily, Rule, Table,
};

use crate::plan::{ChainKind, NftRule, Ruleset};

fn be<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

fn nft_proto(p: Protocol) -> NftProto {
    match p {
        Protocol::Tcp => NftProto::TCP,
        Protocol::Udp => NftProto::UDP,
    }
}

fn chain_name(kind: ChainKind) -> &'static str {
    match kind {
        ChainKind::Prerouting => "prerouting",
        ChainKind::Forward => "forward",
        ChainKind::Input => "input",
        ChainKind::Output => "output",
        ChainKind::Postrouting => "postrouting",
    }
}

/// (type, hook, priority, optional policy) for each chain kind.
fn chain_attrs(kind: ChainKind) -> (ChainType, HookClass, i32, Option<ChainPolicy>) {
    match kind {
        ChainKind::Prerouting => (ChainType::Nat, HookClass::PreRouting, -100, None),
        ChainKind::Postrouting => (ChainType::Nat, HookClass::PostRouting, 100, None),
        ChainKind::Output => (ChainType::Nat, HookClass::Out, -100, None),
        ChainKind::Forward => (
            ChainType::Filter,
            HookClass::Forward,
            0,
            Some(ChainPolicy::Accept),
        ),
        ChainKind::Input => (
            ChainType::Filter,
            HookClass::In,
            0,
            Some(ChainPolicy::Accept),
        ),
    }
}

/// `ct state <mask> ... != 0` — matches if any of the masked states is set.
fn add_ct_state(rule: &mut Rule, states: ConnTrackState) -> Result<()> {
    rule.add_expr(Conntrack::new(ConntrackKey::State));
    rule.add_expr(Bitwise::new(states.bits().to_le_bytes(), 0u32.to_be_bytes()).map_err(be)?);
    rule.add_expr(Cmp::new(CmpOp::Neq, 0u32.to_be_bytes()));
    Ok(())
}

/// Loads the target into registers and appends the NAT statement.
fn add_nat(rule: &mut Rule, ty: NatType, to: Ipv4Addr, port: Option<u16>) {
    rule.add_expr(Immediate::new_data(to.octets().to_vec(), Register::Reg1));
    let mut nat = Nat::default()
        .with_nat_type(ty)
        .with_family(ProtocolFamily::Ipv4)
        .with_ip_register(Register::Reg1);
    if let Some(p) = port {
        rule.add_expr(Immediate::new_data(p.to_be_bytes().to_vec(), Register::Reg2));
        nat = nat.with_port_register(Register::Reg2);
    }
    rule.add_expr(nat);
}

fn build_rule(chain: &Chain, r: &NftRule) -> Result<Rule> {
    let mut rule = Rule::new(chain).map_err(be)?;
    match r {
        NftRule::AcceptEstablished => {
            add_ct_state(&mut rule, ConnTrackState::ESTABLISHED | ConnTrackState::RELATED)?;
            rule = rule.accept();
        }
        NftRule::AcceptInbound { iif, oif } => {
            rule = rule.iiface(iif).map_err(be)?.oiface(oif).map_err(be)?;
            add_ct_state(&mut rule, ConnTrackState::NEW)?;
            rule = rule.accept();
        }
        NftRule::AcceptEgress { iif, oif } => {
            rule = rule
                .iiface(iif)
                .map_err(be)?
                .oiface(oif)
                .map_err(be)?
                .accept();
        }
        NftRule::AcceptServices { iif, daddr } => {
            rule = rule.iiface(iif).map_err(be)?.daddr(IpAddr::V4(*daddr)).accept();
        }
        NftRule::DropToNet { iif, net, prefix } => {
            let n = IpNetwork::V4(Ipv4Network::new(*net, *prefix).map_err(be)?);
            rule = rule.iiface(iif).map_err(be)?.dnetwork(n).map_err(be)?.drop();
        }
        NftRule::DropFrom { iif } => {
            rule = rule.iiface(iif).map_err(be)?.drop();
        }
        NftRule::Masquerade { saddr, oif } => {
            rule = rule
                .saddr(IpAddr::V4(*saddr))
                .oiface(oif)
                .map_err(be)?
                .masquerade();
        }
        NftRule::Snat { oif, to } => {
            rule = rule.oiface(oif).map_err(be)?;
            add_nat(&mut rule, NatType::SNat, *to, None);
        }
        NftRule::Dnat {
            iif,
            proto,
            dport,
            to,
            to_port,
        } => {
            rule = rule.iiface(iif).map_err(be)?.dport(*dport, nft_proto(*proto));
            add_nat(&mut rule, NatType::DNat, *to, Some(*to_port));
        }
        NftRule::DnatInner {
            iif,
            daddr,
            proto,
            dport,
            to,
        } => {
            rule = rule
                .iiface(iif)
                .map_err(be)?
                .daddr(IpAddr::V4(*daddr))
                .dport(*dport, nft_proto(*proto));
            add_nat(&mut rule, NatType::DNat, *to, None);
        }
        NftRule::DnatHairpin {
            host_addr,
            proto,
            host_port,
            to,
            to_port,
        } => {
            rule = rule
                .daddr(IpAddr::V4(*host_addr))
                .dport(*host_port, nft_proto(*proto));
            add_nat(&mut rule, NatType::DNat, *to, Some(*to_port));
        }
        NftRule::RedirectProxy {
            iif,
            except,
            proto,
            to,
            to_port,
        } => {
            rule = rule.iiface(iif).map_err(be)?;
            // ip daddr != <except>
            rule.add_expr(
                HighLevelPayload::Network(NetworkHeaderField::IPv4(IPv4HeaderField::Daddr)).build(),
            );
            rule.add_expr(Cmp::new(CmpOp::Neq, except.octets()));
            rule = rule.protocol(nft_proto(*proto));
            add_nat(&mut rule, NatType::DNat, *to, Some(*to_port));
        }
    }
    Ok(rule)
}

/// Render `ruleset` into `batch`, resetting the table atomically first.
pub fn render(ruleset: &Ruleset, batch: &mut Batch) -> Result<()> {
    let table = Table::new(ProtocolFamily::Inet).with_name(ruleset.table.as_str());
    // add-before-delete makes the reset idempotent; final add starts it fresh.
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    batch.add(&table, MsgType::Add);

    for cs in &ruleset.chains {
        let (ty, hook, prio, policy) = chain_attrs(cs.kind);
        let mut chain = Chain::new(&table)
            .with_name(chain_name(cs.kind))
            .with_type(ty)
            .with_hook(Hook::new(hook, prio));
        if let Some(p) = policy {
            chain = chain.with_policy(p);
        }
        let chain = chain.add_to_batch(batch);
        for r in &cs.rules {
            build_rule(&chain, r)?.add_to_batch(batch);
        }
    }
    Ok(())
}

/// Apply a single ruleset (in the current network namespace). Requires root.
pub fn apply(ruleset: &Ruleset) -> Result<()> {
    let mut batch = Batch::new();
    render(ruleset, &mut batch)?;
    send_batch(batch.finalize())
}

/// Idempotently delete a table by name (in the current netns). Requires root.
pub fn delete_table(name: &str) -> Result<()> {
    let mut batch = Batch::new();
    let table = Table::new(ProtocolFamily::Inet).with_name(name);
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    send_batch(batch.finalize())
}

/// fd that closes exactly once on drop (no `OwnedFd` double-close).
struct Fd(libc::c_int);
impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Send a finalized nftables batch over our own NETLINK_NETFILTER socket and
/// read the acks, surfacing the first kernel error.
///
/// We do transport ourselves because `rustables::Batch::send` double-closes its
/// socket fd under `nix` 0.30 (`socket()` returns an `OwnedFd` *and* it calls
/// `close()` on the raw fd), which aborts the process via libstd IO safety.
fn send_batch(buf: Vec<u8>) -> Result<()> {
    // The kernel acks every object message (rustables sets NLM_F_ACK) but not
    // the trailing batch-end delimiter, so the terminal ack is for the last
    // *object* = the second-to-last netlink header.
    let seqs: Vec<u32> = nlmsg_iter(&buf).map(|(_, _, seq)| seq).collect();
    let terminal_seq = match seqs.as_slice() {
        [] => return Ok(()),
        [only] => *only,
        [.., last_obj, _batch_end] => *last_obj,
    };

    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        );
        if fd < 0 {
            return Err(Error::Backend(format!(
                "netlink socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        let fd = Fd(fd);

        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as u16;
        if libc::bind(
            fd.0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            return Err(Error::Backend(format!(
                "netlink bind: {}",
                std::io::Error::last_os_error()
            )));
        }

        // bound the ack wait so a lost message can't hang us forever.
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        libc::setsockopt(
            fd.0,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        let mut sent = 0usize;
        while sent < buf.len() {
            let n = libc::send(
                fd.0,
                buf[sent..].as_ptr() as *const libc::c_void,
                buf.len() - sent,
                0,
            );
            if n < 0 {
                return Err(Error::Backend(format!(
                    "netlink send: {}",
                    std::io::Error::last_os_error()
                )));
            }
            sent += n as usize;
        }

        let mut rbuf = vec![0u8; 16 * 1024];
        loop {
            let n = libc::recv(
                fd.0,
                rbuf.as_mut_ptr() as *mut libc::c_void,
                rbuf.len(),
                0,
            );
            if n < 0 {
                let e = std::io::Error::last_os_error();
                match e.raw_os_error() {
                    // recv timeout with no error seen: treat as success.
                    Some(c) if c == libc::EAGAIN || c == libc::EWOULDBLOCK => return Ok(()),
                    _ => return Err(Error::Backend(format!("netlink recv: {e}"))),
                }
            }
            if n == 0 {
                return Ok(());
            }
            for (ty, payload, seq) in nlmsg_iter(&rbuf[..n as usize]) {
                if ty == libc::NLMSG_ERROR as u16 && payload.len() >= 4 {
                    // payload begins with the i32 error code (-errno; 0 = ack).
                    let code = i32::from_ne_bytes(payload[..4].try_into().unwrap());
                    if code != 0 {
                        return Err(Error::Backend(format!(
                            "nftables: {}",
                            std::io::Error::from_raw_os_error(-code)
                        )));
                    }
                    if seq == terminal_seq {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Iterate `(nlmsg_type, payload, nlmsg_seq)` over a netlink buffer.
fn nlmsg_iter(buf: &[u8]) -> impl Iterator<Item = (u16, &[u8], u32)> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        if pos + 16 > buf.len() {
            return None;
        }
        let len = u32::from_ne_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[pos + 4..pos + 6].try_into().unwrap());
        let seq = u32::from_ne_bytes(buf[pos + 8..pos + 12].try_into().unwrap());
        if len < 16 || pos + len > buf.len() {
            return None;
        }
        let payload = &buf[pos + 16..pos + len];
        pos += (len + 3) & !3; // NLMSG_ALIGN
        Some((ty, payload, seq))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::{fixture, plan};
    use iso_common::{EgressMode, NetworkPolicy, PortForward, SlotId};

    /// Rendering builds valid netlink messages for every egress mode (no root
    /// needed: `finalize` serializes without sending).
    #[test]
    fn every_mode_renders_to_nonempty_netlink() {
        let cfg = Config::default();
        let fx = fixture::derive(SlotId::new(1).unwrap(), &cfg);
        for mode in [EgressMode::Allow, EgressMode::Proxy, EgressMode::Deny] {
            let policy = NetworkPolicy {
                egress: mode,
                ingress: vec![PortForward {
                    host_port: 8080,
                    vm_port: 80,
                    proto: Protocol::Tcp,
                }],
            };
            let p = plan::build(&fx, &policy, &cfg);

            let mut batch = Batch::new();
            render(&p.host, &mut batch).expect("host renders");
            render(&p.netns, &mut batch).expect("netns renders");
            let bytes = batch.finalize();
            assert!(!bytes.is_empty(), "mode {mode:?} produced no netlink data");
        }
    }

    #[test]
    fn delete_table_builds_without_panicking() {
        let mut batch = Batch::new();
        let table = Table::new(ProtocolFamily::Inet).with_name("iso_vm0001");
        batch.add(&table, MsgType::Add);
        batch.add(&table, MsgType::Del);
        assert!(!batch.finalize().is_empty());
    }
}
