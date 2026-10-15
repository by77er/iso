//! Native execution of a [`Plan`] against the kernel: links/addresses/routes via
//! `rtnetlink`, namespaces via `netns-rs`, the TAP via a `/dev/net/tun` ioctl,
//! and nftables via `nft`. No subprocesses.
//!
//! Threading discipline (see `DESIGN.md`): `setns` is thread-scoped and we run
//! under tokio, so all *in-netns* work happens synchronously inside a single
//! [`NetNs::run`] closure (driven by a private current-thread runtime), never
//! crossing an `.await` while switched in. Callers invoke [`converge`] /
//! [`destroy`] / [`host_init`] via `spawn_blocking`.

use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;

use futures::TryStreamExt;
use iso_common::{Error, MacAddr, NetworkFixture, Result};
use netns_rs::NetNs;
use rtnetlink::{Handle, LinkDummy, LinkUnspec, LinkVeth, RouteMessageBuilder, new_connection};

use crate::config::Config;
use crate::plan::{self, Plan, Route};
use crate::{conntrack, nft};

fn be<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

/// Treat EEXIST as success (idempotent create).
fn ignore_exists<T>(res: std::result::Result<T, rtnetlink::Error>) -> Result<()> {
    match res {
        Ok(_) => Ok(()),
        Err(rtnetlink::Error::NetlinkError(e))
            if e.code.map(|c| c.get()) == Some(-libc::EEXIST) =>
        {
            Ok(())
        }
        Err(e) => Err(be(e)),
    }
}

/// Look up a link index by name; `None` if it doesn't exist.
async fn link_index(handle: &Handle, name: &str) -> Result<Option<u32>> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    match links.try_next().await {
        Ok(Some(link)) => return Ok(Some(link.header.index)),
        Ok(None) => {}
        Err(e) => {
            if let rtnetlink::Error::NetlinkError(ref msg) = e {
                let code = msg.code.map(|c| c.get());
                if code == Some(-libc::ENODEV) || code == Some(-libc::ENOENT) {
                    return Ok(None);
                }
            }
            return Err(be(e));
        }
    }
    // A filtered GETLINK came back empty. Not every kernel honours the name
    // filter (WSL2's did not for its built-in dummy0), so confirm with a dump
    // before concluding the link is absent: creating one that exists fails.
    use rtnetlink::packet_route::link::LinkAttribute;
    let mut all = handle.link().get().execute();
    while let Some(link) = all.try_next().await.map_err(be)? {
        if link
            .attributes
            .iter()
            .any(|a| matches!(a, LinkAttribute::IfName(n) if n == name))
        {
            return Ok(Some(link.header.index));
        }
    }
    Ok(None)
}

/// Add `ip/prefix` to a link (by name) and bring it up. Idempotent.
async fn addr_and_up(handle: &Handle, name: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    let Some(idx) = link_index(handle, name).await? else {
        return Err(Error::Backend(format!("link {name} not found")));
    };
    ignore_exists(
        handle
            .address()
            .add(idx, IpAddr::V4(ip), prefix)
            .execute()
            .await,
    )?;
    handle
        .link()
        .set(LinkUnspec::new_with_index(idx).up().build())
        .execute()
        .await
        .map_err(be)
}

async fn set_up(handle: &Handle, name: &str) -> Result<()> {
    if let Some(idx) = link_index(handle, name).await? {
        handle
            .link()
            .set(LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await
            .map_err(be)?;
    }
    Ok(())
}

async fn add_route(handle: &Handle, r: &Route) -> Result<()> {
    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new();
    if let Some((dst, plen)) = r.dest {
        builder = builder.destination_prefix(dst, plen);
    }
    let route = builder.gateway(r.gateway).build();
    ignore_exists(handle.route().add(route).execute().await)
}

fn write_sysctl(key: &str, val: &str) -> Result<()> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::write(&path, val).map_err(|e| Error::Backend(format!("sysctl {key}: {e}")))
}

// ---- TAP via /dev/net/tun ioctl -------------------------------------------

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
const TUNSETOWNER: libc::c_ulong = 0x4004_54cc;
const TUNSETGROUP: libc::c_ulong = 0x4004_54ce;
/// Sets a TAP's hardware address. The tun driver serves this on its own fd, so
/// no auxiliary socket is needed.
const SIOCSIFHWADDR: libc::c_ulong = 0x8924;
const ARPHRD_ETHER: libc::sa_family_t = 1;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// `ifreq` in its `ifr_hwaddr` shape. Padded to a full `struct ifreq` (40
/// bytes on x86_64, where the union's widest member is `struct ifmap`): the tun
/// driver copies `sizeof(struct ifreq)` in from userspace regardless of which
/// member the ioctl uses, so a struct sized to `sa_family_t + sa_data` alone
/// would have the kernel reading past the end of it.
#[repr(C)]
struct IfReqHwAddr {
    name: [libc::c_char; libc::IFNAMSIZ],
    family: libc::sa_family_t,
    data: [u8; 14],
    _pad: [u8; 8],
}

/// Create a persistent TAP in the *current* network namespace, owned by
/// `owner` when given (so an unprivileged VMM can attach to it), with a
/// constant hardware address.
///
/// The MAC has to be the same in every netns. Guests resume from one shared
/// memory snapshot, and that snapshot restores the guest's ARP cache, which
/// names the MAC of whichever TAP existed when the template was baked. A
/// kernel-assigned random MAC per TAP invalidates that entry for every clone,
/// and the guest keeps sending to the baked-in MAC — reachable as far as it
/// knows — until the neighbour entry decays and it re-ARPs, about thirty
/// seconds during which nothing the guest sends leaves the link.
fn create_tap(name: &str, owner: Option<(u32, u32)>, mac: MacAddr) -> Result<()> {
    if name.len() >= libc::IFNAMSIZ {
        return Err(Error::Backend(format!("tap name too long: {name}")));
    }
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(Error::Backend(format!(
            "open /dev/net/tun: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut req = IfReq {
        name: [0; libc::IFNAMSIZ],
        flags: IFF_TAP | IFF_NO_PI,
        _pad: [0; 22],
    };
    for (i, b) in name.bytes().enumerate() {
        req.name[i] = b as libc::c_char;
    }

    let result = (|| {
        if unsafe { libc::ioctl(fd, TUNSETIFF, &req) } < 0 {
            return Err(Error::Backend(format!(
                "TUNSETIFF {name}: {}",
                std::io::Error::last_os_error()
            )));
        }
        if let Some((uid, gid)) = owner {
            if unsafe { libc::ioctl(fd, TUNSETOWNER, uid as libc::c_int) } < 0 {
                return Err(Error::Backend(format!(
                    "TUNSETOWNER {name}: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if unsafe { libc::ioctl(fd, TUNSETGROUP, gid as libc::c_int) } < 0 {
                return Err(Error::Backend(format!(
                    "TUNSETGROUP {name}: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        let mut hw = IfReqHwAddr {
            name: [0; libc::IFNAMSIZ],
            family: ARPHRD_ETHER,
            data: [0; 14],
            _pad: [0; 8],
        };
        for (i, b) in name.bytes().enumerate() {
            hw.name[i] = b as libc::c_char;
        }
        hw.data[..6].copy_from_slice(&mac.0);
        // Set while the link is still down. Re-provisioning is idempotent and
        // can land on a TAP that is already up, where the kernel refuses with
        // EBUSY; that TAP already has whatever MAC it was created with, and
        // taking the fixture down to change it would cut a running VM off for
        // the sake of a boot-time optimisation.
        if unsafe { libc::ioctl(fd, SIOCSIFHWADDR, &hw) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EBUSY) {
                return Err(Error::Backend(format!("SIOCSIFHWADDR {name}: {e}")));
            }
        }
        if unsafe { libc::ioctl(fd, TUNSETPERSIST, 1) } < 0 {
            return Err(Error::Backend(format!(
                "TUNSETPERSIST {name}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    })();
    unsafe { libc::close(fd) };
    result
}

// ---- runtime helpers -------------------------------------------------------

fn runtime() -> Result<tokio::runtime::Runtime> {
    // Only IO — `enable_all()` also starts the signal driver, whose global
    // self-pipe gets double-closed across the several short-lived runtimes we
    // create (root ns + each netns), aborting with an IO-safety violation.
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(be)
}

// ---- public API ------------------------------------------------------------

/// One-time host setup: forwarding, loose RPF on the uplink, and the services
/// dummy interface. Idempotent. Requires root. Call from `spawn_blocking`.
pub fn host_init(cfg: &Config) -> Result<()> {
    write_sysctl("net.ipv4.ip_forward", "1")?;
    write_sysctl(&format!("net.ipv4.conf.{}.rp_filter", cfg.uplink), "2")?;

    let services = cfg.services;
    runtime()?.block_on(async move {
        let (conn, handle, _) = new_connection().map_err(be)?;
        tokio::spawn(conn);
        if link_index(&handle, "dummy0").await?.is_none() {
            // Idempotent: a dummy0 that appeared between the lookup and here
            // (or that the lookup missed) is what we wanted anyway.
            ignore_exists(
                handle
                    .link()
                    .add(LinkDummy::new("dummy0").build())
                    .execute()
                    .await,
            )
            .map_err(|e| Error::Backend(format!("host init: create dummy0: {e}")))?;
        }
        addr_and_up(&handle, "dummy0", services, 32)
            .await
            .map_err(|e| Error::Backend(format!("host init: {services}/32 on dummy0: {e}")))
    })
}

/// Re-apply only the nftables rulesets (root + netns) for an already-placed
/// slot — egress steering reconciles via nft flush+add, and we never touch the
/// interfaces, so it's safe while the VMM holds the TAP. Requires root.
pub fn reapply(plan: &Plan) -> Result<()> {
    nft::apply(&plan.host)?;
    let ns = NetNs::new(&plan.fixture.netns)
        .or_else(|_| NetNs::get(&plan.fixture.netns))
        .map_err(be)?;
    let netns_rules = plan.netns.clone();
    ns.run(move |_| -> Result<()> {
        nft::apply(&netns_rules)?;
        Ok(())
    })
    .map_err(be)??;
    Ok(())
}

/// Converge a slot to `plan`: create/ensure the netns, veth, addressing, TAP,
/// routes, sysctls, and both nftables tables. Idempotent. Requires root.
pub fn converge(plan: &Plan, cfg: &Config) -> Result<()> {
    let fx = &plan.fixture;
    let ns = NetNs::new(&fx.netns)
        .or_else(|_| NetNs::get(&fx.netns))
        .map_err(be)?;
    let ns_fd = ns.file().as_raw_fd();

    // --- root namespace: veth, host-side address, move peer into the netns ---
    runtime()?.block_on(async {
        let (conn, handle, _) = new_connection().map_err(be)?;
        tokio::spawn(conn);

        if link_index(&handle, &fx.veth_host).await?.is_none() {
            handle
                .link()
                .add(LinkVeth::new(fx.veth_host.as_str(), fx.veth_netns.as_str()).build())
                .execute()
                .await
                .map_err(be)?;
        }
        addr_and_up(&handle, &fx.veth_host, fx.vh_ip, 31).await?;

        if let Some(idx) = link_index(&handle, &fx.veth_netns).await? {
            handle
                .link()
                .set(LinkUnspec::new_with_index(idx).setns_by_fd(ns_fd).build())
                .execute()
                .await
                .map_err(be)?;
        }
        Ok::<(), Error>(())
    })?;

    // --- root namespace: host nftables table ---
    nft::apply(&plan.host)?;

    // --- target namespace: peer config, TAP, routes, sysctls, nft ---
    let fx = fx.clone();
    let routes = plan.routes.clone();
    let sysctls = plan.sysctls.clone();
    let netns_rules = plan.netns.clone();
    let inner_tap = plan.inner_tap;

    ns.run(move |_| -> Result<()> {
        runtime()?.block_on(async {
            let (conn, handle, _) = new_connection().map_err(be)?;
            tokio::spawn(conn);

            addr_and_up(&handle, &fx.veth_netns, fx.vp_ip, 31).await?;
            set_up(&handle, "lo").await?;

            create_tap(&fx.tap, cfg.tap_owner, cfg.tap_mac)?;
            addr_and_up(&handle, &fx.tap, inner_tap, 31).await?;

            for r in &routes {
                add_route(&handle, r).await?;
            }
            Ok::<(), Error>(())
        })?;

        for (k, v) in &sysctls {
            write_sysctl(k, v)?;
        }
        nft::apply(&netns_rules)?;
        Ok(())
    })
    .map_err(be)??;

    Ok(())
}

/// Tear a slot down: delete the host table, then remove the netns (which takes
/// the veth peer, TAP, and the in-netns table with it), then flush what the
/// host's conntrack holds for the slot's addresses, which the next VM placed
/// on the slot gets. Idempotent.
pub fn destroy(fx: &NetworkFixture) -> Result<()> {
    // host-side table (root ns); ignore if already gone.
    let _ = nft::delete_table(&plan::table_name(fx.slot));

    // removing the netns deletes the veth peer (hence the host side too) + tap.
    if let Ok(ns) = NetNs::get(&fx.netns) {
        ns.remove().map_err(be)?;
    }

    // backstop: drop the host veth if it somehow survived.
    let veth_host = fx.veth_host.clone();
    runtime()?.block_on(async move {
        let (conn, handle, _) = new_connection().map_err(be)?;
        tokio::spawn(conn);
        if let Some(idx) = link_index(&handle, &veth_host).await? {
            let _ = handle.link().del(idx).execute().await;
        }
        Ok::<(), Error>(())
    })?;

    // Last: with its links gone, the VM can add no entry after the flush.
    conntrack::flush_slot(fx)?;
    Ok(())
}

#[cfg(test)]
mod ifreq_tests {
    use super::*;

    /// The tun driver copies a whole `struct ifreq` in from userspace whichever
    /// member the ioctl names, so both shapes must be that size or the kernel
    /// reads past them.
    #[test]
    fn ifreq_shapes_match_the_kernel_struct() {
        const IFREQ_SIZE: usize = 40; // x86_64: 16-byte name + 24-byte union
        assert_eq!(std::mem::size_of::<IfReq>(), IFREQ_SIZE);
        assert_eq!(std::mem::size_of::<IfReqHwAddr>(), IFREQ_SIZE);
    }
}

/// What a VM can open to the host, measured on packets. A TUN named like
/// slot 1's host-side veth stands in for the VM's link (L3, so there is no
/// ARP to answer), inside a network namespace of the test's own with the
/// services address on its `lo`, under the host table [`converge`] installs.
/// Self-skips without root or a namespace.
#[cfg(test)]
mod live_input_tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream, UdpSocket};
    use std::time::{Duration, Instant};

    use iso_common::{EgressMode, NetworkPolicy, PortForward, Protocol, SlotId};

    use super::*;
    use crate::fixture;

    const IFF_TUN: libc::c_short = 0x0001;
    /// How long a probe waits before calling itself dropped.
    const SILENCE: Duration = Duration::from_millis(250);

    fn open_tun(name: &str) -> std::io::Result<std::fs::File> {
        let tun = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let mut req = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        for (i, b) in name.bytes().enumerate() {
            req.name[i] = b as libc::c_char;
        }
        if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &req) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(tun)
    }

    fn csum(data: &[u8], seed: u32) -> [u8; 2] {
        let mut sum = seed;
        for c in data.chunks(2) {
            sum += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        (!(sum as u16)).to_be_bytes()
    }

    fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(20 + l4.len() as u16).to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let c = csum(&p, 0);
        p[10..12].copy_from_slice(&c);
        p.extend_from_slice(l4);
        p
    }

    fn tcp(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ports: (u16, u16),
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&ports.0.to_be_bytes());
        t[2..4].copy_from_slice(&ports.1.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        let pseudo: u32 = [src.octets(), dst.octets()]
            .iter()
            .flat_map(|o| {
                [
                    u16::from_be_bytes([o[0], o[1]]),
                    u16::from_be_bytes([o[2], o[3]]),
                ]
            })
            .map(u32::from)
            .sum::<u32>()
            + 6
            + 20;
        let c = csum(&t, pseudo);
        t[16..18].copy_from_slice(&c);
        ipv4(src, dst, 6, &t)
    }

    /// A one-byte datagram.
    fn udp(src: Ipv4Addr, dst: Ipv4Addr, ports: (u16, u16)) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&ports.0.to_be_bytes());
        u[2..4].copy_from_slice(&ports.1.to_be_bytes());
        u[4..6].copy_from_slice(&9u16.to_be_bytes());
        u.push(b'q'); // checksum 0: none, as IPv4 allows
        ipv4(src, dst, 17, &u)
    }

    const SYN: u8 = 0x02;
    const SYN_ACK: u8 = 0x12;

    /// `(src, dst, protocol, l4 bytes)` of an IPv4 packet.
    fn parse(p: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u8, &[u8])> {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return None;
        }
        let ihl = (p[0] & 0xf) as usize * 4;
        let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
        let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
        Some((src, dst, p[9], p.get(ihl..)?))
    }

    /// The first packet the kernel routes out of `tun` within `wait` that
    /// `want` picks, if any.
    fn recv(
        tun: &mut std::fs::File,
        wait: Duration,
        want: impl Fn(&[u8]) -> bool,
    ) -> Option<Vec<u8>> {
        let until = Instant::now() + wait;
        let mut buf = [0u8; 2048];
        loop {
            let left = until.checked_duration_since(Instant::now())?;
            let mut pfd = libc::pollfd {
                fd: tun.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pfd, 1, left.as_millis() as libc::c_int) } <= 0 {
                continue;
            }
            if let Ok(n) = tun.read(&mut buf)
                && want(&buf[..n])
            {
                return Some(buf[..n].to_vec());
            }
        }
    }

    /// Everything the test measures, in the namespace it is called in.
    struct Probe {
        tun: std::fs::File,
        fx: NetworkFixture,
        cfg: Config,
        /// A host resolver on every interface, as an operator might run one.
        dns: UdpSocket,
        sport: u16,
    }

    impl Probe {
        /// Does the host answer a SYN from the VM to `dst:port` at all (a
        /// SYN-ACK or a reset: either way input let it in)?
        fn syn(&mut self, dst: Ipv4Addr, port: u16) -> bool {
            self.sport += 1;
            let (vp, sport) = (self.fx.vp_ip, self.sport);
            self.tun
                .write_all(&tcp(vp, dst, (sport, port), 1, 0, SYN))
                .unwrap();
            recv(&mut self.tun, SILENCE, |p| {
                matches!(parse(p), Some((_, d, 6, l4)) if d == vp && l4[2..4] == sport.to_be_bytes())
            })
            .is_some()
        }

        /// Does the host answer the VM's ping to `dst`?
        fn ping(&mut self, dst: Ipv4Addr) -> bool {
            let mut echo = vec![8, 0, 0, 0, 0x15, 0x0, 0, 1];
            let c = csum(&echo, 0);
            echo[2..4].copy_from_slice(&c);
            let vp = self.fx.vp_ip;
            self.tun.write_all(&ipv4(vp, dst, 1, &echo)).unwrap();
            recv(
                &mut self.tun,
                SILENCE,
                |p| matches!(parse(p), Some((_, d, 1, l4)) if d == vp && l4[0] == 0),
            )
            .is_some()
        }

        /// Does a datagram from the VM to `dst:53` reach the host resolver?
        fn dns(&mut self, dst: Ipv4Addr) -> bool {
            self.sport += 1;
            self.tun
                .write_all(&udp(self.fx.vp_ip, dst, (self.sport, 53)))
                .unwrap();
            self.dns.recv_from(&mut [0u8; 16]).is_ok()
        }

        /// Does a connection the host starts to the VM complete? The test
        /// plays the guest's SYN-ACK; input must let it back in.
        fn host_dials_vm(&mut self) -> bool {
            let vp = self.fx.vp_ip;
            std::thread::scope(|s| {
                let dial = s.spawn(move || {
                    TcpStream::connect_timeout(
                        &SocketAddr::from((vp, 8080)),
                        Duration::from_secs(3),
                    )
                });
                let syn = recv(&mut self.tun, Duration::from_secs(2), |p| {
                    matches!(parse(p), Some((_, d, 6, l4)) if d == vp && l4[2..4] == 8080u16.to_be_bytes() && l4[13] == SYN)
                })
                .expect("the host's SYN leaves through the VM's link");
                let (src, _, _, l4) = parse(&syn).unwrap();
                let sport = u16::from_be_bytes([l4[0], l4[1]]);
                let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
                let syn_ack = tcp(vp, src, (8080, sport), 7, seq.wrapping_add(1), SYN_ACK);
                self.tun.write_all(&syn_ack).unwrap();
                dial.join().unwrap().is_ok()
            })
        }
    }

    fn setup() -> Option<Probe> {
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return None;
        }
        let cfg = Config::default();
        let fx = fixture::derive(SlotId::new(1).unwrap(), &cfg);
        let tun = open_tun(&fx.veth_host).ok()?;
        runtime()
            .unwrap()
            .block_on(async {
                let (conn, handle, _) = new_connection().map_err(be)?;
                tokio::spawn(conn);
                set_up(&handle, "lo").await?;
                addr_and_up(&handle, "lo", cfg.services, 32).await?;
                addr_and_up(&handle, &fx.veth_host, fx.vh_ip, 31).await
            })
            .expect("namespace addressing");
        let dns = UdpSocket::bind("0.0.0.0:53").unwrap();
        dns.set_read_timeout(Some(SILENCE)).unwrap();
        let flags = unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFL) };
        unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        Some(Probe {
            tun,
            fx,
            cfg,
            dns,
            sport: 40000,
        })
    }

    #[test]
    fn a_vm_opens_only_what_iso_serves_on_the_host() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping a_vm_opens_only_what_iso_serves_on_the_host: requires root");
            return;
        }
        // A namespace is per thread: unshare on one of our own.
        std::thread::spawn(|| {
            let Some(mut p) = setup() else {
                eprintln!(
                    "skipping a_vm_opens_only_what_iso_serves_on_the_host: no namespace or TUN"
                );
                return;
            };
            let (svc, vh, proxy_port) = (p.cfg.services, p.fx.vh_ip, p.cfg.proxy_port);
            for egress in [EgressMode::Deny, EgressMode::Proxy] {
                let policy = NetworkPolicy {
                    egress,
                    ..NetworkPolicy::default()
                };
                nft::apply(&plan::build(&p.fx, &policy, &p.cfg).host).expect("host table");

                // What iso serves on the services address.
                assert!(p.syn(svc, 53), "{egress:?}: dns over tcp");
                assert!(p.dns(svc), "{egress:?}: dns");
                assert!(p.syn(svc, 80), "{egress:?}: metadata");
                assert!(p.syn(svc, proxy_port), "{egress:?}: proxy");

                // Any other host listener, on any of the host's addresses.
                assert!(!p.syn(svc, 22), "{egress:?}: sshd on the services address");
                assert!(
                    !p.syn(svc, 5432),
                    "{egress:?}: a database on the services address"
                );
                assert!(!p.dns(vh), "{egress:?}: a resolver on the veth's address");
                assert!(!p.ping(svc), "{egress:?}: ping");

                // A flow the host starts still gets its replies.
                assert!(p.host_dials_vm(), "{egress:?}: host dials the VM");
            }
            // Proxy's intercept still lands on the proxy through input.
            assert!(
                p.syn(Ipv4Addr::new(192, 0, 2, 1), 443),
                "intercepted to the proxy"
            );
        })
        .join()
        .unwrap();
    }

    /// This thread's namespace's conntrack entries, as the kernel lists them
    /// (not through ctnetlink): `(original source, reply source)`.
    fn tracked() -> Option<Vec<(Ipv4Addr, Ipv4Addr)>> {
        let table = std::fs::read_to_string("/proc/thread-self/net/nf_conntrack").ok()?;
        let entry = |line: &str| {
            let mut srcs = line
                .split_whitespace()
                .filter_map(|f| f.strip_prefix("src=")?.parse().ok());
            Some((srcs.next()?, srcs.next()?))
        };
        Some(table.lines().filter_map(entry).collect())
    }

    /// Nothing flushed a freed slot's entries in the host's table, so the
    /// next VM placed on the slot inherited the last one's flows and NAT
    /// bindings.
    #[test]
    fn teardown_flushes_the_slots_conntrack_entries() {
        const NAME: &str = "teardown_flushes_the_slots_conntrack_entries";
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping {NAME}: requires root");
            return;
        }
        std::thread::spawn(|| {
            let (Some(mut p), Some(_)) = (setup(), tracked()) else {
                eprintln!("skipping {NAME}: no namespace, TUN or /proc conntrack table");
                return;
            };
            let (vp, vh, svc) = (p.fx.vp_ip, p.fx.vh_ip, p.cfg.services);
            // An uplink, for a flow forwarded to the VM and one that is not
            // the VM's at all.
            let (up, client, other) = (
                Ipv4Addr::new(198, 51, 100, 1),
                Ipv4Addr::new(198, 51, 100, 2),
                Ipv4Addr::new(198, 51, 100, 3),
            );
            let mut uplink = open_tun(&p.cfg.uplink).expect("uplink TUN");
            runtime()
                .unwrap()
                .block_on(async {
                    let (conn, handle, _) = new_connection().map_err(be)?;
                    tokio::spawn(conn);
                    addr_and_up(&handle, &p.cfg.uplink, up, 24).await
                })
                .expect("uplink addressing");
            write_sysctl("net.ipv4.ip_forward", "1").unwrap();
            let policy = NetworkPolicy {
                egress: EgressMode::Proxy,
                ingress: vec![PortForward {
                    host_port: 18080,
                    vm_port: 80,
                    proto: Protocol::Tcp,
                }],
                ..NetworkPolicy::default()
            };
            // Its NAT is also what has the namespace track connections.
            nft::apply(&plan::build(&p.fx, &policy, &p.cfg).host).expect("host table");

            // The VM's flow, the host's to the VM, one forwarded to the VM.
            assert!(p.dns(svc), "the VM's query");
            assert!(p.host_dials_vm(), "the host dials the VM");
            uplink
                .write_all(&tcp(client, up, (50000, 18080), 1, 0, SYN))
                .unwrap();
            let forwarded = recv(&mut p.tun, Duration::from_secs(2), |pk| {
                matches!(parse(pk), Some((s, d, 6, l4)) if s == client && d == vp && l4[2..4] == 80u16.to_be_bytes())
            });
            assert!(forwarded.is_some(), "the forward reaches the VM");
            // Another client's query to the host, which is not the slot's.
            uplink.write_all(&udp(other, up, (40000, 53))).unwrap();
            assert!(p.dns.recv_from(&mut [0u8; 16]).is_ok(), "another client");

            let before = tracked().unwrap();
            for (flow, orig, reply) in [
                ("the VM's", vp, svc),
                ("the host's to the VM", vh, vp),
                ("forwarded to the VM", client, vp),
                ("another client's", other, up),
            ] {
                assert!(before.contains(&(orig, reply)), "{flow}: {before:?}");
            }

            assert_eq!(conntrack::flush_slot(&p.fx).expect("flush"), 3);
            let after = tracked().unwrap();
            assert!(
                !after.iter().any(|&(o, r)| o == vp || o == vh || r == vp),
                "the slot's flows are gone: {after:?}"
            );
            assert!(after.contains(&(other, up)), "another client's stays");
            assert_eq!(conntrack::flush_slot(&p.fx).expect("flush"), 0);
        })
        .join()
        .unwrap();
    }
}
