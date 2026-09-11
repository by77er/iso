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
use iso_common::{Error, NetworkFixture, Result};
use netns_rs::NetNs;
use rtnetlink::{
    new_connection, Handle, LinkDummy, LinkUnspec, LinkVeth, RouteMessageBuilder,
};

use crate::config::Config;
use crate::nft;
use crate::plan::{self, Plan, Route};

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
        Ok(Some(link)) => Ok(Some(link.header.index)),
        Ok(None) => Ok(None),
        Err(e) => {
            if let rtnetlink::Error::NetlinkError(ref msg) = e {
                let code = msg.code.map(|c| c.get());
                if code == Some(-libc::ENODEV) || code == Some(-libc::ENOENT) {
                    return Ok(None);
                }
            }
            Err(be(e))
        }
    }
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
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// Create a persistent TAP in the *current* network namespace, owned by
/// `owner` when given (so an unprivileged VMM can attach to it).
fn create_tap(name: &str, owner: Option<(u32, u32)>) -> Result<()> {
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
            handle
                .link()
                .add(LinkDummy::new("dummy0").build())
                .execute()
                .await
                .map_err(be)?;
        }
        addr_and_up(&handle, "dummy0", services, 32).await
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

            create_tap(&fx.tap, cfg.tap_owner)?;
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
/// the veth peer, TAP, and the in-netns table with it). Idempotent.
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
    })
}
