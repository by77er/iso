//! Flushes a slot's connection tracking entries on teardown, over ctnetlink:
//! a raw `NETLINK_NETFILTER` socket, no `conntrack` binary.
//!
//! The next VM placed on a slot gets the slot's addresses, and with them
//! whatever the host's conntrack table still holds for those addresses: the
//! last VM's NAT bindings, its `established` flows, an inbound forward to
//! it. Removing the netns takes the namespace's own table with it; the
//! host's, where the masquerade, the proxy intercept and inbound DNAT are
//! tracked, is flushed here, once the slot's links are gone and the VM can
//! add nothing to it.
//!
//! Two steps, as `conntrack -D` takes them: dump the IPv4 table and pick the
//! entries in user space, then delete each by its original tuple and id.

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use iso_common::{Error, NetworkFixture, Result};

// `linux/netfilter/nfnetlink_conntrack.h`; libc has the generic netlink
// constants but not these.
const NFNL_SUBSYS_CTNETLINK: u16 = libc::NFNL_SUBSYS_CTNETLINK as u16;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;
/// An entry's attributes.
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_ID: u16 = 12;
const CTA_ZONE: u16 = 18;
/// A tuple's addresses, and their IPv4 source.
const CTA_TUPLE_IP: u16 = 1;
const CTA_IP_V4_SRC: u16 = 1;

const NLMSG_HDRLEN: usize = 16;
const DONE: u16 = libc::NLMSG_DONE as u16;
const ERROR: u16 = libc::NLMSG_ERROR as u16;
/// The flags of a dump, and of a request answered with an ack.
const DUMP: u16 = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
const DELETE: u16 = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
/// `struct nfgenmsg`: family, version, resource id.
const NFGENMSG_LEN: usize = 4;
/// Room for any batch of a dump: the kernel fills at most 32 KiB per read.
const RECV_BUF: usize = 64 * 1024;

fn align(len: usize) -> usize {
    (len + 3) & !3
}

fn backend(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Backend(format!("conntrack: {what}: {e}"))
}

/// Delete the calling thread's namespace's entries for `fx`'s slot: those
/// the VM started (original source `vp`, the address its traffic has after
/// the in-netns SNAT), those the host side of its link started (`vh`), and
/// those that were DNATed to it (reply source `vp`: an inbound forward, the
/// host's hairpin). Returns how many were deleted.
pub fn flush_slot(fx: &NetworkFixture) -> Result<usize> {
    let (vp, vh) = (fx.vp_ip, fx.vh_ip);
    flush(|orig, reply| orig == vp || orig == vh || reply == vp)
}

/// Delete every IPv4 entry `doomed(original source, reply source)` picks.
/// A kernel without conntrack, or without its netlink interface, has
/// nothing to flush.
pub fn flush(doomed: impl Fn(Ipv4Addr, Ipv4Addr) -> bool) -> Result<usize> {
    let Some(sock) = Socket::open()? else {
        return Ok(0);
    };
    let mut buf = vec![0u8; RECV_BUF];

    // Dump, collecting the deletes: the socket answers one request at a time.
    sock.send(&request(IPCTNL_MSG_CT_GET, DUMP, 1, &[]))?;
    let mut deletes = Vec::new();
    'dump: loop {
        for (ty, payload) in messages(sock.recv(&mut buf)?) {
            match ty {
                DONE => match status(payload) {
                    0 => break 'dump,
                    e => return Err(backend("dump", errno(e))),
                },
                ERROR => match status(payload) {
                    0 => {}
                    e if unsupported(e) => return Ok(0),
                    e => return Err(backend("dump", errno(e))),
                },
                ty if ty >> 8 == NFNL_SUBSYS_CTNETLINK => {
                    let seq = 2 + deletes.len() as u32;
                    let entry = payload.get(NFGENMSG_LEN..).unwrap_or_default();
                    deletes.extend(delete_for(entry, seq, &doomed));
                }
                _ => {}
            }
        }
    }

    let (mut flushed, mut failed) = (0, None);
    for del in &deletes {
        sock.send(del)?;
        match ack(&sock, &mut buf)? {
            0 => flushed += 1,
            // Gone since the dump: timed out, or closed.
            e if e == libc::ENOENT => {}
            e => {
                failed.get_or_insert(e);
            }
        }
    }
    match failed {
        None => Ok(flushed),
        Some(e) => Err(backend("delete", errno(e))),
    }
}

/// What a kernel without ctnetlink answers: nfnetlink refuses a subsystem it
/// has no handler for with `EINVAL`.
fn unsupported(e: i32) -> bool {
    matches!(
        e,
        libc::EINVAL | libc::EOPNOTSUPP | libc::EPROTONOSUPPORT | libc::ENOENT
    )
}

fn errno(e: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(e)
}

/// The errno of an `NLMSG_ERROR` (0 is an ack) or `NLMSG_DONE` payload.
fn status(payload: &[u8]) -> i32 {
    match payload.get(..4) {
        Some(b) => -i32::from_ne_bytes(b.try_into().unwrap()),
        None => libc::EBADMSG,
    }
}

/// The answer to one delete.
fn ack(sock: &Socket, buf: &mut [u8]) -> Result<i32> {
    loop {
        for (ty, payload) in messages(sock.recv(buf)?) {
            if ty == ERROR {
                return Ok(status(payload));
            }
        }
    }
}

/// A ctnetlink request for IPv4 entries: `nlmsghdr`, `nfgenmsg`, `attrs`.
fn request(msg: u16, flags: u16, seq: u32, attrs: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + NFGENMSG_LEN + attrs.len();
    let mut m = Vec::with_capacity(len);
    m.extend_from_slice(&(len as u32).to_ne_bytes());
    m.extend_from_slice(&(NFNL_SUBSYS_CTNETLINK << 8 | msg).to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel's
    m.extend_from_slice(&[libc::AF_INET as u8, libc::NFNETLINK_V0 as u8, 0, 0]);
    m.extend_from_slice(attrs);
    m
}

/// The delete for a dumped entry (its attributes, after `nfgenmsg`), if
/// `doomed` picks it: its original tuple, and its id and zone so that only
/// the entry seen goes, not one that took its tuple since.
fn delete_for(
    entry: &[u8],
    seq: u32,
    doomed: &impl Fn(Ipv4Addr, Ipv4Addr) -> bool,
) -> Option<Vec<u8>> {
    let (mut orig, mut reply, mut id, mut zone) = (None, None, None, None);
    for (ty, whole, payload) in attrs(entry) {
        match ty {
            CTA_TUPLE_ORIG => orig = Some((whole, payload)),
            CTA_TUPLE_REPLY => reply = Some(payload),
            CTA_ID => id = Some(whole),
            CTA_ZONE => zone = Some(whole),
            _ => {}
        }
    }
    // Never a delete without the tuple: ctnetlink reads one as "flush the
    // whole table".
    let (orig, orig_tuple) = orig?;
    if !doomed(source(orig_tuple)?, source(reply?)?) {
        return None;
    }
    let mut out = Vec::new();
    for a in [Some(orig), id, zone].into_iter().flatten() {
        out.extend_from_slice(a);
        out.resize(align(out.len()), 0);
    }
    Some(request(IPCTNL_MSG_CT_DELETE, DELETE, seq, &out))
}

/// A tuple's IPv4 source address.
fn source(tuple: &[u8]) -> Option<Ipv4Addr> {
    let (_, _, ip) = attrs(tuple).find(|(ty, ..)| *ty == CTA_TUPLE_IP)?;
    let (_, _, src) = attrs(ip).find(|(ty, ..)| *ty == CTA_IP_V4_SRC)?;
    Some(Ipv4Addr::from(<[u8; 4]>::try_from(src).ok()?))
}

/// The netlink attributes in `buf`: type (without the nested and byte-order
/// flags), the whole attribute, its payload.
fn attrs(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8], &[u8])> {
    std::iter::from_fn(move || {
        let len = u16::from_ne_bytes(buf.get(..2)?.try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf.get(2..4)?.try_into().unwrap());
        if len < 4 || len > buf.len() {
            return None;
        }
        let attr = (ty & libc::NLA_TYPE_MASK as u16, &buf[..len], &buf[4..len]);
        buf = &buf[align(len).min(buf.len())..];
        Some(attr)
    })
}

/// The netlink messages in `buf`: type and payload.
fn messages(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let len = u32::from_ne_bytes(buf.get(..4)?.try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf.get(4..6)?.try_into().unwrap());
        if len < NLMSG_HDRLEN || len > buf.len() {
            return None;
        }
        let msg = (ty, &buf[NLMSG_HDRLEN..len]);
        buf = &buf[align(len).min(buf.len())..];
        Some(msg)
    })
}

struct Socket(OwnedFd);

impl Socket {
    /// `None` when the kernel has no nfnetlink, so tracks nothing to flush.
    fn open() -> Result<Option<Self>> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EPROTONOSUPPORT) {
                return Ok(None);
            }
            return Err(backend("socket", e));
        }
        let sock = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        // A kernel that never answers must not hang a teardown.
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        let set = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if set < 0 {
            return Err(backend("SO_RCVTIMEO", std::io::Error::last_os_error()));
        }
        Ok(Some(sock))
    }

    /// Send `msg` to the kernel, the default destination of a netlink socket.
    fn send(&self, msg: &[u8]) -> Result<()> {
        let n = unsafe { libc::send(self.0.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
        if n < 0 {
            return Err(backend("send", std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// One datagram of the kernel's answer.
    fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8]> {
        loop {
            // MSG_TRUNC: the datagram's full length, to tell a cut one.
            let n = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_TRUNC,
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(backend("recv", e));
            }
            let n = n as usize;
            if n > buf.len() {
                return Err(backend("recv", format!("a {n}-byte answer was cut")));
            }
            return Ok(&buf[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&(4 + payload.len() as u16).to_ne_bytes());
        a.extend_from_slice(&ty.to_ne_bytes());
        a.extend_from_slice(payload);
        a.resize(align(a.len()), 0);
        a
    }

    fn nest(ty: u16, inner: &[Vec<u8>]) -> Vec<u8> {
        attr(ty | libc::NLA_F_NESTED as u16, &inner.concat())
    }

    /// A tuple as ctnetlink dumps one: addresses, then ports.
    fn tuple(ty: u16, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let ip = nest(
            CTA_TUPLE_IP,
            &[attr(CTA_IP_V4_SRC, &src.octets()), attr(2, &dst.octets())],
        );
        let proto = nest(2, &[attr(1, &[17]), attr(2, &53u16.to_be_bytes())]);
        nest(ty, &[ip, proto])
    }

    const VP: Ipv4Addr = Ipv4Addr::new(172, 21, 0, 3);
    const SVC: Ipv4Addr = Ipv4Addr::new(172, 22, 0, 1);

    fn ours(orig: Ipv4Addr, reply: Ipv4Addr) -> bool {
        orig == VP || reply == VP
    }

    #[test]
    fn deletes_a_picked_entry_by_its_tuple_id_and_zone_only() {
        let orig = tuple(CTA_TUPLE_ORIG, VP, SVC);
        let id = attr(CTA_ID, &7u32.to_be_bytes());
        let zone = attr(CTA_ZONE, &0u16.to_be_bytes());
        let entry = [
            orig.clone(),
            tuple(CTA_TUPLE_REPLY, SVC, VP),
            attr(3, &[0; 4]), // status: not named in a delete
            id.clone(),
            zone.clone(),
        ]
        .concat();

        let del = delete_for(&entry, 9, &ours).expect("the VM's flow");
        let (ty, payload) = messages(&del).next().unwrap();
        assert_eq!(ty, NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_DELETE);
        assert_eq!(u16::from_ne_bytes([del[6], del[7]]), DELETE);
        assert_eq!(u32::from_ne_bytes(del[8..12].try_into().unwrap()), 9);
        assert_eq!(&payload[..2], [libc::AF_INET as u8, 0]);
        assert_eq!(payload[NFGENMSG_LEN..], [orig, id, zone].concat());
    }

    #[test]
    fn picks_by_original_and_reply_source() {
        let entry = |o: (Ipv4Addr, Ipv4Addr)| {
            [
                tuple(CTA_TUPLE_ORIG, o.0, o.1),
                tuple(CTA_TUPLE_REPLY, o.1, o.0),
            ]
            .concat()
        };
        let client = Ipv4Addr::new(198, 51, 100, 2);
        let neighbour = Ipv4Addr::new(172, 21, 0, 5);
        assert!(delete_for(&entry((VP, SVC)), 2, &ours).is_some());
        // DNATed to the VM: the reply comes from it.
        assert!(delete_for(&entry((client, VP)), 2, &ours).is_some());
        assert!(delete_for(&entry((neighbour, SVC)), 2, &ours).is_none());
        assert!(delete_for(&entry((client, neighbour)), 2, &ours).is_none());
    }

    #[test]
    fn never_deletes_without_the_original_tuple() {
        // ctnetlink would take a delete without one for "everything".
        let entry = [tuple(CTA_TUPLE_REPLY, SVC, VP), attr(CTA_ID, &[0; 4])].concat();
        assert!(delete_for(&entry, 2, &|_, _| true).is_none());
    }
}
