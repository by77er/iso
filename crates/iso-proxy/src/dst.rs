//! Where a guest connection was going before the host redirected it to the
//! proxy, and what the proxy does with that.
//!
//! The nftables intercept sends every TCP connection a VM makes to the
//! proxy's one listener, whatever its port. The kernel's connection
//! tracking remembers the original destination (`SO_ORIGINAL_DST`), so the
//! proxy knows the port: 443 is TLS and the SNI names the host; any other
//! port carries no name of its own, and the name is what the VM resolved
//! the address from, asked of the host's DNS memory.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use tokio::net::TcpStream;

/// The destination a guest connection was dialling.
#[derive(Clone, Debug, Default)]
pub struct Dst {
    /// The original destination, when the kernel knows it. `None` on a
    /// connection that was not redirected (tests, a misconfigured host),
    /// which is treated as port 443.
    pub addr: Option<SocketAddrV4>,
    /// The name the VM resolved the address from, for a port with no SNI.
    pub name: Option<String>,
}

impl Dst {
    pub fn port(&self) -> u16 {
        self.addr.map(|a| a.port()).unwrap_or(443)
    }
    pub fn ip(&self) -> Option<Ipv4Addr> {
        self.addr.map(|a| *a.ip())
    }
    /// What to call the destination in a log line: the resolved name, else
    /// the address, else nothing.
    pub fn label(&self) -> String {
        match (&self.name, self.addr) {
            (Some(n), _) => n.clone(),
            (None, Some(a)) => a.ip().to_string(),
            (None, None) => String::new(),
        }
    }
}

/// How the proxy learns a connection's original destination. The default
/// asks the kernel; tests substitute a fixed answer, since nothing is
/// redirected on loopback.
pub type DstLookup = Arc<dyn Fn(&TcpStream) -> Option<SocketAddrV4> + Send + Sync>;

/// The kernel's record of where a redirected connection was going.
pub fn original_dst(tcp: &TcpStream) -> Option<SocketAddrV4> {
    use std::os::fd::AsRawFd;
    let fd = tcp.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || addr.sin_family as i32 != libc::AF_INET {
        return None;
    }
    Some(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

pub fn kernel_lookup() -> DstLookup {
    Arc::new(original_dst)
}
