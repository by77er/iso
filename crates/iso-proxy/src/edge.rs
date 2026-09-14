//! The edge: the part of the proxy that stays on every host.
//!
//! It names a connection (source IP → the VM's policy, via the host's
//! identify RPC), refuses what should never be proxied, and either serves the
//! connection in-process (`Single` role) or carries it to a proxy replica with
//! the policy in a PROXY protocol v2 header over mutual TLS (`Edge` role).
//!
//! It also owns connection lifetime. Every live connection is registered
//! under its VM and policy generation; a watcher re-reads each VM's policy
//! every `ttl` and closes connections held at an older generation. That is
//! what retires an h2 session or a WebSocket tunnel after a policy change,
//! without the replica knowing anything happened.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls_pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::AbortHandle;
use tokio_rustls::TlsConnector;

use crate::policy::{Policy, PolicyResolver, WirePolicy};

/// Why a connection was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The source IP maps to no VM (or identify is down).
    Unknown,
    /// The VM is in deny mode: it has no egress, and reaching the services
    /// address is not a licence to proxy for it.
    DenyMode,
}

/// Name a connection and decide whether to carry it at all.
pub async fn admit(resolver: &dyn PolicyResolver, peer: IpAddr) -> Result<Policy, Refusal> {
    let policy = resolver.resolve(peer).await.ok_or(Refusal::Unknown)?;
    if policy.is_deny_mode() {
        return Err(Refusal::DenyMode);
    }
    Ok(policy)
}

struct Live {
    id: usize,
    vm: Option<String>,
    policy_gen: u64,
    handle: AbortHandle,
}

/// Every connection the edge is carrying, by the VM's source address.
#[derive(Default)]
pub struct Registry {
    live: Mutex<HashMap<IpAddr, Vec<Live>>>,
    next_id: AtomicUsize,
}

/// Removes a registration when dropped, so a connection that ends on its
/// own leaves nothing behind.
#[must_use = "dropping the registration removes the connection from the registry"]
pub struct Registration {
    registry: Arc<Registry>,
    ip: IpAddr,
    id: usize,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut live = self.registry.live.lock().unwrap();
        if let Some(v) = live.get_mut(&self.ip) {
            v.retain(|l| l.id != self.id);
            if v.is_empty() {
                live.remove(&self.ip);
            }
        }
    }
}

impl Registry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record a connection's task so a policy change can end it.
    pub fn register(
        self: &Arc<Self>,
        ip: IpAddr,
        policy: &Policy,
        handle: AbortHandle,
    ) -> Registration {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.live.lock().unwrap().entry(ip).or_default().push(Live {
            id,
            vm: policy.vm.clone(),
            policy_gen: policy.policy_gen,
            handle,
        });
        Registration {
            registry: self.clone(),
            ip,
            id,
        }
    }

    /// Source addresses with at least one live connection.
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.live.lock().unwrap().keys().copied().collect()
    }

    /// Live connections for `ip`.
    pub fn count(&self, ip: IpAddr) -> usize {
        self.live
            .lock()
            .unwrap()
            .get(&ip)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Close every connection from `ip` not at `keep_gen` (all of them when
    /// `keep_gen` is `None`). Returns how many were closed.
    pub fn close_stale(&self, ip: IpAddr, keep_gen: Option<u64>) -> usize {
        let mut live = self.live.lock().unwrap();
        let Some(v) = live.get_mut(&ip) else { return 0 };
        let before = v.len();
        v.retain(|l| {
            let keep = keep_gen == Some(l.policy_gen);
            if !keep {
                tracing::info!(
                    "closing connection from {ip} (vm {:?}) at policy gen {} (now {:?})",
                    l.vm,
                    l.policy_gen,
                    keep_gen
                );
                l.handle.abort();
            }
            keep
        });
        let closed = before - v.len();
        if v.is_empty() {
            live.remove(&ip);
        }
        closed
    }
}

/// Re-read the policy of every VM with live connections every `every`, and
/// close what is held at an older generation, or by a VM that is now unknown
/// or in deny mode. Runs forever.
pub async fn watch(registry: Arc<Registry>, resolver: Arc<dyn PolicyResolver>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        for ip in registry.addresses() {
            let keep = match admit(&*resolver, ip).await {
                Ok(p) => Some(p.policy_gen),
                Err(_) => None,
            };
            registry.close_stale(ip, keep);
        }
    }
}

/// Where an edge sends connections: the tier's addresses, round-robin, and
/// the TLS client identity to present.
pub struct Tier {
    addrs: Vec<SocketAddr>,
    server_name: Option<ServerName<'static>>,
    connector: TlsConnector,
    next: AtomicUsize,
    host_id: String,
}

impl Tier {
    pub fn new(
        addrs: Vec<SocketAddr>,
        server_name: Option<String>,
        tls: Arc<rustls::ClientConfig>,
        host_id: String,
    ) -> std::io::Result<Self> {
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "edge needs at least one tier address",
            ));
        }
        let server_name = match server_name {
            Some(n) => Some(ServerName::try_from(n.clone()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("bad tier server name {n:?}"),
                )
            })?),
            None => None,
        };
        Ok(Self {
            addrs,
            server_name,
            connector: TlsConnector::from(tls),
            next: AtomicUsize::new(0),
            host_id,
        })
    }

    /// Open a connection to the next replica, complete the mTLS handshake,
    /// and send the PROXY v2 header for `peer` carrying `policy`. What comes
    /// back is ready for the guest's bytes.
    pub async fn open(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        policy: &Policy,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.addrs.len();
        let addr = self.addrs[i];
        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("connect to tier {addr} timed out"),
                )
            })??;
        tcp.set_nodelay(true)?;
        let name = match &self.server_name {
            Some(n) => n.clone(),
            None => ServerName::IpAddress(addr.ip().into()),
        };
        let mut tls =
            tokio::time::timeout(Duration::from_secs(10), self.connector.connect(name, tcp))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("tls to tier {addr} timed out"),
                    )
                })??;
        let header = crate::proxyproto::encode(
            peer,
            local,
            &WirePolicy::from_policy(&self.host_id, policy),
        )?;
        tls.write_all(&header).await?;
        Ok(tls)
    }
}
