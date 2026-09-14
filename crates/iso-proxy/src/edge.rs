//! The edge: the part of the proxy that stays on every host.
//!
//! It names a connection (source IP → the VM's policy, via the host's
//! identify RPC), refuses what should never be proxied, and either serves the
//! connection in-process (`Single` role) or carries it to a proxy replica as
//! a CONNECT stream on a pooled mutual-TLS HTTP/2 tunnel, with the policy in
//! the stream's headers (`Edge` role; see `tunnel.rs`).
//!
//! It also owns connection lifetime. Every live connection is registered
//! under its VM and policy generation; a watcher re-reads each VM's policy
//! every `ttl` and closes connections held at an older generation. That is
//! what retires an h2 session or a WebSocket tunnel after a policy change,
//! without the replica knowing anything happened.

use crate::dst::Dst;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls_pki_types::ServerName;
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

/// Counters an operator or a test can read: how many tunnel connections
/// the edge has opened to replicas, and how many guest streams it has
/// carried over them. Reuse shows as streams far outnumbering connections.
#[derive(Default, Debug)]
pub struct Metrics {
    pub tier_connections_opened: AtomicUsize,
    pub tier_streams_opened: AtomicUsize,
}

/// One pooled HTTP/2 connection to a replica.
struct Conn {
    send: hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
}

/// Where an edge sends connections: the tier's addresses, each with a small
/// pool of long-lived mutual-TLS HTTP/2 connections, and the identity to
/// present. Guest connections are CONNECT streams on those, spread over the
/// replicas and their pools round-robin.
pub struct Tier {
    addrs: Vec<SocketAddr>,
    server_name: Option<ServerName<'static>>,
    connector: TlsConnector,
    host_id: String,
    pool_size: usize,
    pools: Vec<Mutex<Vec<Conn>>>,
    next_replica: AtomicUsize,
    next_conn: AtomicUsize,
    metrics: Arc<Metrics>,
}

impl Tier {
    pub fn new(
        addrs: Vec<SocketAddr>,
        server_name: Option<String>,
        tls: Arc<rustls::ClientConfig>,
        host_id: String,
        pool_size: usize,
        metrics: Arc<Metrics>,
    ) -> std::io::Result<Self> {
        if addrs.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "edge needs at least one tier address"));
        }
        let server_name = match server_name {
            Some(n) => Some(
                ServerName::try_from(n.clone())
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("bad tier server name {n:?}")))?,
            ),
            None => None,
        };
        // The tunnel is HTTP/2 and nothing else.
        let mut tls = (*tls).clone();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let pools = addrs.iter().map(|_| Mutex::new(Vec::new())).collect();
        Ok(Self {
            addrs,
            server_name,
            connector: TlsConnector::from(Arc::new(tls)),
            host_id,
            pool_size: pool_size.max(1),
            pools,
            next_replica: AtomicUsize::new(0),
            next_conn: AtomicUsize::new(0),
            metrics,
        })
    }

    /// Dial a replica, finish the mutual-TLS handshake, and start an HTTP/2
    /// connection on it. The connection's driver runs until it ends.
    async fn dial(&self, addr: SocketAddr) -> std::io::Result<Conn> {
        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("connect to tier {addr} timed out")))??;
        tcp.set_nodelay(true)?;
        let name = match &self.server_name {
            Some(n) => n.clone(),
            None => ServerName::IpAddress(addr.ip().into()),
        };
        let tls = tokio::time::timeout(Duration::from_secs(10), self.connector.connect(name, tcp))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("tls to tier {addr} timed out")))??;
        let (send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .keep_alive_timeout(Duration::from_secs(20))
            .keep_alive_while_idle(true)
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|e| std::io::Error::other(format!("h2 handshake with tier {addr}: {e}")))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::info!("edge: tunnel to {addr} ended: {e}");
            }
        });
        self.metrics.tier_connections_opened.fetch_add(1, Ordering::Relaxed);
        tracing::info!("edge: tunnel to {addr} open");
        Ok(Conn { send })
    }

    /// A ready connection to replica `i`: an open one from its pool, or a
    /// new one while the pool is below size. Closed ones are dropped.
    async fn conn_for(&self, i: usize) -> std::io::Result<hyper::client::conn::http2::SendRequest<Empty<Bytes>>> {
        let addr = self.addrs[i];
        let pick = {
            let mut pool = self.pools[i].lock().unwrap();
            pool.retain(|c| !c.send.is_closed());
            if pool.len() < self.pool_size {
                None
            } else {
                let k = self.next_conn.fetch_add(1, Ordering::Relaxed) % pool.len();
                Some(pool[k].send.clone())
            }
        };
        match pick {
            Some(send) => Ok(send),
            None => {
                let conn = self.dial(addr).await?;
                let send = conn.send.clone();
                let mut pool = self.pools[i].lock().unwrap();
                if pool.len() < self.pool_size {
                    pool.push(conn);
                }
                Ok(send)
            }
        }
    }

    /// Open a stream for the guest connection from `peer` carrying `policy`:
    /// a CONNECT on the next replica's pool. What comes back is ready for the
    /// guest's bytes. One replica that fails is skipped for the next.
    pub async fn open(&self, peer: SocketAddr, policy: &Policy, dst: &Dst) -> std::io::Result<TokioIo<hyper::upgrade::Upgraded>> {
        let start = self.next_replica.fetch_add(1, Ordering::Relaxed);
        let mut last = None;
        for n in 0..self.addrs.len() {
            let i = (start + n) % self.addrs.len();
            match self.open_on(i, peer, policy, dst).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    tracing::warn!("edge: replica {} unusable: {e}", self.addrs[i]);
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no replica")))
    }

    async fn open_on(&self, i: usize, peer: SocketAddr, policy: &Policy, dst: &Dst) -> std::io::Result<TokioIo<hyper::upgrade::Upgraded>> {
        let mut send = self.conn_for(i).await?;
        let mut req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(crate::tunnel::AUTHORITY)
            .body(Empty::<Bytes>::new())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        *req.headers_mut() = crate::tunnel::encode(peer, &WirePolicy::from_policy(&self.host_id, policy), dst)?;
        // Waits for stream capacity on a busy connection rather than failing.
        send.ready().await.map_err(|e| std::io::Error::other(format!("tunnel not ready: {e}")))?;
        let resp = tokio::time::timeout(Duration::from_secs(10), send.send_request(req))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tier did not answer the CONNECT"))?
            .map_err(|e| std::io::Error::other(format!("tunnel CONNECT: {e}")))?;
        if !resp.status().is_success() {
            return Err(std::io::Error::other(format!("tier refused the connection: {}", resp.status())));
        }
        let up = hyper::upgrade::on(resp)
            .await
            .map_err(|e| std::io::Error::other(format!("tunnel upgrade: {e}")))?;
        self.metrics.tier_streams_opened.fetch_add(1, Ordering::Relaxed);
        Ok(TokioIo::new(up))
    }
}
