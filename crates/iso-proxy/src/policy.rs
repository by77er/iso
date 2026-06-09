//! Per-connection policy resolution: source IP → the VM's current egress policy.
//!
//! `RpcResolver` calls the control-plane `identify` RPC and caches by source IP
//! with a short TTL, so a mutable principal (pushed per agent turn) takes effect
//! within the TTL without a lookup per connection.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use iso_common::identify::{IdentifyRequest, IdentifyResponse};

use crate::rpc::call;

/// A VM's resolved egress policy.
#[derive(Clone)]
pub struct Policy {
    /// `"allow" | "proxy" | "deny"` (informational; the proxy only sees traffic
    /// that was steered to it either way).
    pub egress: String,
    /// Opaque principal selecting per-principal injected credentials.
    pub principal: Option<String>,
    /// Domains this VM may reach through the proxy.
    pub allow: HashSet<String>,
}

#[async_trait]
pub trait PolicyResolver: Send + Sync {
    /// Resolve the policy for a connection's source IP, or `None` if unknown.
    async fn resolve(&self, ip: IpAddr) -> Option<Policy>;
}

/// A fixed policy for every source (tests / static single-tenant deployments).
pub struct StaticResolver(pub Policy);

#[async_trait]
impl PolicyResolver for StaticResolver {
    async fn resolve(&self, _ip: IpAddr) -> Option<Policy> {
        Some(self.0.clone())
    }
}

/// Resolves via the control-plane `identify` RPC, cached by source IP for `ttl`.
pub struct RpcResolver {
    sock: PathBuf,
    ttl: Duration,
    cache: Mutex<HashMap<IpAddr, (Instant, Option<Policy>)>>,
}

impl RpcResolver {
    pub fn new(sock: PathBuf, ttl: Duration) -> Self {
        Self {
            sock,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl PolicyResolver for RpcResolver {
    async fn resolve(&self, ip: IpAddr) -> Option<Policy> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some((at, pol)) = cache.get(&ip)
                && at.elapsed() < self.ttl
            {
                return pol.clone();
            }
        }

        let pol = match call::<_, IdentifyResponse>(
            &self.sock,
            &IdentifyRequest { ip: ip.to_string() },
        )
        .await
        {
            Ok(resp) if resp.found => Some(Policy {
                egress: resp.egress,
                principal: resp.principal,
                allow: resp.allow.into_iter().collect(),
            }),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!("identify rpc failed for {ip}: {e}");
                None
            }
        };

        self.cache
            .lock()
            .unwrap()
            .insert(ip, (Instant::now(), pol.clone()));
        pol
    }
}
