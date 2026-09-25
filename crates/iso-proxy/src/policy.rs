//! Per-connection policy resolution: source IP → the VM's current egress
//! policy, and the identity a connection carries through the proxy.
//!
//! `RpcResolver` calls the control-plane `identify` RPC and caches by source
//! IP with a short TTL. In the single-host and edge roles that is how a
//! connection is named; in the tier role the edge has already done it and
//! the answer arrives in the tunnel stream's headers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use iso_common::identify::{IdentifyRequest, IdentifyResponse, SignedPolicy};
use iso_policy::signed::PolicyClaims;
use iso_policy::RuleSet;
use serde::{Deserialize, Serialize};

/// A VM's resolved egress policy, as the proxy uses it.
#[derive(Clone)]
pub struct Policy {
    /// `"proxy" | "deny"`. `deny` is refused outright: such a VM
    /// has no egress, and the services address being reachable from it is
    /// not a licence to proxy for it.
    pub egress: String,
    /// Opaque principal selecting per-principal injected credentials.
    pub principal: Option<String>,
    /// The compiled rule set: host phase and URI phase.
    pub rules: Arc<RuleSet>,
    /// Policy generation. Connections are closed when it moves.
    pub policy_gen: u64,
    /// The VM's id, when the resolver knows it (a static resolver may not).
    pub vm: Option<String>,
    /// The fleet's signature over this policy, relayed to the tier as is.
    pub signed: Option<SignedPolicy>,
}

impl Policy {
    /// From the control plane's answer. A response with `rules` uses them; an
    /// older control plane that only sends `allow` gets the sugar expansion.
    pub fn from_identify(r: IdentifyResponse) -> Option<Self> {
        if !r.found {
            return None;
        }
        let rules = if r.rules.is_empty() {
            RuleSet::from_allow_list(&r.allow)
        } else {
            RuleSet::parse(&r.rules)
        };
        let rules = match rules {
            Ok(rs) => rs,
            Err(e) => {
                tracing::warn!("identify answered with an unparsable policy ({e}); denying");
                RuleSet::default()
            }
        };
        Some(Policy {
            egress: r.egress,
            principal: r.principal,
            rules: Arc::new(rules),
            policy_gen: r.policy_gen,
            vm: r.vm,
            signed: r.signed,
        })
    }

    /// From claims the tier verified: the policy is what the fleet signed,
    /// and nothing the edge said beside it is consulted.
    pub fn from_claims(c: PolicyClaims, signed: SignedPolicy) -> Result<Self, iso_policy::ParseError> {
        Ok(Policy {
            egress: c.egress,
            principal: c.principal,
            rules: Arc::new(RuleSet::parse(&c.rules)?),
            policy_gen: c.policy_gen,
            vm: Some(c.vm),
            signed: Some(signed),
        })
    }

    pub fn is_deny_mode(&self) -> bool {
        self.egress == "deny"
    }
}

/// What travels from an edge to a proxy replica in the CONNECT stream's
/// header: the connection's identity and its whole policy, so the replica
/// needs no lookup, no cache and no watch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePolicy {
    pub host: String,
    pub vm: Option<String>,
    pub egress: String,
    pub principal: Option<String>,
    pub rules: Vec<String>,
    pub policy_gen: u64,
    /// The fleet's signature, when the host holds one. A tier that verifies
    /// reads the policy out of this and ignores the fields above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedPolicy>,
}

impl WirePolicy {
    pub fn from_policy(host: &str, p: &Policy) -> Self {
        Self {
            host: host.to_string(),
            vm: p.vm.clone(),
            egress: p.egress.clone(),
            principal: p.principal.clone(),
            rules: p.rules.to_strings(),
            policy_gen: p.policy_gen,
            signed: p.signed.clone(),
        }
    }

    pub fn into_policy(self) -> Result<Policy, iso_policy::ParseError> {
        Ok(Policy {
            egress: self.egress,
            principal: self.principal,
            rules: Arc::new(RuleSet::parse(&self.rules)?),
            policy_gen: self.policy_gen,
            vm: self.vm,
            signed: self.signed,
        })
    }
}

#[async_trait]
pub trait PolicyResolver: Send + Sync {
    /// Resolve the policy for a connection's source IP, or `None` if unknown.
    async fn resolve(&self, ip: IpAddr) -> Option<Policy>;

    /// The name the VM at `ip` resolved `dst` from, for a connection that
    /// carries no SNI. `None` when the VM never resolved it, which refuses
    /// the connection: a `tunnel tcp://` rule names hosts, not addresses.
    async fn resolve_dst(&self, ip: IpAddr, dst: std::net::Ipv4Addr) -> Option<String> {
        let _ = (ip, dst);
        None
    }
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

        let pol = match iso_rpc::call_unix::<_, IdentifyResponse>(
            &self.sock,
            &IdentifyRequest { ip: ip.to_string(), dst: None },
        )
        .await
        {
            Ok(resp) => Policy::from_identify(resp),
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

    /// Not cached: the answer is per destination and the call is made once
    /// per plain TCP connection, which is rare next to requests.
    async fn resolve_dst(&self, ip: IpAddr, dst: std::net::Ipv4Addr) -> Option<String> {
        match iso_rpc::call_unix::<_, IdentifyResponse>(
            &self.sock,
            &IdentifyRequest { ip: ip.to_string(), dst: Some(dst.to_string()) },
        )
        .await
        {
            Ok(resp) if resp.found => resp.dst_name,
            Ok(_) => None,
            Err(e) => {
                tracing::warn!("identify rpc (dst) failed for {ip}: {e}");
                None
            }
        }
    }
}
