//! Wire types for the proxy ↔ control-plane `identify` RPC: map a VM's source
//! IP to its current egress policy (opaque principal + proxied-domain allow).

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentifyRequest {
    /// The connection's source IP (the VM's `vp` address).
    pub ip: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IdentifyResponse {
    /// Whether `ip` mapped to a known VM.
    pub found: bool,
    /// `"allow" | "proxy" | "deny"`.
    pub egress: String,
    /// Opaque principal the VM acts as (selects per-principal injected creds).
    pub principal: Option<String>,
    /// Domains routed through the proxy.
    pub allow: Vec<String>,
}
