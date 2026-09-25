//! Wire types for the proxy ↔ control-plane `identify` RPC: map a VM's source
//! IP to its current egress policy (opaque principal + proxied-domain allow).

use serde::{Deserialize, Serialize};

/// A policy as the fleet signed it: the claims (canonical JSON, base64) and
/// an ed25519 signature over those exact bytes. Opaque to a host, which
/// stores and serves it; the edge relays it; the tier verifies it with the
/// fleet's public key. The crypto lives in `iso_policy::signed`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicy {
    /// Base64 of the claims JSON, signed byte for byte.
    pub claims: String,
    /// Base64 of the 64-byte ed25519 signature.
    pub sig: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentifyRequest {
    /// The connection's source IP (the VM's `vp` address).
    pub ip: String,
    /// The address the VM dialled, when the caller needs to know what name
    /// the VM resolved to it: a TCP connection to a port that carries no
    /// SNI. The answer is in `dst_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IdentifyResponse {
    /// Whether `ip` mapped to a known VM.
    pub found: bool,
    /// `"proxy" | "deny"`.
    pub egress: String,
    /// Opaque principal the VM acts as (selects per-principal injected creds).
    pub principal: Option<String>,
    /// Domains routed through the proxy (the legacy host allow-list, kept for
    /// callers that predate `rules`).
    pub allow: Vec<String>,
    /// The VM's id, so a caller can key state by VM rather than by address.
    #[serde(default)]
    pub vm: Option<String>,
    /// The effective rule set, expanded: `allow` sugar plus explicit rules,
    /// in `iso-policy` syntax. A caller with rules ignores `allow`.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Policy generation: bumped on every policy change. Equal generations
    /// mean equal policy; a caller closes what it holds at an older one.
    #[serde(default)]
    pub policy_gen: u64,
    /// The fleet's signature over this policy, when a fleet placed the VM.
    /// An edge relays it to the tier, which trusts nothing else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedPolicy>,
    /// The name this VM resolved `dst` from through the host's DNS, if it
    /// did and recently. What a `tunnel tcp://name:port` rule is matched
    /// against for a connection that carries no SNI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_name: Option<String>,
}
