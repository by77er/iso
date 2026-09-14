//! The edge to tier hop: TCP over HTTP/2 CONNECT, the way Envoy tunnels TCP.
//!
//! An edge keeps a small pool of long-lived mutual-TLS HTTP/2 connections to
//! each replica. Every guest connection becomes one CONNECT stream on one of
//! them, with the connection's identity and whole policy in the request
//! headers. The replica answers 200 and both sides get the stream as a byte
//! pipe: the edge copies the guest's bytes into it, the replica terminates
//! the guest's TLS out of it. Ending the stream (a policy change at the
//! edge, a replica going away) is a RST_STREAM, not a TCP teardown, and
//! HTTP/2 PINGs notice a dead peer in seconds.

use std::net::SocketAddr;

use base64::Engine as _;
use http::{HeaderMap, HeaderValue};

use crate::policy::WirePolicy;

/// The connection's identity and policy, base64 of the `WirePolicy` JSON.
pub const H_POLICY: &str = "x-iso-policy";
/// The guest's source address as the edge saw it, `ip:port`.
pub const H_SRC: &str = "x-iso-src";
/// The authority a CONNECT names; nothing dials it, HTTP/2 just needs one.
pub const AUTHORITY: &str = "guest.iso.internal:443";

/// Headers for a CONNECT that carries `policy` for a guest connection from `src`.
pub fn encode(src: SocketAddr, policy: &WirePolicy) -> std::io::Result<HeaderMap> {
    let json = serde_json::to_vec(policy)?;
    let mut h = HeaderMap::new();
    let v = base64::engine::general_purpose::STANDARD.encode(json);
    h.insert(H_POLICY, HeaderValue::from_str(&v).map_err(bad)?);
    h.insert(H_SRC, HeaderValue::from_str(&src.to_string()).map_err(bad)?);
    Ok(h)
}

/// What a decoded CONNECT says.
pub struct Decoded {
    pub src: Option<SocketAddr>,
    pub policy: WirePolicy,
}

/// Read the identity out of a CONNECT's headers. A request without the
/// policy header is not one of ours.
pub fn decode(headers: &HeaderMap) -> std::io::Result<Decoded> {
    let raw = headers
        .get(H_POLICY)
        .ok_or_else(|| bad(format!("no {H_POLICY} header")))?;
    let json = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(bad)?;
    let policy: WirePolicy = serde_json::from_slice(&json)?;
    let src = headers
        .get(H_SRC)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    Ok(Decoded { src, policy })
}

fn bad(e: impl ToString) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_identity_and_policy() {
        let p = WirePolicy {
            host: "host-a".into(),
            vm: Some("vm-1".into()),
            egress: "proxy".into(),
            principal: Some("alice".into()),
            rules: vec!["allow https://api.github.com/**".into(), "deny https://api.github.com/user/keys".into()],
            policy_gen: 7,
            signed: None,
        };
        let src: SocketAddr = "172.21.0.3:41000".parse().unwrap();
        let h = encode(src, &p).unwrap();
        let d = decode(&h).unwrap();
        assert_eq!(d.src, Some(src));
        assert_eq!(d.policy.vm.as_deref(), Some("vm-1"));
        assert_eq!(d.policy.policy_gen, 7);
        assert_eq!(d.policy.rules, p.rules);
        assert_eq!(d.policy.principal.as_deref(), Some("alice"));
    }

    #[test]
    fn rejects_requests_without_the_policy_header() {
        assert!(decode(&HeaderMap::new()).is_err());
        let mut h = HeaderMap::new();
        h.insert(H_POLICY, HeaderValue::from_static("not base64!"));
        assert!(decode(&h).is_err());
        h.insert(H_POLICY, HeaderValue::from_static("bm90IGpzb24="));
        assert!(decode(&h).is_err());
    }
}
