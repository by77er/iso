//! The access log: one structured event for every request the proxy
//! terminates and one for every tunnel it closes, under the target
//! `iso_proxy::access`, so an operator can answer "what did this VM do"
//! by filtering on `vm` (and `iso-proxyd --log-format json` makes each
//! line a JSON object).
//!
//! What is logged is deliberately bounded: the request line minus the
//! query string, the decision and the rule that made it, the *names* of
//! the headers injected, the upstream's status and the time it took. Never
//! a header value, never a query string, never a body: those can carry
//! credentials, and this log is meant to be shipped.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::policy::Policy;

/// The tracing target every access event is emitted under.
pub const TARGET: &str = "iso_proxy::access";

/// Who a connection is, for the log: the guest's address, the edge (host)
/// it arrived through, and the VM and principal its policy names. In the
/// single role the edge is this host; on the tier it is the name on the
/// edge's certificate.
#[derive(Clone)]
pub struct Conn {
    pub src: IpAddr,
    pub edge: Arc<str>,
    pub vm: Arc<str>,
    pub principal: Arc<str>,
}

impl Conn {
    pub fn new(src: IpAddr, edge: &str, policy: &Policy) -> Self {
        Self {
            src,
            edge: edge.into(),
            vm: policy.vm.as_deref().unwrap_or("").into(),
            principal: policy.principal.as_deref().unwrap_or("").into(),
        }
    }

    /// A ClientHello for a host no allow rule names: dropped before any
    /// certificate, so there is no request to speak of.
    pub fn sni_denied(&self, host: &str) {
        tracing::info!(
            target: TARGET,
            src = %self.src, edge = %self.edge, vm = %self.vm, principal = %self.principal,
            host, decision = "deny", phase = "sni",
            "sni"
        );
    }

    /// One request, however it ended.
    pub fn request(&self, r: &RequestOutcome<'_>) {
        tracing::info!(
            target: TARGET,
            src = %self.src, edge = %self.edge, vm = %self.vm, principal = %self.principal,
            method = %r.method, scheme = r.scheme, host = r.host, path = r.path,
            decision = r.decision, rule = r.rule.unwrap_or(""),
            injected = %r.injected.join(","),
            status = r.status, latency_ms = r.latency.as_millis() as u64, upgrade = r.upgrade,
            "request"
        );
    }

    /// A tunnel (a WebSocket after its 101, a TCP passthrough) that ended.
    pub fn tunnel_closed(&self, kind: &str, host: &str, port: u16, path: &str, up: u64, down: u64, duration: Duration) {
        tracing::info!(
            target: TARGET,
            src = %self.src, edge = %self.edge, vm = %self.vm, principal = %self.principal,
            kind, host, port, path, bytes_up = up, bytes_down = down,
            duration_ms = duration.as_millis() as u64,
            "tunnel"
        );
    }

    /// A TCP connection refused before any byte was carried: no tunnel rule
    /// for the host and port, or no name for the address at all.
    pub fn tcp_denied(&self, host: &str, port: u16, why: &str) {
        tracing::info!(
            target: TARGET,
            src = %self.src, edge = %self.edge, vm = %self.vm, principal = %self.principal,
            host, port, decision = "deny", phase = "tcp", rule = why,
            "tcp"
        );
    }
}

/// What a request became.
pub struct RequestOutcome<'a> {
    pub method: &'a http::Method,
    /// `https` or `wss`.
    pub scheme: &'a str,
    pub host: &'a str,
    /// The path only; the query string is never logged.
    pub path: &'a str,
    /// `allow` or `deny`.
    pub decision: &'a str,
    /// The rule that decided a deny, or what refused it (`authority`).
    pub rule: Option<&'a str>,
    /// Names of the headers injected, never their values.
    pub injected: &'a [String],
    pub status: u16,
    pub latency: Duration,
    pub upgrade: bool,
}
