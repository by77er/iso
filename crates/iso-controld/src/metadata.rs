//! VM-facing metadata server, bound on the services dummy (`metadata.iso.local`).
//!
//! Identifies the caller by its source IP (the VM's post-SNAT `vp`) and returns
//! *only that VM's own* identity — never host-global state (side-channel rule).
//! The one host-derived value it returns, `host`, is the VM's *own* reachable
//! address (the iso server's IP that its forwarded ports live on), so the guest
//! can construct the external endpoint for a service it's running.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::routing::get;
use axum::{Json, Router};
use iso_common::{NetworkManager, StorageManager, VmRuntime};
use iso_control_plane::ControlPlane;
use serde_json::json;

type Cp<N, S, R> = Arc<ControlPlane<N, S, R>>;

/// Router state: the control plane (for caller identification) plus the host's
/// reachable IPv4 — the address a VM's forwarded ports are exposed on.
struct MetaState<N, S, R> {
    cp: Cp<N, S, R>,
    host: Option<Ipv4Addr>,
}

// A derived `Clone` would demand `N/S/R: Clone`; only the `Arc` is cloned.
impl<N, S, R> Clone for MetaState<N, S, R> {
    fn clone(&self) -> Self {
        Self { cp: self.cp.clone(), host: self.host }
    }
}

async fn whoami<N, S, R>(
    State(st): State<MetaState<N, S, R>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Json<serde_json::Value>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let IpAddr::V4(ip) = peer.ip() else {
        return Json(json!({ "error": "unsupported source" }));
    };
    match st.cp.identify(ip) {
        Ok(Some(rec)) => {
            let host = st.host.map(|h| h.to_string());
            // Each forwarded port, with the external `host:host_port` to reach
            // the service the VM runs on `vm_port`. `endpoint` is null if the
            // host address couldn't be determined.
            let endpoints: Vec<_> = rec
                .ingress
                .iter()
                .map(|f| {
                    json!({
                        "vm_port": f.vm_port,
                        "host_port": f.host_port,
                        "proto": f.proto.to_string(),
                        "endpoint": host.as_ref().map(|h| format!("{h}:{}", f.host_port)),
                    })
                })
                .collect();
            Json(json!({
                "id": rec.id.to_string(),
                "name": rec.labels.get("name"),
                "slot": rec.slot.map(|s| s.get()),
                "template": rec.template,
                "labels": rec.labels,
                // The VM's own reachable address (the iso server's IP); combine
                // with an `endpoints[].host_port` to form a service URL.
                "host": host,
                "endpoints": endpoints,
            }))
        }
        Ok(None) => Json(json!({ "error": "unknown caller", "src": ip.to_string() })),
        Err(e) => Json(json!({ "error": e.to_string() })),
    }
}

pub fn router<N, S, R>(cp: Cp<N, S, R>, host: Option<Ipv4Addr>) -> Router
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(whoami::<N, S, R>))
        .with_state(MetaState { cp, host })
}
