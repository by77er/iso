//! VM-facing metadata server, bound on the services dummy (`metadata.iso.local`).
//!
//! Identifies the caller by its source IP (the VM's post-SNAT `vp`) and returns
//! *only that VM's own* identity — never host-global state (side-channel rule).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::routing::get;
use axum::{Json, Router};
use iso_common::{NetworkManager, StorageManager, VmRuntime};
use iso_control_plane::ControlPlane;
use serde_json::json;

type Cp<N, S, R> = Arc<ControlPlane<N, S, R>>;

async fn whoami<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
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
    match cp.identify(ip) {
        Ok(Some(rec)) => Json(json!({
            "id": rec.id.to_string(),
            "slot": rec.slot.map(|s| s.get()),
            "template": rec.template,
            "labels": rec.labels,
        })),
        Ok(None) => Json(json!({ "error": "unknown caller", "src": ip.to_string() })),
        Err(e) => Json(json!({ "error": e.to_string() })),
    }
}

pub fn router<N, S, R>(cp: Cp<N, S, R>) -> Router
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    Router::new().route("/", get(whoami::<N, S, R>)).with_state(cp)
}
