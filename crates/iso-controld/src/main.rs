//! `iso-controld` — the iso control-plane daemon.
//!
//! Wires the real network/storage managers + the Firecracker runtime into the
//! control-plane core, starts host subsystems, runs the supervisor, and serves
//! the admin HTTP API over a unix socket. All state lives under `ISO_STATE_DIR`.

use std::sync::Arc;
use std::time::Duration;

use std::net::SocketAddr;

use iso_control_plane::ControlPlane;
use iso_controld::{http, metadata, settings};
use iso_firecracker::FirecrackerRuntime;
use iso_storage_manager::command::SystemRunner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let s = settings::from_env();
    let control_sock = s.control_sock.clone();
    let control_tcp = s.control_tcp;

    let cp = Arc::new(ControlPlane::new(
        s.control,
        iso_network_manager::Manager::new(s.network),
        iso_storage_manager::Manager::new(s.storage, Arc::new(SystemRunner)),
        FirecrackerRuntime::new(s.firecracker),
    )?);

    let host = cp.start().await?;
    eprintln!(
        "iso-controld: host network ready (services {}:{})",
        host.services_addr, host.proxy_port
    );

    tokio::spawn(cp.clone().supervise(Duration::from_secs(2)));

    // dual-horizon DNS on the dummy: metadata.iso.local -> dummy, else forward.
    let dns_cfg = iso_dns_server::Config {
        bind: SocketAddr::new(host.services_addr.into(), 53),
        metadata_ip: host.services_addr,
        ..Default::default()
    };
    tokio::spawn(async move {
        if let Err(e) = iso_dns_server::run(dns_cfg).await {
            eprintln!("iso-controld: dns server exited: {e}");
        }
    });

    // VM-facing metadata server on the dummy (:80).
    let meta_addr = SocketAddr::new(host.services_addr.into(), 80);
    let meta_cp = cp.clone();
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(meta_addr).await {
            Ok(l) => {
                eprintln!("iso-controld: metadata server on {meta_addr}");
                let svc = metadata::router(meta_cp)
                    .into_make_service_with_connect_info::<SocketAddr>();
                if let Err(e) = axum::serve(l, svc).await {
                    eprintln!("iso-controld: metadata server exited: {e}");
                }
            }
            Err(e) => eprintln!("iso-controld: metadata bind {meta_addr} failed: {e}"),
        }
    });

    if let Some(parent) = control_sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&control_sock);
    let unix = tokio::net::UnixListener::bind(&control_sock)?;
    eprintln!("iso-controld: admin API on {} and {control_tcp}", control_sock.display());

    // TCP admin listener for the agentd frontend's HTTP client.
    let tcp_cp = cp.clone();
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(control_tcp).await {
            Ok(l) => {
                if let Err(e) = axum::serve(l, http::router(tcp_cp)).await {
                    eprintln!("iso-controld: tcp admin exited: {e}");
                }
            }
            Err(e) => eprintln!("iso-controld: tcp admin bind {control_tcp} failed: {e}"),
        }
    });

    axum::serve(unix, http::router(cp)).await?;
    Ok(())
}
