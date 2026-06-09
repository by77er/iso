//! `iso-controld` — the iso control-plane daemon.
//!
//! Wires the real network/storage managers + the Firecracker runtime into the
//! control-plane core, starts host subsystems, runs the supervisor, and serves
//! the admin HTTP API over a unix socket. All state lives under `ISO_STATE_DIR`.

use std::sync::Arc;
use std::time::Duration;

use iso_control_plane::ControlPlane;
use iso_controld::{http, settings};
use iso_firecracker::FirecrackerRuntime;
use iso_storage_manager::command::SystemRunner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let s = settings::from_env();
    let control_sock = s.control_sock.clone();

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

    if let Some(parent) = control_sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&control_sock);
    let listener = tokio::net::UnixListener::bind(&control_sock)?;
    eprintln!("iso-controld: admin API on {}", control_sock.display());
    axum::serve(listener, http::router(cp)).await?;
    Ok(())
}
