//! `iso-controld` — the iso control-plane daemon.
//!
//! Wires the real network/storage managers + the Firecracker runtime into the
//! control-plane core, starts host subsystems, runs the supervisor, and serves
//! the admin HTTP API over a unix socket.

mod http;

use std::sync::Arc;
use std::time::Duration;

use iso_control_plane::{Config, ControlPlane};
use iso_firecracker::FirecrackerRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cp = Arc::new(ControlPlane::new(
        Config::default(),
        iso_network_manager::Manager::default(),
        iso_storage_manager::Manager::with_defaults(),
        FirecrackerRuntime::new(iso_firecracker::Config::default()),
    )?);

    let host = cp.start().await?;
    eprintln!(
        "iso-controld: host network ready (services {}:{})",
        host.services_addr, host.proxy_port
    );

    // background supervisor: reconcile running VMs against the VMM.
    tokio::spawn(cp.clone().supervise(Duration::from_secs(2)));

    let sock = "/run/iso/control.sock";
    if let Some(parent) = std::path::Path::new(sock).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(sock);
    let listener = tokio::net::UnixListener::bind(sock)?;
    eprintln!("iso-controld: admin API listening on {sock}");
    axum::serve(listener, http::router(cp)).await?;
    Ok(())
}
