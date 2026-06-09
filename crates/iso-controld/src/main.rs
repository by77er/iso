//! `iso-controld` — the iso control-plane daemon.
//!
//! Wires the real network/storage managers + the Firecracker runtime into the
//! control-plane core, starts host subsystems, runs the supervisor, and serves
//! the admin HTTP API over a unix socket. All state lives under `ISO_STATE_DIR`.

use std::sync::Arc;
use std::time::Duration;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use iso_common::network::NetworkManager;
use iso_common::runtime::VmRuntime;
use iso_common::storage::StorageManager;
use iso_common::EgressMode;
use iso_control_plane::ControlPlane;
use iso_controld::{http, identify, metadata, settings};
use iso_firecracker::FirecrackerRuntime;
use iso_storage_manager::command::SystemRunner;

/// DNS redirect resolver: `Allow`-mode VMs get their proxied domains steered to
/// the egress proxy (the services IP); everything else resolves normally.
struct CpRedirect<N, S, R> {
    cp: Arc<ControlPlane<N, S, R>>,
    proxy_ip: Ipv4Addr,
}

impl<N, S, R> iso_dns_server::RedirectResolver for CpRedirect<N, S, R>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    fn redirect(&self, src: IpAddr, name: &str) -> Option<Ipv4Addr> {
        let IpAddr::V4(v4) = src else { return None };
        let rec = self.cp.identify(v4).ok()??;
        if rec.egress == EgressMode::Allow && rec.allow.iter().any(|d| d == name) {
            Some(self.proxy_ip)
        } else {
            None
        }
    }
}

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
    let dns_resolver: Arc<dyn iso_dns_server::RedirectResolver> = Arc::new(CpRedirect {
        cp: cp.clone(),
        proxy_ip: host.services_addr,
    });
    tokio::spawn(async move {
        if let Err(e) = iso_dns_server::run(dns_cfg, dns_resolver).await {
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

    // identify RPC for the egress proxy (src_ip -> policy), same dir as the
    // admin socket.
    let id_sock = control_sock
        .parent()
        .map(|p| p.join("identify.sock"))
        .unwrap_or_else(|| std::path::PathBuf::from("identify.sock"));
    let id_cp = cp.clone();
    tokio::spawn(async move {
        if let Err(e) = identify::serve(id_cp, &id_sock).await {
            eprintln!("iso-controld: identify server exited: {e}");
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
