//! `iso-controld` — the iso control-plane daemon.
//!
//! Wires the real network/storage managers + the Firecracker runtime into the
//! control-plane core, starts host subsystems, runs the supervisor, and serves
//! the admin HTTP API over a unix socket. All state lives under `ISO_STATE_DIR`.

use std::sync::Arc;
use std::time::Duration;

use std::net::SocketAddr;

use iso_common::{NetworkManager, SlotId};
use iso_control_plane::ControlPlane;
use iso_controld::{dns_gate, dns_memory, http, identify, metadata, settings, tls};
use iso_firecracker::FirecrackerRuntime;
use iso_storage_manager::command::SystemRunner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // The daemon's own lines are `eprintln!`s; the control plane library
    // reports through `tracing` (a guest clock it could not set, say), and
    // those need a subscriber to reach the journal. `RUST_LOG` narrows it.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let mut s = settings::from_env()?;
    let bake_settings = s.bake.take();

    // The jailer is the default, so resolve it before anything boots. If it is
    // on but unusable, stop here: falling back to an unjailed VMM would hand
    // the operator less isolation than they are entitled to assume, without
    // saying so. Opting out is a decision, and has to look like one.
    match s.firecracker.jailer.as_mut() {
        Some(j) => {
            j.bin = iso_firecracker::jail::resolve_bin(&j.bin).map_err(|e| {
                format!(
                    "{e}. Install Firecracker's jailer, point ISO_JAILER_BIN at it, \
                     or set ISO_JAILER=0 to run VMs as direct children of root."
                )
            })?;
            // Each VM runs as `id_base + slot` unless one identity is pinned
            // for all of them; say which, not the pinned one's fallback.
            let ids = match j.id_base {
                Some(base) => format!(
                    "each its own uid and gid, {base}..={}",
                    base.saturating_add(SlotId::MAX.into())
                ),
                None => format!("all as uid {} gid {}", j.uid, j.gid),
            };
            eprintln!(
                "iso-controld: VMs are jailed ({ids}, chroot {})",
                j.chroot_base.display()
            );
        }
        None => eprintln!(
            "iso-controld: ISO_JAILER is off — VMs run as direct children of root, unjailed"
        ),
    }

    let control_sock = s.control_sock.clone();
    let control_tcp = s.control_tcp;
    let admin_tls_dir = s.admin_tls_dir.clone();
    let admin_insecure = s.admin_insecure;
    let admin_extra_sans = s.admin_extra_sans.clone();
    // The host's reachable IPv4 (where VM forwarded ports are exposed) — handed
    // to the metadata server so guests can learn their own external endpoint.
    let host_addr = s.network.host_addr;
    // Described to guests, never dereferenced for values: the metadata server
    // only ever asks this socket `names_only`.
    let secrets_sock = s.secrets_sock.clone();

    let net = iso_network_manager::Manager::new(s.network);
    // Its slot -> address arithmetic, for state kept by a VM's address.
    let addressing = net.clone();
    let cp = Arc::new(ControlPlane::new(
        s.control,
        net,
        iso_storage_manager::Manager::new(s.storage, Arc::new(SystemRunner)),
        FirecrackerRuntime::new(s.firecracker),
    )?);

    let host = cp.start().await?;
    eprintln!(
        "iso-controld: host network ready (services {}:{})",
        host.services_addr, host.proxy_port
    );

    tokio::spawn(cp.clone().supervise(Duration::from_secs(2)));

    // What every VM resolves is remembered, so the proxy can name an
    // address a VM dials without SNI (a `tunnel tcp://name:port` rule).
    let dns_memory = Arc::new(dns_memory::DnsMemory::default());
    let vp = addressing.clone();
    dns_memory.forget_released(&cp, move |slot| vp.fixture(slot).vp_ip);

    // What a VM may have resolved upstream is what its egress reaches. A
    // bake's builder holds no VM record and egresses directly: the slot
    // builds through the API use, and the one `dev-up.sh` and the deploy
    // scripts bake on.
    let builders = [
        bake_settings.as_ref().map_or(32766, |b| b.slot),
        SlotId::MAX,
    ]
    .into_iter()
    .filter_map(|s| SlotId::new(s).ok())
    .collect();
    let gate = dns_gate::DnsGate::new(
        cp.clone(),
        move |ip| addressing.address_to_slot(ip),
        builders,
    );

    // dual-horizon DNS on the dummy: metadata.iso.local -> dummy, else forward.
    let dns_cfg = iso_dns_server::Config {
        bind: SocketAddr::new(host.services_addr.into(), 53),
        metadata_ip: host.services_addr,
        gate: Some(Arc::new(gate)),
        ..Default::default()
    };
    let observer: Arc<dyn iso_dns_server::Observer> = dns_memory.clone();
    // Template builds through the API, when this host has what a bake needs.
    let builds = iso_controld::build::Builds::new(bake_settings);
    if builds.configured() {
        eprintln!("iso-controld: template builds enabled (POST /templates/build)");
    }
    tokio::spawn(async move {
        if let Err(e) = iso_dns_server::run(dns_cfg, observer).await {
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
                let secrets = Some(Arc::new(iso_secrets::Client::new(secrets_sock)));
                let svc = metadata::router(meta_cp, host_addr, secrets)
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
    let id_dns = dns_memory.clone();
    tokio::spawn(async move {
        if let Err(e) = identify::serve(id_cp, id_dns, &id_sock).await {
            eprintln!("iso-controld: identify server exited: {e}");
        }
    });

    if let Some(parent) = control_sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&control_sock);
    let unix = tokio::net::UnixListener::bind(&control_sock)?;
    // Root only: the socket carries no authentication of its own.
    let _ = std::fs::set_permissions(&control_sock, std::os::unix::fs::PermissionsExt::from_mode(0o600));

    // TCP admin listener for a remote orchestrator's HTTP client: mutual TLS
    // with the admin CA, unless explicitly told to serve plain HTTP.
    let tcp_cp = cp.clone();
    let builds_tcp = builds.clone();
    // Say who can reach it, not just where it is. Whether this ends up on
    // loopback or on the host's primary interface depends on ISO_ADMIN_TCP,
    // and any certificate from the admin CA is a full administrator.
    let reach = if control_tcp.ip().is_loopback() {
        "loopback only"
    } else if control_tcp.ip().is_unspecified() {
        "EVERY interface"
    } else {
        "reachable from the network"
    };
    let tcp_listener = tokio::net::TcpListener::bind(control_tcp).await;
    match (tcp_listener, admin_insecure) {
        (Err(e), _) => eprintln!("iso-controld: tcp admin bind {control_tcp} failed: {e}"),
        (Ok(l), true) => {
            eprintln!(
                "iso-controld: admin API on {} and PLAIN HTTP {control_tcp} — {reach}, \
                 UNAUTHENTICATED (ISO_ADMIN_INSECURE)",
                control_sock.display()
            );
            tokio::spawn(async move {
                if let Err(e) = axum::serve(l, http::router(tcp_cp, builds_tcp)).await {
                    eprintln!("iso-controld: tcp admin exited: {e}");
                }
            });
        }
        (Ok(l), false) => {
            let sans = tls::server_sans(control_tcp, &admin_extra_sans);
            let pki = iso_admin_pki::AdminPki::load_or_generate(&admin_tls_dir, &sans)?;
            if !pki.can_issue() {
                eprintln!(
                    "iso-controld: admin identity issued elsewhere (no ca.key in {}); this host cannot mint credentials",
                    admin_tls_dir.display()
                );
                let missing = pki.uncovered_server_sans(&sans);
                if !missing.is_empty() {
                    eprintln!(
                        "iso-controld: warning: the issued server certificate does not name {missing:?}; \
                         clients dialing those names will fail TLS (reissue with --san to add them)"
                    );
                }
            }
            let acceptor = tls::acceptor(&pki).map_err(|e| e.to_string())?;
            eprintln!(
                "iso-controld: admin API on {} and https://{control_tcp} — {reach} (client certs from {})",
                control_sock.display(),
                admin_tls_dir.join("ca.crt").display()
            );
            tokio::spawn(tls::serve(l, acceptor, http::router(tcp_cp, builds_tcp)));
        }
    }

    axum::serve(unix, http::router(cp, builds.clone())).await?;
    Ok(())
}
