//! Daemon settings: everything is derived from a single configurable state dir
//! (`ISO_STATE_DIR`), so all persistent/runtime state lives in one place.

use std::path::PathBuf;

/// Fully-resolved configuration for every subsystem.
pub struct Settings {
    pub control: iso_control_plane::Config,
    pub network: iso_network_manager::Config,
    pub storage: iso_storage_manager::Config,
    pub firecracker: iso_firecracker::Config,
    /// Admin API unix socket.
    pub control_sock: PathBuf,
    /// Admin API TCP listener (for a remote orchestrator's HTTP client).
    pub control_tcp: std::net::SocketAddr,
    /// Where the admin CA and server identity live (`ISO_ADMIN_TLS_DIR`).
    pub admin_tls_dir: PathBuf,
    /// Serve the TCP listener as plain HTTP with no authentication
    /// (`ISO_ADMIN_INSECURE=1`). For a lab host on a private network only.
    pub admin_insecure: bool,
    /// Extra names for the server certificate (`ISO_ADMIN_SANS`, comma-separated).
    pub admin_extra_sans: Vec<String>,
}

/// The host's primary IPv4 (source IP toward the internet) — used for the
/// host-local hairpin to VM forwarded ports.
pub fn primary_ipv4() -> Option<std::net::Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:53").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v) => Some(v),
        _ => None,
    }
}

/// The default-route interface, parsed from `/proc/net/route`.
pub fn default_uplink() -> Option<String> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in table.lines().skip(1) {
        let mut f = line.split_whitespace();
        let iface = f.next()?;
        let dest = f.next()?;
        if dest == "00000000" {
            return Some(iface.to_string());
        }
    }
    None
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// Build settings from the environment.
///
/// - `ISO_STATE_DIR` (default `/var/lib/iso`): root for *all* state — the
///   SQLite db, the storage backing file, Firecracker sockets/state/snapshots,
///   and the admin socket.
/// - `ISO_VG` (default `iso`), `ISO_UPLINK` (default: detected), and
///   `ISO_IMAGE_SIZE_GIB` (default `100`) tune the rest.
/// - `ISO_FIRECRACKER_BIN` (default `firecracker`); `ISO_JAILER=1` runs every
///   VM under `jailer`, see [`iso_firecracker::JailerConfig::from_env`].
/// - `ISO_VETH_NET` (default `172.21.0.0`): base of the /16 used for veth pairs.
/// - `ISO_ADMIN_TCP` (default `<primary ip>:7070`), `ISO_ADMIN_TLS_DIR`
///   (default `<state>/admin-pki`), `ISO_ADMIN_SANS`, and `ISO_ADMIN_INSECURE=1`
///   to serve plain HTTP on TCP.
pub fn from_env() -> Settings {
    let state = PathBuf::from(env("ISO_STATE_DIR").unwrap_or_else(|| "/var/lib/iso".into()));
    let vg = env("ISO_VG").unwrap_or_else(|| "iso".into());
    let uplink = env("ISO_UPLINK")
        .or_else(default_uplink)
        .unwrap_or_else(|| "eth0".into());
    let img_gib: u64 = env("ISO_IMAGE_SIZE_GIB")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let jailer = iso_firecracker::JailerConfig::from_env(&state);
    Settings {
        control: iso_control_plane::Config {
            db_path: state.join("control.db"),
            ..Default::default()
        },
        network: iso_network_manager::Config {
            uplink,
            host_addr: primary_ipv4(),
            // A jailed VMM can only attach to a TAP it owns.
            tap_owner: jailer.as_ref().map(|j| (j.uid, j.gid)),
            // The /16 the per-slot veth pairs are carved from; move it when the
            // host's own network already uses 172.21.0.0/16.
            veth_net: env("ISO_VETH_NET")
                .and_then(|v| v.parse().ok())
                .unwrap_or(iso_network_manager::Config::default().veth_net),
            ..Default::default()
        },
        storage: iso_storage_manager::Config {
            image_path: state.join("storage.img"),
            image_size: img_gib * 1024 * 1024 * 1024,
            vg,
            ..Default::default()
        },
        firecracker: iso_firecracker::Config {
            bin: env("ISO_FIRECRACKER_BIN").map(PathBuf::from).unwrap_or_else(|| "firecracker".into()),
            socket_dir: state.join("fc/sock"),
            state_dir: state.join("fc/state"),
            jailer,
            ..Default::default()
        },
        control_sock: state.join("control.sock"),
        admin_tls_dir: env("ISO_ADMIN_TLS_DIR").map(PathBuf::from).unwrap_or_else(|| state.join("admin-pki")),
        admin_insecure: env("ISO_ADMIN_INSECURE")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false),
        admin_extra_sans: env("ISO_ADMIN_SANS")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default(),
        // Bind the admin API on the host's reachable IP so a co-located *or*
        // remote orchestrator can use it (and derive the same address for ssh).
        // Authenticated with client certificates from the admin CA unless
        // ISO_ADMIN_INSECURE says otherwise.
        control_tcp: env("ISO_ADMIN_TCP")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                let ip = primary_ipv4()
                    .map(std::net::IpAddr::V4)
                    .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
                std::net::SocketAddr::new(ip, 7070)
            }),
    }
}
