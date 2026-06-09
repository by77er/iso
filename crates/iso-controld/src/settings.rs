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
pub fn from_env() -> Settings {
    let state = PathBuf::from(env("ISO_STATE_DIR").unwrap_or_else(|| "/var/lib/iso".into()));
    let vg = env("ISO_VG").unwrap_or_else(|| "iso".into());
    let uplink = env("ISO_UPLINK")
        .or_else(default_uplink)
        .unwrap_or_else(|| "eth0".into());
    let img_gib: u64 = env("ISO_IMAGE_SIZE_GIB")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    Settings {
        control: iso_control_plane::Config {
            db_path: state.join("control.db"),
            ..Default::default()
        },
        network: iso_network_manager::Config {
            uplink,
            ..Default::default()
        },
        storage: iso_storage_manager::Config {
            image_path: state.join("storage.img"),
            image_size: img_gib * 1024 * 1024 * 1024,
            vg,
            ..Default::default()
        },
        firecracker: iso_firecracker::Config {
            socket_dir: state.join("fc/sock"),
            state_dir: state.join("fc/state"),
            ..Default::default()
        },
        control_sock: state.join("control.sock"),
    }
}
