//! iso-proxyd — the egress proxy daemon, in one of three roles.
//!
//! Configuration comes from a TOML file named by `ISO_PROXY_CONFIG`; without
//! one, the environment describes today's single-host deployment:
//! `ISO_STATE_DIR` for the three Unix sockets and `ISO_PROXY_LISTEN` for the
//! addresses. `--log-format json` (or `ISO_LOG_FORMAT=json`) writes every
//! log line, the access log included, as one JSON object; `RUST_LOG`
//! filters (`iso_proxy::access=info` is the access log alone). The file
//! (every key optional unless the role needs it):
//!
//! ```toml
//! role = "single"                  # single | edge | proxy
//! listen = ["172.22.0.1:3128", "172.22.0.1:443"]
//! host_id = "hostA"                # default: /etc/hostname
//! state_dir = "/var/lib/iso"       # default: $ISO_STATE_DIR
//!
//! [identify]                       # single, edge
//! socket = "/var/lib/iso/identify.sock"
//! ttl_ms = 1000
//!
//! [ca]                             # single, proxy: one of
//! socket = "/var/lib/iso/ca.sock"
//! url = "https://10.0.0.7:7443"
//!
//! [secrets]                        # single, proxy: one of
//! socket = "/var/lib/iso/secrets.sock"
//! url = "https://10.0.0.7:7444"
//!
//! [tier]                           # edge
//! addrs = ["10.0.0.9:3129"]
//! server_name = "proxy-tier"       # optional; default: the address
//!
//! [fleet]                          # proxy: the fleet's policy signing key, one of
//! policy_key_file = "/etc/iso-fleet/policy-signing.pub"
//! policy_key = "base64…"           # without it, an edge's policy is taken on faith
//!
//! [tls]                            # edge and proxy: this process's identity
//! ca = "/etc/iso/creds/ca.crt"     # (isoctl admin issue-server)
//! cert = "/etc/iso/creds/edge.crt"
//! key = "/etc/iso/creds/edge.key"
//!
//! [upstream]
//! extra_roots = ["/etc/ssl/corp-ca.pem"]
//! pins = { "api.internal.example" = "10.0.0.5:8443" }
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iso_proxy::{ProxyConfig, Role, RpcResolver};
use serde::Deserialize;

#[derive(Deserialize, Default)]
struct File {
    role: Option<String>,
    listen: Option<Vec<String>>,
    host_id: Option<String>,
    state_dir: Option<PathBuf>,
    identify: Option<Identify>,
    ca: Option<Service>,
    secrets: Option<Service>,
    tier: Option<Tier>,
    tls: Option<Tls>,
    upstream: Option<Upstream>,
    fleet: Option<FleetKey>,
}
#[derive(Deserialize, Default)]
struct FleetKey {
    policy_key: Option<String>,
    policy_key_file: Option<PathBuf>,
}
#[derive(Deserialize, Default)]
struct Identify {
    socket: Option<PathBuf>,
    ttl_ms: Option<u64>,
}
#[derive(Deserialize, Default)]
struct Service {
    socket: Option<PathBuf>,
    url: Option<String>,
}
#[derive(Deserialize, Default)]
struct Tier {
    addrs: Vec<String>,
    server_name: Option<String>,
}
#[derive(Deserialize)]
struct Tls {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}
#[derive(Deserialize, Default)]
struct Upstream {
    #[serde(default)]
    extra_roots: Vec<PathBuf>,
    /// Host → `ip:port` dialled instead of DNS, like `curl --resolve`.
    #[serde(default)]
    pins: std::collections::HashMap<String, String>,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut log_format = env("ISO_LOG_FORMAT");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--log-format" => log_format = args.next(),
            other => return Err(format!("unknown argument {other:?} (usage: iso-proxyd [--log-format text|json])").into()),
        }
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let fmt = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr);
    match log_format.as_deref() {
        Some("json") => fmt.json().flatten_event(true).init(),
        None | Some("text") => fmt.init(),
        Some(other) => return Err(format!("unknown log format {other:?} (text | json)").into()),
    }

    let file: File = match env("ISO_PROXY_CONFIG") {
        Some(p) => toml::from_str(&std::fs::read_to_string(&p).map_err(|e| format!("{p}: {e}"))?)
            .map_err(|e| format!("{p}: {e}"))?,
        None => File::default(),
    };

    let role: Role = file
        .role
        .clone()
        .or_else(|| env("ISO_PROXY_ROLE"))
        .unwrap_or_else(|| "single".into())
        .parse()?;
    let state = file
        .state_dir
        .clone()
        .or_else(|| env("ISO_STATE_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    let listen: Vec<SocketAddr> = match (&file.listen, env("ISO_PROXY_LISTEN")) {
        (Some(l), _) => l.iter().map(|s| s.parse()).collect::<Result<_, _>>()?,
        (None, Some(e)) => e
            .split(',')
            .map(|s| s.trim().parse())
            .collect::<Result<_, _>>()?,
        // The nft Proxy-mode DNAT target (:3128) and the Allow-mode DNS-redirect
        // target (:443), both on the services IP; a replica listens on :3129.
        (None, None) => match role {
            Role::Proxy => vec!["0.0.0.0:3129".parse()?],
            _ => vec!["172.22.0.1:3128".parse()?, "172.22.0.1:443".parse()?],
        },
    };

    // This process's service identity, when the role talks to anything off-host.
    let creds = match &file.tls {
        Some(t) => Some(iso_admin_pki::Creds::from_files(&t.ca, &t.cert, &t.key)?),
        None => iso_admin_pki::Creds::from_env()?,
    };
    let client_tls = || -> Result<Arc<rustls::ClientConfig>, Box<dyn std::error::Error>> {
        Ok(creds
            .as_ref()
            .ok_or(
                "this role needs a service identity: [tls] in the config or ISO_TLS_CA/CERT/KEY",
            )?
            .client_config()?)
    };

    let endpoint = |svc: &Option<Service>,
                    default_sock: &str|
     -> Result<iso_rpc::Endpoint, Box<dyn std::error::Error>> {
        match svc {
            Some(Service { url: Some(url), .. }) => {
                Ok(iso_rpc::Endpoint::https(url, client_tls()?))
            }
            Some(Service {
                socket: Some(p), ..
            }) => Ok(iso_rpc::Endpoint::unix(p.clone())),
            _ => Ok(iso_rpc::Endpoint::unix(state.join(default_sock))),
        }
    };

    let resolver = |id: &Option<Identify>| -> Arc<dyn iso_proxy::PolicyResolver> {
        let sock = id
            .as_ref()
            .and_then(|i| i.socket.clone())
            .unwrap_or_else(|| state.join("identify.sock"));
        let ttl = Duration::from_millis(id.as_ref().and_then(|i| i.ttl_ms).unwrap_or(1000));
        Arc::new(RpcResolver::new(sock, ttl))
    };

    let mut cfg = match role {
        Role::Single => ProxyConfig::single(
            listen,
            resolver(&file.identify),
            endpoint(&file.ca, "ca.sock")?,
            endpoint(&file.secrets, "secrets.sock")?,
        ),
        Role::Edge => {
            let tier = file.tier.as_ref().ok_or("edge needs [tier] addrs")?;
            let addrs: Vec<SocketAddr> = tier
                .addrs
                .iter()
                .map(|s| s.parse())
                .collect::<Result<_, _>>()?;
            let mut c = ProxyConfig::edge(listen, resolver(&file.identify), addrs, client_tls()?);
            c.tier_server_name = tier.server_name.clone();
            c
        }
        Role::Proxy => {
            let accept = creds
                .as_ref()
                .ok_or(
                    "proxy needs a service identity: [tls] in the config or ISO_TLS_CA/CERT/KEY",
                )?
                .server_config()?;
            ProxyConfig::proxy(
                listen,
                accept,
                endpoint(&file.ca, "ca.sock")?,
                endpoint(&file.secrets, "secrets.sock")?,
            )
        }
    };
    if let Some(h) = file.host_id.or_else(|| env("ISO_HOST_ID")) {
        cfg.host_id = h;
    }
    if let Some(f) = &file.fleet {
        let key = match (&f.policy_key, &f.policy_key_file) {
            (Some(k), _) => k.clone(),
            (None, Some(p)) => std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?,
            (None, None) => return Err("[fleet] needs policy_key or policy_key_file".into()),
        };
        cfg.policy_verifier = Some(iso_policy::signed::Verifier::from_b64(&key).map_err(|e| format!("[fleet] policy key: {e}"))?);
    }
    if let Some(u) = &file.upstream {
        for p in &u.extra_roots {
            cfg.extra_upstream_roots.extend(load_pem_certs(p)?);
        }
        for (host, addr) in &u.pins {
            cfg.upstream_pins.insert(
                host.to_ascii_lowercase(),
                addr.parse().map_err(|e| format!("pin {host}: {e}"))?,
            );
        }
    }

    iso_proxy::run(cfg).await?;
    Ok(())
}

fn load_pem_certs(
    path: &Path,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let pem = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body: String = block
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap_or("")
            .lines()
            .map(str::trim)
            .collect();
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)?;
        out.push(rustls_pki_types::CertificateDer::from(der));
    }
    Ok(out)
}
