//! iso-proxyd — the egress proxy daemon.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use iso_proxy::{ProxyConfig, RpcResolver, run};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let state = PathBuf::from(std::env::var("ISO_STATE_DIR").unwrap_or_else(|_| ".".into()));
    let listen = std::env::var("ISO_PROXY_LISTEN")
        .unwrap_or_else(|_| "172.22.0.1:443".into())
        .parse()?;

    // Per-VM policy comes from the control plane (identify RPC), short-TTL cached.
    let resolver = Arc::new(RpcResolver::new(
        state.join("identify.sock"),
        Duration::from_secs(1),
    ));

    run(ProxyConfig {
        listen,
        ca_sock: state.join("ca.sock"),
        secrets_sock: state.join("secrets.sock"),
        resolver,
    })
    .await?;
    Ok(())
}
