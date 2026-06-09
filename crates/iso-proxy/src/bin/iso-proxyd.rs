//! iso-proxyd — the egress proxy daemon.

use std::collections::HashSet;
use std::path::PathBuf;

use iso_proxy::{ProxyConfig, run};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let state = std::env::var("ISO_STATE_DIR").unwrap_or_else(|_| ".".into());
    let state = PathBuf::from(state);
    let listen = std::env::var("ISO_PROXY_LISTEN")
        .unwrap_or_else(|_| "172.22.0.1:8443".into())
        .parse()?;
    let principal = std::env::var("ISO_PROXY_PRINCIPAL").ok();
    let allow: HashSet<String> = std::env::var("ISO_PROXY_ALLOW")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    run(ProxyConfig {
        listen,
        ca_sock: state.join("ca.sock"),
        secrets_sock: state.join("secrets.sock"),
        principal,
        allow,
    })
    .await?;
    Ok(())
}
