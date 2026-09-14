//! iso-fleetd — the fleet service. `iso-fleetd fleet.toml` (or
//! `ISO_FLEET_CONFIG`). See `config.rs` for the file.

use std::path::PathBuf;
use std::time::Duration;

use iso_fleet::{Config, Fleet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ISO_FLEET_CONFIG").ok())
        .ok_or("usage: iso-fleetd <config.toml> (or ISO_FLEET_CONFIG)")?;
    let cfg = Config::load(&PathBuf::from(path))?;
    let listen = cfg.listen;
    let insecure = cfg.insecure;
    let pki_dir = cfg.pki_dir.clone();
    let extra_sans = cfg.extra_sans.clone();
    let every = Duration::from_millis(cfg.sync_every_ms);

    let fleet = Fleet::new(cfg)?;
    tracing::info!("iso-fleetd: {} host(s) configured", fleet.hosts.len());
    tokio::spawn(iso_fleet::sync::run(fleet.clone(), every));

    let listener = tokio::net::TcpListener::bind(listen).await?;
    let router = iso_fleet::router(fleet);
    if insecure {
        tracing::warn!("iso-fleetd: PLAIN HTTP on {listen}, unauthenticated (insecure = true)");
        axum::serve(listener, router).await?;
    } else {
        let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        if !listen.ip().is_unspecified() {
            sans.push(listen.ip().to_string());
        }
        sans.extend(extra_sans);
        let pki = iso_admin_pki::AdminPki::load_or_generate(&pki_dir, &sans)?;
        let acceptor = iso_fleet::tls::acceptor(&pki)?;
        tracing::info!(
            "iso-fleetd: https://{listen} (mutual TLS; client certs from {})",
            pki_dir.join("ca.crt").display()
        );
        iso_fleet::tls::serve(listener, acceptor, router).await;
    }
    Ok(())
}
