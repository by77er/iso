//! iso-cad — the CertAuthority RPC server.
//!
//! Always serves the Unix socket `$ISO_STATE_DIR/ca.sock` with CA material
//! under `$ISO_STATE_DIR/ca/`. With `ISO_CA_LISTEN=host:port` and a service
//! identity in `ISO_TLS_CA`, `ISO_TLS_CERT`, `ISO_TLS_KEY` (from `isoctl admin
//! issue-server`), it also serves `POST /sign` over HTTPS with mutual TLS for
//! proxy replicas on other machines.

use std::path::Path;
use std::sync::Arc;

use iso_ca::Ca;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let state = std::env::var("ISO_STATE_DIR").unwrap_or_else(|_| ".".into());
    let dir = Path::new(&state);
    let ca = Arc::new(Ca::load_or_generate(&dir.join("ca"))?);
    let sock = dir.join("ca.sock");

    if let Ok(listen) = std::env::var("ISO_CA_LISTEN") {
        let creds = iso_admin_pki::Creds::from_env()?
            .ok_or("ISO_CA_LISTEN needs ISO_TLS_CA, ISO_TLS_CERT and ISO_TLS_KEY")?;
        // Only the proxy tier signs CSRs here; every other identity the CA
        // issued (edges, hosts) is refused by name.
        let allow = iso_rpc::ClientAllow::parse(
            &std::env::var("ISO_ALLOWED_CLIENTS")
                .map_err(|_| "ISO_CA_LISTEN needs ISO_ALLOWED_CLIENTS=<name>[,<name>...]: the client certificate names allowed to sign")?,
        )?;
        let cfg = creds.server_config()?;
        let listener = tokio::net::TcpListener::bind(iso_rpc::parse_listen(&listen)?).await?;
        tracing::info!("iso-cad: https://{listen}/sign (mutual TLS)");
        let ca = ca.clone();
        tokio::spawn(async move {
            if let Err(e) = iso_ca::serve_https(ca, listener, cfg, allow).await {
                tracing::error!("iso-cad: https listener exited: {e}");
            }
        });
    }

    tracing::info!("iso-cad: listening on {}", sock.display());
    iso_ca::serve_unix(ca, &sock).await?;
    Ok(())
}
