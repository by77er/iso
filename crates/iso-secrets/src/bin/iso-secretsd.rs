//! iso-secretsd — the SecretProvider RPC server.
//!
//! Always serves the Unix socket `$ISO_STATE_DIR/secrets.sock`. The backend
//! is an adapter picked by `ISO_SECRETS_PROVIDER`:
//!
//! - `toml` (default): `$ISO_STATE_DIR/secrets.toml`, hot-reloaded.
//! - `exec`: the program in `ISO_SECRETS_EXEC` (with `ISO_SECRETS_EXEC_ARGS`,
//!   whitespace-separated) answers both calls; see `ExecProvider`.
//!
//! With `ISO_SECRETS_LISTEN=host:port` and a service identity in
//! `ISO_TLS_CA`, `ISO_TLS_CERT`, `ISO_TLS_KEY`, it also serves `POST /headers`
//! over HTTPS with mutual TLS for proxy replicas on other machines.

use std::path::Path;
use std::sync::Arc;

use iso_secrets::{ExecProvider, SecretProvider, TomlSecretProvider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Log to stderr (RUST_LOG-overridable, default `info`) so `reload_if_changed`'s
    // "secrets reloaded" / "reload skipped" lines are visible in the daemon log.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let state = std::env::var("ISO_STATE_DIR").unwrap_or_else(|_| ".".into());
    let dir = Path::new(&state);

    let kind = std::env::var("ISO_SECRETS_PROVIDER").unwrap_or_else(|_| "toml".into());
    let provider: Arc<dyn SecretProvider> = match kind.as_str() {
        "toml" => {
            let p = Arc::new(TomlSecretProvider::load(&dir.join("secrets.toml"))?);
            iso_secrets::spawn_reload_watcher(p.clone());
            tracing::info!(
                "iso-secretsd: toml provider {}",
                dir.join("secrets.toml").display()
            );
            p
        }
        "exec" => {
            let program = std::env::var("ISO_SECRETS_EXEC")
                .map_err(|_| "ISO_SECRETS_PROVIDER=exec needs ISO_SECRETS_EXEC=<program>")?;
            let args: Vec<String> = std::env::var("ISO_SECRETS_EXEC_ARGS")
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_string)
                .collect();
            tracing::info!("iso-secretsd: exec provider {program} {}", args.join(" "));
            Arc::new(ExecProvider::new(program, args))
        }
        other => {
            return Err(format!("unknown ISO_SECRETS_PROVIDER {other:?} (toml | exec)").into());
        }
    };

    if let Ok(listen) = std::env::var("ISO_SECRETS_LISTEN") {
        let creds = iso_admin_pki::Creds::from_env()?
            .ok_or("ISO_SECRETS_LISTEN needs ISO_TLS_CA, ISO_TLS_CERT and ISO_TLS_KEY")?;
        let cfg = creds.server_config()?;
        let listener = tokio::net::TcpListener::bind(iso_rpc::parse_listen(&listen)?).await?;
        tracing::info!("iso-secretsd: https://{listen}/headers (mutual TLS)");
        let provider = provider.clone();
        tokio::spawn(async move {
            if let Err(e) = iso_secrets::serve_https(provider, listener, cfg).await {
                tracing::error!("iso-secretsd: https listener exited: {e}");
            }
        });
    }

    let sock = dir.join("secrets.sock");
    tracing::info!("iso-secretsd: listening on {}", sock.display());
    iso_secrets::serve_unix(provider, &sock).await?;
    Ok(())
}
