//! iso-secretsd — the SecretProvider RPC server. Socket
//! `$ISO_STATE_DIR/secrets.sock`, TOML at `$ISO_STATE_DIR/secrets.toml`.

use std::path::Path;
use std::sync::Arc;

use iso_secrets::TomlSecretProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let provider = Arc::new(TomlSecretProvider::load(&dir.join("secrets.toml"))?);
    let sock = dir.join("secrets.sock");
    tracing::info!("iso-secretsd: listening on {}", sock.display());
    iso_secrets::serve_unix(provider, &sock).await?;
    Ok(())
}
