//! iso-cad — the CertAuthority RPC server. Socket `$ISO_STATE_DIR/ca.sock`,
//! CA material under `$ISO_STATE_DIR/ca/`.

use std::path::Path;
use std::sync::Arc;

use iso_ca::Ca;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = std::env::var("ISO_STATE_DIR").unwrap_or_else(|_| ".".into());
    let dir = Path::new(&state);
    let ca = Arc::new(Ca::load_or_generate(&dir.join("ca"))?);
    let sock = dir.join("ca.sock");
    eprintln!("iso-cad: listening on {}", sock.display());
    iso_ca::serve_unix(ca, &sock).await?;
    Ok(())
}
