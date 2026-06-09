//! iso-secrets — the SecretProvider: header injections keyed by (domain, principal).
//!
//! Backed by a static TOML (`$ISO_STATE_DIR/secrets.toml`). The provider merges
//! **global OVER per-principal** and returns the effective header set. See
//! `iso-proxy/DESIGN.md`.
//!
//! ```toml
//! [global."api.anthropic.com"]
//! "x-api-key" = "sk-ant-..."
//! [principals.default."api.github.com"]
//! "authorization" = "Bearer ghp_..."
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// `(domain, principal)` lookup request.
#[derive(Debug, Serialize, Deserialize)]
pub struct HeadersRequest {
    pub domain: String,
    pub principal: Option<String>,
}

/// Effective headers to set/override (empty = inject nothing).
#[derive(Debug, Serialize, Deserialize)]
pub struct HeadersResponse {
    pub headers: HashMap<String, String>,
}

type DomainHeaders = HashMap<String, HashMap<String, String>>;

#[derive(Debug, Default, Deserialize)]
struct SecretsFile {
    /// domain -> headers, injected for every principal (override per-principal).
    #[serde(default)]
    global: DomainHeaders,
    /// principal -> domain -> headers.
    #[serde(default)]
    principals: HashMap<String, DomainHeaders>,
}

struct Cached {
    file: SecretsFile,
    mtime: Option<SystemTime>,
}

fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// TOML-backed secret provider. Hot-reloads the file when it changes on disk
/// (checked per request + by a background watcher in [`serve_unix`]).
pub struct TomlSecretProvider {
    path: Option<PathBuf>,
    cache: RwLock<Cached>,
}

impl TomlSecretProvider {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self {
            path: Some(path.to_path_buf()),
            cache: RwLock::new(Cached {
                file: toml::from_str(&text)?,
                mtime: mtime_of(path),
            }),
        })
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        Ok(Self {
            path: None,
            cache: RwLock::new(Cached {
                file: toml::from_str(text)?,
                mtime: None,
            }),
        })
    }

    /// Reload the TOML if it changed since the last read (cheap mtime check).
    /// A parse failure keeps the last-good config and logs, so a bad edit can't
    /// take down injection.
    pub fn reload_if_changed(&self) {
        let Some(path) = &self.path else { return };
        let cur = mtime_of(path);
        if self.cache.read().unwrap().mtime == cur {
            return;
        }
        match std::fs::read_to_string(path).and_then(|t| {
            toml::from_str::<SecretsFile>(&t)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }) {
            Ok(file) => {
                *self.cache.write().unwrap() = Cached { file, mtime: cur };
                tracing::info!("secrets reloaded from {}", path.display());
            }
            Err(e) => tracing::warn!("secrets reload skipped ({e}); keeping previous config"),
        }
    }

    /// Effective headers for `(domain, principal)`: per-principal first, then
    /// global overlaid on top (global wins).
    pub fn headers(&self, domain: &str, principal: Option<&str>) -> HashMap<String, String> {
        self.reload_if_changed();
        let cache = self.cache.read().unwrap();
        let mut out = HashMap::new();
        if let Some(p) = principal
            && let Some(by_domain) = cache.file.principals.get(p)
            && let Some(h) = by_domain.get(domain)
        {
            out.extend(h.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        if let Some(h) = cache.file.global.get(domain) {
            out.extend(h.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        out
    }
}

/// Serve the SecretProvider RPC on `sock` (JSON, half-close delimited).
pub async fn serve_unix(provider: Arc<TomlSecretProvider>, sock: &Path) -> std::io::Result<()> {
    // Watch the config file: reload on change even when idle.
    {
        let provider = provider.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                provider.reload_if_changed();
            }
        });
    }

    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock)?;
    loop {
        let (mut conn, _) = listener.accept().await?;
        let provider = provider.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            if conn.read_to_end(&mut buf).await.is_err() {
                return;
            }
            let headers = match serde_json::from_slice::<HeadersRequest>(&buf) {
                Ok(r) => provider.headers(&r.domain, r.principal.as_deref()),
                Err(_) => Default::default(), // fail-open
            };
            let resp = serde_json::to_vec(&HeadersResponse { headers }).unwrap_or_default();
            let _ = conn.write_all(&resp).await;
            let _ = conn.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOML: &str = r#"
[global."api.anthropic.com"]
"x-api-key" = "global-key"
"anthropic-version" = "2023-06-01"

[principals.default."api.anthropic.com"]
"x-api-key" = "per-principal-key"
"x-user" = "default"

[principals.default."api.github.com"]
"authorization" = "Bearer gh"
"#;

    #[test]
    fn global_overrides_principal_and_merges() {
        let p = TomlSecretProvider::from_toml(TOML).unwrap();
        let h = p.headers("api.anthropic.com", Some("default"));
        // global wins on the shared key...
        assert_eq!(h.get("x-api-key").unwrap(), "global-key");
        // ...global-only and principal-only keys both present.
        assert_eq!(h.get("anthropic-version").unwrap(), "2023-06-01");
        assert_eq!(h.get("x-user").unwrap(), "default");
    }

    #[test]
    fn principal_only_domain() {
        let p = TomlSecretProvider::from_toml(TOML).unwrap();
        assert_eq!(
            p.headers("api.github.com", Some("default")).get("authorization").unwrap(),
            "Bearer gh"
        );
        // no principal => no per-principal headers, only (absent) global.
        assert!(p.headers("api.github.com", None).is_empty());
    }

    #[test]
    fn unknown_domain_empty() {
        let p = TomlSecretProvider::from_toml(TOML).unwrap();
        assert!(p.headers("example.com", Some("default")).is_empty());
    }
}
