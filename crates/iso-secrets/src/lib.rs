//! iso-secrets — the SecretProvider: header injections keyed by (domain, principal).
//!
//! Backed by a static TOML (`$ISO_STATE_DIR/secrets.toml`). The provider merges
//! **global OVER per-principal** and returns the effective header set. See
//! `iso-proxy/DESIGN.md`.
//!
//! A header value is either a literal string (used verbatim) or a structured
//! token table that secretsd renders into the final value. The token form lets
//! the file say *what kind* of credential it holds instead of hand-encoding the
//! `Authorization` value — notably `basic` (which would otherwise require
//! base64). Resolution happens here, so the proxy still receives plain
//! `name -> value` headers; the RPC contract is unchanged.
//!
//! ```toml
//! [global."api.anthropic.com"]
//! "x-api-key" = "sk-ant-..."                          # literal, verbatim
//!
//! [principals.default."api.github.com"]
//! "authorization" = { bearer = "ghu_..." }            # -> "Bearer ghu_..."
//!
//! [principals.default."github.com"]
//! # git-over-HTTPS wants Basic, with the token as the password. `user`
//! # defaults to "x-access-token" (GitHub's convention).
//! "authorization" = { basic = "ghu_..." }             # -> "Basic base64(x-access-token:ghu_...)"
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Lookup request.
///
/// `domain` and `principal` are the original two fields. The other two are
/// additive and default, so a new caller and an old provider (or the reverse)
/// still understand each other: unknown fields are ignored on the way in, and
/// a missing field reads as the pre-existing behaviour.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HeadersRequest {
    pub domain: String,
    pub principal: Option<String>,
    /// Request path, **without** the query string, when the caller has one.
    ///
    /// A provider whose rules are path-scoped (Keysmith publishes `paths` and
    /// `exclude_paths` per endpoint, and is normative that `exclude_paths` must
    /// be honored) cannot apply them to a domain-only question, and has to
    /// choose between over-injecting and refusing. The query string is
    /// deliberately excluded: it routinely carries tokens and identifiers, and
    /// no path rule needs it.
    #[serde(default)]
    pub path: Option<String>,
    /// Ask what *would* be injected, without producing a credential.
    ///
    /// The answer is header **names** only, in [`HeadersResponse::names`]. A
    /// provider that mints on demand must not mint to answer this — the point
    /// is to let callers that are merely describing the environment (the guest
    /// metadata service) do so without issuing credentials, and without a
    /// guest being able to drive credential issuance by polling.
    #[serde(default)]
    pub names_only: bool,
}

impl HeadersRequest {
    pub fn new(domain: impl Into<String>, principal: Option<&str>) -> Self {
        Self {
            domain: domain.into(),
            principal: principal.map(str::to_string),
            ..Default::default()
        }
    }

    /// Attach the request path. Strips any query string for the caller.
    pub fn with_path(mut self, path: Option<&str>) -> Self {
        self.path = path.map(|p| p.split('?').next().unwrap_or(p).to_string());
        self
    }

    pub fn names_only(mut self) -> Self {
        self.names_only = true;
        self
    }
}

/// Effective headers to set/override (empty = inject nothing).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HeadersResponse {
    pub headers: HashMap<String, String>,
    /// Header names, for a [`HeadersRequest::names_only`] request. Empty
    /// otherwise, and empty from a provider that predates the field.
    #[serde(default)]
    pub names: Vec<String>,
}

impl HeadersResponse {
    /// The header names this response describes, whichever way the provider
    /// answered. A names-only caller must use this rather than reading
    /// `headers`: a provider that predates `names_only` answers such a request
    /// with the full headers, values included, and this keeps those values from
    /// reaching a caller that asked not to have them.
    pub fn header_names(&self) -> Vec<String> {
        let mut names: Vec<String> = if self.names.is_empty() {
            self.headers.keys().cloned().collect()
        } else {
            self.names.clone()
        };
        names.sort();
        names
    }
}

/// SecretProvider RPC client: one connection per call — write JSON, half-close,
/// read the JSON reply. Fail-open, matching the daemon: any error answers as
/// though nothing is configured, so a provider that is down degrades to "no
/// injection" rather than blocking egress.
pub struct Client {
    sock: PathBuf,
}

impl Client {
    pub fn new(sock: impl Into<PathBuf>) -> Self {
        Self { sock: sock.into() }
    }

    async fn call(&self, req: &HeadersRequest) -> std::io::Result<HeadersResponse> {
        let mut conn = UnixStream::connect(&self.sock).await?;
        conn.write_all(&serde_json::to_vec(req)?).await?;
        conn.shutdown().await?; // half-close: end of request
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await?;
        Ok(serde_json::from_slice(&buf)?)
    }

    /// Headers to inject for this request. `path` may be `None` when the caller
    /// has no path (or is not making a request on anyone's behalf).
    pub async fn headers(
        &self,
        domain: &str,
        principal: Option<&str>,
        path: Option<&str>,
    ) -> HashMap<String, String> {
        let req = HeadersRequest::new(domain, principal).with_path(path);
        match self.call(&req).await {
            Ok(r) => r.headers,
            Err(e) => {
                tracing::warn!("secrets rpc failed, injecting nothing: {e}");
                HashMap::new()
            }
        }
    }

    /// Which headers *would* be injected, without minting anything.
    pub async fn names(
        &self,
        domain: &str,
        principal: Option<&str>,
        path: Option<&str>,
    ) -> Vec<String> {
        let req = HeadersRequest::new(domain, principal)
            .with_path(path)
            .names_only();
        match self.call(&req).await {
            Ok(r) => r.header_names(),
            Err(e) => {
                tracing::warn!("secrets rpc failed, describing nothing: {e}");
                Vec::new()
            }
        }
    }
}

type DomainHeaders = HashMap<String, HashMap<String, HeaderSpec>>;

/// A header value as written in the secrets file. Either used verbatim or
/// rendered from a token table. Resolved to a plain string by [`HeaderSpec::render`]
/// before it ever leaves secretsd, so the proxy never sees this enum.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum HeaderSpec {
    /// Used verbatim, e.g. `x-api-key = "sk-..."` or `authorization = "Bearer x"`.
    Literal(String),
    /// `authorization = { bearer = "<token>" }` -> `Bearer <token>`.
    Bearer { bearer: String },
    /// `authorization = { basic = "<token>", user = "<user>" }` ->
    /// `Basic base64("<user>:<token>")`. `user` defaults to `x-access-token`
    /// (the GitHub git-over-HTTPS convention: the token is the password).
    Basic {
        basic: String,
        #[serde(default = "default_basic_user")]
        user: String,
    },
}

fn default_basic_user() -> String {
    "x-access-token".to_string()
}

impl HeaderSpec {
    /// Render to the final header value the proxy will inject.
    fn render(&self) -> String {
        use base64::Engine as _;
        match self {
            HeaderSpec::Literal(s) => s.clone(),
            HeaderSpec::Bearer { bearer } => format!("Bearer {bearer}"),
            HeaderSpec::Basic { basic, user } => {
                let creds =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{basic}"));
                format!("Basic {creds}")
            }
        }
    }
}

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
            out.extend(h.iter().map(|(k, v)| (k.clone(), v.render())));
        }
        if let Some(h) = cache.file.global.get(domain) {
            out.extend(h.iter().map(|(k, v)| (k.clone(), v.render())));
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
            // The TOML file is keyed by domain alone, so `path` has nothing to
            // narrow here; it exists for providers whose rules are path-scoped.
            // Nothing is minted either way, so `names_only` is just a projection.
            let out = match serde_json::from_slice::<HeadersRequest>(&buf) {
                Ok(r) => {
                    let headers = provider.headers(&r.domain, r.principal.as_deref());
                    if r.names_only {
                        let mut names: Vec<String> = headers.into_keys().collect();
                        names.sort();
                        HeadersResponse { names, ..Default::default() }
                    } else {
                        HeadersResponse { headers, ..Default::default() }
                    }
                }
                Err(_) => Default::default(), // fail-open
            };
            let resp = serde_json::to_vec(&out).unwrap_or_default();
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
"authorization" = { bearer = "gh" }

[principals.default."github.com"]
"authorization" = { basic = "gh" }

[principals.default."example.test"]
"authorization" = { basic = "tok", user = "alice" }

[principals.default."verbatim.test"]
"authorization" = "Bearer literal"
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
    fn bearer_basic_and_literal_render() {
        let p = TomlSecretProvider::from_toml(TOML).unwrap();
        // bearer token table -> "Bearer <token>".
        assert_eq!(
            p.headers("api.github.com", Some("default")).get("authorization").unwrap(),
            "Bearer gh"
        );
        // basic token table -> "Basic base64(x-access-token:<token>)" (default user).
        assert_eq!(
            p.headers("github.com", Some("default")).get("authorization").unwrap(),
            "Basic eC1hY2Nlc3MtdG9rZW46Z2g=" // base64("x-access-token:gh")
        );
        // basic with explicit user.
        assert_eq!(
            p.headers("example.test", Some("default")).get("authorization").unwrap(),
            "Basic YWxpY2U6dG9r" // base64("alice:tok")
        );
        // a plain string is still used verbatim.
        assert_eq!(
            p.headers("verbatim.test", Some("default")).get("authorization").unwrap(),
            "Bearer literal"
        );
    }

    #[test]
    fn unknown_domain_empty() {
        let p = TomlSecretProvider::from_toml(TOML).unwrap();
        assert!(p.headers("example.com", Some("default")).is_empty());
    }

    #[test]
    fn request_defaults_are_the_old_wire_format() {
        // A request written before `path`/`names_only` existed still parses,
        // and reads as the behaviour it had then.
        let r: HeadersRequest =
            serde_json::from_str(r#"{"domain":"api.example.com","principal":"alice"}"#).unwrap();
        assert_eq!(r.domain, "api.example.com");
        assert_eq!(r.path, None);
        assert!(!r.names_only);
    }

    #[test]
    fn with_path_drops_the_query_string() {
        // Query strings carry tokens and identifiers; no path rule needs them.
        let r = HeadersRequest::new("api.example.com", None).with_path(Some("/v1/x?token=sk-secret"));
        assert_eq!(r.path.as_deref(), Some("/v1/x"));
    }

    #[test]
    fn header_names_never_exposes_values() {
        // A provider that predates `names_only` answers a names-only request
        // with full headers. The accessor must still yield only names.
        let old_style = HeadersResponse {
            headers: HashMap::from([("authorization".into(), "Bearer sk-secret".into())]),
            names: vec![],
        };
        assert_eq!(old_style.header_names(), vec!["authorization".to_string()]);

        let new_style = HeadersResponse {
            headers: HashMap::new(),
            names: vec!["x-api-key".into(), "authorization".into()],
        };
        assert_eq!(
            new_style.header_names(),
            vec!["authorization".to_string(), "x-api-key".to_string()] // sorted
        );
    }

    #[tokio::test]
    async fn names_only_answers_names_and_withholds_values() {
        let dir = std::env::temp_dir().join(format!("iso-secrets-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("secrets.sock");

        let provider = Arc::new(TomlSecretProvider::from_toml(TOML).unwrap());
        let listen = sock.clone();
        tokio::spawn(async move { serve_unix(provider, &listen).await });
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let client = Client::new(&sock);
        let headers = client.headers("api.anthropic.com", Some("default"), None).await;
        assert_eq!(headers.get("x-api-key").map(String::as_str), Some("global-key"));

        let names = client.names("api.anthropic.com", Some("default"), None).await;
        assert!(names.contains(&"x-api-key".to_string()));
        assert!(!names.contains(&"global-key".to_string()));

        // And the raw response for a names-only request carries no values.
        let resp = client
            .call(&HeadersRequest::new("api.anthropic.com", Some("default")).names_only())
            .await
            .unwrap();
        assert!(resp.headers.is_empty(), "names_only must not return values");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
