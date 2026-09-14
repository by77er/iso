//! A template rootfs from an OCI image.
//!
//! Three sources, one result: the image's filesystem laid out in a mounted
//! volume, layer by layer with whiteouts honoured, plus the image config
//! the guest's init needs (environment, working directory, user).
//!
//! - `pull(reference)`: the registry API, anonymous or with a bearer token
//!   the registry hands out on demand (Docker Hub, GHCR, Quay all do), a
//!   manifest list narrowed to linux/amd64, blobs checked against their
//!   digests. No daemon needed: an iso host has no Docker.
//! - `from_archive(path)`: a `docker save` tarball, an OCI image layout
//!   tarball, or a plain `docker export` rootfs tarball.
//!
//! What is *not* here is anything the guest runs at boot: an image has no
//! init, so the agent is one (see `iso_guest_agent::init`), and `install`
//! puts the agent, the image config, the resolver and the proxy's CA where
//! that init and every runtime in the image will find them.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

type R<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// What the guest's init reads at boot (`/etc/iso/image.json`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub workdir: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    /// Where it came from, for the record.
    #[serde(default)]
    pub source: String,
}

// ------------------------------------------------------------ reference ----

/// `[registry/]repository[:tag|@digest]`, Docker's conventions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    /// A tag or a `sha256:…` digest.
    pub reference: String,
}

impl Reference {
    pub fn parse(s: &str) -> R<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty image reference".into());
        }
        let (name, reference) = match s.split_once('@') {
            Some((n, d)) => (n.to_string(), d.to_string()),
            None => {
                // The last ':' is a tag only if it is after the last '/'.
                match s.rsplit_once(':') {
                    Some((n, t)) if !t.contains('/') => (n.to_string(), t.to_string()),
                    _ => (s.to_string(), "latest".to_string()),
                }
            }
        };
        let (registry, mut repository) = match name.split_once('/') {
            Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
                (first.to_string(), rest.to_string())
            }
            _ => ("docker.io".to_string(), name),
        };
        let registry = if registry == "docker.io" || registry == "index.docker.io" {
            if !repository.contains('/') {
                repository = format!("library/{repository}");
            }
            "registry-1.docker.io".to_string()
        } else {
            registry
        };
        Ok(Self { registry, repository, reference })
    }

    fn url(&self, path: &str) -> String {
        let scheme = if self.registry.starts_with("localhost") || self.registry.starts_with("127.") {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{}/v2/{}/{path}", self.registry, self.repository)
    }
}

// ------------------------------------------------------------- registry ----

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
                      application/vnd.oci.image.manifest.v1+json, \
                      application/vnd.docker.distribution.manifest.list.v2+json, \
                      application/vnd.docker.distribution.manifest.v2+json";

#[derive(Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}
#[derive(Deserialize)]
struct Platform {
    #[serde(default)]
    os: String,
    #[serde(default)]
    architecture: String,
}
#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    manifests: Vec<Descriptor>,
    #[serde(default)]
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}
#[derive(Deserialize, Default)]
struct ConfigBlob {
    #[serde(default)]
    config: Option<ContainerConfig>,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct ContainerConfig {
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    user: Option<String>,
}

/// One registry, one repository, a token once it has been asked for.
struct Registry {
    http: reqwest::Client,
    reference: Reference,
    token: Option<String>,
    /// `Basic …` for a private registry, from `ISO_REGISTRY_AUTH=user:pass`.
    basic: Option<String>,
}

impl Registry {
    fn new(reference: Reference) -> R<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let basic = std::env::var("ISO_REGISTRY_AUTH").ok().filter(|v| !v.is_empty()).map(|up| {
            use base64::Engine as _;
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(up))
        });
        Ok(Self {
            http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(5)).build()?,
            reference,
            token: None,
            basic,
        })
    }

    /// GET with the token we have; on 401, get the token the registry asks
    /// for (anonymous pull, or the basic credentials) and try once more.
    async fn get(&mut self, url: &str, accept: &str) -> R<reqwest::Response> {
        for attempt in 0..2 {
            let mut req = self.http.get(url).header("accept", accept);
            if let Some(t) = &self.token {
                req = req.bearer_auth(t);
            } else if let Some(b) = &self.basic {
                req = req.header("authorization", b);
            }
            let resp = req.send().await?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                let challenge = resp
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                self.token = Some(self.fetch_token(&challenge).await?);
                continue;
            }
            if !resp.status().is_success() {
                return Err(format!("{url}: http {}", resp.status()).into());
            }
            return Ok(resp);
        }
        unreachable!()
    }

    /// `Bearer realm="…",service="…",scope="…"` → a token.
    async fn fetch_token(&self, challenge: &str) -> R<String> {
        let rest = challenge
            .strip_prefix("Bearer ")
            .ok_or_else(|| format!("unsupported auth challenge: {challenge:?}"))?;
        let mut params: HashMap<String, String> = HashMap::new();
        for part in rest.split(',') {
            if let Some((k, v)) = part.trim().split_once('=') {
                params.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
        let realm = params.get("realm").ok_or("auth challenge without a realm")?;
        let mut req = self.http.get(realm).query(&[
            ("service", params.get("service").cloned().unwrap_or_default()),
            ("scope", params.get("scope").cloned().unwrap_or_else(|| format!("repository:{}:pull", self.reference.repository))),
        ]);
        if let Some(b) = &self.basic {
            req = req.header("authorization", b);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(format!("token from {realm}: http {}", resp.status()).into());
        }
        #[derive(Deserialize)]
        struct Token {
            #[serde(default)]
            token: Option<String>,
            #[serde(default)]
            access_token: Option<String>,
        }
        let t: Token = resp.json().await?;
        t.token.or(t.access_token).ok_or_else(|| "token response without a token".into())
    }

    async fn manifest(&mut self, reference: &str) -> R<Manifest> {
        let url = self.reference.url(&format!("manifests/{reference}"));
        let m: Manifest = self.get(&url, ACCEPT).await?.json().await?;
        Ok(m)
    }

    /// Download a blob to `into`, checking its digest on the way.
    async fn blob(&mut self, digest: &str, into: &Path) -> R<()> {
        use futures_util::StreamExt as _;
        let url = self.reference.url(&format!("blobs/{digest}"));
        let resp = self.get(&url, "*/*").await?;
        let mut file = std::fs::File::create(into)?;
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            file.write_all(&chunk)?;
        }
        let got = format!("sha256:{}", hex(hasher.finish().as_ref()));
        if got != digest {
            let _ = std::fs::remove_file(into);
            return Err(format!("blob {digest}: digest mismatch ({got})").into());
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Pull `reference` and lay its filesystem out in `dest`. Returns the
/// image config the guest's init will need.
pub async fn pull(reference: &str, dest: &Path) -> R<ImageConfig> {
    let r = Reference::parse(reference)?;
    eprintln!("[bake] pulling {}/{}:{}", r.registry, r.repository, r.reference);
    let mut reg = Registry::new(r.clone())?;
    let mut m = reg.manifest(&r.reference).await?;
    if !m.manifests.is_empty() {
        // An index: the linux/amd64 entry, which is what the guest kernel runs.
        let pick = m
            .manifests
            .iter()
            .find(|d| d.platform.as_ref().is_some_and(|p| p.os == "linux" && p.architecture == "amd64"))
            .or_else(|| m.manifests.iter().find(|d| d.platform.is_none()))
            .ok_or("the image has no linux/amd64 manifest")?;
        let digest = pick.digest.clone();
        m = reg.manifest(&digest).await?;
    }
    if m.layers.is_empty() {
        return Err(format!("no layers in the manifest ({})", m.media_type).into());
    }
    let tmp = tempfile::Builder::new().prefix("iso-oci-").tempdir()?;
    let mut config = ImageConfig { source: reference.to_string(), ..Default::default() };
    if let Some(c) = &m.config {
        let path = tmp.path().join("config.json");
        reg.blob(&c.digest, &path).await?;
        let blob: ConfigBlob = serde_json::from_slice(&std::fs::read(&path)?)?;
        if let Some(cc) = blob.config {
            config.env = cc.env;
            config.workdir = cc.working_dir.filter(|w| !w.is_empty());
            config.user = cc.user.filter(|u| !u.is_empty());
        }
    }
    for (i, layer) in m.layers.iter().enumerate() {
        let path = tmp.path().join(format!("layer-{i}"));
        eprintln!("[bake] layer {}/{} {}", i + 1, m.layers.len(), &layer.digest[..19]);
        reg.blob(&layer.digest, &path).await?;
        apply_layer(&path, &layer.media_type, dest)?;
        let _ = std::fs::remove_file(&path);
    }
    Ok(config)
}

// -------------------------------------------------------------- archives ----

/// Lay out the image in `path` (a `docker save` tarball, an OCI layout
/// tarball, or a bare rootfs tarball from `docker export`) in `dest`.
pub fn from_archive(path: &Path, dest: &Path) -> R<ImageConfig> {
    let tmp = tempfile::Builder::new().prefix("iso-oci-").tempdir()?;
    // Unpack the outer archive to look at it: manifest.json (docker save),
    // index.json (OCI layout), or neither (a plain rootfs).
    tar::Archive::new(std::fs::File::open(path)?).unpack(tmp.path())?;
    let mut config = ImageConfig { source: path.display().to_string(), ..Default::default() };

    let docker_manifest = tmp.path().join("manifest.json");
    let oci_index = tmp.path().join("index.json");
    let (layers, config_path): (Vec<PathBuf>, Option<PathBuf>) = if docker_manifest.exists() {
        #[derive(Deserialize)]
        struct Entry {
            #[serde(rename = "Config")]
            config: String,
            #[serde(rename = "Layers")]
            layers: Vec<String>,
        }
        let entries: Vec<Entry> = serde_json::from_slice(&std::fs::read(&docker_manifest)?)?;
        let e = entries.into_iter().next().ok_or("empty docker manifest")?;
        (
            e.layers.iter().map(|l| tmp.path().join(l)).collect(),
            Some(tmp.path().join(e.config)),
        )
    } else if oci_index.exists() {
        #[derive(Deserialize)]
        struct Index {
            manifests: Vec<Descriptor>,
        }
        let blob = |digest: &str| -> PathBuf {
            let (algo, hexd) = digest.split_once(':').unwrap_or(("sha256", digest));
            tmp.path().join("blobs").join(algo).join(hexd)
        };
        let idx: Index = serde_json::from_slice(&std::fs::read(&oci_index)?)?;
        let mut d = idx.manifests.into_iter().next().ok_or("empty OCI index")?;
        let mut m: Manifest = serde_json::from_slice(&std::fs::read(blob(&d.digest))?)?;
        if !m.manifests.is_empty() {
            let pick = m
                .manifests
                .into_iter()
                .find(|x| x.platform.as_ref().is_none_or(|p| p.os == "linux" && p.architecture == "amd64"))
                .ok_or("no linux/amd64 manifest in the index")?;
            d = pick;
            m = serde_json::from_slice(&std::fs::read(blob(&d.digest))?)?;
        }
        (
            m.layers.iter().map(|l| blob(&l.digest)).collect(),
            m.config.as_ref().map(|c| blob(&c.digest)),
        )
    } else {
        // A bare rootfs: what was unpacked is the filesystem.
        eprintln!("[bake] {} is a plain rootfs archive", path.display());
        copy_tree(tmp.path(), dest)?;
        return Ok(config);
    };
    if let Some(cp) = config_path {
        let blob: ConfigBlob = serde_json::from_slice(&std::fs::read(&cp)?)?;
        if let Some(cc) = blob.config {
            config.env = cc.env;
            config.workdir = cc.working_dir.filter(|w| !w.is_empty());
            config.user = cc.user.filter(|u| !u.is_empty());
        }
    }
    for (i, layer) in layers.iter().enumerate() {
        eprintln!("[bake] layer {}/{}", i + 1, layers.len());
        apply_layer(layer, "", dest)?;
    }
    Ok(config)
}

fn copy_tree(from: &Path, to: &Path) -> R<()> {
    let st = std::process::Command::new("cp").args(["-a", "--"]).arg(format!("{}/.", from.display())).arg(to).status()?;
    if !st.success() {
        return Err("cp -a failed".into());
    }
    Ok(())
}

// ---------------------------------------------------------------- layers ----

/// Apply one layer tarball (gzip, zstd not supported, or plain) to `dest`:
/// whiteouts delete, opaque whiteouts empty a directory, everything else
/// is unpacked over what is there, ownership and modes kept.
pub fn apply_layer(path: &Path, media_type: &str, dest: &Path) -> R<()> {
    let file = std::fs::File::open(path)?;
    let mut magic = [0u8; 4];
    {
        let mut f = std::fs::File::open(path)?;
        let _ = f.read(&mut magic);
    }
    let gzip = media_type.ends_with("gzip") || magic[..2] == [0x1f, 0x8b];
    if media_type.ends_with("zstd") || magic == [0x28, 0xb5, 0x2f, 0xfd] {
        return Err("zstd-compressed layers are not supported; re-push the image with gzip layers".into());
    }
    let reader: Box<dyn Read> = if gzip { Box::new(flate2::read::GzDecoder::new(file)) } else { Box::new(file) };
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    // Ownership only when it can be set: the bake runs as root, tests do not.
    archive.set_preserve_ownerships(unsafe { libc::geteuid() } == 0);
    archive.set_unpack_xattrs(true);
    archive.set_overwrite(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let rel = entry.path()?.into_owned();
        let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        let parent = rel.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        if name == ".wh..wh..opq" {
            let dir = dest.join(&parent);
            if dir.is_dir() {
                for e in std::fs::read_dir(&dir)? {
                    remove_any(&e?.path())?;
                }
            }
            continue;
        }
        if let Some(victim) = name.strip_prefix(".wh.") {
            remove_any(&dest.join(&parent).join(victim))?;
            continue;
        }
        // A directory turning into something else, or the reverse.
        let target = dest.join(&rel);
        let is_dir_entry = entry.header().entry_type().is_dir();
        if let Ok(meta) = std::fs::symlink_metadata(&target) {
            if meta.is_dir() != is_dir_entry || meta.file_type().is_symlink() {
                remove_any(&target)?;
            }
        }
        entry.unpack_in(dest)?;
    }
    Ok(())
}

fn remove_any(p: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// --------------------------------------------------------------- install ----

/// What the bake adds on top of the image: the agent (as init and as the
/// agent), the image config for the init, the resolver, the hostname, and
/// the proxy's CA in the system bundle and in a bundle of our own that the
/// environment points every runtime at. `ca` is the tier's certificate, PEM.
pub fn install(rootfs: &Path, agent_bin: &Path, mut config: ImageConfig, ca_pem: Option<&str>) -> R<()> {
    let bin = rootfs.join("usr/local/bin");
    std::fs::create_dir_all(&bin)?;
    std::fs::copy(agent_bin, bin.join("iso-guest-agent"))?;
    set_mode(&bin.join("iso-guest-agent"), 0o755)?;

    let etc = rootfs.join("etc");
    std::fs::create_dir_all(etc.join("iso"))?;
    std::fs::write(etc.join("resolv.conf"), "nameserver 172.22.0.1\n")?;
    std::fs::write(etc.join("hostname"), "iso-guest\n")?;
    let hosts = etc.join("hosts");
    let mut h = std::fs::read_to_string(&hosts).unwrap_or_default();
    if !h.contains("iso-guest") {
        h.push_str("127.0.0.1 localhost\n127.0.1.1 iso-guest\n");
        std::fs::write(&hosts, h)?;
    }

    if let Some(ca) = ca_pem {
        std::fs::write(etc.join("iso/ca.crt"), ca)?;
        // Into every system bundle the image has, so tools that read the
        // system store need nothing else.
        let mut bundle = String::new();
        for system in ["etc/ssl/certs/ca-certificates.crt", "etc/pki/tls/certs/ca-bundle.crt", "etc/ssl/cert.pem"] {
            let p = rootfs.join(system);
            if p.is_file() {
                let mut existing = std::fs::read_to_string(&p).unwrap_or_default();
                if bundle.is_empty() {
                    bundle = existing.clone();
                }
                if !existing.contains(ca.trim()) {
                    if !existing.ends_with('\n') && !existing.is_empty() {
                        existing.push('\n');
                    }
                    existing.push_str(ca);
                    std::fs::write(&p, existing)?;
                }
            }
        }
        if !bundle.ends_with('\n') && !bundle.is_empty() {
            bundle.push('\n');
        }
        bundle.push_str(ca);
        std::fs::write(etc.join("iso/ca-bundle.crt"), bundle)?;
        let anchors = rootfs.join("usr/local/share/ca-certificates");
        std::fs::create_dir_all(&anchors)?;
        std::fs::write(anchors.join("iso-egress-proxy.crt"), ca)?;
        // Runtimes that keep their own store read these; the init hands
        // them to the agent, the agent to every command.
        for (k, v) in [
            ("SSL_CERT_FILE", "/etc/iso/ca-bundle.crt"),
            ("SSL_CERT_DIR", "/etc/ssl/certs"),
            ("REQUESTS_CA_BUNDLE", "/etc/iso/ca-bundle.crt"),
            ("CURL_CA_BUNDLE", "/etc/iso/ca-bundle.crt"),
            ("GIT_SSL_CAINFO", "/etc/iso/ca-bundle.crt"),
            ("NODE_EXTRA_CA_CERTS", "/etc/iso/ca.crt"),
            ("PIP_CERT", "/etc/iso/ca-bundle.crt"),
        ] {
            if !config.env.iter().any(|e| e.starts_with(&format!("{k}="))) {
                config.env.push(format!("{k}={v}"));
            }
        }
    }
    if !config.env.iter().any(|e| e.starts_with("PATH=")) {
        config.env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }
    std::fs::write(etc.join("iso/image.json"), serde_json::to_string_pretty(&config)?)?;
    std::fs::write(
        etc.join("iso/AGENTS.md"),
        "# Notes for agents running in this VM\n\n\
         This VM is the image it was built from, booted under iso with the guest agent as init.\n\
         Outbound network goes through iso's egress proxy on the host: the proxy terminates TLS and\n\
         injects credentials in flight, so real credentials never exist in here. Use https://; plain\n\
         HTTP and other ports pass only where a tunnel rule allows them. The proxy's CA is in the\n\
         system store and in /etc/iso/ca-bundle.crt, which SSL_CERT_FILE and friends point at.\n",
    )?;
    Ok(())
}

fn set_mode(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_follow_docker_conventions() {
        let r = Reference::parse("python:3.12-slim").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("registry-1.docker.io", "library/python", "3.12-slim"));
        let r = Reference::parse("ghcr.io/acme/tool").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("ghcr.io", "acme/tool", "latest"));
        let r = Reference::parse("localhost:5000/x/y:v1").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("localhost:5000", "x/y", "v1"));
        assert_eq!(r.url("manifests/v1"), "http://localhost:5000/v2/x/y/manifests/v1");
        let r = Reference::parse("docker.io/acme/tool@sha256:abcd").unwrap();
        assert_eq!((r.repository.as_str(), r.reference.as_str()), ("acme/tool", "sha256:abcd"));
        assert!(Reference::parse("").is_err());
    }

    /// Build a layer tarball in memory.
    fn layer(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            match content {
                Some(data) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(data.len() as u64);
                    h.set_mode(0o644);
                    h.set_cksum();
                    b.append_data(&mut h, path, *data).unwrap();
                }
                None => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_size(0);
                    h.set_mode(0o755);
                    h.set_cksum();
                    b.append_data(&mut h, path, std::io::empty()).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn layers_stack_and_whiteouts_delete() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("rootfs");
        std::fs::create_dir_all(&dest).unwrap();
        let l1 = dir.path().join("l1.tar");
        std::fs::write(&l1, layer(&[("etc/", None), ("etc/a", Some(b"one")), ("etc/b", Some(b"two")), ("opt/", None), ("opt/x", Some(b"x")), ("opt/y", Some(b"y"))])).unwrap();
        let l2 = dir.path().join("l2.tar");
        std::fs::write(&l2, layer(&[("etc/a", Some(b"ONE")), ("etc/.wh.b", Some(b"")), ("opt/.wh..wh..opq", Some(b"")), ("opt/z", Some(b"z"))])).unwrap();
        apply_layer(&l1, "", &dest).unwrap();
        apply_layer(&l2, "", &dest).unwrap();
        assert_eq!(std::fs::read(dest.join("etc/a")).unwrap(), b"ONE", "a later layer replaces");
        assert!(!dest.join("etc/b").exists(), "a whiteout deletes");
        assert!(!dest.join("opt/x").exists() && !dest.join("opt/y").exists(), "an opaque whiteout empties");
        assert_eq!(std::fs::read(dest.join("opt/z")).unwrap(), b"z");
        assert!(!dest.join("etc/.wh.b").exists());
    }

    #[test]
    fn install_adds_the_agent_the_config_and_the_ca_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("etc/ssl/certs")).unwrap();
        std::fs::write(rootfs.join("etc/ssl/certs/ca-certificates.crt"), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").unwrap();
        let agent = dir.path().join("agent");
        std::fs::write(&agent, b"#!/bin/sh\n").unwrap();
        let cfg = ImageConfig { env: vec!["PATH=/custom".into(), "FOO=bar".into()], workdir: Some("/app".into()), user: Some("node".into()), source: "x".into() };
        let ca = "-----BEGIN CERTIFICATE-----\nISO\n-----END CERTIFICATE-----\n";
        install(&rootfs, &agent, cfg, Some(ca)).unwrap();
        let written: ImageConfig = serde_json::from_slice(&std::fs::read(rootfs.join("etc/iso/image.json")).unwrap()).unwrap();
        assert_eq!(written.workdir.as_deref(), Some("/app"));
        assert_eq!(written.user.as_deref(), Some("node"));
        assert!(written.env.contains(&"PATH=/custom".to_string()), "the image's PATH is kept");
        assert!(written.env.contains(&"SSL_CERT_FILE=/etc/iso/ca-bundle.crt".to_string()));
        let system = std::fs::read_to_string(rootfs.join("etc/ssl/certs/ca-certificates.crt")).unwrap();
        assert!(system.contains("ISO") && system.contains("AAAA"), "appended to the system bundle");
        let bundle = std::fs::read_to_string(rootfs.join("etc/iso/ca-bundle.crt")).unwrap();
        assert!(bundle.contains("AAAA") && bundle.ends_with(ca));
        assert_eq!(std::fs::read_to_string(rootfs.join("etc/resolv.conf")).unwrap(), "nameserver 172.22.0.1\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(rootfs.join("usr/local/bin/iso-guest-agent")).unwrap().permissions().mode() & 0o777, 0o755);
    }
}
