//! A template rootfs from an OCI image.
//!
//! Three sources, one result: the image's filesystem laid out in a mounted
//! volume, layer by layer with whiteouts honoured, plus the image config
//! the guest's init needs (environment, working directory, user). Every
//! path an image names is resolved inside that volume (see `Rootfs`).
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
use std::ffi::{CString, OsStr};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

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
/// takes the place of what is there (a directory over a directory is
/// merged into it), ownership and modes kept.
///
/// Every path is read the way the guest will read it, inside `dest` (see
/// [`Rootfs`]), never on the host: a leading `/` is dropped and an entry
/// with `..` in its path is skipped, as `tar` does, and a symlink an
/// earlier layer left is followed with `dest` as `/`.
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
    let root = Rootfs::open(dest)?;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.into_owned();
        let at = |e: std::io::Error| format!("{}: {e}", raw.display());
        let Some(rel) = in_image(&raw) else {
            eprintln!("[bake] skipped {}: `..` in the path", raw.display());
            continue;
        };
        // `./`, the rootfs itself, which `tar` leaves alone too.
        let (Some(name), Some(parent)) = (rel.file_name(), rel.parent()) else { continue };
        if name == ".wh..wh..opq" {
            if let Some(dir) = root.find_dir(parent).map_err(at)? {
                for e in std::fs::read_dir(fd_path(&dir)).map_err(at)? {
                    remove_any(&fd_path(&dir).join(e.map_err(at)?.file_name())).map_err(at)?;
                }
            }
            continue;
        }
        if let Some(victim) = name.as_bytes().strip_prefix(b".wh.") {
            // `.wh.`, `.wh..` and `.wh...` would name the directory or its parent.
            if !matches!(victim, b"" | b"." | b"..")
                && let Some(dir) = root.find_dir(parent).map_err(at)?
            {
                remove_any(&fd_path(&dir).join(OsStr::from_bytes(victim))).map_err(at)?;
            }
            continue;
        }
        let dir = root.make_dir(parent).map_err(at)?;
        let target = fd_path(&dir).join(name);
        // What is there goes unless both are directories: a file over a
        // directory, a directory over a file or a symlink, a link over a file.
        let kind = entry.header().entry_type();
        if std::fs::symlink_metadata(&target).is_ok_and(|m| !(m.is_dir() && kind.is_dir())) {
            remove_any(&target).map_err(at)?;
        }
        if kind.is_hard_link() {
            // `tar` would take the link's target as a host path. It is a
            // path in the image, with `..` stopping at the top, as for a
            // symlink; the target itself is linked, not followed.
            let link = entry.link_name()?.ok_or_else(|| format!("{}: a hard link without a target", raw.display()))?.into_owned();
            let missing = || format!("{}: no {} in the image to link to", raw.display(), link.display());
            let (Some(from), Some(from_dir)) = (link.file_name(), link.parent()) else {
                return Err(missing().into());
            };
            let from_dir = root.find_dir(from_dir).map_err(at)?.ok_or_else(missing)?;
            std::fs::hard_link(fd_path(&from_dir).join(from), &target).map_err(at)?;
        } else {
            entry.unpack(&target).map_err(at)?;
        }
    }
    Ok(())
}

/// An entry's path relative to the rootfs, the way `tar`'s own `unpack_in`
/// takes it: `/` and `.` components dropped, so `/etc/x` is the image's
/// `etc/x`, and `None` for a path with `..` in it, which is skipped.
fn in_image(path: &Path) -> Option<PathBuf> {
    let mut rel = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(p) => rel.push(p),
            Component::ParentDir => return None,
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    Some(rel)
}

/// Remove what `p` names without following it: a symlink goes, not what it
/// points at. `remove_dir_all` does not follow symlinks below it either.
fn remove_any(p: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------- rootfs ----

/// The rootfs being laid out, held open, with every path in it looked up
/// through `openat2(2)` and `RESOLVE_IN_ROOT`, which makes it `/` for the
/// lookup: a path resolves the way it will in the guest. An absolute
/// symlink in the image (Debian's `var/run -> /run`) lands on the image's
/// `/run`, and `..` stops at the top, as in a chroot. The bake runs as
/// root on the host, and this is what keeps what an image holds from
/// naming a host file. Linux 5.6 or later.
struct Rootfs(OwnedFd);

impl Rootfs {
    fn open(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let dir = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(path)?;
        Ok(Self(dir.into()))
    }

    /// `rel` opened under the rootfs; `mode` is for `O_CREAT`, else 0.
    fn open_at(&self, rel: &Path, flags: libc::c_int, mode: libc::mode_t) -> std::io::Result<OwnedFd> {
        let rel = if rel.as_os_str().is_empty() { Path::new(".") } else { rel };
        let name = CString::new(rel.as_os_str().as_bytes())?;
        // SAFETY: `open_how` is three integers, and zero is no flags.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (flags | libc::O_CLOEXEC) as u64;
        how.mode = mode.into();
        how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
        for _ in 0..64 {
            // SAFETY: an open directory, a NUL-terminated path, `how` and its size.
            let fd = unsafe {
                libc::syscall(libc::SYS_openat2, self.0.as_raw_fd(), name.as_ptr(), &how as *const libc::open_how, std::mem::size_of::<libc::open_how>())
            };
            if fd >= 0 {
                // SAFETY: a descriptor just opened, owned by nothing else.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) });
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                // A rename or a mount somewhere on the host while the lookup
                // went through `..`: the kernel asks for another try.
                Some(libc::EAGAIN) => continue,
                Some(libc::ENOSYS) => {
                    return Err(std::io::Error::other("no openat2: baking an OCI image needs Linux 5.6 or later"));
                }
                _ => return Err(e),
            }
        }
        Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
    }

    /// The directory at `rel`, if there is one.
    fn find_dir(&self, rel: &Path) -> std::io::Result<Option<OwnedFd>> {
        match self.open_at(rel, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(fd) => Ok(Some(fd)),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The directory at `rel`, made where it is missing, one component at a
    /// time in the directory the one before resolved to (`mkdir -p` in the
    /// guest). A file or a dangling symlink in the way is an error.
    fn make_dir(&self, rel: &Path) -> std::io::Result<OwnedFd> {
        if let Some(dir) = self.find_dir(rel)? {
            return Ok(dir);
        }
        let mut dir = self.open_at(Path::new(""), libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let mut sofar = PathBuf::new();
        for part in rel.iter() {
            sofar.push(part);
            dir = match self.find_dir(&sofar)? {
                Some(next) => next,
                None => {
                    std::fs::create_dir(fd_path(&dir).join(part))?;
                    self.open_at(&sofar, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
                }
            };
        }
        Ok(dir)
    }

    /// The file at `rel`, made or emptied, for writing.
    fn create(&self, rel: &str, mode: libc::mode_t) -> std::io::Result<std::fs::File> {
        let fd = self.open_at(Path::new(rel), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, mode);
        Ok(fd.map_err(|e| std::io::Error::new(e.kind(), format!("{rel}: {e}")))?.into())
    }

    fn write(&self, rel: &str, data: impl AsRef<[u8]>) -> std::io::Result<()> {
        self.create(rel, 0o666)?.write_all(data.as_ref())
    }

    fn read(&self, rel: &str) -> std::io::Result<String> {
        let mut s = String::new();
        std::fs::File::from(self.open_at(Path::new(rel), libc::O_RDONLY, 0)?).read_to_string(&mut s)?;
        Ok(s)
    }

    fn is_file(&self, rel: &str) -> bool {
        let fd = self.open_at(Path::new(rel), libc::O_PATH, 0);
        fd.and_then(|fd| std::fs::File::from(fd).metadata()).is_ok_and(|m| m.is_file())
    }
}

/// The open directory `dir` as a path for the calls that want one: the
/// kernel resolves `/proc/self/fd/N` to the directory itself, not to a
/// name, so `fd_path(dir).join(name)` looks up `name` in `dir` and nothing
/// else. What is done to such a path here never follows `name` itself.
fn fd_path(dir: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}

// --------------------------------------------------------------- install ----

/// What the bake adds on top of the image: the agent (as init and as the
/// agent), the image config for the init, the resolver, the hostname, and
/// the proxy's CA in the system bundle and in a bundle of our own that the
/// environment points every runtime at. `ca` is the tier's certificate, PEM.
/// Paths are the image's (see [`Rootfs`]): its own symlinks, such as a
/// `resolv.conf` or Fedora's CA bundle links, are followed inside it.
pub fn install(rootfs: &Path, agent_bin: &Path, mut config: ImageConfig, ca_pem: Option<&str>) -> R<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let root = Rootfs::open(rootfs)?;
    root.make_dir(Path::new("usr/local/bin"))?;
    let mut agent = root.create("usr/local/bin/iso-guest-agent", 0o755)?;
    std::io::copy(&mut std::fs::File::open(agent_bin)?, &mut agent)?;
    agent.set_permissions(std::fs::Permissions::from_mode(0o755))?;

    root.make_dir(Path::new("etc/iso"))?;
    root.write("etc/resolv.conf", "nameserver 172.22.0.1\n")?;
    root.write("etc/hostname", "iso-guest\n")?;
    let mut h = root.read("etc/hosts").unwrap_or_default();
    if !h.contains("iso-guest") {
        h.push_str("127.0.0.1 localhost\n127.0.1.1 iso-guest\n");
        root.write("etc/hosts", h)?;
    }

    if let Some(ca) = ca_pem {
        root.write("etc/iso/ca.crt", ca)?;
        // Into every system bundle the image has, so tools that read the
        // system store need nothing else.
        let mut bundle = String::new();
        for system in ["etc/ssl/certs/ca-certificates.crt", "etc/pki/tls/certs/ca-bundle.crt", "etc/ssl/cert.pem"] {
            if root.is_file(system) {
                let mut existing = root.read(system).unwrap_or_default();
                if bundle.is_empty() {
                    bundle = existing.clone();
                }
                if !existing.contains(ca.trim()) {
                    if !existing.ends_with('\n') && !existing.is_empty() {
                        existing.push('\n');
                    }
                    existing.push_str(ca);
                    root.write(system, existing)?;
                }
            }
        }
        if !bundle.ends_with('\n') && !bundle.is_empty() {
            bundle.push('\n');
        }
        bundle.push_str(ca);
        root.write("etc/iso/ca-bundle.crt", bundle)?;
        root.make_dir(Path::new("usr/local/share/ca-certificates"))?;
        root.write("usr/local/share/ca-certificates/iso-egress-proxy.crt", ca)?;
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
    root.write("etc/iso/image.json", serde_json::to_string_pretty(&config)?)?;
    root.write(
        "etc/iso/AGENTS.md",
        "# Notes for agents running in this VM\n\n\
         This VM is the image it was built from, booted under iso with the guest agent as init.\n\
         Outbound network goes through iso's egress proxy on the host: the proxy terminates TLS and\n\
         injects credentials in flight, so real credentials never exist in here. Use https://; plain\n\
         HTTP and other ports pass only where a tunnel rule allows them. The proxy's CA is in the\n\
         system store and in /etc/iso/ca-bundle.crt, which SSL_CERT_FILE and friends point at.\n",
    )?;
    Ok(())
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

    use tar::EntryType::{Directory as D, Link as H, Regular as F, Symlink as S};

    /// A layer as an image may hold it, which `tar::Builder` will not
    /// write: names as they are, absolute or with `..`. The third field is
    /// a file's content or a link's target.
    fn raw_layer(entries: &[(&str, tar::EntryType, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for &(path, kind, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
            h.set_entry_type(kind);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            h.set_mode(if kind.is_dir() { 0o755 } else { 0o644 });
            let data = if kind.is_symlink() || kind.is_hard_link() {
                h.as_old_mut().linkname[..body.len()].copy_from_slice(body.as_bytes());
                &b""[..]
            } else {
                body.as_bytes()
            };
            h.set_size(data.len() as u64);
            h.set_cksum();
            b.append(&h, data).unwrap();
        }
        b.into_inner().unwrap()
    }

    /// A rootfs, and beside it `outside/` holding a decoy that no layer
    /// may touch. `out` is that directory's absolute path, `inner` the
    /// same path read inside the rootfs.
    struct Fixture {
        dir: tempfile::TempDir,
        rootfs: PathBuf,
        outside: PathBuf,
        layers: std::cell::Cell<usize>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let rootfs = dir.path().join("rootfs");
            let outside = dir.path().join("outside");
            std::fs::create_dir_all(&rootfs).unwrap();
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("decoy"), "host").unwrap();
            Self { dir, rootfs, outside, layers: Default::default() }
        }
        fn out(&self) -> String {
            self.outside.to_str().unwrap().to_string()
        }
        fn inner(&self) -> String {
            self.out()[1..].to_string()
        }
        fn apply(&self, entries: &[(&str, tar::EntryType, &str)]) -> R<()> {
            let n = self.layers.get();
            self.layers.set(n + 1);
            let path = self.dir.path().join(format!("layer-{n}.tar"));
            std::fs::write(&path, raw_layer(entries)).unwrap();
            apply_layer(&path, "", &self.rootfs)
        }
        fn decoy(&self, name: &str) -> String {
            std::fs::read_to_string(self.outside.join(name)).unwrap_or_else(|e| format!("{name}: {e}"))
        }
    }

    #[test]
    fn a_whiteout_with_an_absolute_path_is_read_inside_the_rootfs() {
        let f = Fixture::new();
        let (out, inner) = (f.out(), f.inner());
        f.apply(&[(&format!("{inner}/"), D, ""), (&format!("{inner}/decoy"), F, "image")]).unwrap();
        let r = f.apply(&[(&format!("{out}/.wh.decoy"), F, "")]);
        assert_eq!(f.decoy("decoy"), "host");
        r.unwrap();
        assert!(!f.rootfs.join(&inner).join("decoy").exists(), "the leading / names the rootfs");
    }

    #[test]
    fn a_whiteout_with_dotdot_is_skipped() {
        let f = Fixture::new();
        f.apply(&[("etc/", D, ""), ("etc/keep", F, "k")]).unwrap();
        let r = f.apply(&[
            ("../outside/.wh.decoy", F, ""),
            ("etc/../../outside/.wh.decoy", F, ""),
            ("etc/.wh...", F, ""),
            (".wh...", F, ""),
            (".wh..", F, ""),
            (".wh.", F, ""),
        ]);
        assert_eq!(f.decoy("decoy"), "host");
        r.unwrap();
        assert_eq!(std::fs::read(f.rootfs.join("etc/keep")).unwrap(), b"k");
    }

    #[test]
    fn a_whiteout_under_a_symlink_stays_in_the_rootfs() {
        let f = Fixture::new();
        std::fs::write(f.outside.join("decoy2"), "host").unwrap();
        // `rel` climbs out of the rootfs when read on the host, and onto
        // the rootfs's own `outside/` when read as the guest reads it.
        f.apply(&[("abs", S, &f.out()), ("rel", S, "../outside"), ("outside/", D, ""), ("outside/decoy2", F, "image")]).unwrap();
        let r = f.apply(&[("abs/.wh.decoy", F, ""), ("rel/.wh.decoy2", F, "")]);
        assert_eq!((f.decoy("decoy").as_str(), f.decoy("decoy2").as_str()), ("host", "host"));
        r.unwrap();
        assert!(!f.rootfs.join("outside/decoy2").exists(), "`..` stops at the top of the rootfs");
        assert!(f.rootfs.join("abs").symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn an_opaque_whiteout_under_a_symlink_stays_in_the_rootfs() {
        let f = Fixture::new();
        f.apply(&[("abs", S, &f.out()), ("rel", S, "../outside"), ("outside/", D, ""), ("outside/x", F, "image")]).unwrap();
        let r = f.apply(&[("abs/.wh..wh..opq", F, ""), ("rel/.wh..wh..opq", F, "")]);
        assert_eq!(f.decoy("decoy"), "host");
        r.unwrap();
        assert!(f.rootfs.join("outside").is_dir() && !f.rootfs.join("outside/x").exists());
    }

    #[test]
    fn a_type_change_stays_in_the_rootfs() {
        let f = Fixture::new();
        let (out, inner) = (f.out(), f.inner());
        std::fs::create_dir(f.outside.join("victim")).unwrap();
        std::fs::write(f.outside.join("victim/decoy"), "host").unwrap();
        f.apply(&[("abs", S, &out), (&format!("{inner}/"), D, ""), (&format!("{inner}/victim/"), D, ""), (&format!("{inner}/decoy"), F, "image")]).unwrap();
        // A file where a directory is, through the symlink; a directory
        // where a file is, by an absolute path.
        let r = f.apply(&[("abs/victim", F, "file now"), (&format!("{out}/decoy/"), D, "")]);
        assert_eq!((f.decoy("victim/decoy").as_str(), f.decoy("decoy").as_str()), ("host", "host"));
        r.unwrap();
        assert_eq!(std::fs::read(f.rootfs.join(&inner).join("victim")).unwrap(), b"file now");
        assert!(f.rootfs.join(&inner).join("decoy").is_dir());
    }

    #[test]
    fn entries_under_a_symlink_land_in_the_rootfs() {
        let f = Fixture::new();
        let (out, inner) = (f.out(), f.inner());
        let pid = format!("{}.pid", f.dir.path().file_name().unwrap().to_str().unwrap());
        // Debian's `var/run -> /run`, and a symlink naming a host directory.
        f.apply(&[
            ("run/", D, ""),
            ("var/", D, ""),
            ("var/run", S, "/run"),
            ("abs", S, &out),
            (&format!("{inner}/"), D, ""),
            (&format!("{inner}/decoy"), F, "image"),
        ])
        .unwrap();
        let r = f.apply(&[(&format!("var/run/{pid}"), F, "1"), ("abs/new", F, "new"), ("abs/sub/deeper", F, "deep"), ("hard", H, &format!("{out}/decoy"))]);
        assert!(!Path::new("/run").join(&pid).exists());
        assert!(!f.outside.join("new").exists() && !f.outside.join("sub").exists());
        assert_eq!(f.decoy("decoy"), "host");
        r.unwrap();
        assert_eq!(std::fs::read(f.rootfs.join("run").join(&pid)).unwrap(), b"1", "an absolute symlink points into the image");
        assert_eq!(std::fs::read(f.rootfs.join(&inner).join("new")).unwrap(), b"new");
        assert_eq!(std::fs::read(f.rootfs.join(&inner).join("sub/deeper")).unwrap(), b"deep");
        assert_eq!(std::fs::read(f.rootfs.join("hard")).unwrap(), b"image", "a hard link's target is in the image");
    }

    #[test]
    fn an_entry_replaces_what_is_there_unless_both_are_directories() {
        let f = Fixture::new();
        f.apply(&[("bin/", D, ""), ("bin/perl5.36", F, "old"), ("bin/perl", F, "old"), ("b", F, "b"), ("c", S, "b"), ("d/", D, ""), ("d/x", F, "x")]).unwrap();
        f.apply(&[("bin/perl5.36", F, "new"), ("bin/perl", H, "bin/perl5.36"), ("b/", D, ""), ("b/y", F, "y"), ("c/", D, ""), ("d/", D, "")]).unwrap();
        assert_eq!(std::fs::read(f.rootfs.join("bin/perl")).unwrap(), b"new", "a hard link over a file");
        assert_eq!(std::fs::read(f.rootfs.join("b/y")).unwrap(), b"y", "a directory over a file");
        assert!(f.rootfs.join("c").symlink_metadata().unwrap().is_dir(), "a directory over a symlink");
        assert_eq!(std::fs::read(f.rootfs.join("d/x")).unwrap(), b"x", "a directory over a directory keeps it");
    }

    #[test]
    fn ordinary_layers_apply_as_before() {
        let f = Fixture::new();
        f.apply(&[
            ("usr/", D, ""),
            ("usr/bin/", D, ""),
            ("bin", S, "usr/bin"),
            ("a/", D, ""),
            ("a/x", F, "x"),
            ("gone/", D, ""),
            ("gone/deep/", D, ""),
            ("gone/deep/f", F, "f"),
            ("link-out", S, &f.out()),
            ("o/", D, ""),
            ("o/old", F, "old"),
        ])
        .unwrap();
        f.apply(&[
            ("bin/tool", F, "tool"),
            ("a", F, "a is a file now"),
            (".wh.gone", F, ""),
            (".wh.link-out", F, ""),
            ("o/.wh..wh..opq", F, ""),
            ("o/new", F, "new"),
        ])
        .unwrap();
        let read = |p: &str| std::fs::read_to_string(f.rootfs.join(p)).unwrap();
        assert_eq!(read("usr/bin/tool"), "tool", "a symlink inside the rootfs is followed");
        assert_eq!(read("a"), "a is a file now");
        assert!(!f.rootfs.join("gone").exists(), "a directory whited out with what is in it");
        assert!(f.rootfs.join("link-out").symlink_metadata().is_err(), "the link goes");
        assert_eq!(f.decoy("decoy"), "host", "not what it points at");
        assert!(!f.rootfs.join("o/old").exists());
        assert_eq!(read("o/new"), "new");
    }

    #[test]
    fn modes_and_owners_are_kept() {
        let f = Fixture::new();
        let mut b = tar::Builder::new(Vec::new());
        for (path, kind, mode) in [("tmp/", D, 0o1777), ("usr/", D, 0o755), ("usr/su", F, 0o4755), ("usr/sh", S, 0o777)] {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_mode(mode);
            h.set_uid(1000);
            h.set_gid(1000);
            h.set_size(0);
            if kind.is_symlink() {
                h.set_link_name("su").unwrap();
            }
            h.set_cksum();
            b.append_data(&mut h, path, std::io::empty()).unwrap();
        }
        let path = f.dir.path().join("modes.tar");
        std::fs::write(&path, b.into_inner().unwrap()).unwrap();
        apply_layer(&path, "", &f.rootfs).unwrap();
        use std::os::unix::fs::MetadataExt;
        let meta = |p: &str| std::fs::symlink_metadata(f.rootfs.join(p)).unwrap();
        assert_eq!((meta("tmp").mode() & 0o7777, meta("usr/su").mode() & 0o7777), (0o1777, 0o4755));
        assert_eq!(std::fs::read_link(f.rootfs.join("usr/sh")).unwrap(), Path::new("su"));
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!((meta("tmp").uid(), meta("usr/su").gid(), meta("usr/sh").uid()), (1000, 1000, 1000));
        }
    }

    #[test]
    fn install_writes_inside_the_rootfs() {
        let f = Fixture::new();
        let (out, inner) = (f.out(), f.inner());
        std::fs::write(f.outside.join("resolv.conf"), "host").unwrap();
        std::fs::write(f.outside.join("bundle.pem"), "HOST CA\n").unwrap();
        // Absolute links as images have them (Fedora's CA bundles, a
        // resolver's resolv.conf), here naming host paths.
        let image = f.rootfs.join(&inner);
        std::fs::create_dir_all(&image).unwrap();
        std::fs::write(image.join("bundle.pem"), "IMAGE CA\n").unwrap();
        std::fs::create_dir_all(f.rootfs.join("etc/ssl")).unwrap();
        std::fs::create_dir_all(f.rootfs.join("usr")).unwrap();
        std::os::unix::fs::symlink(format!("{out}/bundle.pem"), f.rootfs.join("etc/ssl/cert.pem")).unwrap();
        std::os::unix::fs::symlink(format!("{out}/resolv.conf"), f.rootfs.join("etc/resolv.conf")).unwrap();
        std::os::unix::fs::symlink(&out, f.rootfs.join("usr/local")).unwrap();
        let agent = f.dir.path().join("agent");
        std::fs::write(&agent, b"#!/bin/sh\n").unwrap();
        let ca = "-----BEGIN CERTIFICATE-----\nISO\n-----END CERTIFICATE-----\n";
        let r = install(&f.rootfs, &agent, ImageConfig::default(), Some(ca));
        assert_eq!(f.decoy("resolv.conf"), "host");
        assert_eq!(f.decoy("bundle.pem"), "HOST CA\n");
        assert!(!f.outside.join("bin").exists() && !f.outside.join("share").exists());
        r.unwrap();
        assert_eq!(std::fs::read_to_string(image.join("resolv.conf")).unwrap(), "nameserver 172.22.0.1\n");
        assert_eq!(std::fs::read_to_string(image.join("bundle.pem")).unwrap(), format!("IMAGE CA\n{ca}"));
        assert!(image.join("bin/iso-guest-agent").is_file() && image.join("share/ca-certificates/iso-egress-proxy.crt").is_file());
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
