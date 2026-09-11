//! Minimal async HTTP/1.1 client for the Firecracker API unix socket.
//!
//! Firecracker's API is small (tiny JSON PUT/PATCH/GET, `204`/`200` responses),
//! so we hand-roll a Content-Length-aware client over a `UnixStream` rather than
//! pull in hyper + a unix connector.

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use iso_common::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// `sun_path` holds 108 bytes including the NUL. A jailed VM's sockets sit at
/// `<base>/<firecracker>/<uuid>/root/...`, which is over that with any but
/// the shortest base. Connecting through the directory's fd sidesteps the
/// limit entirely, so every connect goes through here.
const SUN_PATH_MAX: usize = 107;

/// A path the kernel will accept in `sun_path`: `path` itself when short
/// enough, else `/proc/self/fd/<dir>/<name>` with `dir` held open.
pub(crate) struct SocketPath {
    pub path: PathBuf,
    _dir: Option<OwnedFd>,
}

impl SocketPath {
    pub fn new(path: &Path) -> std::io::Result<Self> {
        if path.as_os_str().len() <= SUN_PATH_MAX {
            return Ok(Self { path: path.to_path_buf(), _dir: None });
        }
        let (dir, name) = match (path.parent(), path.file_name()) {
            (Some(d), Some(n)) if !d.as_os_str().is_empty() => (d, n),
            _ => return Err(std::io::Error::other(format!("socket path {} has no directory", path.display()))),
        };
        let dir = std::fs::File::open(dir)?;
        let via = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name);
        Ok(Self { path: via, _dir: Some(dir.into()) })
    }
}

/// Connect to a unix socket at `path`, however long the path is.
pub(crate) async fn connect(path: &Path) -> std::io::Result<UnixStream> {
    let sp = SocketPath::new(path)?;
    UnixStream::connect(&sp.path).await
}

// Cap on a single firecracker API request. The API is sub-millisecond in
// practice (the slowest is a full-memory snapshot); this only exists so a
// wedged or orphaned VMM (e.g. one inherited across a control-plane restart)
// can't block lifecycle ops (stop/destroy) forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn be<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(headers: &str) -> Option<usize> {
    headers
        .lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-length")))
        .and_then(|(_, v)| v.trim().parse().ok())
}

/// One request/response. Returns `(status_code, body)`. Bounded by
/// [`REQUEST_TIMEOUT`] so a hung VMM can't block the caller indefinitely.
pub async fn request(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<(u16, String)> {
    tokio::time::timeout(REQUEST_TIMEOUT, request_inner(socket, method, path, body))
        .await
        .map_err(|_| Error::Backend(format!("firecracker API {method} {path} timed out")))?
}

async fn request_inner(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<(u16, String)> {
    let mut stream = connect(socket).await.map_err(be)?;
    let body_str = body.map(|v| v.to_string()).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    stream.write_all(req.as_bytes()).await.map_err(be)?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        // stop once we have the full header + declared body
        if let Some(he) = find(&buf, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buf[..he]);
            let need = content_length(&headers).unwrap_or(0);
            if buf.len() >= he + 4 + need {
                break;
            }
        }
        let n = stream.read(&mut tmp).await.map_err(be)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let text = String::from_utf8_lossy(&buf);
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| Error::Backend(format!("malformed firecracker response: {text:?}")))?;
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((code, body))
}

/// Send a request and require a 2xx status.
async fn expect_ok(
    socket: &Path,
    method: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<()> {
    let (code, resp) = request(socket, method, path, Some(body)).await?;
    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(Error::Backend(format!("{method} {path} -> {code}: {resp}")))
    }
}

pub async fn put(socket: &Path, path: &str, body: serde_json::Value) -> Result<()> {
    expect_ok(socket, "PUT", path, &body).await
}

pub async fn patch(socket: &Path, path: &str, body: serde_json::Value) -> Result<()> {
    expect_ok(socket, "PATCH", path, &body).await
}

/// `GET /` → the instance's `state` string ("Not started" / "Running" / "Paused").
pub async fn state(socket: &Path) -> Result<String> {
    let (code, body) = request(socket, "GET", "/", None).await?;
    if !(200..300).contains(&code) {
        return Err(Error::Backend(format!("GET / -> {code}")));
    }
    let v: serde_json::Value = serde_json::from_str(&body).map_err(be)?;
    Ok(v.get("state")
        .and_then(|s| s.as_str())
        .unwrap_or_default()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bind and connect at a path well past `sun_path`, the way a jailed VM's
    /// sockets are laid out.
    #[tokio::test]
    async fn long_socket_paths_work_through_the_directory_fd() {
        let base = std::env::temp_dir().join(format!("iso-fc-sunlen-{}", std::process::id()));
        let long = base.join("a".repeat(60)).join("b".repeat(60));
        std::fs::create_dir_all(&long).unwrap();
        let sock = long.join("firecracker.socket");
        assert!(sock.as_os_str().len() > SUN_PATH_MAX);

        let bind_at = SocketPath::new(&sock).unwrap();
        let listener = tokio::net::UnixListener::bind(&bind_at.path).expect("bind through /proc/self/fd");
        assert!(sock.exists(), "the socket really is at the long path");

        let (client, server) = tokio::join!(connect(&sock), listener.accept());
        let mut client = client.expect("connect through /proc/self/fd");
        let (mut server, _) = server.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn short_paths_are_left_alone() {
        let sp = SocketPath::new(Path::new("/run/iso/fc/x.sock")).unwrap();
        assert_eq!(sp.path, Path::new("/run/iso/fc/x.sock"));
    }
}
