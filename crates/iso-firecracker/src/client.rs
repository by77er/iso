//! Minimal async HTTP/1.1 client for the Firecracker API unix socket.
//!
//! Firecracker's API is small (tiny JSON PUT/PATCH/GET, `204`/`200` responses),
//! so we hand-roll a Content-Length-aware client over a `UnixStream` rather than
//! pull in hyper + a unix connector.

use std::path::Path;
use std::time::Duration;

use iso_common::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

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
    let mut stream = UnixStream::connect(socket).await.map_err(be)?;
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
