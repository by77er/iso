//! iso-guest-proto — the host ↔ guest agent protocol.
//!
//! The guest agent listens on a vsock port inside the VM. The host reaches it
//! through the VMM (for Firecracker, the vsock unix socket plus a `CONNECT`
//! handshake) and then speaks this protocol: **length-prefixed JSON frames**,
//! one [`Request`] per frame, answered by exactly one [`Response`] frame. A
//! connection may carry any number of requests in sequence.
//!
//! Framing is a `u32` big-endian byte length followed by the JSON body. It is
//! deliberately not half-close delimited: vsock half-close semantics through a
//! VMM are not something to depend on, and a length prefix also lets one
//! connection serve several calls.
//!
//! This crate is shared by the agent (inside the guest) and the host, so it
//! stays dependency-light and avoids unstable language features: the guest
//! image builds it with the stable compiler nixpkgs ships.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The vsock port the guest agent listens on by default.
pub const DEFAULT_PORT: u32 = 5000;

/// Largest frame either side will accept. Bounds a `write_file` body and an
/// `exec` capture; anything larger must be chunked by the caller.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// Default cap on captured `exec` output (stdout and stderr each).
pub const DEFAULT_MAX_OUTPUT: u64 = 1024 * 1024;

/// Default cap on a `read_file` body.
pub const DEFAULT_MAX_READ: u64 = 16 * 1024 * 1024;

/// Default `exec` timeout.
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 120_000;

fn default_true() -> bool {
    true
}

/// A request to the guest agent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness and identity of the agent.
    Ping,
    /// Run a program and capture its output.
    Exec(ExecRequest),
    /// Read a file, base64 in the response.
    ReadFile {
        path: String,
        /// Bytes to return at most (default [`DEFAULT_MAX_READ`]); the
        /// response says whether it was cut.
        #[serde(default)]
        max_bytes: Option<u64>,
    },
    /// Write (create or replace) a file from base64 content.
    WriteFile {
        path: String,
        content_b64: String,
        /// Unix permission bits, e.g. `0o755`. Default: leave as created.
        #[serde(default)]
        mode: Option<u32>,
        /// Create missing parent directories.
        #[serde(default)]
        mkdir: bool,
    },
    /// List a directory (not recursive).
    ListDir { path: String },
    /// Metadata for one path.
    Stat { path: String },
    /// Remove a file or directory.
    Remove {
        path: String,
        #[serde(default)]
        recursive: bool,
    },
    /// Create a directory.
    Mkdir {
        path: String,
        #[serde(default = "default_true")]
        parents: bool,
    },
}

/// `exec` parameters.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ExecRequest {
    /// Program to run, resolved on the guest's `PATH`.
    pub cmd: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory; default is the agent's.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Extra environment, layered over the agent's.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Bytes written to the program's stdin before it is closed.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Wall-clock limit; the process group is killed when it elapses.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Cap on captured bytes per stream (default [`DEFAULT_MAX_OUTPUT`]).
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
}

/// The agent's answer. `ok` is the discriminator: on success `result` is set,
/// on failure `error` carries a message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ResponseBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok(body: ResponseBody) -> Self {
        Self { ok: true, result: Some(body), error: None }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, result: None, error: Some(msg.into()) }
    }
    /// Turn the response into a `Result`.
    pub fn into_result(self) -> Result<ResponseBody, String> {
        if self.ok {
            self.result.ok_or_else(|| "agent returned ok without a result".to_string())
        } else {
            Err(self.error.unwrap_or_else(|| "agent returned an error without a message".into()))
        }
    }
}

/// Successful result payloads, tagged by `type` so a caller can match without
/// guessing from the shape. (`kind` is taken: it is the file type in `stat`
/// and directory entries.)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseBody {
    Pong(AgentInfo),
    Exec(ExecResult),
    File(FileContent),
    Written { bytes: u64 },
    Dir { entries: Vec<DirEntry> },
    Stat(FileStat),
    Done,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentInfo {
    pub agent: String,
    pub version: String,
    pub hostname: String,
    pub uid: u32,
    pub cwd: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ExecResult {
    /// The process exit code, or `None` if it was killed by a signal.
    pub exit_code: Option<i32>,
    /// Signal number that terminated the process, when there was one.
    #[serde(default)]
    pub signal: Option<i32>,
    /// Captured stdout, lossily decoded as UTF-8.
    pub stdout: String,
    /// Captured stderr, lossily decoded as UTF-8.
    pub stderr: String,
    /// The timeout elapsed and the process group was killed.
    pub timed_out: bool,
    /// One of the captures hit `max_output_bytes`.
    pub truncated: bool,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FileContent {
    pub path: String,
    /// Total size of the file on disk.
    pub size: u64,
    pub content_b64: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DirEntry {
    pub name: String,
    pub kind: FileKind,
    pub size: u64,
    /// Permission bits (the low 12 bits of `st_mode`).
    pub mode: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FileStat {
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Seconds since the Unix epoch.
    pub modified: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    Other,
}

// ---- framing ----

/// Write one frame: `u32` big-endian length, then the bytes.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("frame of {} bytes exceeds the {MAX_FRAME}-byte limit", body.len()),
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await
}

/// Read one frame. `Ok(None)` on a clean EOF before any length byte.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame of {n} bytes exceeds the {MAX_FRAME}-byte limit"),
        ));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Serialize and send a value as one frame.
pub async fn send<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, v: &T) -> std::io::Result<()> {
    let body = serde_json::to_vec(v).map_err(std::io::Error::other)?;
    write_frame(w, &body).await
}

/// Receive and parse one frame. `Ok(None)` on clean EOF.
pub async fn recv<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    r: &mut R,
) -> std::io::Result<Option<T>> {
    match read_frame(r).await? {
        None => Ok(None),
        Some(body) => serde_json::from_slice(&body)
            .map(Some)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
    }
}

// ---- host-side client ----

/// Errors from a [`GuestClient`] call.
#[derive(Debug)]
pub enum ClientError {
    /// Transport failure or malformed frame.
    Io(std::io::Error),
    /// The agent answered with `ok: false`.
    Agent(String),
    /// The agent answered a different kind of result than the call expects.
    UnexpectedResult(&'static str),
    /// The connection closed before a response arrived.
    Closed,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "guest channel: {e}"),
            ClientError::Agent(m) => write!(f, "guest agent: {m}"),
            ClientError::UnexpectedResult(k) => write!(f, "guest agent returned an unexpected {k}"),
            ClientError::Closed => write!(f, "guest agent closed the connection"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// A typed client over any connected stream to the guest agent.
pub struct GuestClient<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> GuestClient<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    /// One round trip.
    pub async fn call(&mut self, req: &Request) -> Result<ResponseBody, ClientError> {
        send(&mut self.stream, req).await?;
        let resp: Response = recv(&mut self.stream).await?.ok_or(ClientError::Closed)?;
        resp.into_result().map_err(ClientError::Agent)
    }

    pub async fn ping(&mut self) -> Result<AgentInfo, ClientError> {
        match self.call(&Request::Ping).await? {
            ResponseBody::Pong(i) => Ok(i),
            _ => Err(ClientError::UnexpectedResult("result kind for ping")),
        }
    }

    pub async fn exec(&mut self, req: ExecRequest) -> Result<ExecResult, ClientError> {
        match self.call(&Request::Exec(req)).await? {
            ResponseBody::Exec(r) => Ok(r),
            _ => Err(ClientError::UnexpectedResult("result kind for exec")),
        }
    }

    pub async fn read_file(&mut self, path: &str, max_bytes: Option<u64>) -> Result<FileContent, ClientError> {
        match self.call(&Request::ReadFile { path: path.into(), max_bytes }).await? {
            ResponseBody::File(f) => Ok(f),
            _ => Err(ClientError::UnexpectedResult("result kind for read_file")),
        }
    }

    pub async fn write_file(
        &mut self,
        path: &str,
        content_b64: String,
        mode: Option<u32>,
        mkdir: bool,
    ) -> Result<u64, ClientError> {
        let req = Request::WriteFile { path: path.into(), content_b64, mode, mkdir };
        match self.call(&req).await? {
            ResponseBody::Written { bytes } => Ok(bytes),
            _ => Err(ClientError::UnexpectedResult("result kind for write_file")),
        }
    }

    pub async fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntry>, ClientError> {
        match self.call(&Request::ListDir { path: path.into() }).await? {
            ResponseBody::Dir { entries } => Ok(entries),
            _ => Err(ClientError::UnexpectedResult("result kind for list_dir")),
        }
    }

    pub async fn stat(&mut self, path: &str) -> Result<FileStat, ClientError> {
        match self.call(&Request::Stat { path: path.into() }).await? {
            ResponseBody::Stat(s) => Ok(s),
            _ => Err(ClientError::UnexpectedResult("result kind for stat")),
        }
    }

    pub async fn remove(&mut self, path: &str, recursive: bool) -> Result<(), ClientError> {
        match self.call(&Request::Remove { path: path.into(), recursive }).await? {
            ResponseBody::Done => Ok(()),
            _ => Err(ClientError::UnexpectedResult("result kind for remove")),
        }
    }

    pub async fn mkdir(&mut self, path: &str, parents: bool) -> Result<(), ClientError> {
        match self.call(&Request::Mkdir { path: path.into(), parents }).await? {
            ResponseBody::Done => Ok(()),
            _ => Err(ClientError::UnexpectedResult("result kind for mkdir")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_eof_is_clean() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let req = Request::Exec(ExecRequest { cmd: "true".into(), ..Default::default() });
        send(&mut a, &req).await.unwrap();
        send(&mut a, &Request::Ping).await.unwrap();
        drop(a);
        let got: Request = recv(&mut b).await.unwrap().unwrap();
        assert_eq!(got, req);
        let got: Request = recv(&mut b).await.unwrap().unwrap();
        assert_eq!(got, Request::Ping);
        let eof: Option<Request> = recv(&mut b).await.unwrap();
        assert!(eof.is_none());
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = a.write_all(&(u32::MAX).to_be_bytes()).await;
        });
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn wire_shape_is_stable() {
        let v = serde_json::to_value(Request::ReadFile { path: "/x".into(), max_bytes: None }).unwrap();
        assert_eq!(v, serde_json::json!({ "op": "read_file", "path": "/x", "max_bytes": null }));
        let r = Response::ok(ResponseBody::Written { bytes: 3 });
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            serde_json::json!({ "ok": true, "result": { "type": "written", "bytes": 3 } })
        );
        let e: Response = serde_json::from_str(r#"{"ok":false,"error":"nope"}"#).unwrap();
        assert_eq!(e.into_result().unwrap_err(), "nope");
    }
}
