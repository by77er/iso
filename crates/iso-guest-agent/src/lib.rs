//! iso-guest-agent — runs inside the VM and answers [`iso_guest_proto`]
//! requests: run a program, read or write a file, list a directory.
//!
//! The library half is transport-agnostic ([`serve_connection`] takes any
//! stream) so the host can exercise the real handlers in tests over a
//! socketpair; the binary binds a vsock port. The agent runs as whatever user
//! its service unit says (the image runs it as `coder`), and everything it does
//! is done with that user's permissions.
//!
//! Written against stable Rust on purpose: the guest image compiles this crate
//! with the compiler nixpkgs ships, not the workspace's nightly.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant, UNIX_EPOCH};

use base64::Engine as _;
use iso_guest_proto::{
    AgentInfo, DirEntry, ExecRequest, ExecResult, FileContent, FileKind, FileStat, Request, Response,
    ResponseBody, DEFAULT_EXEC_TIMEOUT_MS, DEFAULT_MAX_OUTPUT, DEFAULT_MAX_READ,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Serve requests on one connection until the peer closes it.
pub async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    loop {
        let req: Request = match iso_guest_proto::recv(&mut stream).await {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => {
                // A malformed frame gets an error reply, then we close: the
                // stream position is no longer trustworthy.
                let _ = iso_guest_proto::send(&mut stream, &Response::err(format!("bad request: {e}"))).await;
                return;
            }
        };
        let resp = handle(req).await;
        if iso_guest_proto::send(&mut stream, &resp).await.is_err() {
            return;
        }
    }
}

/// Execute one request.
pub async fn handle(req: Request) -> Response {
    match dispatch(req).await {
        Ok(body) => Response::ok(body),
        Err(e) => Response::err(e),
    }
}

async fn dispatch(req: Request) -> Result<ResponseBody, String> {
    match req {
        Request::Ping => Ok(ResponseBody::Pong(info())),
        Request::Exec(e) => exec(e).await.map(ResponseBody::Exec),
        Request::ReadFile { path, max_bytes } => read_file(&path, max_bytes).await.map(ResponseBody::File),
        Request::WriteFile { path, content_b64, mode, mkdir } => {
            write_file(&path, &content_b64, mode, mkdir).await.map(|bytes| ResponseBody::Written { bytes })
        }
        Request::ListDir { path } => list_dir(&path).await.map(|entries| ResponseBody::Dir { entries }),
        Request::Stat { path } => stat(&path).await.map(ResponseBody::Stat),
        Request::Remove { path, recursive } => remove(&path, recursive).await.map(|_| ResponseBody::Done),
        Request::Mkdir { path, parents } => mkdir(&path, parents).await.map(|_| ResponseBody::Done),
    }
}

fn info() -> AgentInfo {
    AgentInfo {
        agent: "iso-guest-agent".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        hostname: std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        uid: unsafe { libc::getuid() },
        cwd: std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
    }
}

fn io_err(what: &str, path: &str, e: std::io::Error) -> String {
    format!("{what} {path}: {e}")
}

/// Read a child stream into `buf`, keeping at most `cap` bytes. Returns whether
/// anything was dropped.
async fn capture<R: AsyncRead + Unpin>(mut r: R, buf: &mut Vec<u8>, cap: usize) -> bool {
    let mut truncated = false;
    let mut chunk = [0u8; 8192];
    loop {
        let n = match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let room = cap.saturating_sub(buf.len());
        if n > room {
            buf.extend_from_slice(&chunk[..room]);
            truncated = true;
        } else {
            buf.extend_from_slice(&chunk[..n]);
        }
    }
    truncated
}

async fn exec(req: ExecRequest) -> Result<ExecResult, String> {
    let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(DEFAULT_EXEC_TIMEOUT_MS));
    let cap = req.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT) as usize;

    let mut cmd = tokio::process::Command::new(&req.cmd);
    cmd.args(&req.args)
        .envs(&req.env)
        .stdin(if req.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group, so a timeout can take the whole tree down.
        .process_group(0)
        .kill_on_drop(true);
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }
    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", req.cmd))?;
    let pid = child.id().map(|p| p as i32);

    let stdin = child.stdin.take();
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let stderr = child.stderr.take().ok_or("no stderr pipe")?;
    let stdin_body = req.stdin.clone();
    let feed = async move {
        if let (Some(mut w), Some(body)) = (stdin, stdin_body) {
            let _ = w.write_all(body.as_bytes()).await;
            let _ = w.shutdown().await;
        }
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let run = async {
        let ((), t1, t2, status) = tokio::join!(
            feed,
            capture(stdout, &mut out, cap),
            capture(stderr, &mut err, cap),
            child.wait()
        );
        (t1 || t2, status)
    };

    let (truncated, status, timed_out) = match tokio::time::timeout(timeout, run).await {
        Ok((truncated, status)) => (truncated, Some(status.map_err(|e| format!("wait: {e}"))?), false),
        Err(_) => {
            if let Some(pid) = pid {
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
            (true, None, true)
        }
    };

    let (exit_code, signal) = match status {
        Some(s) => {
            use std::os::unix::process::ExitStatusExt;
            (s.code(), s.signal())
        }
        None => (None, Some(libc::SIGKILL)),
    };
    Ok(ExecResult {
        exit_code,
        signal,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
        timed_out,
        truncated,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

async fn read_file(path: &str, max_bytes: Option<u64>) -> Result<FileContent, String> {
    let cap = max_bytes.unwrap_or(DEFAULT_MAX_READ);
    let meta = tokio::fs::metadata(path).await.map_err(|e| io_err("stat", path, e))?;
    if !meta.is_file() {
        return Err(format!("read {path}: not a regular file"));
    }
    let size = meta.len();
    let mut f = tokio::fs::File::open(path).await.map_err(|e| io_err("open", path, e))?;
    let mut buf = Vec::with_capacity(size.min(cap) as usize);
    (&mut f).take(cap).read_to_end(&mut buf).await.map_err(|e| io_err("read", path, e))?;
    Ok(FileContent {
        path: path.into(),
        size,
        truncated: size > cap,
        content_b64: B64.encode(&buf),
    })
}

async fn write_file(path: &str, content_b64: &str, mode: Option<u32>, mkdir: bool) -> Result<u64, String> {
    let bytes = B64.decode(content_b64).map_err(|e| format!("write {path}: content is not base64: {e}"))?;
    // (No let-chains here: the guest image builds this crate on stable.)
    let parent = if mkdir {
        Path::new(path).parent().filter(|p| !p.as_os_str().is_empty())
    } else {
        None
    };
    if let Some(parent) = parent {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| io_err("mkdir", &parent.display().to_string(), e))?;
    }
    tokio::fs::write(path, &bytes).await.map_err(|e| io_err("write", path, e))?;
    if let Some(mode) = mode {
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .await
            .map_err(|e| io_err("chmod", path, e))?;
    }
    Ok(bytes.len() as u64)
}

fn kind_of(ft: std::fs::FileType) -> FileKind {
    if ft.is_symlink() {
        FileKind::Symlink
    } else if ft.is_dir() {
        FileKind::Dir
    } else if ft.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    }
}

async fn list_dir(path: &str) -> Result<Vec<DirEntry>, String> {
    let mut rd = tokio::fs::read_dir(path).await.map_err(|e| io_err("list", path, e))?;
    let mut entries = Vec::new();
    while let Some(entry) = rd.next_entry().await.map_err(|e| io_err("list", path, e))? {
        // symlink_metadata: report the link itself, never follow it.
        let meta = match tokio::fs::symlink_metadata(entry.path()).await {
            Ok(m) => m,
            Err(_) => continue,
        };
        entries.push(DirEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            kind: kind_of(meta.file_type()),
            size: meta.len(),
            mode: meta.mode() & 0o7777,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

async fn stat(path: &str) -> Result<FileStat, String> {
    let meta = tokio::fs::symlink_metadata(path).await.map_err(|e| io_err("stat", path, e))?;
    Ok(FileStat {
        path: path.into(),
        kind: kind_of(meta.file_type()),
        size: meta.len(),
        mode: meta.mode() & 0o7777,
        uid: meta.uid(),
        gid: meta.gid(),
        modified: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
    })
}

async fn remove(path: &str, recursive: bool) -> Result<(), String> {
    let meta = tokio::fs::symlink_metadata(path).await.map_err(|e| io_err("remove", path, e))?;
    let r = if meta.is_dir() {
        if recursive {
            tokio::fs::remove_dir_all(path).await
        } else {
            tokio::fs::remove_dir(path).await
        }
    } else {
        tokio::fs::remove_file(path).await
    };
    r.map_err(|e| io_err("remove", path, e))
}

async fn mkdir(path: &str, parents: bool) -> Result<(), String> {
    let r = if parents {
        tokio::fs::create_dir_all(path).await
    } else {
        tokio::fs::create_dir(path).await
    };
    r.map_err(|e| io_err("mkdir", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iso_guest_proto::GuestClient;

    /// The real handlers, driven through a socketpair exactly as the host would.
    async fn client() -> GuestClient<tokio::net::UnixStream> {
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(serve_connection(b));
        GuestClient::new(a)
    }

    #[tokio::test]
    async fn exec_captures_output_and_exit_code() {
        let mut c = client().await;
        let r = c
            .exec(ExecRequest {
                cmd: "sh".into(),
                args: vec!["-c".into(), "echo out; echo err >&2; exit 3".into()],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(r.exit_code, Some(3));
        assert_eq!(r.stdout, "out\n");
        assert_eq!(r.stderr, "err\n");
        assert!(!r.timed_out && !r.truncated);
    }

    #[tokio::test]
    async fn exec_feeds_stdin_and_env_and_cwd() {
        let mut c = client().await;
        let r = c
            .exec(ExecRequest {
                cmd: "sh".into(),
                args: vec!["-c".into(), "cat; echo $ISO_X; pwd".into()],
                cwd: Some("/tmp".into()),
                env: [("ISO_X".to_string(), "y".to_string())].into_iter().collect(),
                stdin: Some("in\n".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(r.stdout, "in\ny\n/tmp\n");
    }

    #[tokio::test]
    async fn exec_timeout_kills_the_process_group() {
        let mut c = client().await;
        let started = Instant::now();
        let r = c
            .exec(ExecRequest {
                cmd: "sh".into(),
                args: vec!["-c".into(), "sleep 30 & sleep 30".into()],
                timeout_ms: Some(300),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(r.timed_out);
        assert_eq!(r.exit_code, None);
        assert!(started.elapsed() < Duration::from_secs(5), "must not wait for the sleeps");
    }

    #[tokio::test]
    async fn exec_truncates_at_the_cap() {
        let mut c = client().await;
        let r = c
            .exec(ExecRequest {
                cmd: "sh".into(),
                args: vec!["-c".into(), "yes | head -c 100000".into()],
                max_output_bytes: Some(1000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(r.truncated);
        assert_eq!(r.stdout.len(), 1000);
    }

    #[tokio::test]
    async fn files_round_trip_and_errors_are_messages() {
        let dir = std::env::temp_dir().join(format!("iso-guest-agent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut c = client().await;
        let file = dir.join("a/b/hello.txt");
        let path = file.to_str().unwrap();

        let n = c.write_file(path, B64.encode("hello"), Some(0o640), true).await.unwrap();
        assert_eq!(n, 5);
        let got = c.read_file(path, None).await.unwrap();
        assert_eq!(B64.decode(got.content_b64).unwrap(), b"hello");
        assert_eq!(got.size, 5);
        let st = c.stat(path).await.unwrap();
        assert_eq!(st.mode, 0o640);
        assert_eq!(st.kind, FileKind::File);

        let entries = c.list_dir(dir.join("a/b").to_str().unwrap()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");

        let cut = c.read_file(path, Some(2)).await.unwrap();
        assert!(cut.truncated);
        assert_eq!(B64.decode(cut.content_b64).unwrap(), b"he");

        let err = c.read_file(dir.join("missing").to_str().unwrap(), None).await.unwrap_err();
        assert!(matches!(err, iso_guest_proto::ClientError::Agent(m) if m.contains("missing")));

        assert!(c.remove(dir.to_str().unwrap(), false).await.is_err(), "non-recursive on a tree");
        c.remove(dir.to_str().unwrap(), true).await.unwrap();
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn several_calls_share_one_connection() {
        let mut c = client().await;
        for _ in 0..3 {
            let i = c.ping().await.unwrap();
            assert_eq!(i.agent, "iso-guest-agent");
        }
    }
}
