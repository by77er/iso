//! WebSocket (and any other HTTP/1.1 `Upgrade`) through the proxy.
//!
//! The handshake is an ordinary request: it has passed the authority check,
//! the URI phase (with scheme `wss`) and credential injection before it gets
//! here. What is special is what happens after the upstream says `101`: both
//! sides hand their connection over, and from then on the proxy copies bytes
//! and never looks at a frame. The tunnel ends when either side closes, or
//! when the edge closes the guest connection on a policy change.

use bytes::Bytes;
use http::header::{CONNECTION, UPGRADE};
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;

use crate::{BoxError, Resp, UpstreamClient};

/// Whether `headers` ask for a WebSocket upgrade (HTTP/1.1 only; h2 has no
/// `Upgrade` header and its extended CONNECT is deliberately not offered).
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let wants_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    let is_ws = headers
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    wants_upgrade && is_ws
}

/// Forward an upgrade request over HTTP/1.1 and, on `101`, bridge the two
/// upgraded connections. Any other upstream answer is returned as-is.
pub async fn proxy_upgrade(
    mut req: Request<Incoming>,
    client_h1: &UpstreamClient,
    on_task: Option<crate::OnTask>,
    conn: crate::access::Conn,
    host: String,
    path: String,
) -> Result<Resp, BoxError> {
    // Take the guest side now: hyper resolves it once the 101 is written.
    let on_guest = hyper::upgrade::on(&mut req);

    let mut resp = client_h1.request(req).await?;
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Ok(resp.map(|b| b.map_err(|e| Box::new(e) as BoxError).boxed()));
    }
    let on_upstream = hyper::upgrade::on(&mut resp);

    // Echo the upstream's handshake answer to the guest: accept key, subprotocol,
    // extensions. hyper writes the 101 and then resolves `on_guest`.
    let mut out = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (k, v) in resp.headers() {
        out = out.header(k, v);
    }
    let out: Resp = out.body(
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed(),
    )?;

    let tunnel = tokio::spawn(async move {
        let (guest, upstream) = match tokio::try_join!(on_guest, on_upstream) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("websocket upgrade did not complete: {e}");
                return;
            }
        };
        let started = std::time::Instant::now();
        // Metered on the way in, so the counts survive a tunnel that ends in
        // an error (a reset from either side is the usual way one ends).
        let mut guest = Metered::new(TokioIo::new(guest));
        let mut upstream = Metered::new(TokioIo::new(upstream));
        let (to_guest, to_upstream) = (guest.written(), upstream.written());
        // No timer of its own: the tunnel lives exactly as long as the guest
        // connection, and the edge ends that on a policy change.
        if let Err(e) = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await {
            tracing::debug!("websocket tunnel ended: {e}");
        }
        let up = to_upstream.load(std::sync::atomic::Ordering::Relaxed);
        let down = to_guest.load(std::sync::atomic::Ordering::Relaxed);
        conn.tunnel_closed("websocket", &host, 443, &path, up, down, started.elapsed());
    });
    // Register the tunnel where the connection is registered, and hold that
    // registration exactly as long as the tunnel runs.
    if let Some(register) = on_task {
        let guard = register(tunnel.abort_handle());
        tokio::spawn(async move {
            let _guard = guard;
            let _ = tunnel.await;
        });
    }
    Ok(out)
}

#[allow(dead_code)]
fn _assert_types(_: BoxBody<Bytes, BoxError>) {}

/// A stream that counts the bytes written to it. The count is what a tunnel
/// reports on close, whether it closed cleanly or not.
pub struct Metered<S> {
    inner: S,
    written: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl<S> Metered<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, written: Default::default() }
    }
    /// A handle on the count, readable after the stream is gone.
    pub fn written(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        self.written.clone()
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Metered<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Metered<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            self.written.fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
