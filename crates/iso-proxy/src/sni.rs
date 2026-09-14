//! A look at a TLS ClientHello that keeps the bytes.
//!
//! The proxy has to see the SNI before it decides whether to terminate a
//! connection or carry it through as bytes. rustls's acceptor sees the SNI
//! but keeps the ClientHello for itself, so a passthrough would have
//! nothing to send upstream. This reads one TLS record, finds the
//! `server_name` extension in it, and hands both the name and the bytes
//! back; [`Prefixed`] then replays the bytes to whichever side reads next.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// What one record's worth of a connection said.
pub struct Peeked {
    /// Every byte read, to be replayed.
    pub bytes: Vec<u8>,
    /// The record was a TLS handshake record.
    pub is_tls: bool,
    /// The SNI in the ClientHello, when there was one.
    pub sni: Option<String>,
}

/// Largest ClientHello record read; anything bigger is not a ClientHello.
const MAX_RECORD: usize = 16 * 1024 + 5;

/// Read the first TLS record from `s`, within `timeout`.
pub async fn peek<S: AsyncRead + Unpin>(s: &mut S, timeout: Duration) -> io::Result<Peeked> {
    tokio::time::timeout(timeout, async {
        let mut head = [0u8; 5];
        s.read_exact(&mut head).await?;
        let mut bytes = head.to_vec();
        // content type 22 = handshake; version major 3
        if head[0] != 0x16 || head[1] != 0x03 {
            return Ok(Peeked { bytes, is_tls: false, sni: None });
        }
        let len = u16::from_be_bytes([head[3], head[4]]) as usize;
        if len == 0 || len + 5 > MAX_RECORD {
            return Ok(Peeked { bytes, is_tls: false, sni: None });
        }
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await?;
        bytes.extend_from_slice(&body);
        let sni = server_name(&body);
        Ok(Peeked { bytes, is_tls: true, sni })
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no ClientHello in time"))?
}

/// The `server_name` extension of a ClientHello handshake message.
fn server_name(hs: &[u8]) -> Option<String> {
    // handshake type 1 = ClientHello, 3-byte length
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let mut p = 4;
    let take = |p: &mut usize, n: usize| -> Option<&[u8]> {
        let out = hs.get(*p..*p + n)?;
        *p += n;
        Some(out)
    };
    take(&mut p, 2)?; // client version
    take(&mut p, 32)?; // random
    let sid = take(&mut p, 1)?[0] as usize;
    take(&mut p, sid)?;
    let cs = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?) as usize;
    take(&mut p, cs)?;
    let comp = take(&mut p, 1)?[0] as usize;
    take(&mut p, comp)?;
    let ext_len = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?) as usize;
    let end = p + ext_len;
    while p + 4 <= end.min(hs.len()) {
        let ty = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?);
        let len = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?) as usize;
        let data = take(&mut p, len)?;
        if ty == 0 {
            // server_name list: len(2), then entries of type(1) len(2) name
            let mut q = 2;
            while q + 3 <= data.len() {
                let name_type = data[q];
                let n = u16::from_be_bytes([data[q + 1], data[q + 2]]) as usize;
                let name = data.get(q + 3..q + 3 + n)?;
                if name_type == 0 {
                    return std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase());
                }
                q += 3 + n;
            }
            return None;
        }
    }
    None
}

/// A stream that first replays `prefix`, then reads from the inner stream.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello with an SNI, as rustls would send one.
    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // extended_master_secret, empty
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0); // no session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[tokio::test]
    async fn finds_the_sni_and_replays_the_bytes() {
        let hello = client_hello("Api.Example.Test");
        let (mut a, b) = tokio::io::duplex(4096);
        tokio::io::AsyncWriteExt::write_all(&mut a, &hello).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut a, b"after").await.unwrap();
        let mut b = b;
        let p = peek(&mut b, Duration::from_secs(1)).await.unwrap();
        assert!(p.is_tls);
        assert_eq!(p.sni.as_deref(), Some("api.example.test"));
        assert_eq!(p.bytes, hello);
        let mut replay = Prefixed::new(p.bytes.clone(), b);
        let mut got = vec![0u8; hello.len() + 5];
        tokio::io::AsyncReadExt::read_exact(&mut replay, &mut got).await.unwrap();
        assert_eq!(&got[..hello.len()], &hello[..]);
        assert_eq!(&got[hello.len()..], b"after");
    }

    #[tokio::test]
    async fn plain_bytes_are_not_tls() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, b"GET / HTTP/1.1\r\n").await.unwrap();
        let p = peek(&mut b, Duration::from_secs(1)).await.unwrap();
        assert!(!p.is_tls);
        assert_eq!(p.sni, None);
        assert_eq!(p.bytes, b"GET /");
    }
}
