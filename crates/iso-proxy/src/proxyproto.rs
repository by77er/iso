//! The PROXY protocol v2 header the edge sends a proxy replica: the guest
//! connection's addresses plus one custom TLV carrying the connection's
//! identity and policy as JSON. Reading it is the first thing a replica does
//! on an accepted connection; everything after it is the guest's TLS.

use std::net::SocketAddr;

use ppp::v2::{Addresses, Builder, Command, Header, PROTOCOL_PREFIX, Protocol, Version};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::policy::WirePolicy;

/// The custom TLV type (the spec reserves 0xE0–0xEF for custom use).
pub const TLV_ISO_POLICY: u8 = 0xE5;

/// Encode a header for a connection from `src` to `dst` carrying `policy`.
pub fn encode(src: SocketAddr, dst: SocketAddr, policy: &WirePolicy) -> std::io::Result<Vec<u8>> {
    let body = serde_json::to_vec(policy)?;
    Builder::with_addresses(Version::Two | Command::Proxy, Protocol::Stream, (src, dst))
        .write_tlv(TLV_ISO_POLICY, &body)?
        .build()
}

/// What a decoded header says.
pub struct Decoded {
    pub src: Option<SocketAddr>,
    pub policy: WirePolicy,
}

/// Read exactly one header from the start of `stream`. Bytes after it are
/// left unread for the caller. Anything that is not a v2 PROXY header with
/// our TLV is an error: a replica accepts nothing else.
pub async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Decoded> {
    // 12-byte signature, then version/command, family/protocol, u16 length.
    let mut head = [0u8; 16];
    stream.read_exact(&mut head).await?;
    if &head[..12] != PROTOCOL_PREFIX {
        return Err(bad("not a PROXY protocol v2 header"));
    }
    let len = u16::from_be_bytes([head[14], head[15]]) as usize;
    let mut buf = head.to_vec();
    buf.resize(16 + len, 0);
    stream.read_exact(&mut buf[16..]).await?;
    decode(&buf)
}

pub fn decode(buf: &[u8]) -> std::io::Result<Decoded> {
    let header = Header::try_from(buf).map_err(|e| bad(&format!("proxy header: {e}")))?;
    let src = match header.addresses {
        Addresses::IPv4(a) => Some(SocketAddr::from((a.source_address, a.source_port))),
        Addresses::IPv6(a) => Some(SocketAddr::from((a.source_address, a.source_port))),
        _ => None,
    };
    let mut policy = None;
    for tlv in header.tlvs() {
        let tlv = tlv.map_err(|e| bad(&format!("proxy tlv: {e}")))?;
        if tlv.kind == TLV_ISO_POLICY {
            policy = Some(serde_json::from_slice::<WirePolicy>(&tlv.value)?);
        }
    }
    let policy = policy.ok_or_else(|| bad("proxy header carries no iso policy"))?;
    Ok(Decoded { src, policy })
}

fn bad(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_addresses_and_policy() {
        let p = WirePolicy {
            host: "host-a".into(),
            vm: Some("vm-1".into()),
            egress: "proxy".into(),
            principal: Some("alice".into()),
            rules: vec!["allow https://api.github.com/**".into()],
            policy_gen: 7,
        };
        let src: SocketAddr = "172.21.0.3:41000".parse().unwrap();
        let dst: SocketAddr = "172.22.0.1:3128".parse().unwrap();
        let mut bytes = encode(src, dst, &p).unwrap();
        bytes.extend_from_slice(b"\x16\x03\x01 rest of stream");
        let mut cursor = std::io::Cursor::new(bytes);
        let d = read(&mut cursor).await.unwrap();
        assert_eq!(d.src, Some(src));
        assert_eq!(d.policy.vm.as_deref(), Some("vm-1"));
        assert_eq!(d.policy.policy_gen, 7);
        assert_eq!(d.policy.rules, p.rules);
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await.unwrap();
        assert_eq!(&rest, b"\x16\x03\x01 rest of stream");
    }

    #[tokio::test]
    async fn rejects_plain_tls_and_headers_without_the_tlv() {
        let mut tls = std::io::Cursor::new(vec![0x16u8; 64]);
        assert!(read(&mut tls).await.is_err());
        let plain = Builder::with_addresses(
            Version::Two | Command::Proxy,
            Protocol::Stream,
            (
                "1.2.3.4:5".parse::<SocketAddr>().unwrap(),
                "6.7.8.9:10".parse::<SocketAddr>().unwrap(),
            ),
        )
        .build()
        .unwrap();
        let mut cursor = std::io::Cursor::new(plain);
        assert!(read(&mut cursor).await.is_err());
    }
}
