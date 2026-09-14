//! Multi-host configuration: an `edge` on each host carries connections over
//! mutual TLS, with the policy in a PROXY protocol v2 header, to a `proxy`
//! replica that is nowhere near the host. The replica reaches the CA and the
//! secrets service over HTTPS with mutual TLS. Two "hosts" here are two edge
//! listeners on loopback with their own policy sources; the tier is one
//! replica listener. No Unix socket is shared between an edge and the tier.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use iso_admin_pki::Creds;
use iso_proxy::{ProxyConfig, run_with_listeners};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Split {
    tier: SocketAddr,
    tier_ca: String,
    upstream: TestUpstream,
    pki: TestPki,
    ca_url: String,
    secrets_url: String,
}

async fn start_tier() -> Split {
    init();
    let dir = tempdir("split");
    let pki = TestPki::new(&dir);
    let ca = TestCa::start(&dir, Some(pki.ca_svc.server_config().unwrap())).await;
    let secrets = TestSecrets::start(&dir, Some(pki.secrets_svc.server_config().unwrap())).await;
    let upstream = TestUpstream::start(&dir).await;
    let ca_url = format!("https://{}", ca.https.unwrap());
    let secrets_url = format!("https://{}", secrets.https.unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tier = listener.local_addr().unwrap();
    let mut cfg = ProxyConfig::proxy(
        vec![tier],
        pki.proxy.server_config().unwrap(),
        iso_rpc::Endpoint::https(&ca_url, pki.proxy.client_config().unwrap()),
        iso_rpc::Endpoint::https(&secrets_url, pki.proxy.client_config().unwrap()),
    );
    cfg.extra_upstream_roots = vec![upstream.ca_der.clone()];
    cfg.upstream_pins
        .insert(UPSTREAM_HOST.into(), upstream.addr);
    tokio::spawn(run_with_listeners(vec![listener], cfg));
    Split {
        tier,
        tier_ca: ca.cert_pem.clone(),
        upstream,
        pki,
        ca_url,
        secrets_url,
    }
}

struct Edge {
    addr: SocketAddr,
    resolver: Arc<TestResolver>,
}

/// An edge "on host `host_id`" with its own identity and policy source.
async fn start_edge(
    split: &Split,
    host_id: &str,
    creds: &Creds,
    rules: &[&str],
    principal: Option<&str>,
    egress: &str,
) -> Edge {
    let resolver = TestResolver::new(policy(egress, principal, rules));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut cfg = ProxyConfig::edge(
        vec![addr],
        resolver.clone(),
        vec![split.tier],
        creds.client_config().unwrap(),
    );
    cfg.host_id = host_id.into();
    cfg.watch_every = Duration::from_millis(50);
    tokio::spawn(run_with_listeners(vec![listener], cfg));
    Edge { addr, resolver }
}

#[tokio::test]
async fn split_injects_and_forwards_through_the_tier() {
    let s = start_tier().await;
    let e = start_edge(
        &s,
        "hostA",
        &s.pki.edge,
        &["allow https://api.example.test/**"],
        Some("alice"),
        "proxy",
    )
    .await;
    let client = guest_client(e.addr, &s.tier_ca, false);
    let body: serde_json::Value = client
        .get(url("/get"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["headers"]["x-iso-injected"], "hello-from-iso");
    assert_eq!(body["headers"]["authorization"], "Bearer alice-token");
    assert_eq!(s.upstream.hit_paths(), vec!["/get"]);
}

#[tokio::test]
async fn split_enforces_rules_on_the_tier_from_the_header() {
    let s = start_tier().await;
    let e = start_edge(
        &s,
        "hostA",
        &s.pki.edge,
        &[
            "allow https://api.example.test/**",
            "deny https://api.example.test/user/keys",
        ],
        None,
        "proxy",
    )
    .await;
    let client = guest_client(e.addr, &s.tier_ca, false);
    let resp = client.get(url("/user/keys")).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["rule"], "deny https://api.example.test/user/keys");
    assert_eq!(
        client.get(url("/repos/x")).send().await.unwrap().status(),
        200
    );
    assert_eq!(s.upstream.hit_paths(), vec!["/repos/x"]);

    // A host no allow rule names is dropped at SNI time on the tier.
    let e2 = start_edge(
        &s,
        "hostA",
        &s.pki.edge,
        &["allow https://other.example.test/**"],
        None,
        "proxy",
    )
    .await;
    let client2 = guest_client(e2.addr, &s.tier_ca, false);
    assert!(client2.get(url("/get")).send().await.is_err());
}

#[tokio::test]
async fn split_tunnels_websockets() {
    let s = start_tier().await;
    let e = start_edge(
        &s,
        "hostA",
        &s.pki.edge,
        &[
            "allow https://api.example.test/**",
            "allow wss://api.example.test/ws",
        ],
        Some("alice"),
        "proxy",
    )
    .await;
    let client = guest_client(e.addr, &s.tier_ca, true);
    let (mut ws, headers) = open_ws(&client, "/ws")
        .await
        .expect("101 through edge and tier");
    assert_eq!(headers.get("x-ws-saw-injected").unwrap(), "hello-from-iso");
    ws.write_all(b"through two hops").await.unwrap();
    let mut buf = [0u8; 16];
    ws.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"through two hops");
}

#[tokio::test]
async fn the_edge_closes_connections_when_the_generation_moves() {
    let s = start_tier().await;
    let e = start_edge(
        &s,
        "hostA",
        &s.pki.edge,
        &[
            "allow https://api.example.test/**",
            "allow wss://api.example.test/ws",
        ],
        None,
        "proxy",
    )
    .await;
    let client = guest_client(e.addr, &s.tier_ca, true);
    let (mut ws, _) = open_ws(&client, "/ws").await.unwrap();
    ws.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    ws.read_exact(&mut b).await.unwrap();

    e.resolver.bump();
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        let mut sink = [0u8; 16];
        loop {
            match ws.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the edge must close the tunnel after a policy change"
    );

    // The tier never learned anything happened; a new connection just works.
    let client = guest_client(e.addr, &s.tier_ca, false);
    assert_eq!(client.get(url("/get")).send().await.unwrap().status(), 200);
}

#[tokio::test]
async fn deny_mode_never_reaches_the_tier() {
    let s = start_tier().await;
    let e = start_edge(
        &s,
        "hostA",
        &s.pki.edge,
        &["allow https://api.example.test/**"],
        None,
        "deny",
    )
    .await;
    let client = guest_client(e.addr, &s.tier_ca, false);
    assert!(client.get(url("/get")).send().await.is_err());
    assert!(s.upstream.hit_paths().is_empty());
}

#[tokio::test]
async fn two_hosts_share_one_tier_with_their_own_principals() {
    let s = start_tier().await;
    let a = start_edge(
        &s,
        "hostA",
        &s.pki.edge,
        &["allow https://api.example.test/**"],
        Some("alice"),
        "proxy",
    )
    .await;
    let b = start_edge(
        &s,
        "hostB",
        &s.pki.edge,
        &["allow https://api.example.test/get"],
        None,
        "proxy",
    )
    .await;

    let ca = guest_client(a.addr, &s.tier_ca, false);
    let body: serde_json::Value = ca
        .get(url("/get"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["headers"]["authorization"], "Bearer alice-token");

    let cb = guest_client(b.addr, &s.tier_ca, false);
    let body: serde_json::Value = cb
        .get(url("/get"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["headers"]["x-iso-injected"], "hello-from-iso");
    assert!(
        body["headers"].get("authorization").is_none(),
        "host B has no principal"
    );
    assert_eq!(
        cb.get(url("/other")).send().await.unwrap().status(),
        403,
        "host B's narrower rules apply"
    );
}

#[tokio::test]
async fn the_tier_refuses_anything_but_an_admin_ca_edge() {
    let s = start_tier().await;

    // An edge with an identity from another CA never gets past the handshake.
    let stranger = start_edge(
        &s,
        "hostX",
        &s.pki.stranger,
        &["allow https://api.example.test/**"],
        None,
        "proxy",
    )
    .await;
    let client = guest_client(stranger.addr, &s.tier_ca, false);
    assert!(client.get(url("/get")).send().await.is_err());

    // A raw TCP connection straight to the tier, no TLS, no header: closed.
    let mut raw = tokio::net::TcpStream::connect(s.tier).await.unwrap();
    raw.write_all(b"\x16\x03\x01\x00\x05hello").await.unwrap();
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(5), raw.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(
        n, 0,
        "the tier must close a connection that is not mTLS from an edge"
    );
    assert!(s.upstream.hit_paths().is_empty());
}

#[tokio::test]
async fn a_tier_with_a_stranger_identity_cannot_mint_or_inject() {
    let s = start_tier().await;
    // A second replica whose identity the CA and secrets services do not trust.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_tier = listener.local_addr().unwrap();
    let mut cfg = ProxyConfig::proxy(
        vec![bad_tier],
        s.pki.proxy.server_config().unwrap(),
        iso_rpc::Endpoint::https(&s.ca_url, s.pki.stranger.client_config().unwrap()),
        iso_rpc::Endpoint::https(&s.secrets_url, s.pki.stranger.client_config().unwrap()),
    );
    cfg.extra_upstream_roots = vec![s.upstream.ca_der.clone()];
    cfg.upstream_pins
        .insert(UPSTREAM_HOST.into(), s.upstream.addr);
    tokio::spawn(run_with_listeners(vec![listener], cfg));

    let resolver = TestResolver::new(policy(
        "proxy",
        Some("alice"),
        &["allow https://api.example.test/**"],
    ));
    let el = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge = el.local_addr().unwrap();
    let cfg = ProxyConfig::edge(
        vec![edge],
        resolver,
        vec![bad_tier],
        s.pki.edge.client_config().unwrap(),
    );
    tokio::spawn(run_with_listeners(vec![el], cfg));

    // The CA refuses to sign for it, so it cannot terminate: fail closed.
    let client = guest_client(edge, &s.tier_ca, false);
    assert!(client.get(url("/get")).send().await.is_err());
    assert!(s.upstream.hit_paths().is_empty());
}
