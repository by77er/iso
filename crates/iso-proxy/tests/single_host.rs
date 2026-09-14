//! Single-host configuration: one `iso-proxyd` in the `single` role on the
//! host, the CA and secrets services on Unix sockets beside it, policy from
//! the host's identify RPC. Everything runs in-process on loopback; the
//! "guest" is a reqwest client that resolves the upstream's name to the proxy,
//! which is what the nftables DNAT does for a real guest.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use iso_proxy::{ProxyConfig, run_with_listeners};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Single {
    proxy: SocketAddr,
    tier_ca: String,
    resolver: Arc<TestResolver>,
    upstream: TestUpstream,
}

async fn start(rules: &[&str], principal: Option<&str>, egress: &str) -> Single {
    init();
    let dir = tempdir("single");
    let ca = TestCa::start(&dir, None).await;
    let secrets = TestSecrets::start(&dir, None).await;
    let upstream = TestUpstream::start(&dir).await;
    let resolver = TestResolver::new(policy(egress, principal, rules));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let mut cfg = ProxyConfig::single(
        vec![proxy],
        resolver.clone(),
        iso_rpc::Endpoint::unix(ca.sock.clone()),
        iso_rpc::Endpoint::unix(secrets.sock.clone()),
    );
    cfg.extra_upstream_roots = vec![upstream.ca_der.clone()];
    cfg.upstream_pins
        .insert(UPSTREAM_HOST.into(), upstream.addr);
    cfg.watch_every = Duration::from_millis(50);
    tokio::spawn(run_with_listeners(vec![listener], cfg));
    Single {
        proxy,
        tier_ca: ca.cert_pem.clone(),
        resolver,
        upstream,
    }
}

#[tokio::test]
async fn allowed_request_is_injected_and_forwarded() {
    let s = start(
        &["allow https://api.example.test/**"],
        Some("alice"),
        "proxy",
    )
    .await;
    let client = guest_client(s.proxy, &s.tier_ca, false);
    let body: serde_json::Value = client
        .get(url("/get?x=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["path"], "/get");
    assert_eq!(
        body["headers"]["x-iso-injected"], "hello-from-iso",
        "global secret injected"
    );
    assert_eq!(
        body["headers"]["authorization"], "Bearer alice-token",
        "per-principal secret injected"
    );
    assert_eq!(s.upstream.hit_paths(), vec!["/get"]);
}

#[tokio::test]
async fn host_without_an_allow_rule_is_never_terminated() {
    let s = start(
        &[
            "allow https://other.example.test/**",
            "deny https://api.example.test/**",
        ],
        None,
        "proxy",
    )
    .await;
    let client = guest_client(s.proxy, &s.tier_ca, false);
    let err = client.get(url("/get")).send().await.unwrap_err();
    assert!(
        err.is_connect() || err.is_request(),
        "expected the connection to be dropped, got {err}"
    );
    assert!(
        s.upstream.hit_paths().is_empty(),
        "the upstream must never be dialled"
    );
}

#[tokio::test]
async fn deny_rule_beats_allow_and_answers_403() {
    let s = start(
        &[
            "allow https://api.example.test/**",
            "deny https://api.example.test/user/keys",
        ],
        Some("alice"),
        "proxy",
    )
    .await;
    let client = guest_client(s.proxy, &s.tier_ca, false);
    let resp = client
        .get(url("/user/keys?per_page=5"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.headers().get("x-iso-denied").unwrap(), "policy");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "denied by policy");
    assert_eq!(body["rule"], "deny https://api.example.test/user/keys");
    assert_eq!(body["request"], "https://api.example.test/user/keys");
    // The denied path never reached the upstream, and never carried a credential.
    assert!(s.upstream.hit_paths().is_empty());
    // A sibling path is still allowed.
    let resp = client.get(url("/user/keys/1")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(s.upstream.hit_paths(), vec!["/user/keys/1"]);
}

#[tokio::test]
async fn default_deny_inside_an_allowed_host() {
    let s = start(&["allow https://api.example.test/v1/*"], None, "proxy").await;
    let client = guest_client(s.proxy, &s.tier_ca, false);
    assert_eq!(client.get(url("/v1/x")).send().await.unwrap().status(), 200);
    let resp = client.get(url("/v2/x")).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["rule"].is_null(), "default deny names no rule");
    let resp = client.get(url("/v1/x/deeper")).send().await.unwrap();
    assert_eq!(resp.status(), 403, "`*` is one segment");
}

#[tokio::test]
async fn websocket_upgrade_is_tunnelled_with_injection_on_the_handshake() {
    let s = start(
        &[
            "allow https://api.example.test/**",
            "allow wss://api.example.test/ws",
        ],
        Some("alice"),
        "proxy",
    )
    .await;
    let client = guest_client(s.proxy, &s.tier_ca, true);
    let (mut ws, headers) = open_ws(&client, "/ws")
        .await
        .expect("101 through the proxy");
    assert_eq!(headers.get("x-ws-upstream").unwrap(), "echo");
    assert_eq!(
        headers.get("x-ws-saw-injected").unwrap(),
        "hello-from-iso",
        "handshake carried the credential"
    );
    for msg in [
        "ping-1",
        "a much longer frame payload that spans more bytes",
        "bye",
    ] {
        ws.write_all(msg.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        ws.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg.as_bytes());
    }
}

#[tokio::test]
async fn websocket_needs_a_wss_rule() {
    let s = start(&["allow https://api.example.test/**"], None, "proxy").await;
    let client = guest_client(s.proxy, &s.tier_ca, true);
    let err = open_ws(&client, "/ws").await.unwrap_err();
    assert_eq!(err.status(), Some(reqwest::StatusCode::FORBIDDEN));
    assert!(s.upstream.hit_paths().is_empty());
}

#[tokio::test]
async fn deny_mode_vm_is_refused_even_with_rules() {
    let s = start(
        &["allow https://api.example.test/**"],
        Some("alice"),
        "deny",
    )
    .await;
    let client = guest_client(s.proxy, &s.tier_ca, false);
    assert!(client.get(url("/get")).send().await.is_err());
    assert!(s.upstream.hit_paths().is_empty());
}

#[tokio::test]
async fn unknown_source_is_refused() {
    let s = start(&["allow https://api.example.test/**"], None, "proxy").await;
    s.resolver.set(None);
    let client = guest_client(s.proxy, &s.tier_ca, false);
    assert!(client.get(url("/get")).send().await.is_err());
}

#[tokio::test]
async fn a_policy_change_closes_open_connections() {
    let s = start(
        &[
            "allow https://api.example.test/**",
            "allow wss://api.example.test/ws",
        ],
        None,
        "proxy",
    )
    .await;
    let client = guest_client(s.proxy, &s.tier_ca, true);
    let (mut ws, _) = open_ws(&client, "/ws").await.unwrap();
    ws.write_all(b"before").await.unwrap();
    let mut buf = [0u8; 6];
    ws.read_exact(&mut buf).await.unwrap();

    // The control plane bumps the generation; the edge half of the proxy
    // notices on its next watch tick and closes what it holds.
    s.resolver.bump();
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
        "the tunnel must close after a policy change"
    );

    // New connections carry the new generation and work.
    let client = guest_client(s.proxy, &s.tier_ca, true);
    let (mut ws, _) = open_ws(&client, "/ws")
        .await
        .expect("new connection after the change");
    ws.write_all(b"after").await.unwrap();
    let mut buf = [0u8; 5];
    ws.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"after");
}

#[tokio::test]
async fn authority_must_match_the_sni() {
    let s = start(&["allow https://api.example.test/**"], None, "proxy").await;
    let client = guest_client(s.proxy, &s.tier_ca, true);
    let resp = client
        .get(url("/get"))
        .header("host", "evil.example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 421);
    assert!(s.upstream.hit_paths().is_empty());
}
