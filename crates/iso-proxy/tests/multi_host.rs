//! Multi-host configuration: an `edge` on each host carries connections as
//! CONNECT streams on a pooled mutual-TLS HTTP/2 tunnel, with the policy in
//! the stream's headers, to a `proxy` replica that is nowhere near the host. The replica reaches the CA and the
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
    start_tier_with(None).await
}

/// A tier that, given the fleet's key, serves only policies the fleet signed.
async fn start_tier_with(verifier: Option<iso_policy::signed::Verifier>) -> Split {
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
    cfg.policy_verifier = verifier;
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
    metrics: Arc<iso_proxy::edge::Metrics>,
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
    let metrics = cfg.metrics.clone();
    tokio::spawn(run_with_listeners(vec![listener], cfg));
    Edge { addr, resolver, metrics }
}

#[tokio::test]
async fn guest_connections_share_a_pooled_tunnel() {
    use std::sync::atomic::Ordering;
    let s = start_tier().await;
    let e = start_edge(&s, "hostA", &s.pki.edge, &["allow https://api.example.test/**"], None, "proxy").await;
    // Twenty guest connections: a fresh client each time, so nothing is
    // pooled on the guest side and each is its own TCP connection to the edge.
    for i in 0..20 {
        let client = guest_client(e.addr, &s.tier_ca, false);
        let resp = client.get(url(&format!("/get?i={i}"))).send().await.unwrap();
        assert_eq!(resp.status(), 200);
    }
    assert_eq!(e.metrics.tier_streams_opened.load(Ordering::Relaxed), 20, "one stream per guest connection");
    let conns = e.metrics.tier_connections_opened.load(Ordering::Relaxed);
    assert!((1..=2).contains(&conns), "at most the pool size of tunnels, got {conns}");
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

/// With the fleet's key, the tier takes the policy from the fleet's signed
/// claims and nothing else: an unsigned policy, one signed for another host
/// than the edge presenting it, an expired one, or one under another key is
/// refused at the CONNECT, and a principal the edge claims beside the
/// signature is ignored in favour of the signed one.
#[tokio::test]
async fn tier_serves_only_policies_the_fleet_signed_for_this_edge() {
    use iso_common::identify::SignedPolicy;
    use iso_policy::signed::{PolicyClaims, Signer, Verifier, now};
    let (signer, _) = Signer::generate().unwrap();
    let s = start_tier_with(Some(Verifier::from_b64(&signer.public_key_b64()).unwrap())).await;
    let rule = format!("allow https://{UPSTREAM_HOST}/**");
    let claims = |host: &str, expires: u64| PolicyClaims {
        host: host.into(),
        vm: "vm-1".into(),
        egress: "proxy".into(),
        principal: Some("alice".into()),
        rules: vec![rule.clone()],
        policy_gen: 1,
        expires,
    };
    let far = now() + 3600;
    // TestPki issues the edge's certificate under the name "edge-hostA".
    let cases: Vec<(&str, Option<SignedPolicy>, bool)> = vec![
        ("unsigned", None, false),
        ("signed for this edge", Some(signer.sign(&claims("edge-hostA", far))), true),
        ("signed for another host", Some(signer.sign(&claims("edge-hostB", far))), false),
        ("expired", Some(signer.sign(&claims("edge-hostA", now() - 1))), false),
        ("signed under another key", Some(Signer::generate().unwrap().0.sign(&claims("edge-hostA", far))), false),
    ];
    for (what, signed, ok) in cases {
        let e = start_edge(&s, "hostA", &s.pki.edge, &[&rule], Some("alice"), "proxy").await;
        let mut p = policy("proxy", Some("alice"), &[&rule]);
        p.signed = signed;
        e.resolver.set(Some(p));
        let client = guest_client(e.addr, &s.tier_ca, false);
        let r = client.get(url("/get")).send().await;
        if ok {
            let body: serde_json::Value = r.unwrap().json().await.unwrap();
            assert_eq!(body["headers"]["authorization"], "Bearer alice-token", "{what}");
        } else {
            assert!(r.is_err(), "{what}: must be refused at the tier");
        }
    }

    // The signed claims are the policy. What the edge says beside them
    // (here, a different principal) is not read.
    let e = start_edge(&s, "hostA", &s.pki.edge, &[&rule], Some("mallory"), "proxy").await;
    let mut p = policy("proxy", Some("mallory"), &[&rule]);
    p.signed = Some(signer.sign(&claims("edge-hostA", far)));
    e.resolver.set(Some(p));
    let body: serde_json::Value = guest_client(e.addr, &s.tier_ca, false)
        .get(url("/get"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["headers"]["authorization"], "Bearer alice-token", "injection follows the signed principal");
}
