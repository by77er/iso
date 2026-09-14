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
    start_custom(rules, principal, egress, |_| {}).await
}

/// `start`, with a last word on the configuration before it runs.
async fn start_custom(
    rules: &[&str],
    principal: Option<&str>,
    egress: &str,
    tweak: impl FnOnce(&mut ProxyConfig),
) -> Single {
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
    cfg.host_id = "hostT".into();
    tweak(&mut cfg);
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

/// Every request leaves one access event with who, what, the decision and
/// the outcome, and never a query string or a header value; a WebSocket
/// tunnel leaves one more when it closes, with the bytes each way.
#[tokio::test]
async fn every_request_and_tunnel_leaves_an_access_event() {
    let s = start(
        &[
            "allow https://api.example.test/**",
            "allow wss://api.example.test/ws",
            "deny https://api.example.test/traced/denied/**",
        ],
        Some("alice"),
        "proxy",
    )
    .await;
    let client = guest_client(s.proxy, &s.tier_ca, true);
    let tag = unique_path("/traced");

    let r = client.get(url(&format!("{tag}/ok?token=SECRET-VALUE"))).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let r = client.get(url(&format!("/traced/denied{tag}"))).send().await.unwrap();
    assert_eq!(r.status(), 403);

    let events = access_events();
    let ok = events
        .iter()
        .find(|e| e["path"] == format!("{tag}/ok"))
        .expect("the allowed request is logged");
    assert_eq!(ok["decision"], "allow");
    assert_eq!(ok["status"], 200);
    assert_eq!(ok["method"], "GET");
    assert_eq!(ok["scheme"], "https");
    assert_eq!(ok["host"], UPSTREAM_HOST);
    assert_eq!(ok["vm"], "vm-test");
    assert_eq!(ok["principal"], "alice");
    assert_eq!(ok["edge"], "hostT");
    assert_eq!(ok["injected"], "authorization,x-iso-injected", "names only");
    assert_eq!(ok["upgrade"], false);
    assert!(ok["latency_ms"].is_u64(), "{ok}");
    assert_eq!(ok["src"], "127.0.0.1");
    let line = ok.to_string();
    assert!(!line.contains("SECRET-VALUE") && !line.contains("token="), "no query string: {line}");
    assert!(!line.contains("alice-token") && !line.contains("hello-from-iso"), "no header values: {line}");

    let denied = events
        .iter()
        .find(|e| e["path"] == format!("/traced/denied{tag}"))
        .expect("the denied request is logged");
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["rule"], "deny https://api.example.test/traced/denied/**");
    assert_eq!(denied["status"], 403);
    assert_eq!(denied["injected"], "");

    // A tunnel: a payload of a size no other test sends, echoed back.
    let payload = vec![b'x'; 1000 + (tag.len() * 7) % 500];
    let (mut ws, _) = open_ws(&client, "/ws").await.unwrap();
    ws.write_all(&payload).await.unwrap();
    let mut back = vec![0u8; payload.len()];
    ws.read_exact(&mut back).await.unwrap();
    assert_eq!(back, payload);
    drop(ws);
    let n = payload.len() as u64;
    eventually(
        || access_events().iter().any(|e| e["kind"] == "websocket" && e["bytes_up"] == n),
        Duration::from_secs(5),
        "the tunnel's close is logged",
    )
    .await;
    let t = access_events().into_iter().find(|e| e["kind"] == "websocket" && e["bytes_up"] == n).unwrap();
    assert_eq!(t["bytes_down"], n);
    assert_eq!(t["path"], "/ws");
    assert_eq!(t["host"], UPSTREAM_HOST);
    assert_eq!(t["vm"], "vm-test");
    assert!(t["duration_ms"].is_u64(), "{t}");
    // Its handshake was a request too, judged under wss.
    let hs = access_events().into_iter().filter(|e| e["path"] == "/ws" && e["upgrade"] == true).last().unwrap();
    assert_eq!((hs["scheme"].as_str(), hs["status"].as_u64()), (Some("wss"), Some(101)));
}

/// A connection to a port with no SNI is carried through as bytes when a
/// `tunnel tcp://name:port` rule names the host the VM resolved the
/// address from; with no name, or no rule, nothing is carried. Either way
/// there is one access event.
#[tokio::test]
async fn tcp_passthrough_follows_tunnel_rules() {
    let echo = TestTcpEcho::start().await;
    let guest: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let dialled: std::net::Ipv4Addr = "10.9.9.9".parse().unwrap();

    let s = start_custom(&["tunnel tcp://db.internal:5432"], Some("alice"), "proxy", |cfg| {
        cfg.dst_lookup = fixed_dst("10.9.9.9:5432");
        cfg.upstream_pins.insert("db.internal".into(), echo.addr);
    })
    .await;
    s.resolver.name_dst(guest, dialled, "db.internal");
    let mut c = tokio::net::TcpStream::connect(s.proxy).await.unwrap();
    let payload = format!("hello {}", unique_path(""));
    c.write_all(payload.as_bytes()).await.unwrap();
    let mut back = vec![0u8; payload.len()];
    c.read_exact(&mut back).await.unwrap();
    assert_eq!(back, payload.as_bytes(), "carried through, byte for byte");
    drop(c);
    let n = payload.len() as u64;
    eventually(
        || access_events().iter().any(|e| e["kind"] == "tcp" && e["bytes_up"] == n),
        Duration::from_secs(5),
        "the tunnel's close is logged",
    )
    .await;
    let t = access_events().into_iter().find(|e| e["kind"] == "tcp" && e["bytes_up"] == n).unwrap();
    assert_eq!((t["host"].as_str(), t["port"].as_u64(), t["bytes_down"].as_u64()), (Some("db.internal"), Some(5432), Some(n)));
    assert_eq!(t["principal"], "alice");

    // The same address, never resolved by this VM: no name, nothing carried.
    let s = start_custom(&["tunnel tcp://db.internal:5432"], None, "proxy", |cfg| {
        cfg.dst_lookup = fixed_dst("10.9.9.9:5432");
        cfg.upstream_pins.insert("db.internal".into(), echo.addr);
    })
    .await;
    // The proxy closes without reading, so the guest sees EOF or a reset.
    async fn nothing_back(proxy: SocketAddr) {
        let mut c = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let _ = c.write_all(b"hello").await;
        let mut buf = [0u8; 8];
        match c.read(&mut buf).await {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("{n} bytes came back through a refused connection"),
        }
    }
    nothing_back(s.proxy).await;
    eventually(
        || access_events().iter().any(|e| e["phase"] == "tcp" && e["host"] == "10.9.9.9" && e["rule"].as_str().unwrap().starts_with("no name")),
        Duration::from_secs(5),
        "the refusal is logged with its reason",
    )
    .await;

    // Resolved, but no tunnel rule for that host and port.
    let s = start_custom(&["tunnel tcp://db.internal:5432"], None, "proxy", |cfg| {
        cfg.dst_lookup = fixed_dst("10.9.9.9:5433");
        cfg.upstream_pins.insert("db.internal".into(), echo.addr);
    })
    .await;
    s.resolver.name_dst(guest, dialled, "db.internal");
    nothing_back(s.proxy).await;
    eventually(
        || access_events().iter().any(|e| e["phase"] == "tcp" && e["host"] == "db.internal" && e["port"] == 5433 && e["rule"] == "no tunnel rule"),
        Duration::from_secs(5),
        "the missing rule is logged",
    )
    .await;
}

/// `tunnel tcp://host:443` carries the TLS session through untouched: the
/// guest sees the upstream's own certificate and nothing is injected.
#[tokio::test]
async fn a_443_tunnel_rule_passes_tls_through_without_terminating() {
    let s = start(&["tunnel tcp://api.example.test:443"], Some("alice"), "proxy").await;
    // The guest trusts the upstream's CA, not the tier's: no MITM happened.
    let client = guest_client(s.proxy, &s.upstream.ca_pem, true);
    let path = unique_path("/passthrough");
    let body: serde_json::Value = client.get(url(&path)).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["path"], path);
    assert!(body["headers"]["x-iso-injected"].is_null(), "nothing injected on a passthrough: {body}");
    assert!(body["headers"]["authorization"].is_null());
    // Through the tier's CA it does not verify: the proxy never minted a leaf.
    let mitm = guest_client(s.proxy, &s.tier_ca, true);
    assert!(mitm.get(url(&path)).send().await.is_err());
    drop(client);
    eventually(
        || access_events().iter().any(|e| e["kind"] == "tcp" && e["host"] == UPSTREAM_HOST && e["port"] == 443),
        Duration::from_secs(5),
        "the passthrough's close is logged",
    )
    .await;
}
