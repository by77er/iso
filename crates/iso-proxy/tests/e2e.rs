//! Data-path e2e for the proxy (no VMs / nft): client → proxy → real upstream.
//!
//! Network + an external header-reflecting echo (postman-echo.com) → `#[ignore]`;
//! run manually:
//!   cargo test -p iso-proxy --test e2e -- --ignored --nocapture

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use iso_ca::Ca;
use iso_proxy::{Policy, ProxyConfig, StaticResolver, run_with_listener};
use iso_secrets::TomlSecretProvider;
use tokio::net::TcpListener;

const ECHO: &str = "postman-echo.com";

#[tokio::test]
#[ignore = "needs network + external echo service"]
async fn injects_headers_and_enforces_allowlist() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = std::env::temp_dir().join(format!("iso-proxy-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // secrets.toml: a recognizable global header for the echo domain.
    std::fs::write(
        dir.join("secrets.toml"),
        format!("[global.\"{ECHO}\"]\n\"x-iso-injected\" = \"hello-from-iso\"\n"),
    )
    .unwrap();

    // CA + providers in-process.
    let ca = Arc::new(Ca::load_or_generate(&dir.join("ca")).unwrap());
    let ca_sock = dir.join("ca.sock");
    {
        let ca = ca.clone();
        let sock = ca_sock.clone();
        tokio::spawn(async move { iso_ca::serve_unix(ca, &sock).await });
    }
    let secrets_sock = dir.join("secrets.sock");
    {
        let provider = Arc::new(TomlSecretProvider::load(&dir.join("secrets.toml")).unwrap());
        let sock = secrets_sock.clone();
        tokio::spawn(async move { iso_secrets::serve_unix(provider, &sock).await });
    }

    // Proxy on an ephemeral port, allowing only the echo domain.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(run_with_listener(
        listener,
        ProxyConfig {
            listen: proxy_addr,
            ca_sock,
            secrets_sock,
            resolver: Arc::new(StaticResolver(Policy {
                egress: "proxy".into(),
                principal: Some("default".into()),
                allow: HashSet::from([ECHO.to_string()]),
            })),
        },
    ));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Client trusts the proxy CA and is pointed at the proxy for the echo host.
    let ca_pem = std::fs::read(PathBuf::from(&dir).join("ca/ca.crt")).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).unwrap())
        .resolve(ECHO, proxy_addr)
        .build()
        .unwrap();

    // 1. allowed + injected: the echo reflects our injected header.
    let body: serde_json::Value = client
        .get(format!("https://{ECHO}/get"))
        .send()
        .await
        .expect("request through proxy")
        .json()
        .await
        .expect("json");
    let reflected = body["headers"]["x-iso-injected"].as_str();
    assert_eq!(reflected, Some("hello-from-iso"), "injected header reflected");

    // 2. not in allow-list → proxy drops the connection.
    let denied = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).unwrap())
        .resolve("example.com", proxy_addr)
        .build()
        .unwrap()
        .get("https://example.com/")
        .send()
        .await;
    assert!(denied.is_err(), "denied domain must fail, got {denied:?}");

    let _ = std::fs::remove_dir_all(&dir);
}
