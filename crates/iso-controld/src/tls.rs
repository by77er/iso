//! Mutual TLS for the admin API's TCP listener.
//!
//! The server presents the host's admin certificate and requires every client
//! to present one issued by the same admin CA (`isoctl admin issue-client`).
//! Nothing else is checked: a valid client certificate is an administrator.
//! The unix socket is unaffected and stays root-only.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use iso_admin_pki::AdminPki;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// How long a client gets to finish the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Build an acceptor that requires client certificates from `pki`'s CA.
pub fn acceptor(pki: &AdminPki) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca_cert_der()?)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let server = pki.server_identity()?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server.cert_der()?], server.key_der()?)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Accept connections forever, serving `router` over TLS on each.
pub async fn serve(listener: TcpListener, acceptor: TlsAcceptor, router: Router) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("iso-controld: admin tls accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    eprintln!("iso-controld: admin tls handshake from {peer} failed: {e}");
                    return;
                }
                Err(_) => {
                    eprintln!("iso-controld: admin tls handshake from {peer} timed out");
                    return;
                }
            };
            let svc = TowerToHyperService::new(router);
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(tls), svc)
                .await
            {
                eprintln!("iso-controld: admin connection from {peer}: {e}");
            }
        });
    }
}

/// The names the server certificate should carry: loopback, the host's
/// primary address, its hostname, and anything the operator adds.
pub fn server_sans(bind: SocketAddr, extra: &[String]) -> Vec<String> {
    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    if !bind.ip().is_unspecified() {
        sans.push(bind.ip().to_string());
    }
    if let Some(ip) = crate::settings::primary_ipv4() {
        sans.push(ip.to_string());
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim();
        if !h.is_empty() {
            sans.push(h.to_string());
        }
    }
    sans.extend(extra.iter().cloned());
    sans.sort();
    sans.dedup();
    sans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_admin_requires_a_certificate_from_the_admin_ca() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("iso-tls-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pki = AdminPki::load_or_generate(&dir, &["127.0.0.1".into(), "localhost".into()]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, acceptor(&pki).unwrap(), crate::http::tests::app()));
        let url = format!("https://127.0.0.1:{}/stats", addr.port());
        let ca = reqwest::Certificate::from_pem(pki.ca_cert_pem().as_bytes()).unwrap();

        // Trusting the CA is not enough: the server demands a client certificate.
        let anonymous = reqwest::Client::builder().add_root_certificate(ca.clone()).build().unwrap();
        assert!(anonymous.get(&url).send().await.is_err(), "handshake without a client cert must fail");

        // A certificate issued by the admin CA is an administrator.
        let id = pki.issue_client("test-client").unwrap();
        let pem = format!("{}{}", id.cert_pem, id.key_pem);
        let admin = reqwest::Client::builder()
            .add_root_certificate(ca.clone())
            .identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        let resp = admin.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.json::<serde_json::Value>().await.unwrap()["slots_total"].is_number());

        // A certificate from some other CA is refused.
        let other_dir = dir.join("other");
        let other = AdminPki::load_or_generate(&other_dir, &["localhost".into()]).unwrap();
        let stranger = other.issue_client("stranger").unwrap();
        let pem = format!("{}{}", stranger.cert_pem, stranger.key_pem);
        let impostor = reqwest::Client::builder()
            .add_root_certificate(ca)
            .identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        assert!(impostor.get(&url).send().await.is_err(), "a cert from another CA must be refused");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
