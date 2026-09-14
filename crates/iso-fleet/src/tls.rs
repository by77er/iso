//! Mutual TLS for the fleet API, on the fleet's own admin CA. A client
//! certificate from that CA is a fleet administrator, as on a host.

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

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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

pub async fn serve(listener: TcpListener, acceptor: TlsAcceptor, router: Router) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("accept: {e}");
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
                    tracing::info!("tls handshake from {peer} failed: {e}");
                    return;
                }
                Err(_) => return,
            };
            let svc = TowerToHyperService::new(router);
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(tls), svc)
                .await
            {
                tracing::debug!("connection from {peer}: {e}");
            }
        });
    }
}
