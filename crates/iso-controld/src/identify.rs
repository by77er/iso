//! `identify` RPC: map a connection's source IP to the VM's egress policy, for
//! the egress proxy. JSON, half-close framed (like the secret/CA boundaries).

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use iso_common::identify::{IdentifyRequest, IdentifyResponse};
use iso_common::network::NetworkManager;
use iso_common::runtime::VmRuntime;
use iso_common::storage::StorageManager;
use iso_control_plane::ControlPlane;
use iso_control_plane::types::egress_str;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

pub async fn serve<N, S, R>(cp: Arc<ControlPlane<N, S, R>>, sock: &Path) -> std::io::Result<()>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock)?;
    eprintln!("iso-controld: identify RPC on {}", sock.display());
    loop {
        let (mut conn, _) = listener.accept().await?;
        let cp = cp.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            if conn.read_to_end(&mut buf).await.is_err() {
                return;
            }
            let resp = handle(&cp, &buf);
            let _ = conn.write_all(&resp).await;
            let _ = conn.shutdown().await;
        });
    }
}

fn handle<N, S, R>(cp: &ControlPlane<N, S, R>, req: &[u8]) -> Vec<u8>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let resp = (|| -> Option<IdentifyResponse> {
        let req: IdentifyRequest = serde_json::from_slice(req).ok()?;
        let ip: Ipv4Addr = req.ip.parse().ok()?;
        let rec = cp.identify(ip).ok()??;
        Some(IdentifyResponse {
            found: true,
            egress: egress_str(rec.egress).to_string(),
            principal: rec.principal,
            allow: rec.allow,
        })
    })()
    .unwrap_or_default();
    serde_json::to_vec(&resp).unwrap_or_default()
}
