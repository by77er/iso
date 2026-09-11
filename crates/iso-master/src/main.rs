mod config;
mod engine;
mod model;
mod pi;
mod plane;
mod store;
mod web;

use anyhow::Result;
use fs2::FileExt;
use std::{fs::OpenOptions, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "master.json".into());
    let cfg = config::Config::load(&path)?;
    let auth = web::Auth::new(
        std::env::var("MASTER_USER").unwrap_or_else(|_| "admin".into()),
        std::env::var("MASTER_PASSWORD")?,
    )?;
    std::fs::create_dir_all(&cfg.data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg.data_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(cfg.data_dir.join("master.lock"))?;
    lock.try_lock_exclusive()
        .map_err(|_| anyhow::anyhow!("Another master is using this data directory"))?;
    let store = Arc::new(store::Store::open(&cfg.data_dir.join("master.sqlite3"))?);
    let engine = engine::Engine::new(cfg.clone(), store)?;
    let web = web::Web {
        engine: engine.clone(),
        auth: Arc::new(auth),
    };
    let socket = cfg.data_dir.join("swarm.sock");
    if let Ok(meta) = std::fs::symlink_metadata(&socket) {
        use std::os::unix::fs::FileTypeExt;
        anyhow::ensure!(
            meta.file_type().is_socket(),
            "Swarm socket path is not a socket"
        );
        std::fs::remove_file(&socket)?;
    }
    let unix = tokio::net::UnixListener::bind(&socket)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let worker_app = web::worker_router(web.clone());
    let worker_server = tokio::spawn(async move { axum::serve(unix, worker_app).await });
    let app = web::router(web);
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    let timer = tokio::spawn(engine.clone().timer());
    eprintln!(
        "iso-master listening on {}{}",
        cfg.bind,
        if cfg.demo {
            " (DEMO: no real VMs or model calls)"
        } else {
            ""
        }
    );
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            #[cfg(unix)]
            {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM handler");
                tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            timer.abort();
        })
        .await;
    engine.shutdown().await;
    worker_server.abort();
    result?;
    Ok(())
}
