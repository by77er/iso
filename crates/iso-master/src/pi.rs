use crate::{
    config::{Config, PlaneConfig},
    store::Store,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::{Mutex, oneshot},
    task::JoinHandle,
};

type Pending = Arc<StdMutex<HashMap<String, oneshot::Sender<Result<Value>>>>>;

pub struct Pi {
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    pending: Pending,
    closed: Arc<AtomicBool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    demo_task: Mutex<Option<JoinHandle<()>>>,
    store: Arc<Store>,
    id: String,
    demo: bool,
}
impl Pi {
    pub async fn start(
        cfg: &Config,
        plane: &PlaneConfig,
        vm: &str,
        id: &str,
        store: Arc<Store>,
        swarm: Option<Value>,
    ) -> Result<Arc<Self>> {
        let dir = cfg.data_dir.join("sessions").join(id);
        std::fs::create_dir_all(&dir)?;
        let pi = Arc::new(Self {
            child: Mutex::new(None),
            stdin: Mutex::new(None),
            pending: Default::default(),
            closed: Arc::new(AtomicBool::new(false)),
            tasks: Default::default(),
            demo_task: Default::default(),
            store: store.clone(),
            id: id.into(),
            demo: cfg.demo,
        });
        if cfg.demo {
            return Ok(pi);
        }
        let mut cmd = Command::new(&cfg.pi_bin);
        configure(&mut cmd, cfg, &dir)?;
        if let Some(swarm) = swarm {
            cmd.env("MASTER_SWARM", serde_json::to_string(&swarm)?);
        }
        cmd.env(
            "MASTER_REMOTE",
            serde_json::to_string(
                &json!({"server":plane.server,"creds":plane.creds,"client":plane.client,"vm":vm}),
            )?,
        );
        let mut child = cmd.spawn().context("Could not start headless pi")?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        *pi.stdin.lock().await = Some(stdin);
        *pi.child.lock().await = Some(child);
        let pending = pi.pending.clone();
        let closed = pi.closed.clone();
        let session = id.to_string();
        let (ready_tx, ready_rx) = oneshot::channel();
        let reader = tokio::spawn(async move {
            let mut ready = Some(ready_tx);
            let mut reader = BufReader::new(stdout);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                // take() bounds memory even if the child emits a malformed giant line.
                let read = (&mut reader)
                    .take(32 * 1024 * 1024)
                    .read_until(b'\n', &mut buf)
                    .await;
                if !matches!(read,Ok(n) if n>0) || buf.last() != Some(&b'\n') {
                    break;
                }
                let event: Value = match serde_json::from_slice(&buf) {
                    Ok(e) => e,
                    Err(_) => break,
                };
                if event["type"] == "response" {
                    let id = event["id"].as_str().unwrap_or("");
                    if let Some(tx) = pending.lock().unwrap().remove(id) {
                        let result = if event["success"] == true {
                            Ok(event["data"].clone())
                        } else {
                            Err(anyhow::anyhow!("pi rejected the command"))
                        };
                        let _ = tx.send(result);
                    }
                } else if event["type"] == "extension_ui_request"
                    && event["message"] == "iso-master-remote-ready"
                {
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(());
                    }
                } else {
                    store.pi_event(&session, event);
                }
            }
            pending.lock().unwrap().clear();
            if !closed.load(Ordering::SeqCst) {
                store.interrupt(&session,"Headless pi disconnected. Recover explicitly; prompts are never replayed automatically.");
            }
        });
        let drain = tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            while matches!(stderr.read(&mut buf).await,Ok(n) if n>0) {}
        });
        pi.tasks.lock().await.extend([reader, drain]);
        if !matches!(
            tokio::time::timeout(Duration::from_secs(30), ready_rx).await,
            Ok(Ok(()))
        ) {
            pi.close().await;
            bail!("pi remote-tool readiness handshake failed");
        }
        if let Err(e) = pi.command("get_state", json!({})).await {
            pi.close().await;
            return Err(e);
        }
        Ok(pi)
    }
    pub async fn command(&self, kind: &str, payload: Value) -> Result<Value> {
        if self.closed.load(Ordering::SeqCst) {
            bail!("pi is closed");
        }
        if self.demo {
            if kind == "prompt" {
                let store = self.store.clone();
                let id = self.id.clone();
                let text = payload["message"].clone();
                let task = tokio::spawn(async move {
                    store.pi_event(
                        &id,
                        json!({"type":"message_end","message":{"role":"user","content":text}}),
                    );
                    store.pi_event(
                        &id,
                        json!({"type":"message_start","message":{"role":"assistant"}}),
                    );
                    let answer = "This is a demo agent. In live mode, pi streams its response here and runs tools in your isolated workspace. Sleeping and resumption work without allocating real VMs.";
                    for word in answer.split(' ') {
                        store.pi_event(&id,json!({"type":"message_update","assistantMessageEvent":{"type":"text_delta","delta":format!("{word} ")}}));
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    store.pi_event(&id,json!({"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":answer}]}}));
                    store.pi_event(&id, json!({"type":"agent_settled"}));
                });
                *self.demo_task.lock().await = Some(task);
            }
            return Ok(json!({}));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut message = payload;
        message["type"] = json!(kind);
        message["id"] = json!(id);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id.clone(), tx);
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            {
                let mut stdin = self.stdin.lock().await;
                let stdin = stdin.as_mut().context("pi stdin closed")?;
                let mut bytes = serde_json::to_vec(&message)?;
                bytes.push(b'\n');
                stdin.write_all(&bytes).await?;
                stdin.flush().await?;
            }
            rx.await.context("pi disconnected")?
        })
        .await
        .context("pi command timed out")
        .and_then(|r| r);
        self.pending.lock().unwrap().remove(&id);
        result
    }
    pub async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(task) = self.demo_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(mut input) = self.stdin.lock().await.take() {
            let _ = input.shutdown().await;
        }
        if let Some(mut child) = self.child.lock().await.take()
            && tokio::time::timeout(Duration::from_secs(3), child.wait())
                .await
                .is_err()
        {
            let _ = child.kill().await;
        }
        for task in self.tasks.lock().await.drain(..) {
            task.abort();
            let _ = task.await;
        }
        self.pending.lock().unwrap().clear();
    }
}

fn configure(cmd: &mut Command, cfg: &Config, dir: &Path) -> Result<()> {
    cmd.env_clear()
        .envs(cfg.pi_env()?)
        .env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
        )
        .env("HOME", dir)
        .env("PI_CODING_AGENT_DIR", dir.join("config"))
        .env("PI_OFFLINE", "1")
        .env("PI_TELEMETRY", "0")
        .current_dir(dir)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .args([
            "--mode",
            "rpc",
            "--no-builtin-tools",
            "--no-extensions",
            "--no-skills",
            "--no-prompt-templates",
            "--no-themes",
            "--no-context-files",
            "--no-approve",
        ])
        .arg("-e")
        .arg(&cfg.pi_extension)
        .arg("--session")
        .arg(dir.join("session.jsonl"));
    if let Some(model) = &cfg.pi_model {
        cmd.arg("--model").arg(model);
    }
    Ok(())
}
