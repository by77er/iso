use crate::{
    config::Config,
    model::{Phase, Session, now},
    pi::Pi,
    plane::Plane,
    store::Store,
};
use anyhow::{Context, Result, bail, ensure};
use futures_util::future::join_all;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::sync::Mutex;

pub struct Engine {
    pub cfg: Config,
    pub store: Arc<Store>,
    pub planes: Vec<Plane>,
    workers: Mutex<HashMap<String, Arc<Pi>>>,
    locks: StdMutex<HashMap<String, Arc<Mutex<()>>>>,
    placement: Mutex<()>,
    launch_gate: Mutex<()>,
}
impl Engine {
    pub fn new(cfg: Config, store: Arc<Store>) -> Result<Arc<Self>> {
        let planes = cfg
            .planes
            .iter()
            .map(|p| Plane::new(p.clone(), cfg.demo))
            .collect::<Result<Vec<_>>>()?;
        store.recover()?;
        Ok(Arc::new(Self {
            cfg,
            store,
            planes,
            workers: Default::default(),
            locks: Default::default(),
            placement: Default::default(),
            launch_gate: Default::default(),
        }))
    }
    fn lock(&self, id: &str) -> Arc<Mutex<()>> {
        self.locks
            .lock()
            .unwrap()
            .entry(id.into())
            .or_default()
            .clone()
    }
    fn plane(&self, id: &str) -> Result<&Plane> {
        self.planes
            .iter()
            .find(|p| p.config.id == id)
            .context("Control plane is no longer configured")
    }
    pub async fn fleet(&self) -> Vec<Value> {
        join_all(self.planes.iter().map(|p|async move {
            match p.list().await {
                Ok(vms)=>json!({"id":p.config.id,"available":true,"count":vms.len(),"capacity":p.config.max_vms,"vms":vms}),
                Err(_)=>json!({"id":p.config.id,"available":false,"capacity":p.config.max_vms}),
            }
        })).await
    }
    pub async fn create(&self, name: &str) -> Result<Session> {
        ensure!(
            !name.trim().is_empty() && name.len() <= 120,
            "Name must be 1–120 bytes"
        );
        let _placement = self.placement.lock().await;
        ensure!(
            self.workers.lock().await.len() < self.cfg.max_agents,
            "Active agent limit reached"
        );
        let mut candidates = join_all(self.planes.iter().map(|p| async move {
            p.list()
                .await
                .ok()
                .filter(|v| v.len() < p.config.max_vms)
                .map(|v| (v.len(), p))
        }))
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        candidates.sort_by_key(|(count, p)| (*count, p.config.id.clone()));
        let (_, plane) = candidates
            .first()
            .context("No available control plane with capacity")?;
        let id = uuid::Uuid::new_v4().to_string();
        let s = Session {
            id: id.clone(),
            name: name.into(),
            plane: plane.config.id.clone(),
            vm: None,
            phase: Phase::Allocating,
            created_at: now(),
            last_active: now(),
            error: None,
        };
        self.store.insert(&s)?;
        let lock = self.lock(&id);
        let _guard = lock.lock().await;
        match plane.create(&id, name).await {
            Ok(vm) => {
                self.store.update(&id, |s| {
                    s.vm = Some(vm);
                    Ok(())
                })?;
            }
            Err(_) => {
                self.store.phase(&id, Phase::AllocationUnknown)?;
                self.store.event(&id,json!({"type":"notice","text":"Allocation outcome unknown. Reconcile by session label before creating another workspace."}))?;
                return self.store.get(&id);
            }
        }
        if self.launch(&id, false).await.is_err() {
            self.store.interrupt(&id,"Could not start pi. Check the configured executable, remote extension, and provider settings. Workspace retained.");
        }
        self.store.get(&id)
    }
    async fn launch(&self, id: &str, recover: bool) -> Result<()> {
        let _launch = self.launch_gate.lock().await;
        ensure!(
            self.workers.lock().await.len() < self.cfg.max_agents,
            "Active agent limit reached"
        );
        let s = self.store.get(id)?;
        let plane = self.plane(&s.plane)?;
        let vm = s.vm.as_deref().context("No workspace allocated")?;
        self.store.phase(
            id,
            if s.phase == Phase::Asleep {
                Phase::Waking
            } else {
                Phase::Starting
            },
        )?;
        let info = plane.get(vm).await?;
        if recover && info["state"] != "stopped" {
            plane.action(vm, "halt").await?;
        }
        if recover || info["state"] != "running" {
            plane.action(vm, "start").await?;
        }
        plane.ready(vm).await?;
        let worker = Pi::start(&self.cfg, &plane.config, vm, id, self.store.clone()).await?;
        self.workers.lock().await.insert(id.into(), worker);
        self.store.phase(id, Phase::Idle)?;
        Ok(())
    }
    pub async fn prompt(&self, id: &str, message: &str) -> Result<()> {
        ensure!(
            !message.trim().is_empty() && message.len() <= 100000,
            "Message must be 1–100000 bytes"
        );
        ensure!(
            !message.trim_start().starts_with(['/', '!']),
            "Harness commands are disabled; use natural-language instructions"
        );
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        if self.store.get(id)?.phase == Phase::Asleep
            && let Err(e) = self.launch(id, false).await
        {
            self.store
                .interrupt(id, "Wake failed. The new prompt was not sent.");
            return Err(e);
        }
        ensure!(
            self.store.get(id)?.phase == Phase::Idle,
            "Agent is not idle; wait or recover the session"
        );
        let worker = self
            .workers
            .lock()
            .await
            .get(id)
            .cloned()
            .context("Agent disconnected")?;
        self.store.phase(id, Phase::Working)?;
        if worker
            .command("prompt", json!({"message":message}))
            .await
            .is_err()
        {
            self.store.interrupt(
                id,
                "Prompt was not acknowledged. Recover before continuing; do not blindly resend.",
            );
            bail!("Prompt outcome unknown");
        }
        Ok(())
    }
    pub async fn recover_session(&self, id: &str) -> Result<Session> {
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        ensure!(
            self.store.get(id)?.phase == Phase::Interrupted,
            "Only interrupted sessions need recovery"
        );
        self.stop_worker(id).await;
        if self.launch(id, true).await.is_err() {
            self.store.interrupt(
                id,
                "Recovery failed; workspace retained. Restore plane connectivity and retry.",
            );
            bail!("Recovery failed");
        }
        self.store.event(id,json!({"type":"notice","text":"Recovered pi history and rebooted the workspace to fence off previous commands. No prompts were replayed."}))?;
        self.store.get(id)
    }
    async fn stop_worker(&self, id: &str) {
        let worker = self.workers.lock().await.remove(id);
        if let Some(worker) = worker {
            worker.close().await;
        }
    }
    pub async fn abort(&self, id: &str) -> Result<()> {
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        let s = self.store.get(id)?;
        ensure!(s.phase == Phase::Working, "Agent is not working");
        // HTTP disconnect does not promise cancellation of guest exec. Fence the VM.
        self.store.interrupt(
            id,
            "Agent stopped. Recover will reboot the workspace, retaining files and conversation.",
        );
        self.stop_worker(id).await;
        self.plane(&s.plane)?
            .action(s.vm.as_deref().context("No workspace")?, "halt")
            .await?;
        Ok(())
    }
    pub async fn sleep(&self, id: &str) -> Result<()> {
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        self.sleep_locked(id).await
    }
    async fn sleep_locked(&self, id: &str) -> Result<()> {
        let s = self.store.get(id)?;
        ensure!(s.phase == Phase::Idle, "Only idle agents can sleep");
        self.store.phase(id, Phase::Sleeping)?;
        self.stop_worker(id).await;
        let result = self
            .plane(&s.plane)?
            .action(s.vm.as_deref().context("No workspace")?, "suspend")
            .await;
        if result.is_err() {
            self.store
                .interrupt(id, "Suspend outcome unknown; recover to continue.");
            return result;
        }
        self.store.phase(id, Phase::Asleep)?;
        self.store.event(id,json!({"type":"notice","text":"Workspace asleep. Your next message will wake it and resume the conversation."}))?;
        Ok(())
    }
    pub async fn sweep(&self) {
        for s in self.store.list().unwrap_or_default() {
            if s.phase == Phase::Idle
                && now().saturating_sub(s.last_active) >= self.cfg.idle_seconds
            {
                let lock = self.lock(&s.id);
                if let Ok(_guard) = lock.try_lock()
                    && let Ok(current) = self.store.get(&s.id)
                    && current.phase == Phase::Idle
                    && now().saturating_sub(current.last_active) >= self.cfg.idle_seconds
                {
                    let _ = self.sleep_locked(&s.id).await;
                }
            }
        }
    }
    pub async fn close_session(&self, id: &str) -> Result<()> {
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        let s = self.store.get(id)?;
        if s.phase == Phase::Closed {
            return Ok(());
        }
        s.phase.check(Phase::Closing)?;
        self.store.phase(id, Phase::Closing)?;
        self.stop_worker(id).await;
        let result = async {
            let plane = self.plane(&s.plane)?;
            let vm = s.vm.as_deref().context("No workspace")?;
            // Safe retry after a lost DELETE response: authoritative list confirms absence.
            if plane.list().await?.iter().any(|v| v["id"] == vm) {
                plane.action(vm, "destroy").await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(e) = result {
            self.store.interrupt(
                id,
                "Workspace deletion not confirmed. Retry Close after restoring connectivity.",
            );
            return Err(e);
        }
        self.store.phase(id, Phase::Closed)?;
        Ok(())
    }
    pub async fn reconcile(&self, id: &str) -> Result<Session> {
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        let s = self.store.get(id)?;
        ensure!(
            s.phase == Phase::AllocationUnknown,
            "Only ambiguous allocations require reconciliation"
        );
        let found = self
            .plane(&s.plane)?
            .list()
            .await?
            .into_iter()
            .filter(|v| v["labels"]["master-session"] == id)
            .collect::<Vec<_>>();
        ensure!(
            found.len() == 1,
            "Expected exactly one VM with this session label; inspect the plane before retrying"
        );
        self.store.update(id, |s| {
            s.vm = Some(found[0]["id"].as_str().context("Invalid VM ID")?.into());
            s.phase = Phase::Interrupted;
            Ok(())
        })
    }
    pub async fn shutdown(&self) {
        let workers = std::mem::take(&mut *self.workers.lock().await);
        for (id, worker) in workers {
            worker.close().await;
            self.store.interrupt(
                &id,
                "Master stopped. Recover to resume; no prompts will be replayed.",
            );
        }
    }
    pub async fn timer(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(self.cfg.idle_seconds.min(30))).await;
            self.sweep().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PlaneConfig;
    #[tokio::test]
    async fn placement_sleep_wake_and_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            demo: true,
            data_dir: dir.path().into(),
            idle_seconds: 1,
            planes: ["east", "west"]
                .iter()
                .map(|id| PlaneConfig {
                    id: (*id).into(),
                    server: "demo".into(),
                    creds: "unused".into(),
                    client: "unused".into(),
                    template: "debian".into(),
                    egress: "deny".into(),
                    principal: None,
                    allow: vec![],
                    max_vms: 2,
                })
                .collect(),
            ..Config::default()
        };
        let store = Arc::new(Store::open(&dir.path().join("db")).unwrap());
        let e = Engine::new(cfg, store.clone()).unwrap();
        let a = e.create("a").await.unwrap();
        let b = e.create("b").await.unwrap();
        assert_ne!(a.plane, b.plane);
        e.sleep(&a.id).await.unwrap();
        assert_eq!(store.get(&a.id).unwrap().phase, Phase::Asleep);
        e.prompt(&a.id, "hello").await.unwrap();
        assert_eq!(store.get(&a.id).unwrap().vm, a.vm);
        assert!(e.sleep(&a.id).await.is_err());
        e.abort(&a.id).await.unwrap();
        assert_eq!(store.get(&a.id).unwrap().phase, Phase::Interrupted);
        e.recover_session(&a.id).await.unwrap();
        store
            .update(&a.id, |s| {
                s.last_active = 0;
                Ok(())
            })
            .unwrap();
        e.sweep().await;
        assert_eq!(store.get(&a.id).unwrap().phase, Phase::Asleep);
        e.close_session(&a.id).await.unwrap();
        e.close_session(&a.id).await.unwrap();
        assert_eq!(store.get(&a.id).unwrap().phase, Phase::Closed);
        assert!(e.prompt(&a.id, "hello").await.is_err());
        e.shutdown().await;
    }
    fn fixture() -> (tempfile::TempDir, Arc<Engine>) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            demo: true,
            data_dir: dir.path().into(),
            planes: vec![PlaneConfig {
                id: "east".into(),
                server: "demo".into(),
                creds: "unused".into(),
                client: "unused".into(),
                template: "debian".into(),
                egress: "deny".into(),
                principal: None,
                allow: vec![],
                max_vms: 1,
            }],
            ..Config::default()
        };
        let store = Arc::new(Store::open(&dir.path().join("db")).unwrap());
        (dir, Engine::new(cfg, store).unwrap())
    }

    #[tokio::test]
    async fn capacity_and_concurrent_prompt_guard() {
        let (_dir, e) = fixture();
        let s = e.create("one").await.unwrap();
        assert!(e.create("over capacity").await.is_err());
        let (a, b) = tokio::join!(e.prompt(&s.id, "first"), e.prompt(&s.id, "second"));
        assert_ne!(a.is_ok(), b.is_ok());
        assert_eq!(e.store.list().unwrap().len(), 1);
        e.shutdown().await;
    }

    #[tokio::test]
    async fn reconcile_adopts_only_one_labelled_vm_without_allocating() {
        let (_dir, e) = fixture();
        let id = uuid::Uuid::new_v4().to_string();
        e.store
            .insert(&Session {
                id: id.clone(),
                name: "ambiguous".into(),
                plane: "east".into(),
                vm: None,
                phase: Phase::AllocationUnknown,
                created_at: now(),
                last_active: now(),
                error: None,
            })
            .unwrap();
        assert!(e.reconcile(&id).await.is_err());
        assert!(e.planes[0].list().await.unwrap().is_empty());
        let vm = e.planes[0].create(&id, "ambiguous").await.unwrap();
        let s = e.reconcile(&id).await.unwrap();
        assert_eq!(s.vm.as_deref(), Some(vm.as_str()));
        assert_eq!(s.phase, Phase::Interrupted);
        assert_eq!(e.planes[0].list().await.unwrap().len(), 1);
        e.close_session(&id).await.unwrap();
    }

    #[tokio::test]
    async fn failed_wake_retains_session_and_does_not_allocate_or_prompt() {
        let (_dir, e) = fixture();
        let s = e.create("one").await.unwrap();
        e.sleep(&s.id).await.unwrap();
        e.planes[0]
            .action(s.vm.as_deref().unwrap(), "destroy")
            .await
            .unwrap();
        assert!(e.prompt(&s.id, "must not be replayed").await.is_err());
        assert_eq!(e.store.get(&s.id).unwrap().phase, Phase::Interrupted);
        assert!(e.planes[0].list().await.unwrap().is_empty());
        assert!(
            !e.store
                .events(&s.id, 0)
                .unwrap()
                .iter()
                .any(|e| e["type"] == "message")
        );
        e.close_session(&s.id).await.unwrap();
    }
}
