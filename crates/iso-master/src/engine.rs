use crate::{
    config::Config,
    model::{CreateOptions, Phase, Role, Session, Swarm, now},
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
    worker_tokens: StdMutex<HashMap<String, String>>,
    swarm_gate: Mutex<()>,
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
            worker_tokens: Default::default(),
            swarm_gate: Default::default(),
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
    #[cfg(test)]
    pub async fn create(&self, name: &str) -> Result<Session> {
        self.create_options(name, CreateOptions::default()).await
    }
    pub async fn create_options(&self, name: &str, options: CreateOptions) -> Result<Session> {
        let model = options.model.or_else(|| self.cfg.pi_model.clone());
        self.validate_model(model.as_deref())?;
        let swarm = if options.swarm {
            let planner_model = options
                .planner_model
                .or_else(|| model.clone())
                .context("Select a planner model")?;
            let worker_model = options
                .worker_model
                .or_else(|| model.clone())
                .context("Select a worker model")?;
            self.validate_model(Some(&planner_model))?;
            self.validate_model(Some(&worker_model))?;
            Some(Swarm {
                root: String::new(),
                parent: None,
                role: Role::Planner,
                depth: 0,
                planner_model,
                worker_model,
                task: String::new(),
            })
        } else {
            None
        };
        self.create_node(name, model, swarm).await
    }
    fn validate_model(&self, model: Option<&str>) -> Result<()> {
        if let Some(model) = model {
            ensure!(
                self.cfg.models().iter().any(|m| m == model),
                "Model is not enabled on this master"
            );
        }
        Ok(())
    }
    async fn create_node(
        &self,
        name: &str,
        model: Option<String>,
        mut swarm: Option<Swarm>,
    ) -> Result<Session> {
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
        if let Some(s) = &mut swarm
            && s.root.is_empty()
        {
            s.root = id.clone();
        }
        let model = swarm
            .as_ref()
            .map(|s| {
                if s.role == Role::Planner {
                    s.planner_model.clone()
                } else {
                    s.worker_model.clone()
                }
            })
            .or(model);
        let s = Session {
            id: id.clone(),
            name: name.into(),
            plane: plane.config.id.clone(),
            vm: None,
            phase: Phase::Allocating,
            created_at: now(),
            last_active: now(),
            error: None,
            model,
            swarm,
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
        if let Err(error) = plane.ready(vm).await {
            self.store.event(id, json!({"type":"notice","text":format!("{error}. Workspace retained; pi was not started and no prompts were replayed.")}))?;
            return Err(error);
        }
        let mut cfg = self.cfg.clone();
        cfg.pi_model = s.model.clone().or(cfg.pi_model);
        let token = uuid::Uuid::new_v4().to_string();
        self.worker_tokens
            .lock()
            .unwrap()
            .insert(id.into(), token.clone());
        let swarm = s.swarm.as_ref().map(|swarm| json!({"session":id,"token":token,"socket":self.cfg.data_dir.join("swarm.sock"),"role":swarm.role,"parent":swarm.parent,"task":swarm.task}));
        let worker = match Pi::start(&cfg, &plane.config, vm, id, self.store.clone(), swarm).await {
            Ok(worker) => worker,
            Err(e) => {
                self.worker_tokens.lock().unwrap().remove(id);
                return Err(e);
            }
        };
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
        self.prompt_locked(id, message).await
    }
    async fn prompt_locked(&self, id: &str, message: &str) -> Result<()> {
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
        self.worker_tokens.lock().unwrap().remove(id);
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
        let _swarm = self.swarm_gate.lock().await;
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        let s = self.store.get(id)?;
        if s.phase == Phase::Closed {
            return Ok(());
        }
        ensure!(
            !self
                .store
                .list()?
                .iter()
                .any(|node| node.phase != Phase::Closed
                    && node
                        .swarm
                        .as_ref()
                        .is_some_and(|swarm| swarm.parent.as_deref() == Some(id))),
            "Close this planner's children first"
        );
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
            "Found {} VMs with this session label. If none exist, inspect the plane for unfinished allocations before using Retry allocation; multiple matches require manual inspection.",
            found.len()
        );
        self.store.update(id, |s| {
            s.vm = Some(found[0]["id"].as_str().context("Invalid VM ID")?.into());
            s.phase = Phase::Interrupted;
            Ok(())
        })
    }
    pub async fn retry_allocation(&self, id: &str) -> Result<Session> {
        let _placement = self.placement.lock().await;
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        let s = self.store.get(id)?;
        ensure!(
            s.phase == Phase::AllocationUnknown && s.vm.is_none(),
            "Only an unresolved allocation without a workspace can be retried"
        );
        let plane = self.plane(&s.plane)?;
        let vms = plane.list().await?;
        ensure!(
            !vms.iter().any(|vm| vm["labels"]["master-session"] == id),
            "A VM already has this session label. Use Reconcile; no VM was created."
        );
        ensure!(
            vms.len() < plane.config.max_vms,
            "Control plane is at capacity"
        );
        ensure!(
            self.workers.lock().await.len() < self.cfg.max_agents,
            "Active agent limit reached"
        );
        self.store.phase(id, Phase::Allocating)?;
        self.store.event(id, json!({"type":"notice","text":"Operator explicitly retried allocation after checking the plane. No prompts will be replayed."}))?;
        match plane.create(id, &s.name).await {
            Ok(vm) => {
                self.store.update(id, |session| {
                    session.vm = Some(vm);
                    session.phase = Phase::Interrupted;
                    session.error = None;
                    Ok(())
                })?;
                self.store.event(id, json!({"type":"notice","text":"Workspace allocated. Use Recover to start the agent; no prompts were replayed."}))?;
            }
            Err(_) => {
                self.store.phase(id, Phase::AllocationUnknown)?;
                bail!(
                    "Allocation outcome unknown again. Inspect the plane and reconcile before considering another explicit retry."
                );
            }
        }
        self.store.get(id)
    }
    pub async fn shutdown(&self) {
        self.worker_tokens.lock().unwrap().clear();
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
            tokio::time::sleep(Duration::from_secs(1)).await;
            self.deliver_messages().await;
            self.sweep().await;
        }
    }
    pub fn worker_identity(&self, token: &str) -> Result<String> {
        let id = self
            .worker_tokens
            .lock()
            .unwrap()
            .iter()
            .find(|(_, t)| t.as_str() == token)
            .map(|(id, _)| id.clone())
            .context("Invalid worker token")?;
        let s = self.store.get(&id)?;
        ensure!(
            matches!(
                s.phase,
                Phase::Idle | Phase::Working | Phase::Starting | Phase::Waking
            ),
            "Worker is inactive"
        );
        ensure!(s.swarm.is_some(), "Not a swarm session");
        Ok(id)
    }
    pub fn tree(&self, id: &str) -> Result<Vec<Session>> {
        let s = self.store.get(id)?;
        let swarm = s.swarm.context("Not a swarm session")?;
        Ok(self
            .store
            .list()?
            .into_iter()
            .filter(|s| s.swarm.as_ref().is_some_and(|n| n.root == swarm.root))
            .collect())
    }
    pub async fn spawn_child(
        &self,
        parent: &str,
        name: &str,
        role: Role,
        task: &str,
    ) -> Result<Session> {
        ensure!(
            !task.trim().is_empty() && task.len() <= 32000,
            "Task must be 1–32000 bytes"
        );
        let _gate = self.swarm_gate.lock().await;
        let parent_session = self.store.get(parent)?;
        ensure!(
            !matches!(
                parent_session.phase,
                Phase::Closed | Phase::Closing | Phase::Interrupted
            ),
            "Parent is inactive"
        );
        let p = parent_session.swarm.context("Not a swarm planner")?;
        ensure!(
            p.role == Role::Planner,
            "Only planners can schedule children"
        );
        ensure!(
            p.depth < self.cfg.swarm_max_depth,
            "Swarm depth limit reached"
        );
        ensure!(
            self.tree(parent)?.len() < self.cfg.swarm_max_agents,
            "Swarm size limit reached"
        );
        let child = self
            .create_node(
                name,
                None,
                Some(Swarm {
                    root: p.root,
                    parent: Some(parent.into()),
                    role,
                    depth: p.depth + 1,
                    planner_model: p.planner_model,
                    worker_model: p.worker_model,
                    task: task.into(),
                }),
            )
            .await?;
        self.store.event(
            parent,
            json!({"type":"notice","text":format!("Scheduled {} ({})", child.name, child.id)}),
        )?;
        Ok(child)
    }
    pub fn send_message(&self, sender: &str, recipient: &str, message: &str) -> Result<i64> {
        ensure!(
            !message.trim().is_empty() && message.len() <= 32000,
            "Message must be 1–32000 bytes"
        );
        let from = self.store.get(sender)?;
        let to = self.store.get(recipient)?;
        let a = from.swarm.context("Sender is not in a swarm")?;
        let b = to.swarm.context("Recipient is not in a swarm")?;
        ensure!(
            a.root == b.root
                && (a.parent.as_deref() == Some(recipient) || b.parent.as_deref() == Some(sender)),
            "Messages are limited to direct parent–child relationships"
        );
        ensure!(
            !matches!(to.phase, Phase::Closed | Phase::Closing),
            "Recipient is closed"
        );
        self.store.enqueue(sender, recipient, message)
    }
    pub async fn deliver_messages(&self) {
        let sessions = self.store.list().unwrap_or_default();
        // Each recipient runs independently; a sleeping workspace must not block the others.
        join_all(
            sessions
                .into_iter()
                .filter(|s| s.swarm.is_some())
                .map(|s| async move {
                    let lock = self.lock(&s.id);
                    let Ok(_guard) = lock.try_lock() else {
                        return;
                    };
                    let Ok(current) = self.store.get(&s.id) else {
                        return;
                    };
                    if !matches!(current.phase, Phase::Idle | Phase::Asleep) {
                        return;
                    }
                    if let Ok(Some((mid, sender, text))) = self.store.claim_message(&s.id) {
                        let prompt = self.message_prompt(&sender, &current, &text);
                        let delivered = match prompt {
                            Ok((prompt, event)) => {
                                self.store.stage_delivery(mid, &prompt, &event).is_ok()
                                    && self.prompt_locked(&s.id, &prompt).await.is_ok()
                            }
                            Err(_) => false,
                        };
                        let status = if delivered { "delivered" } else { "uncertain" };
                        let _ = self.store.message_status(mid, status);
                    }
                }),
        )
        .await;
    }
    pub async fn set_model(&self, id: &str, model: &str) -> Result<Session> {
        self.validate_model(Some(model))?;
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        let s = self.store.get(id)?;
        ensure!(
            s.swarm.is_none(),
            "Swarm models are inherited from their root configuration"
        );
        ensure!(
            matches!(s.phase, Phase::Idle | Phase::Asleep | Phase::Interrupted),
            "Wait for the agent to finish before changing models"
        );
        if s.phase == Phase::Idle {
            let worker = self
                .workers
                .lock()
                .await
                .get(id)
                .cloned()
                .context("Agent disconnected")?;
            let (provider, model_id) = model.split_once('/').context("Invalid model")?;
            worker
                .command("set_model", json!({"provider":provider,"modelId":model_id}))
                .await?;
        }
        self.store.update(id, |s| {
            s.model = Some(model.into());
            Ok(())
        })
    }
    fn message_prompt(
        &self,
        sender: &str,
        recipient: &Session,
        text: &str,
    ) -> Result<(String, Value)> {
        let from = self.store.get(sender)?;
        let source = from.swarm.as_ref().context("Sender is not in a swarm")?;
        let target = recipient
            .swarm
            .as_ref()
            .context("Recipient is not in a swarm")?;
        ensure!(source.root == target.root, "Sender is in another swarm");
        let relationship = if target.parent.as_deref() == Some(sender) {
            "parent"
        } else if source.parent.as_deref() == Some(recipient.id.as_str()) {
            "child"
        } else {
            bail!("Sender is not a direct parent or child");
        };
        let role = match source.role {
            Role::Planner => "planner",
            Role::Worker => "worker",
        };
        Ok((
            format!(
                "Message from your {relationship} {role} {name:?} (session {sender}):\n{text}",
                name = from.name
            ),
            json!({"type":"swarm_message","text":text,"source":{"id":sender,"name":from.name,"role":role,"relationship":relationship}}),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PlaneConfig;
    fn swarm_fixture() -> (tempfile::TempDir, Arc<Engine>) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            demo: true,
            data_dir: dir.path().into(),
            pi_model: Some("test/planner".into()),
            pi_models: vec!["test/planner".into(), "test/worker".into()],
            swarm_max_depth: 2,
            planes: vec![PlaneConfig {
                id: "test".into(),
                server: "demo".into(),
                creds: "unused".into(),
                client: "unused".into(),
                template: "debian".into(),
                egress: "deny".into(),
                principal: None,
                allow: vec![],
                max_vms: 16,
            }],
            ..Config::default()
        };
        let store = Arc::new(Store::open(&dir.path().join("db")).unwrap());
        (dir, Engine::new(cfg, store).unwrap())
    }
    fn swarm_options() -> CreateOptions {
        CreateOptions {
            swarm: true,
            planner_model: Some("test/planner".into()),
            worker_model: Some("test/worker".into()),
            ..Default::default()
        }
    }
    #[tokio::test]
    async fn swarm_inherits_models_and_enforces_vertical_relationships() {
        let (_dir, e) = swarm_fixture();
        let root = e.create_options("root", swarm_options()).await.unwrap();
        let sub = e
            .spawn_child(&root.id, "sub", Role::Planner, "Plan the implementation")
            .await
            .unwrap();
        let worker = e
            .spawn_child(&sub.id, "worker", Role::Worker, "Implement it")
            .await
            .unwrap();
        let sibling = e
            .spawn_child(&root.id, "sibling", Role::Worker, "Review it")
            .await
            .unwrap();
        assert_eq!(root.model.as_deref(), Some("test/planner"));
        assert_eq!(sub.model, root.model);
        assert_eq!(worker.model.as_deref(), Some("test/worker"));
        assert_eq!(worker.swarm.as_ref().unwrap().depth, 2);
        assert_eq!(worker.swarm.as_ref().unwrap().root, root.id);
        assert!(
            e.spawn_child(&worker.id, "forbidden", Role::Worker, "task")
                .await
                .is_err()
        );
        assert!(e.send_message(&worker.id, &root.id, "skip parent").is_err());
        assert!(e.send_message(&sub.id, &sibling.id, "sibling").is_err());
        assert!(e.send_message(&worker.id, &sub.id, "Result").is_ok());
        assert!(e.close_session(&root.id).await.is_err());
        let other = e.create_options("other", swarm_options()).await.unwrap();
        assert!(e.send_message(&sub.id, &other.id, "cross swarm").is_err());
        assert!(e.set_model(&root.id, "test/worker").await.is_err());
        assert!(
            e.create_options(
                "invalid",
                CreateOptions {
                    model: Some("not/enabled".into()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
        );
        let deep = e
            .spawn_child(&sub.id, "deep", Role::Planner, "Plan")
            .await
            .unwrap();
        assert!(
            e.spawn_child(&deep.id, "too deep", Role::Worker, "Task")
                .await
                .is_err()
        );
        e.shutdown().await;
    }
    #[tokio::test]
    async fn swarm_mail_waits_for_idle_and_tokens_are_revoked() {
        let (_dir, e) = swarm_fixture();
        let root = e.create_options("root", swarm_options()).await.unwrap();
        let child = e
            .spawn_child(&root.id, "child", Role::Worker, "Do the task")
            .await
            .unwrap();
        let token = e
            .worker_tokens
            .lock()
            .unwrap()
            .get(&child.id)
            .unwrap()
            .clone();
        assert_eq!(e.worker_identity(&token).unwrap(), child.id);
        e.store.phase(&child.id, Phase::Working).unwrap();
        e.deliver_messages().await;
        assert_eq!(e.store.mailbox(&child.id).unwrap()[0]["status"], "pending");
        e.store.phase(&child.id, Phase::Idle).unwrap();
        e.deliver_messages().await;
        assert_eq!(
            e.store.mailbox(&child.id).unwrap()[0]["status"],
            "delivered"
        );
        assert_eq!(e.store.get(&child.id).unwrap().phase, Phase::Working);
        tokio::task::yield_now().await;
        let parent_message = format!(
            "Message from your parent planner \"root\" (session {}):\nDo the task",
            root.id
        );
        assert_eq!(
            e.message_prompt(&root.id, &child, "Do the task").unwrap().0,
            parent_message
        );
        assert!(
            e.store
                .events(&child.id, 0)
                .unwrap()
                .iter()
                .any(|event| event["type"] == "swarm_message"
                    && event["text"] == "Do the task"
                    && event["source"]["relationship"] == "parent"
                    && event["source"]["id"] == root.id)
        );
        e.send_message(&child.id, &root.id, "Here are my findings")
            .unwrap();
        e.deliver_messages().await;
        tokio::task::yield_now().await;
        let child_message = format!(
            "Message from your child worker \"child\" (session {}):\nHere are my findings",
            child.id
        );
        assert_eq!(
            e.message_prompt(&child.id, &root, "Here are my findings")
                .unwrap()
                .0,
            child_message
        );
        assert!(
            e.store
                .events(&root.id, 0)
                .unwrap()
                .iter()
                .any(|event| event["type"] == "swarm_message"
                    && event["text"] == "Here are my findings"
                    && event["source"]["relationship"] == "child"
                    && event["source"]["id"] == child.id)
        );
        e.abort(&child.id).await.unwrap();
        assert!(e.worker_identity(&token).is_err());
        let mid = e.send_message(&root.id, &child.id, "Second task").unwrap();
        e.deliver_messages().await;
        assert_eq!(e.store.mailbox(&child.id).unwrap()[0]["status"], "pending");
        e.store.message_status(mid, "dispatching").unwrap();
        e.store.recover().unwrap();
        assert_eq!(
            e.store.mailbox(&child.id).unwrap()[0]["status"],
            "uncertain"
        );
        e.shutdown().await;
    }
    #[tokio::test]
    async fn model_choice_survives_sleep_and_relaunch() {
        let (_dir, e) = swarm_fixture();
        let s = e.create("single").await.unwrap();
        e.set_model(&s.id, "test/worker").await.unwrap();
        e.sleep(&s.id).await.unwrap();
        assert_eq!(
            e.store.get(&s.id).unwrap().model.as_deref(),
            Some("test/worker")
        );
        e.prompt(&s.id, "hello").await.unwrap();
        assert_eq!(
            e.store.get(&s.id).unwrap().model.as_deref(),
            Some("test/worker")
        );
        assert!(e.set_model(&s.id, "test/planner").await.is_err());
        e.shutdown().await;
    }
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
                model: None,
                swarm: None,
            })
            .unwrap();
        assert!(e.reconcile(&id).await.is_err());
        assert!(e.planes[0].list().await.unwrap().is_empty());
        let vm = e.planes[0].create(&id, "ambiguous").await.unwrap();
        assert!(e.retry_allocation(&id).await.is_err());
        assert_eq!(e.planes[0].list().await.unwrap().len(), 1);
        let duplicate = e.planes[0].create(&id, "duplicate").await.unwrap();
        assert!(e.reconcile(&id).await.is_err());
        assert!(e.retry_allocation(&id).await.is_err());
        assert_eq!(e.planes[0].list().await.unwrap().len(), 2);
        e.planes[0].action(&duplicate, "destroy").await.unwrap();
        let s = e.reconcile(&id).await.unwrap();
        assert_eq!(s.vm.as_deref(), Some(vm.as_str()));
        assert_eq!(s.phase, Phase::Interrupted);
        assert_eq!(e.planes[0].list().await.unwrap().len(), 1);
        e.close_session(&id).await.unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let mut unresolved = s.clone();
        unresolved.id = id.clone();
        unresolved.vm = None;
        unresolved.phase = Phase::AllocationUnknown;
        e.store.insert(&unresolved).unwrap();
        let (a, b) = tokio::join!(e.retry_allocation(&id), e.retry_allocation(&id));
        assert_ne!(a.is_ok(), b.is_ok());
        let retried = e.store.get(&id).unwrap();
        assert_eq!(retried.phase, Phase::Interrupted);
        assert!(retried.vm.is_some());
        assert_eq!(e.planes[0].list().await.unwrap().len(), 1);
        assert!(e.workers.lock().await.is_empty());
        assert!(
            !e.store
                .events(&id, 0)
                .unwrap()
                .iter()
                .any(|event| event["type"] == "message")
        );
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
