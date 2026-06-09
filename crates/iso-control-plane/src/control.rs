//! The control plane: orchestrates network, storage, and the VMM behind the
//! lifecycle state machine, with SQLite as the durable source of truth.
//!
//! Transport-agnostic — the axum HTTP layer is a thin wrapper over these
//! methods.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iso_common::{
    HostNetwork, InstanceSpec, NetworkManager, NetworkPolicy, StorageManager, VmId, VmRuntime,
    VmStatus, VolumeSpec,
};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::slot::SlotAllocator;
use crate::store::Store;
use crate::types::{
    CreateVm, Lifecycle, RestartPolicy, Stats, TemplateDef, VmRecord, VmState,
};

/// Orchestrates VM lifecycle on one host.
pub struct ControlPlane<N, S, R> {
    cfg: Config,
    net: N,
    storage: S,
    runtime: R,
    store: Store,
    slots: Mutex<SlotAllocator>,
    services: Mutex<Option<HostNetwork>>,
}

fn random_vmid() -> VmId {
    use std::io::Read;
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    VmId::from_u128(u128::from_be_bytes(b))
}

impl<N, S, R> ControlPlane<N, S, R>
where
    N: NetworkManager,
    S: StorageManager,
    R: VmRuntime,
{
    /// Open the store and build the (empty) slot allocator. Call [`start`] to
    /// initialize subsystems and recover existing VMs.
    pub fn new(cfg: Config, net: N, storage: S, runtime: R) -> Result<Self> {
        let store = Store::open(&cfg.db_path)?;
        let slots = SlotAllocator::new(cfg.slot_capacity);
        Ok(Self {
            cfg,
            net,
            storage,
            runtime,
            store,
            slots: Mutex::new(slots),
            services: Mutex::new(None),
        })
    }

    /// Initialize host subsystems and recover persisted VMs. Returns the
    /// host-wide network facts (for binding services).
    pub async fn start(&self) -> Result<HostNetwork> {
        self.storage.init().await?;
        let hn = self.net.init().await?;
        *self.services.lock().unwrap() = Some(hn);
        self.recover().await?;
        Ok(hn)
    }

    /// Rebuild the slot allocator from the store and re-adopt or reconcile each
    /// VM against live VMM state.
    async fn recover(&self) -> Result<()> {
        for rec in self.store.list_vms()? {
            if let Some(slot) = rec.slot {
                self.slots.lock().unwrap().reserve(slot);
            }
            // Reconcile against the VMM: a VM the store thinks is running but
            // whose process is gone gets the exit handler.
            if rec.state == VmState::Running {
                let status = self.runtime.status(rec.id).await?;
                if status != iso_common::VmStatus::Running {
                    self.handle_exit(rec.id, true).await?;
                }
            }
        }
        Ok(())
    }

    /// Register (or update) a template. Out-of-band; the bake produces the
    /// artifacts, this just records where they are and the machine config.
    pub fn register_template(&self, def: &TemplateDef) -> Result<()> {
        self.store.upsert_template(def)
    }

    /// Create and boot a VM. Allocates a slot, provisions storage, applies
    /// network, and starts the VMM — rolling everything back on failure.
    pub async fn create_vm(&self, req: CreateVm) -> Result<VmId> {
        let tpl = self
            .store
            .get_template(&req.template)?
            .ok_or_else(|| Error::UnknownTemplate(req.template.clone()))?;

        // gate on pool fullness
        let ps = self.storage.pool_stats().await?;
        if ps.data_percent >= self.cfg.pool_watermark_percent
            || ps.metadata_percent >= self.cfg.pool_watermark_percent
        {
            return Err(Error::PoolFull {
                data_percent: ps.data_percent,
                metadata_percent: ps.metadata_percent,
            });
        }

        let id = random_vmid();
        let slot = self
            .slots
            .lock()
            .unwrap()
            .allocate()
            .ok_or(Error::SlotsExhausted)?;

        let mut rec = VmRecord {
            id,
            slot: Some(slot),
            template: req.template.clone(),
            egress: req.egress,
            ingress: req.ingress.clone(),
            labels: req.labels.clone(),
            lifecycle: req.lifecycle,
            restart: req.restart,
            vcpus: req.vcpus,
            mem_mib: req.mem_mib,
            state: VmState::Creating,
            rootfs_device: None,
            tap: None,
        };
        // write-ahead intent so a crash mid-create is recoverable.
        self.store.insert_vm(&rec)?;

        match self.bring_up(&mut rec, &tpl, true).await {
            Ok(()) => {
                rec.state = VmState::Running;
                self.store.update_vm(&rec)?;
                Ok(id)
            }
            Err(e) => {
                self.rollback(id, slot).await;
                Err(e)
            }
        }
    }

    /// Provision storage, apply network, create+start the VMM into `rec`.
    /// `allow_resume` permits snapshot resume (disabled for restarts, where the
    /// rootfs has diverged from the template).
    async fn bring_up(&self, rec: &mut VmRecord, tpl: &TemplateDef, allow_resume: bool) -> Result<()> {
        let slot = rec.slot.expect("bring_up requires a slot");

        let storage = self
            .storage
            .provision(rec.id, &VolumeSpec { template: tpl.rootfs_template.clone() })
            .await?;

        let policy = NetworkPolicy {
            egress: rec.egress,
            ingress: rec.ingress.clone(),
        };
        let fixture = self.net.apply(slot, &policy).await?;

        // custom vcpu/mem forgoes the snapshot (fresh boot); otherwise resume.
        let custom = rec.vcpus.is_some() || rec.mem_mib.is_some();
        let resume_from = if allow_resume && !custom {
            tpl.snapshot.clone()
        } else {
            None
        };
        let spec = InstanceSpec {
            vm: rec.id,
            netns: fixture.netns.clone(),
            tap: fixture.tap.clone(),
            mac: fixture.mac,
            rootfs_device: storage.device_path.clone(),
            vcpus: rec.vcpus.unwrap_or(tpl.vcpus),
            mem_mib: rec.mem_mib.unwrap_or(tpl.mem_mib),
            kernel: tpl.kernel.clone(),
            boot_args: tpl.boot_args.clone(),
            resume_from,
        };
        self.runtime.create(&spec).await?;
        self.runtime.start(rec.id).await?;

        rec.rootfs_device = Some(storage.device_path);
        rec.tap = Some(fixture.tap);
        Ok(())
    }

    async fn rollback(&self, id: VmId, slot: iso_common::SlotId) {
        let _ = self.runtime.halt(id).await;
        let _ = self.runtime.destroy(id).await;
        let _ = self.net.teardown(slot).await;
        let _ = self.storage.teardown(id).await;
        self.slots.lock().unwrap().free(slot);
        let _ = self.store.delete_vm(id);
    }

    /// Explicitly destroy a VM and all its resources, regardless of lifecycle.
    pub async fn destroy_vm(&self, id: VmId) -> Result<()> {
        let rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        let _ = self.runtime.stop(id).await; // best-effort graceful
        let _ = self.runtime.halt(id).await;
        let _ = self.runtime.destroy(id).await;
        if let Some(slot) = rec.slot {
            let _ = self.net.teardown(slot).await;
            self.slots.lock().unwrap().free(slot);
        }
        let _ = self.storage.teardown(id).await;
        self.store.delete_vm(id)?;
        Ok(())
    }

    /// Graceful shutdown (escalating to force after the timeout), then apply
    /// lifecycle policy.
    pub async fn stop_vm(&self, id: VmId) -> Result<()> {
        let rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        self.runtime.stop(id).await?;
        if !self.wait_exit(id, self.cfg.graceful_stop).await {
            let _ = self.runtime.halt(id).await;
        }
        self.finalize_stop(rec).await
    }

    /// Forceful stop, then apply lifecycle policy.
    pub async fn halt_vm(&self, id: VmId) -> Result<()> {
        let rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        self.runtime.halt(id).await?;
        self.finalize_stop(rec).await
    }

    /// Poll until the VMM reports the instance gone, or `timeout` elapses.
    /// Returns whether it exited.
    async fn wait_exit(&self, id: VmId, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                match self.runtime.status(id).await {
                    Ok(VmStatus::Stopped) | Ok(VmStatus::Absent) => return,
                    _ => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
        })
        .await
        .is_ok()
    }

    /// Release placement; tear down storage + record for Ephemeral, keep storage
    /// (free slot/network only) for Durable.
    async fn finalize_stop(&self, mut rec: VmRecord) -> Result<()> {
        let _ = self.runtime.destroy(rec.id).await;
        if let Some(slot) = rec.slot {
            let _ = self.net.teardown(slot).await;
            self.slots.lock().unwrap().free(slot);
        }
        match rec.lifecycle {
            Lifecycle::Ephemeral => {
                let _ = self.storage.teardown(rec.id).await;
                self.store.delete_vm(rec.id)?;
            }
            Lifecycle::Durable => {
                rec.slot = None;
                rec.tap = None;
                rec.state = VmState::Stopped;
                self.store.update_vm(&rec)?;
            }
        }
        Ok(())
    }

    /// Pause (and snapshot) a running VM.
    pub async fn suspend_vm(&self, id: VmId) -> Result<()> {
        let mut rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        if rec.state != VmState::Running {
            return Err(Error::InvalidState {
                vm: id,
                state: rec.state.as_str(),
                op: "suspend",
            });
        }
        self.runtime.suspend(id).await?;
        rec.state = VmState::Suspended;
        self.store.update_vm(&rec)?;
        Ok(())
    }

    /// Start a suspended VM (resume in place) or a stopped Durable VM (re-place
    /// and boot from its persisted rootfs).
    pub async fn start_vm(&self, id: VmId) -> Result<()> {
        let mut rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        match rec.state {
            VmState::Suspended => {
                self.runtime.start(id).await?;
                rec.state = VmState::Running;
                self.store.update_vm(&rec)?;
                Ok(())
            }
            VmState::Stopped => {
                let tpl = self
                    .store
                    .get_template(&rec.template)?
                    .ok_or_else(|| Error::UnknownTemplate(rec.template.clone()))?;
                let slot = self
                    .slots
                    .lock()
                    .unwrap()
                    .allocate()
                    .ok_or(Error::SlotsExhausted)?;
                rec.slot = Some(slot);
                rec.state = VmState::Creating;
                self.store.update_vm(&rec)?;
                match self.bring_up(&mut rec, &tpl, false).await {
                    Ok(()) => {
                        rec.state = VmState::Running;
                        self.store.update_vm(&rec)?;
                        Ok(())
                    }
                    Err(e) => {
                        self.slots.lock().unwrap().free(slot);
                        rec.slot = None;
                        rec.state = VmState::Stopped;
                        let _ = self.store.update_vm(&rec);
                        Err(e)
                    }
                }
            }
            other => Err(Error::InvalidState {
                vm: id,
                state: other.as_str(),
                op: "start",
            }),
        }
    }

    /// Handle an observed VMM exit (called by the supervisor): restart per
    /// policy, else finalize per lifecycle.
    pub async fn handle_exit(&self, id: VmId, failed: bool) -> Result<()> {
        let Some(rec) = self.store.get_vm(id)? else {
            return Ok(());
        };
        let restart = matches!(rec.restart, RestartPolicy::Always)
            || (failed && matches!(rec.restart, RestartPolicy::OnFailure));
        if restart {
            // free current placement, then re-place + boot.
            if let Some(slot) = rec.slot {
                let _ = self.net.teardown(slot).await;
                self.slots.lock().unwrap().free(slot);
            }
            let mut rec = rec;
            rec.slot = None;
            rec.state = VmState::Stopped;
            self.store.update_vm(&rec)?;
            self.start_vm(id).await
        } else {
            self.finalize_stop(rec).await
        }
    }

    /// One supervision pass: reconcile each Running record against live VMM
    /// state, invoking the exit handler for any that have gone away.
    pub async fn supervise_tick(&self) -> Result<()> {
        for rec in self.store.list_vms()? {
            if rec.state == VmState::Running {
                match self.runtime.status(rec.id).await? {
                    VmStatus::Running | VmStatus::Suspended => {}
                    // unexpected exit; treat as failure so OnFailure restarts.
                    _ => {
                        let _ = self.handle_exit(rec.id, true).await;
                    }
                }
            }
        }
        Ok(())
    }

    /// Run the supervisor loop forever, polling every `interval`.
    pub async fn supervise(self: Arc<Self>, interval: Duration) {
        loop {
            tokio::time::sleep(interval).await;
            let _ = self.supervise_tick().await;
        }
    }

    // ---- queries ----

    pub fn get_vm(&self, id: VmId) -> Result<Option<VmRecord>> {
        self.store.get_vm(id)
    }

    pub fn list_vms(&self) -> Result<Vec<VmRecord>> {
        self.store.list_vms()
    }

    pub fn services(&self) -> Option<HostNetwork> {
        *self.services.lock().unwrap()
    }

    /// Aggregate host stats (admin-only; never exposed to guests).
    pub async fn stats(&self) -> Result<Stats> {
        let pool = self.storage.pool_stats().await?;
        let (used, total) = {
            let s = self.slots.lock().unwrap();
            (s.in_use(), s.capacity())
        };
        Ok(Stats {
            pool,
            slots_used: used,
            slots_total: total,
            vms: self.store.list_vms()?.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use iso_common::{
        Error as IErr, MacAddr, NetworkFixture, PoolStats, Result as IRes, SlotId, SnapshotRef,
        StorageHandle, VmStatus,
    };

    use crate::types::{Lifecycle, RestartPolicy};

    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<String>>>);
    impl Log {
        fn push(&self, s: impl Into<String>) {
            self.0.lock().unwrap().push(s.into());
        }
        fn events(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
        fn has(&self, s: &str) -> bool {
            self.events().iter().any(|e| e == s)
        }
    }

    fn fixture(slot: SlotId) -> NetworkFixture {
        NetworkFixture {
            slot,
            netns: format!("vm{:04x}", slot.get()),
            tap: "tap0".into(),
            veth_host: format!("vm{:04x}", slot.get()),
            veth_netns: format!("vp{:04x}", slot.get()),
            vh_ip: Ipv4Addr::new(172, 21, 0, 0),
            vp_ip: Ipv4Addr::new(172, 21, 0, 1),
            mac: MacAddr([2, 0, 0, 0, 0, 1]),
        }
    }

    struct MockNet {
        log: Log,
    }
    impl NetworkManager for MockNet {
        async fn init(&self) -> IRes<HostNetwork> {
            self.log.push("net.init");
            Ok(HostNetwork {
                services_addr: Ipv4Addr::new(172, 22, 0, 1),
                proxy_port: 3128,
            })
        }
        async fn apply(&self, slot: SlotId, _p: &NetworkPolicy) -> IRes<NetworkFixture> {
            self.log.push(format!("net.apply:{}", slot.get()));
            Ok(fixture(slot))
        }
        async fn teardown(&self, slot: SlotId) -> IRes<()> {
            self.log.push(format!("net.teardown:{}", slot.get()));
            Ok(())
        }
        fn address_to_slot(&self, _addr: Ipv4Addr) -> Option<SlotId> {
            None
        }
    }

    struct MockStorage {
        log: Log,
        pool: PoolStats,
    }
    impl StorageManager for MockStorage {
        async fn init(&self) -> IRes<()> {
            self.log.push("storage.init");
            Ok(())
        }
        async fn provision(&self, vm: VmId, spec: &VolumeSpec) -> IRes<StorageHandle> {
            self.log.push(format!("storage.provision:{}", spec.template));
            Ok(StorageHandle {
                vm,
                device_path: format!("/dev/iso/{vm}").into(),
            })
        }
        async fn teardown(&self, _vm: VmId) -> IRes<()> {
            self.log.push("storage.teardown");
            Ok(())
        }
        async fn pool_stats(&self) -> IRes<PoolStats> {
            Ok(self.pool)
        }
    }

    type States = Arc<Mutex<std::collections::HashMap<VmId, VmStatus>>>;

    struct MockRuntime {
        log: Log,
        fail_start: bool,
        states: States,
    }
    impl MockRuntime {
        fn set(&self, vm: VmId, s: VmStatus) {
            self.states.lock().unwrap().insert(vm, s);
        }
    }
    impl VmRuntime for MockRuntime {
        async fn create(&self, spec: &InstanceSpec) -> IRes<()> {
            self.log.push(format!("rt.create:resume={}", spec.resume_from.is_some()));
            self.set(spec.vm, VmStatus::Created);
            Ok(())
        }
        async fn start(&self, vm: VmId) -> IRes<()> {
            self.log.push("rt.start");
            if self.fail_start {
                Err(IErr::Backend("boom".into()))
            } else {
                self.set(vm, VmStatus::Running);
                Ok(())
            }
        }
        async fn suspend(&self, vm: VmId) -> IRes<()> {
            self.log.push("rt.suspend");
            self.set(vm, VmStatus::Suspended);
            Ok(())
        }
        async fn stop(&self, vm: VmId) -> IRes<()> {
            self.log.push("rt.stop");
            self.set(vm, VmStatus::Stopped);
            Ok(())
        }
        async fn halt(&self, vm: VmId) -> IRes<()> {
            self.log.push("rt.halt");
            self.set(vm, VmStatus::Stopped);
            Ok(())
        }
        async fn destroy(&self, vm: VmId) -> IRes<()> {
            self.log.push("rt.destroy");
            self.states.lock().unwrap().remove(&vm);
            Ok(())
        }
        async fn status(&self, vm: VmId) -> IRes<VmStatus> {
            Ok(self
                .states
                .lock()
                .unwrap()
                .get(&vm)
                .copied()
                .unwrap_or(VmStatus::Absent))
        }
    }

    type Cp = ControlPlane<MockNet, MockStorage, MockRuntime>;

    fn cfg(slot_capacity: usize, pool: f64) -> (Config, PoolStats) {
        (
            Config {
                db_path: ":memory:".into(),
                default_vcpus: 1,
                default_mem_mib: 512,
                pool_watermark_percent: 90.0,
                graceful_stop: Duration::from_secs(30),
                slot_capacity,
            },
            PoolStats {
                data_percent: pool,
                metadata_percent: pool,
            },
        )
    }

    fn build3(slot_capacity: usize, pool: f64, fail_start: bool) -> (Cp, Log, States) {
        let log = Log::default();
        let states: States = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let (config, pstats) = cfg(slot_capacity, pool);
        let cp = ControlPlane::new(
            config,
            MockNet { log: log.clone() },
            MockStorage {
                log: log.clone(),
                pool: pstats,
            },
            MockRuntime {
                log: log.clone(),
                fail_start,
                states: states.clone(),
            },
        )
        .unwrap();
        (cp, log, states)
    }

    fn build(slot_capacity: usize, pool: f64, fail_start: bool) -> (Cp, Log) {
        let (cp, log, _states) = build3(slot_capacity, pool, fail_start);
        (cp, log)
    }

    fn template(snapshot: bool) -> TemplateDef {
        TemplateDef {
            name: "base".into(),
            rootfs_template: "base".into(),
            snapshot: snapshot.then(|| SnapshotRef {
                mem_file: "/snap/mem".into(),
                vmstate: "/snap/state".into(),
            }),
            vcpus: 1,
            mem_mib: 512,
            kernel: "/k".into(),
            boot_args: "".into(),
        }
    }

    fn req(lifecycle: Lifecycle, restart: RestartPolicy) -> CreateVm {
        CreateVm {
            lifecycle,
            restart,
            ..CreateVm::new("base")
        }
    }

    #[tokio::test]
    async fn create_orders_subsystems_and_resumes() {
        let (cp, log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp
            .create_vm(req(Lifecycle::Ephemeral, RestartPolicy::Never))
            .await
            .unwrap();

        let e = log.events();
        let pos = |s: &str| e.iter().position(|x| x == s).unwrap();
        assert!(pos("storage.provision:base") < pos("net.apply:0"));
        assert!(pos("net.apply:0") < pos("rt.create:resume=true"));
        assert!(pos("rt.create:resume=true") < pos("rt.start"));

        let rec = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(rec.state, VmState::Running);
        assert_eq!(rec.slot.unwrap().get(), 0);
    }

    #[tokio::test]
    async fn create_rolls_back_and_frees_slot_on_failure() {
        let (cp, log) = build(8, 10.0, true); // runtime.start fails
        cp.register_template(&template(true)).unwrap();
        let err = cp
            .create_vm(req(Lifecycle::Ephemeral, RestartPolicy::Never))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Component(_)));
        assert!(log.has("net.teardown:0"));
        assert!(log.has("storage.teardown"));
        assert!(cp.list_vms().unwrap().is_empty());
        let s = cp.stats().await.unwrap();
        assert_eq!(s.slots_used, 0);
    }

    #[tokio::test]
    async fn custom_cpu_mem_forces_fresh_boot() {
        let (cp, log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let r = CreateVm {
            vcpus: Some(4),
            ..CreateVm::new("base")
        };
        cp.create_vm(r).await.unwrap();
        assert!(log.has("rt.create:resume=false"));
    }

    #[tokio::test]
    async fn stop_ephemeral_tears_down_everything() {
        let (cp, _log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Ephemeral, RestartPolicy::Never)).await.unwrap();
        cp.stop_vm(id).await.unwrap();
        assert!(cp.get_vm(id).unwrap().is_none());
        assert_eq!(cp.stats().await.unwrap().slots_used, 0);
    }

    #[tokio::test]
    async fn stop_durable_keeps_storage_frees_slot() {
        let (cp, log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Durable, RestartPolicy::Never)).await.unwrap();
        cp.stop_vm(id).await.unwrap();
        let rec = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(rec.state, VmState::Stopped);
        assert!(rec.slot.is_none());
        assert!(!log.has("storage.teardown"), "durable keeps storage");
        assert_eq!(cp.stats().await.unwrap().slots_used, 0);
    }

    #[tokio::test]
    async fn suspend_then_start_resumes_in_place() {
        let (cp, log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Durable, RestartPolicy::Never)).await.unwrap();
        cp.suspend_vm(id).await.unwrap();
        assert_eq!(cp.get_vm(id).unwrap().unwrap().state, VmState::Suspended);
        cp.start_vm(id).await.unwrap();
        assert_eq!(cp.get_vm(id).unwrap().unwrap().state, VmState::Running);
        assert!(log.has("rt.suspend"));
    }

    #[tokio::test]
    async fn start_stopped_durable_replaces_and_fresh_boots() {
        let (cp, log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Durable, RestartPolicy::Never)).await.unwrap();
        cp.stop_vm(id).await.unwrap();
        cp.start_vm(id).await.unwrap();
        let rec = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(rec.state, VmState::Running);
        assert!(rec.slot.is_some());
        // a restart fresh-boots (rootfs has diverged from the template snapshot).
        assert!(log.has("rt.create:resume=false"));
    }

    #[tokio::test]
    async fn handle_exit_restarts_when_policy_always() {
        let (cp, _log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Durable, RestartPolicy::Always)).await.unwrap();
        cp.handle_exit(id, false).await.unwrap();
        assert_eq!(cp.get_vm(id).unwrap().unwrap().state, VmState::Running);
    }

    #[tokio::test]
    async fn handle_exit_finalizes_when_no_restart() {
        let (cp, _log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Ephemeral, RestartPolicy::Never)).await.unwrap();
        cp.handle_exit(id, true).await.unwrap();
        assert!(cp.get_vm(id).unwrap().is_none());
    }

    #[tokio::test]
    async fn pool_full_refuses_provision() {
        let (cp, _log) = build(8, 95.0, false);
        cp.register_template(&template(true)).unwrap();
        let err = cp.create_vm(CreateVm::new("base")).await.unwrap_err();
        assert!(matches!(err, Error::PoolFull { .. }));
        assert_eq!(cp.stats().await.unwrap().slots_used, 0);
    }

    #[tokio::test]
    async fn unknown_template_errors() {
        let (cp, _log) = build(8, 10.0, false);
        let err = cp.create_vm(CreateVm::new("ghost")).await.unwrap_err();
        assert!(matches!(err, Error::UnknownTemplate(_)));
    }

    #[tokio::test]
    async fn supervisor_finalizes_crashed_ephemeral() {
        let (cp, _log, states) = build3(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Ephemeral, RestartPolicy::Never)).await.unwrap();
        // simulate an unexpected exit
        states.lock().unwrap().insert(id, VmStatus::Stopped);
        cp.supervise_tick().await.unwrap();
        assert!(cp.get_vm(id).unwrap().is_none(), "crashed ephemeral is reaped");
    }

    #[tokio::test]
    async fn supervisor_restarts_when_policy_always() {
        let (cp, _log, states) = build3(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Durable, RestartPolicy::Always)).await.unwrap();
        states.lock().unwrap().insert(id, VmStatus::Stopped);
        cp.supervise_tick().await.unwrap();
        assert_eq!(cp.get_vm(id).unwrap().unwrap().state, VmState::Running);
    }

    #[tokio::test]
    async fn slots_exhaust() {
        let (cp, _log) = build(1, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        cp.create_vm(CreateVm::new("base")).await.unwrap();
        let err = cp.create_vm(CreateVm::new("base")).await.unwrap_err();
        assert!(matches!(err, Error::SlotsExhausted));
    }
}
