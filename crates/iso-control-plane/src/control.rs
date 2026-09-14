//! The control plane: orchestrates network, storage, and the VMM behind the
//! lifecycle state machine, with SQLite as the durable source of truth.
//!
//! Transport-agnostic — the axum HTTP layer is a thin wrapper over these
//! methods.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iso_common::{
    EgressMode, HostNetwork, InstanceSpec, NetworkManager, NetworkPolicy, StorageManager, VmId,
    VmRuntime,
    VmStatus, VolumeSpec,
};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::port::PortAllocator;
use crate::slot::SlotAllocator;
use crate::store::Store;
use iso_common::{PortForward, Protocol};
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
    ports: Mutex<PortAllocator>,
    services: Mutex<Option<HostNetwork>>,
    /// Per-VM async locks serializing the *network application* for a VM — its
    /// lifecycle apply/teardown and the policy/forward re-steers — so two of them
    /// can't race the same slot's netns/nft. Data-race safety of the *declaration*
    /// is the store's job now (normalized `port_forwards` rows + disjoint column
    /// updates), not this lock's; different VMs stay fully concurrent.
    vm_locks: Mutex<HashMap<VmId, Arc<tokio::sync::Mutex<()>>>>,
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
        let ports = PortAllocator::new(cfg.forward_ports.0, cfg.forward_ports.1);
        Ok(Self {
            cfg,
            net,
            storage,
            runtime,
            store,
            slots: Mutex::new(slots),
            ports: Mutex::new(ports),
            services: Mutex::new(None),
            vm_locks: Mutex::new(HashMap::new()),
        })
    }

    /// The per-VM serialization lock, created on first use. Callers `.await` its
    /// `.lock()` and hold the guard across the whole read-modify-write.
    fn vm_lock(&self, id: VmId) -> Arc<tokio::sync::Mutex<()>> {
        self.vm_locks
            .lock()
            .unwrap()
            .entry(id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Drop a destroyed VM's lock entry. Safe because VM ids are random and
    /// never reused: any in-flight holder keeps its own `Arc` alive, and no
    /// future op will ever reference this id again (it resolves to `UnknownVm`).
    fn forget_lock(&self, id: VmId) {
        self.vm_locks.lock().unwrap().remove(&id);
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
            for f in &rec.ingress {
                self.ports.lock().unwrap().reserve(f.host_port);
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
    pub fn list_templates(&self) -> Result<Vec<TemplateDef>> {
        self.store.list_templates()
    }

    pub fn register_template(&self, def: &TemplateDef) -> Result<()> {
        self.store.upsert_template(def)
    }

    /// Create and boot a VM. Allocates a slot, provisions storage, applies
    /// network, and starts the VMM — rolling everything back on failure.
    pub async fn create_vm(&self, req: CreateVm) -> Result<VmId> {
        // Reject a policy that would never compile before anything is
        // allocated for it.
        validate_policy(&req.allow, &req.rules)?;
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

        let id = req.id.unwrap_or_else(random_vmid);
        if let Some(signed) = &req.signed {
            check_signed(signed, id, 1, req.egress, req.principal.as_deref(), &req.allow, &req.rules)?;
        }
        // Hold this VM's lock from the moment its id exists, so a concurrent
        // supervise/handle_exit can't act on the half-created record.
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        if self.store.get_vm(id)?.is_some() {
            return Err(Error::VmExists(id));
        }
        let slot = self
            .slots
            .lock()
            .unwrap()
            .allocate()
            .ok_or(Error::SlotsExhausted)?;

        // Allocate an external host port for each requested forward (ssh is
        // just a forward; nothing special). The resolved ports are reported in
        // the VM record.
        let mut ingress: Vec<PortForward> = Vec::with_capacity(req.ingress.len());
        for f in &req.ingress {
            let host_port = match self.ports.lock().unwrap().allocate() {
                Some(p) => p,
                None => {
                    let mut pa = self.ports.lock().unwrap();
                    for done in &ingress {
                        pa.free(done.host_port);
                    }
                    self.slots.lock().unwrap().free(slot);
                    return Err(Error::PortsExhausted);
                }
            };
            ingress.push(PortForward {
                host_port,
                vm_port: f.vm_port,
                proto: f.proto,
            });
        }

        let mut rec = VmRecord {
            id,
            slot: Some(slot),
            template: req.template.clone(),
            egress: req.egress,
            ingress: ingress.clone(),
            labels: req.labels.clone(),
            lifecycle: req.lifecycle,
            restart: req.restart,
            vcpus: req.vcpus,
            mem_mib: req.mem_mib,
            state: VmState::Creating,
            rootfs_device: None,
            tap: None,
            principal: req.principal.clone(),
            allow: req.allow.clone(),
            rules: req.rules.clone(),
            policy_gen: 1,
            signed: req.signed.clone(),
            // A new VM has never suspended; it resumes from its template.
            snapshot: None,
        };
        // write-ahead intent so a crash mid-create is recoverable. `rec.ingress`
        // drives bring_up's apply; the persisted desired state is the normalized
        // `port_forwards` rows we insert next (a crash before they land just
        // means fewer forwards — never a torn record).
        self.store.insert_vm(&rec)?;
        for f in &ingress {
            if let Err(e) = self.store.add_forward(id, f) {
                self.free_ports(&ingress);
                self.rollback(id, slot).await;
                return Err(e);
            }
        }

        match self.bring_up(&mut rec, &tpl, true).await {
            Ok(()) => {
                rec.state = VmState::Running;
                self.store.update_placement(&rec)?;
                Ok(id)
            }
            Err(e) => {
                {
                    let mut pa = self.ports.lock().unwrap();
                    for f in &ingress {
                        pa.free(f.host_port);
                    }
                }
                self.rollback(id, slot).await;
                Err(e)
            }
        }
    }

    fn free_ports(&self, ingress: &[PortForward]) {
        let mut pa = self.ports.lock().unwrap();
        for f in ingress {
            pa.free(f.host_port);
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
            direct: false,
        };
        let fixture = self.net.apply(slot, &policy).await?;

        // Custom vcpu/mem forgoes any snapshot: it was taken at the template's
        // machine shape and cannot resume into a different one.
        //
        // Otherwise this VM's own snapshot wins over the template's. The
        // template's is where every clone *starts*; a VM that has suspended has
        // somewhere of its own to come back to, and `allow_resume` does not
        // gate it — that flag exists to force a stopped durable VM to boot
        // fresh off its rootfs rather than re-enter the template's memory,
        // which is a different question from resuming its own state.
        let custom = rec.vcpus.is_some() || rec.mem_mib.is_some();
        let resume_from = if custom {
            None
        } else if rec.snapshot.is_some() {
            rec.snapshot.clone()
        } else if allow_resume {
            tpl.snapshot.clone()
        } else {
            None
        };
        // On resume, redirect the snapshot's baked rootfs path to this VM's own
        // CoW volume (the runtime binds it in a private mount ns) so clones
        // never write the shared template. The backing device is the storage
        // layer's metadata, recorded when the volume was provisioned.
        let rootfs_backing = resume_from
            .as_ref()
            .and_then(|_| storage.backing_device.clone());
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
            rootfs_backing,
            vsock_cid: self.cfg.vsock_cid,
        };
        self.runtime.create(&spec).await?;
        self.runtime.start(rec.id).await?;
        if spec.resume_from.is_some() {
            self.sync_guest_clock(rec.id).await;
        }

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
        self.forget_lock(id);
    }

    /// Explicitly destroy a VM and all its resources, regardless of lifecycle.
    pub async fn destroy_vm(&self, id: VmId) -> Result<()> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        let rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        let _ = self.runtime.stop(id).await; // best-effort graceful
        let _ = self.runtime.halt(id).await;
        let _ = self.runtime.destroy(id).await;
        if let Some(slot) = rec.slot {
            let _ = self.net.teardown(slot).await;
            self.slots.lock().unwrap().free(slot);
        }
        self.free_ports(&rec.ingress);
        let _ = self.storage.teardown(id).await;
        self.store.delete_vm(id)?;
        self.forget_lock(id);
        Ok(())
    }

    /// Graceful shutdown (escalating to force after the timeout), then apply
    /// lifecycle policy.
    pub async fn stop_vm(&self, id: VmId) -> Result<()> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        let rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        self.runtime.stop(id).await?;
        if !self.wait_exit(id, self.cfg.graceful_stop).await {
            let _ = self.runtime.halt(id).await;
        }
        self.finalize_stop(rec).await
    }

    /// Forceful stop, then apply lifecycle policy.
    pub async fn halt_vm(&self, id: VmId) -> Result<()> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        let rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        self.runtime.halt(id).await?;
        self.finalize_stop(rec).await
    }

    /// Explicit cold stop: discard execution/suspension state, retaining a
    /// durable workspace and its stable ingress ports. No automatic policy.
    pub async fn terminate_vm(&self, id: VmId) -> Result<()> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        self.terminate_vm_locked(id).await
    }

    /// Resume only to request clean guest shutdown. Never force on timeout.
    pub async fn retire_suspension(&self, id: VmId) -> Result<()> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        let rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        if rec.lifecycle != Lifecycle::Durable || rec.state != VmState::Suspended {
            return Err(iso_common::Error::Backend("Suspension retirement requires a suspended durable VM".into()).into());
        }
        self.start_vm_locked(id).await?;
        self.runtime.stop(id).await?;
        if !self.wait_exit(id, self.cfg.graceful_stop).await {
            return Err(iso_common::Error::Backend("Clean shutdown not confirmed; suspension files retained, inspect VM before recovery".into()).into());
        }
        self.terminate_vm_locked(id).await
    }

    async fn terminate_vm_locked(&self, id: VmId) -> Result<()> {
        let mut rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        if rec.lifecycle != Lifecycle::Durable {
            return Err(iso_common::Error::Backend("Terminate requires a durable workspace".into()).into());
        }
        self.runtime.destroy(id).await?;
        if let Some(snapshot) = &rec.snapshot {
            for path in [&snapshot.mem_file, &snapshot.vmstate] {
                match std::fs::symlink_metadata(path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(iso_common::Error::Backend(format!("Check suspension cleanup: {e}")).into()),
                    Ok(_) => return Err(iso_common::Error::Backend("Suspension snapshot cleanup not confirmed".into()).into()),
                }
            }
        }
        if let Some(slot) = rec.slot { self.net.teardown(slot).await?; }
        let slot = rec.slot;
        rec.slot = None;
        rec.tap = None;
        rec.snapshot = None;
        rec.state = VmState::Stopped;
        self.store.update_placement(&rec)?;
        if let Some(slot) = slot { self.slots.lock().unwrap().free(slot); }
        Ok(())
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
        // A durable VM keeps its storage across a stop; it keeps its snapshot
        // for the same reason, so that a stop after a suspend comes back as
        // itself. `destroy` removes both.
        match rec.lifecycle {
            Lifecycle::Durable => {
                let _ = self.runtime.release(rec.id).await;
            }
            Lifecycle::Ephemeral => {
                let _ = self.runtime.destroy(rec.id).await;
            }
        }
        if let Some(slot) = rec.slot {
            let _ = self.net.teardown(slot).await;
            self.slots.lock().unwrap().free(slot);
        }
        match rec.lifecycle {
            Lifecycle::Ephemeral => {
                self.free_ports(&rec.ingress);
                let _ = self.storage.teardown(rec.id).await;
                self.store.delete_vm(rec.id)?;
                self.forget_lock(rec.id);
            }
            Lifecycle::Durable => {
                // keep the host ports reserved so the VM keeps its stable
                // external ports across stop/start (placement/slot is recreated,
                // ports are the durable external identity).
                rec.slot = None;
                rec.tap = None;
                rec.state = VmState::Stopped;
                self.store.update_placement(&rec)?;
            }
        }
        Ok(())
    }

    /// Pause (and snapshot) a running VM.
    pub async fn suspend_vm(&self, id: VmId) -> Result<()> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        let mut rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        if rec.state != VmState::Running {
            return Err(Error::InvalidState {
                vm: id,
                state: rec.state.as_str(),
                op: "suspend",
            });
        }
        // Keep where the snapshot landed: without it, a start after the VMM is
        // gone would fall back to the template and silently discard this VM's
        // state.
        rec.snapshot = Some(self.runtime.suspend(id).await?);
        rec.state = VmState::Suspended;
        self.store.update_placement(&rec)?;
        Ok(())
    }

    /// Start a suspended VM (resume in place) or a stopped Durable VM (re-place
    /// and boot from its persisted rootfs).
    pub async fn start_vm(&self, id: VmId) -> Result<()> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        self.start_vm_locked(id).await
    }

    /// `start_vm` body, assuming this VM's lock is already held. Internal callers
    /// that already hold the guard (e.g. `handle_exit`) use this to avoid
    /// re-acquiring the non-reentrant lock and deadlocking.
    async fn start_vm_locked(&self, id: VmId) -> Result<()> {
        let mut rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        match rec.state {
            VmState::Suspended => {
                self.runtime.start(id).await?;
                self.sync_guest_clock(id).await;
                rec.state = VmState::Running;
                self.store.update_placement(&rec)?;
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
                self.store.update_placement(&rec)?;
                match self.bring_up(&mut rec, &tpl, false).await {
                    Ok(()) => {
                        rec.state = VmState::Running;
                        self.store.update_placement(&rec)?;
                        Ok(())
                    }
                    Err(e) => {
                        self.slots.lock().unwrap().free(slot);
                        rec.slot = None;
                        rec.state = VmState::Stopped;
                        let _ = self.store.update_placement(&rec);
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
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
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
            self.store.update_placement(&rec)?;
            self.start_vm_locked(id).await
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

    /// Resolve a caller's source IP (a VM's post-SNAT `vp`) to its slot, then
    /// to its VM record — used by the metadata server to identify the caller.
    pub fn identify(&self, addr: std::net::Ipv4Addr) -> Result<Option<VmRecord>> {
        let Some(slot) = self.net.address_to_slot(addr) else {
            return Ok(None);
        };
        Ok(self
            .store
            .list_vms()?
            .into_iter()
            .find(|v| v.slot == Some(slot)))
    }

    pub fn get_vm(&self, id: VmId) -> Result<Option<VmRecord>> {
        self.store.get_vm(id)
    }

    pub fn list_vms(&self) -> Result<Vec<VmRecord>> {
        self.store.list_vms()
    }

    /// Update a VM's egress policy: the (opaque) `principal` it acts as, the
    /// `allow` domain list and/or the URI `rules`. `None` fields are left
    /// unchanged. Mutable at runtime (e.g. set per agent turn). Every call
    /// bumps the policy generation, which is what tells the proxy edge to
    /// close connections it holds at the old one. Returns the new generation.
    ///
    /// `signed` is the fleet's signature over the resulting policy. It must
    /// describe this VM at the generation this change produces, or, when
    /// nothing changes, at the current generation: that is a re-signing
    /// before the old signature expires, and bumps nothing. A change without
    /// a signature clears the stored one, since it no longer describes the
    /// policy; a tier that verifies then refuses the VM until the fleet
    /// signs again, which is the point.
    pub async fn set_policy(
        &self,
        id: VmId,
        principal: Option<String>,
        allow: Option<Vec<String>>,
        rules: Option<Vec<String>>,
        egress: Option<EgressMode>,
        signed: Option<iso_common::identify::SignedPolicy>,
    ) -> Result<u64> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        let rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;

        // Merge the provided (Some) fields over the current values, then persist
        // ONLY the policy columns — disjoint from placement, so this can't clobber
        // a concurrent lifecycle transition's slot/state.
        let new_principal = principal.or_else(|| rec.principal.clone());
        let new_allow = allow.unwrap_or_else(|| rec.allow.clone());
        let new_rules = rules.unwrap_or_else(|| rec.rules.clone());
        validate_policy(&new_allow, &new_rules)?;
        let new_egress = egress.unwrap_or(rec.egress);
        let egress_changed = new_egress != rec.egress;
        let unchanged = new_principal == rec.principal
            && new_allow == rec.allow
            && new_rules == rec.rules
            && !egress_changed;
        if let Some(signed) = &signed {
            let claimed_gen = iso_policy::signed::claims_unverified(signed)
                .map_err(|e| Error::SignedMismatch(e.to_string()))?
                .policy_gen;
            if unchanged && claimed_gen == rec.policy_gen {
                check_signed(signed, id, rec.policy_gen, new_egress, new_principal.as_deref(), &new_allow, &new_rules)?;
                self.store.refresh_signed(id, signed)?;
                return Ok(rec.policy_gen);
            }
            check_signed(signed, id, rec.policy_gen + 1, new_egress, new_principal.as_deref(), &new_allow, &new_rules)?;
        }
        let new_gen = self.store.update_policy(
            id,
            new_principal.as_deref(),
            &new_allow,
            &new_rules,
            new_egress,
            signed.as_ref(),
        )?;

        // The policy is read live by the proxy/DNS via `identify`; only an
        // egress *mode* change needs a network re-steer.
        if egress_changed {
            self.apply_network(id).await?;
        }
        Ok(new_gen)
    }

    /// Apply a VM's declared desired state to the live network: an nft-only
    /// re-steer that never disturbs the running VM's netns/veth/tap. Reads the
    /// desired set (egress + forwards) FRESH from the store, so it reflects the
    /// declaration that just committed. No-op for a stopped VM (no slot) — its
    /// forwards materialize at the next `bring_up` — or one that's been removed.
    /// Caller must hold the VM lock (this is the "apply" half of declare→apply).
    async fn apply_network(&self, id: VmId) -> Result<()> {
        let Some(rec) = self.store.get_vm(id)? else {
            return Ok(());
        };
        let Some(slot) = rec.slot else {
            return Ok(());
        };
        let policy = NetworkPolicy {
            egress: rec.egress,
            ingress: rec.ingress,
            direct: false,
        };
        self.net.reapply_policy(slot, &policy).await?;
        Ok(())
    }

    /// Add an ingress port-forward at runtime. Two distinct steps: *declare* the
    /// forward (allocate a host port + insert the `port_forwards` row — an atomic
    /// store op that can't clobber any other field) then *apply* it to the live
    /// network. For a stopped VM (no slot) only the declaration happens; it
    /// materializes at the next `bring_up`. Returns the resolved forward.
    ///
    /// The VM lock here serializes the *application* against the VM's lifecycle
    /// (so a re-steer can't race a teardown/boot); declaration safety comes from
    /// the store, not the lock.
    pub async fn add_forward(&self, id: VmId, vm_port: u16, proto: Protocol) -> Result<PortForward> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        if self.store.get_vm(id)?.is_none() {
            return Err(Error::UnknownVm(id));
        }

        let host_port = self
            .ports
            .lock()
            .unwrap()
            .allocate()
            .ok_or(Error::PortsExhausted)?;
        let fwd = PortForward { host_port, vm_port, proto };

        // Declare (atomic; the FK reports a vanished VM rather than orphaning).
        if let Err(e) = self.store.add_forward(id, &fwd) {
            self.ports.lock().unwrap().free(host_port);
            return Err(e);
        }
        // Apply; retract the declaration if the data plane rejects it.
        if let Err(e) = self.apply_network(id).await {
            let _ = self.store.remove_forward(id, host_port, proto);
            self.ports.lock().unwrap().free(host_port);
            return Err(e);
        }
        Ok(fwd)
    }

    /// Remove an ingress port-forward (by its allocated `host_port` + `proto`) at
    /// runtime: *undeclare* it (delete the row), *apply* the reduced set to the
    /// live network, then release the host port. Errors with `UnknownForward` if
    /// no such forward exists on the VM.
    pub async fn remove_forward(&self, id: VmId, host_port: u16, proto: Protocol) -> Result<()> {
        let lock = self.vm_lock(id);
        let _guard = lock.lock().await;
        if !self.store.remove_forward(id, host_port, proto)? {
            return Err(Error::UnknownForward { host_port, proto });
        }
        self.apply_network(id).await?;
        self.ports.lock().unwrap().free(host_port);
        Ok(())
    }

    pub fn services(&self) -> Option<HostNetwork> {
        *self.services.lock().unwrap()
    }

    /// Open a raw stream to a vsock `port` inside a running VM — by default the
    /// guest agent's. The VMM hands back a connected socket; the caller speaks
    /// the guest protocol over it. Refused unless the VM is `Running`.
    pub async fn guest_channel(&self, id: VmId, port: Option<u32>) -> Result<std::os::fd::OwnedFd> {
        let rec = self.store.get_vm(id)?.ok_or(Error::UnknownVm(id))?;
        if rec.state != VmState::Running {
            return Err(Error::InvalidState {
                vm: id,
                state: rec.state.as_str(),
                op: "open a guest channel to",
            });
        }
        let port = port.unwrap_or(self.cfg.guest_agent_port);
        Ok(self.runtime.guest_channel(id, port).await?)
    }

    /// After a resume the guest's wall clock is where the snapshot left it:
    /// kvm-clock carries the host's time into a fresh boot, not into a
    /// restored one, and nothing in the guest notices. Tell the agent the
    /// time. Best effort and bounded: a template with nothing on the agent's
    /// vsock port costs a short wait and a warning, never the VM. An agent
    /// that answers but cannot do it (too old, or without `CAP_SYS_TIME`) is
    /// not retried.
    async fn sync_guest_clock(&self, id: VmId) {
        const BUDGET: Duration = Duration::from_secs(3);
        const RETRY: Duration = Duration::from_millis(100);
        let started = std::time::Instant::now();
        let mut last = String::new();
        while started.elapsed() < BUDGET {
            match self.tell_guest_time(id).await {
                Ok(c) if c.stepped => {
                    tracing::info!(vm = %id, "guest clock stepped by {} ms after resume", c.offset_ms);
                    return;
                }
                Ok(_) => return,
                Err(ClockAttempt::GiveUp(e)) => {
                    last = e;
                    break;
                }
                Err(ClockAttempt::Retry(e)) => last = e,
            }
            tokio::time::sleep(RETRY).await;
        }
        tracing::warn!(vm = %id, "guest clock not set after resume: {last}");
    }

    /// One `set_clock` round trip with the host's time.
    async fn tell_guest_time(&self, id: VmId) -> std::result::Result<iso_guest_proto::ClockResult, ClockAttempt> {
        use iso_guest_proto::ClientError;
        let retry = |e: &dyn std::fmt::Display| ClockAttempt::Retry(e.to_string());
        let fd = self
            .runtime
            .guest_channel(id, self.cfg.guest_agent_port)
            .await
            .map_err(|e| retry(&e))?;
        let std = std::os::unix::net::UnixStream::from(fd);
        std.set_nonblocking(true).map_err(|e| retry(&e))?;
        let stream = tokio::net::UnixStream::from_std(std).map_err(|e| retry(&e))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut agent = iso_guest_proto::GuestClient::new(stream);
        match tokio::time::timeout(Duration::from_secs(2), agent.set_clock(now)).await {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(ClientError::Agent(m))) => Err(ClockAttempt::GiveUp(format!("guest agent: {m}"))),
            Ok(Err(e)) => Err(retry(&e)),
            Err(_) => Err(ClockAttempt::Retry("guest agent did not answer in time".into())),
        }
    }

    /// Aggregate host stats (admin-only; never exposed to guests).
    pub async fn stats(&self) -> Result<Stats> {
        let pool = self.storage.pool_stats().await?;
        let records = self.store.list_vms()?;
        let paths: std::collections::HashSet<_> = records.iter()
            .filter_map(|r| r.snapshot.as_ref())
            .flat_map(|s| [s.mem_file.clone(), s.vmstate.clone()]).collect();
        let snapshot_bytes = tokio::task::spawn_blocking(move || {
            use std::os::unix::fs::MetadataExt;
            let mut inodes = std::collections::HashSet::new();
            paths.into_iter().try_fold(0u64, |total, path| {
                let metadata = std::fs::metadata(path).ok()?;
                if inodes.insert((metadata.dev(), metadata.ino())) {
                    total.checked_add(metadata.blocks().checked_mul(512)?)
                } else { Some(total) }
            })
        }).await.ok().flatten();
        let (used, total) = {
            let s = self.slots.lock().unwrap();
            (s.in_use(), s.capacity())
        };
        Ok(Stats {
            snapshot_bytes,
            pool,
            slots_used: used,
            slots_total: total,
            vms: records.len(),
        })
    }
}


/// The effective policy must compile: bad input is rejected with the offending
/// rule, never stored to fail later inside the proxy.
fn validate_policy(allow: &[String], rules: &[String]) -> Result<()> {
    iso_policy::RuleSet::from_record(allow, rules)
        .map(|_| ())
        .map_err(|e| Error::InvalidRule(e.to_string()))
}

/// Whether a fleet's signed claims describe exactly the policy this host is
/// about to store: same VM, generation, mode, principal and effective rules.
/// The host cannot check the signature (it holds no key, on purpose) but it
/// can refuse to file a signature under a policy it does not describe, so
/// what the edge relays and what `identify` answers never disagree.
fn check_signed(
    signed: &iso_common::identify::SignedPolicy,
    id: VmId,
    policy_gen: u64,
    egress: EgressMode,
    principal: Option<&str>,
    allow: &[String],
    rules: &[String],
) -> Result<()> {
    let c = iso_policy::signed::claims_unverified(signed).map_err(|e| Error::SignedMismatch(e.to_string()))?;
    let effective = iso_policy::RuleSet::from_record(allow, rules)
        .map_err(|e| Error::InvalidRule(e.to_string()))?
        .to_strings();
    let mut why = Vec::new();
    if c.vm != id.to_string() {
        why.push(format!("it names vm {} not {id}", c.vm));
    }
    if c.policy_gen != policy_gen {
        why.push(format!("it is at generation {} not {policy_gen}", c.policy_gen));
    }
    if c.egress != crate::types::egress_str(egress) {
        why.push(format!("egress {:?} not {:?}", c.egress, crate::types::egress_str(egress)));
    }
    if c.principal.as_deref() != principal {
        why.push(format!("principal {:?} not {:?}", c.principal, principal));
    }
    if c.rules != effective {
        why.push(format!("rules {:?} not {:?}", c.rules, effective));
    }
    if why.is_empty() { Ok(()) } else { Err(Error::SignedMismatch(why.join("; "))) }
}

/// Why one `set_clock` attempt did not succeed: the channel was not there yet
/// (try again shortly) or the agent said no (it will keep saying no).
enum ClockAttempt {
    Retry(String),
    GiveUp(String),
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
        async fn reapply_policy(&self, _slot: SlotId, _p: &NetworkPolicy) -> IRes<()> {
            // Yield so concurrent mutators actually interleave at this await
            // point (exercises the declare/apply paths under real concurrency).
            tokio::task::yield_now().await;
            Ok(())
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
                backing_device: Some(format!("/dev/iso/tpl_{}", spec.template).into()),
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
        hang_stop: bool,
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
        async fn suspend(&self, vm: VmId) -> IRes<SnapshotRef> {
            self.log.push("rt.suspend");
            self.set(vm, VmStatus::Suspended);
            Ok(SnapshotRef {
                mem_file: format!("/state/{vm}/mem").into(),
                vmstate: format!("/state/{vm}/vmstate").into(),
            })
        }
        async fn release(&self, vm: VmId) -> IRes<()> {
            self.log.push("rt.release");
            self.set(vm, VmStatus::Stopped);
            Ok(())
        }
        async fn stop(&self, vm: VmId) -> IRes<()> {
            self.log.push("rt.stop");
            if !self.hang_stop { self.set(vm, VmStatus::Stopped); }
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
        /// A stand-in agent on a socketpair: answers one `set_clock`, logging
        /// whether the time it was handed is a real one.
        async fn guest_channel(&self, _vm: VmId, port: u32) -> IRes<std::os::fd::OwnedFd> {
            use iso_guest_proto::{ClockResult, Request, Response, ResponseBody};
            self.log.push(format!("rt.guest_channel:{port}"));
            let (host, guest) = std::os::unix::net::UnixStream::pair().map_err(|e| IErr::Backend(e.to_string()))?;
            guest.set_nonblocking(true).unwrap();
            let log = self.log.clone();
            tokio::spawn(async move {
                let mut s = tokio::net::UnixStream::from_std(guest).unwrap();
                if let Ok(Some(Request::SetClock { unix_nanos })) = iso_guest_proto::recv::<_, Request>(&mut s).await {
                    let year_2020 = 1_577_836_800_000_000_000u64;
                    log.push(if unix_nanos > year_2020 { "agent.set_clock:plausible" } else { "agent.set_clock:bogus" });
                    let r = Response::ok(ResponseBody::Clock(ClockResult { offset_ms: 180_000, stepped: true }));
                    let _ = iso_guest_proto::send(&mut s, &r).await;
                }
            });
            Ok(std::os::fd::OwnedFd::from(host))
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
                forward_ports: (20000, 20010),
                vsock_cid: Some(3),
                guest_agent_port: 5000,
            },
            PoolStats {
                data_percent: pool,
                metadata_percent: pool,
                ..Default::default()
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
                hang_stop: false,
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
    async fn a_resume_tells_the_guest_the_time_and_a_fresh_boot_does_not() {
        let (cp, log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp
            .create_vm(req(Lifecycle::Ephemeral, RestartPolicy::Never))
            .await
            .unwrap();
        let e = log.events();
        let pos = |s: &str| e.iter().position(|x| x == s).unwrap();
        assert!(pos("rt.start") < pos("rt.guest_channel:5000"), "told after the VMM resumed");
        assert!(log.has("agent.set_clock:plausible"));

        // Suspend and start resumes in place: told again.
        cp.suspend_vm(id).await.unwrap();
        cp.start_vm(id).await.unwrap();
        let told = log.events().iter().filter(|x| *x == "agent.set_clock:plausible").count();
        assert_eq!(told, 2);

        // A fresh boot reads the host's clock on its own.
        let (cp, log) = build(8, 10.0, false);
        cp.register_template(&template(false)).unwrap();
        cp.create_vm(req(Lifecycle::Ephemeral, RestartPolicy::Never))
            .await
            .unwrap();
        assert!(!log.has("rt.guest_channel:5000"));
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
    async fn suspension_retirement_requires_clean_shutdown() {
        let (mut cp, log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Durable, RestartPolicy::Never)).await.unwrap();
        assert!(cp.retire_suspension(id).await.is_err());
        cp.suspend_vm(id).await.unwrap();
        cp.runtime.hang_stop = true;
        cp.cfg.graceful_stop = Duration::from_millis(5);
        assert!(cp.retire_suspension(id).await.is_err());
        assert!(!log.has("rt.halt"));
        assert!(!log.has("rt.destroy"));
        assert!(cp.get_vm(id).unwrap().unwrap().snapshot.is_some());
        cp.runtime.hang_stop = false;
        cp.suspend_vm(id).await.unwrap();
        cp.retire_suspension(id).await.unwrap();
        let rec = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(rec.state, VmState::Stopped);
        assert!(rec.snapshot.is_none());
        assert!(rec.slot.is_none());
        assert!(!log.has("storage.teardown"));
    }

    #[tokio::test]
    async fn explicit_termination_retains_disk_and_discards_execution_state() {
        let (cp, log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Durable, RestartPolicy::Always)).await.unwrap();
        cp.suspend_vm(id).await.unwrap();
        cp.terminate_vm(id).await.unwrap();
        cp.terminate_vm(id).await.unwrap();
        let rec = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(rec.state, VmState::Stopped);
        assert!(rec.slot.is_none());
        assert!(rec.snapshot.is_none());
        assert!(rec.rootfs_device.is_some());
        assert!(log.has("rt.destroy"));
        assert!(!log.has("storage.teardown"));
        cp.supervise_tick().await.unwrap();
        assert_eq!(cp.get_vm(id).unwrap().unwrap().state, VmState::Stopped);
        cp.start_vm(id).await.unwrap();
        assert_eq!(cp.get_vm(id).unwrap().unwrap().state, VmState::Running);
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

    /// A durable VM that suspended and then stopped must come back as itself.
    /// Before per-VM snapshots this fresh-booted, silently discarding the
    /// suspended state; `allow_resume=false` on the stopped path only ever
    /// meant "don't re-enter the *template's* memory".
    #[tokio::test]
    async fn suspended_then_stopped_durable_resumes_its_own_snapshot() {
        let (cp, log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(req(Lifecycle::Durable, RestartPolicy::Never)).await.unwrap();

        cp.suspend_vm(id).await.unwrap();
        let suspended = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(suspended.state, VmState::Suspended);
        let own = suspended.snapshot.clone().expect("suspend records where it wrote");

        cp.stop_vm(id).await.unwrap();
        // Stopping a durable VM releases the VMM but keeps its snapshot, the
        // same way it keeps its rootfs.
        assert!(log.has("rt.release"));
        assert_eq!(cp.get_vm(id).unwrap().unwrap().snapshot, Some(own));

        cp.start_vm(id).await.unwrap();
        assert!(log.has("rt.create:resume=true"));
        assert_eq!(cp.get_vm(id).unwrap().unwrap().state, VmState::Running);
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
    async fn allocates_and_reports_forward_ports() {
        use iso_common::{PortForward, Protocol};
        let (cp, _log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let req = CreateVm {
            // ssh is just a forward: caller gives vm_port, control plane assigns host_port.
            ingress: vec![PortForward { host_port: 0, vm_port: 22, proto: Protocol::Tcp }],
            ..req(Lifecycle::Ephemeral, RestartPolicy::Never)
        };
        let id = cp.create_vm(req).await.unwrap();
        let rec = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(rec.ingress.len(), 1);
        let f = rec.ingress[0];
        assert_eq!(f.vm_port, 22);
        assert!((20000..20010).contains(&f.host_port), "allocated host port reported");

        // freed on destroy
        cp.destroy_vm(id).await.unwrap();
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

    #[tokio::test]
    async fn add_then_remove_forward_roundtrips() {
        let (cp, _log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(CreateVm::new("base")).await.unwrap();

        // add: a host port is allocated from the configured range and persisted.
        let fwd = cp.add_forward(id, 8080, Protocol::Tcp).await.unwrap();
        assert_eq!(fwd.vm_port, 8080);
        assert!((20000..20010).contains(&fwd.host_port));
        let rec = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(rec.ingress, vec![fwd]);

        // remove: gone from the record.
        cp.remove_forward(id, fwd.host_port, Protocol::Tcp).await.unwrap();
        assert!(cp.get_vm(id).unwrap().unwrap().ingress.is_empty());
    }

    #[tokio::test]
    async fn remove_unknown_forward_errs() {
        let (cp, _log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(CreateVm::new("base")).await.unwrap();
        let err = cp.remove_forward(id, 29999, Protocol::Tcp).await.unwrap_err();
        assert!(matches!(err, Error::UnknownForward { host_port: 29999, .. }));
    }

    #[tokio::test]
    async fn add_forward_on_unknown_vm_errs() {
        let (cp, _log) = build(8, 10.0, false);
        let err = cp
            .add_forward(VmId::from_u128(0xdead_beef), 80, Protocol::Tcp)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::UnknownVm(_)));
    }

    #[tokio::test]
    async fn concurrent_adds_dont_clobber() {
        // Five adds fired concurrently on the same VM. Each is now an atomic
        // `port_forwards` INSERT, so all five rows persist regardless of
        // interleaving — the normalized store, not a lock, is what prevents the
        // lost-update that the old JSON-blob read-modify-write suffered.
        let (cp, _log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(CreateVm::new("base")).await.unwrap();

        let (a, b, c, d, e) = tokio::join!(
            cp.add_forward(id, 81, Protocol::Tcp),
            cp.add_forward(id, 82, Protocol::Tcp),
            cp.add_forward(id, 83, Protocol::Tcp),
            cp.add_forward(id, 84, Protocol::Tcp),
            cp.add_forward(id, 85, Protocol::Tcp),
        );
        for r in [&a, &b, &c, &d, &e] {
            assert!(r.is_ok(), "every concurrent add must succeed");
        }

        let rec = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(rec.ingress.len(), 5, "no forward may be lost to a race");

        let mut vm_ports: Vec<u16> = rec.ingress.iter().map(|f| f.vm_port).collect();
        vm_ports.sort();
        assert_eq!(vm_ports, vec![81, 82, 83, 84, 85]);

        let mut host_ports: Vec<u16> = rec.ingress.iter().map(|f| f.host_port).collect();
        host_ports.sort();
        host_ports.dedup();
        assert_eq!(host_ports.len(), 5, "host ports must be distinct");
    }

    #[tokio::test]
    async fn set_policy_does_not_clobber_concurrent_forward() {
        // The old set_policy clobber: an egress change concurrent with an add.
        // They now touch disjoint state — set_policy UPDATEs only the egress
        // column, add INSERTs a port_forwards row — so both stick no matter how
        // they interleave. (Previously each rewrote the whole row and the last
        // writer reverted the other's field.)
        let (cp, _log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(CreateVm::new("base")).await.unwrap();

        let (fwd, pol) = tokio::join!(
            cp.add_forward(id, 90, Protocol::Tcp),
            cp.set_policy(id, None, None, None, Some(EgressMode::Proxy), None),
        );
        fwd.unwrap();
        pol.unwrap();

        let rec = cp.get_vm(id).unwrap().unwrap();
        assert_eq!(rec.ingress.len(), 1, "the forward must survive the egress change");
        assert_eq!(rec.egress, EgressMode::Proxy);
    }

    #[tokio::test]
    async fn removed_forward_port_is_recycled() {
        // 10 ports in the test range; exhaust them, free one, prove reuse.
        let (cp, _log) = build(8, 10.0, false);
        cp.register_template(&template(true)).unwrap();
        let id = cp.create_vm(CreateVm::new("base")).await.unwrap();

        let mut fwds = Vec::new();
        for _ in 0..10 {
            fwds.push(cp.add_forward(id, 80, Protocol::Tcp).await.unwrap());
        }
        assert!(matches!(
            cp.add_forward(id, 80, Protocol::Tcp).await.unwrap_err(),
            Error::PortsExhausted
        ));

        cp.remove_forward(id, fwds[0].host_port, Protocol::Tcp).await.unwrap();
        // a fresh add now succeeds, reusing the freed port.
        let reused = cp.add_forward(id, 80, Protocol::Tcp).await.unwrap();
        assert_eq!(reused.host_port, fwds[0].host_port);
    }
}
