//! A host that needs no root, KVM, LVM or netlink: the real admin API router
//! over mock network, storage and runtime managers, with the real guest agent
//! on the far end of a socketpair. The daemon's own tests use it, and with the
//! `testing` feature so can anything that drives hosts, a fleet service say,
//! without a live host.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use iso_common::{
    HostNetwork, InstanceSpec, MacAddr, NetworkFixture, NetworkManager, NetworkPolicy, PoolStats,
    Result as IRes, SlotId, StorageHandle, StorageManager, VmId, VmRuntime, VmStatus, VolumeSpec,
};
use iso_control_plane::{Config, ControlPlane, TemplateDef};
use std::net::Ipv4Addr;

use crate::http::router;

struct MNet;
impl NetworkManager for MNet {
    async fn init(&self) -> IRes<HostNetwork> {
        Ok(HostNetwork { services_addr: Ipv4Addr::new(172, 22, 0, 1), proxy_port: 3128 })
    }
    async fn apply(&self, slot: SlotId, _p: &NetworkPolicy) -> IRes<NetworkFixture> {
        Ok(NetworkFixture {
            slot,
            netns: format!("vm{:04x}", slot.get()),
            tap: "tap0".into(),
            veth_host: format!("vm{:04x}", slot.get()),
            veth_netns: format!("vp{:04x}", slot.get()),
            vh_ip: Ipv4Addr::new(172, 21, 0, 0),
            vp_ip: Ipv4Addr::new(172, 21, 0, 1),
            mac: MacAddr([2, 0, 0, 0, 0, 1]),
        })
    }
    async fn reapply_policy(&self, _slot: SlotId, _p: &NetworkPolicy) -> IRes<()> {
        Ok(())
    }
    async fn teardown(&self, _slot: SlotId) -> IRes<()> {
        Ok(())
    }
    fn address_to_slot(&self, _a: Ipv4Addr) -> Option<SlotId> {
        None
    }
}

struct MStore;
impl StorageManager for MStore {
    async fn init(&self) -> IRes<()> {
        Ok(())
    }
    async fn provision(&self, vm: VmId, _s: &VolumeSpec) -> IRes<StorageHandle> {
        Ok(StorageHandle {
            vm,
            device_path: "/dev/iso/x".into(),
            backing_device: Some("/dev/iso/tpl_x".into()),
        })
    }
    async fn teardown(&self, _vm: VmId) -> IRes<()> {
        Ok(())
    }
    async fn pool_stats(&self) -> IRes<PoolStats> {
        Ok(PoolStats { data_percent: 10.0, metadata_percent: 5.0, ..Default::default() })
    }
}

struct MRun(Mutex<std::collections::HashMap<VmId, VmStatus>>);
impl VmRuntime for MRun {
    async fn create(&self, s: &InstanceSpec) -> IRes<()> {
        self.0.lock().unwrap().insert(s.vm, VmStatus::Created);
        Ok(())
    }
    async fn start(&self, vm: VmId) -> IRes<()> {
        self.0.lock().unwrap().insert(vm, VmStatus::Running);
        Ok(())
    }
    async fn suspend(&self, vm: VmId) -> IRes<iso_common::SnapshotRef> {
        self.0.lock().unwrap().insert(vm, VmStatus::Suspended);
        Ok(iso_common::SnapshotRef {
            mem_file: format!("/state/{vm}/mem").into(),
            vmstate: format!("/state/{vm}/vmstate").into(),
        })
    }
    async fn release(&self, vm: VmId) -> IRes<()> {
        self.0.lock().unwrap().insert(vm, VmStatus::Stopped);
        Ok(())
    }
    async fn stop(&self, vm: VmId) -> IRes<()> {
        self.0.lock().unwrap().insert(vm, VmStatus::Stopped);
        Ok(())
    }
    async fn halt(&self, vm: VmId) -> IRes<()> {
        self.0.lock().unwrap().insert(vm, VmStatus::Stopped);
        Ok(())
    }
    async fn destroy(&self, vm: VmId) -> IRes<()> {
        self.0.lock().unwrap().remove(&vm);
        Ok(())
    }
    async fn status(&self, vm: VmId) -> IRes<VmStatus> {
        Ok(self.0.lock().unwrap().get(&vm).copied().unwrap_or(VmStatus::Absent))
    }
    /// The real guest agent on the far end of a socketpair: the handlers
    /// under test speak to it exactly as they would to a VM.
    async fn guest_channel(&self, _vm: VmId, _port: u32) -> IRes<std::os::fd::OwnedFd> {
        let (host, guest) = std::os::unix::net::UnixStream::pair().map_err(|e| iso_common::Error::Backend(e.to_string()))?;
        guest.set_nonblocking(true).unwrap();
        let guest = tokio::net::UnixStream::from_std(guest).unwrap();
        tokio::spawn(iso_guest_agent::serve_connection(guest));
        Ok(std::os::fd::OwnedFd::from(host))
    }
}

pub fn app() -> Router {
    app_with_templates(&["base"])
}

/// The daemon's router over the mock managers, with `templates` registered.
pub fn app_with_templates(templates: &[&str]) -> Router {
    let cfg = Config {
        db_path: ":memory:".into(),
        default_vcpus: 1,
        default_mem_mib: 512,
        pool_watermark_percent: 90.0,
        graceful_stop: Duration::from_secs(1),
        slot_capacity: 8,
        forward_ports: (20000, 30000),
        vsock_cid: Some(3),
        guest_agent_port: 5000,
    };
    let cp = Arc::new(
        ControlPlane::new(cfg, MNet, MStore, MRun(Mutex::new(Default::default()))).unwrap(),
    );
    for name in templates {
        cp.register_template(&TemplateDef {
            name: (*name).into(),
            rootfs_template: (*name).into(),
            snapshot: None,
            vcpus: 1,
            mem_mib: 512,
            kernel: "/k".into(),
            boot_args: String::new(),
        })
        .unwrap();
    }
    router(cp, crate::build::Builds::new(None))
}

