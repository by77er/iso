//! What each VM resolved, recently: `(vm address, answered address)` to the
//! name asked for. A guest that dials an address on a port with no SNI can
//! only have got that address from here (the host's DNS is the only
//! resolver it can reach), so the name it resolved is the name a
//! `tunnel tcp://name:port` rule is matched against. An address a VM never
//! resolved has no name and is refused.
//!
//! Entries live for the answer's TTL, floored generously: a connection pool
//! dials long after the lookup. They go sooner if the VM leaves its slot: the
//! next VM placed there has the same address, and must not be credited with
//! names it never looked up.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iso_common::{NetworkManager, SlotId, StorageManager, VmRuntime};
use iso_control_plane::ControlPlane;

/// Below this, an answer's TTL is not trusted to bound when the guest dials.
const MIN_LIFE: Duration = Duration::from_secs(600);
/// Entries per VM, so a guest resolving forever cannot grow this without bound.
const PER_VM: usize = 4096;

/// One VM's answers: address to the name it came from, and until when.
type Answers = HashMap<Ipv4Addr, (String, Instant)>;

#[derive(Default)]
pub struct DnsMemory {
    inner: Mutex<HashMap<Ipv4Addr, Answers>>,
}

impl DnsMemory {
    pub fn record(&self, src: IpAddr, name: &str, addrs: &[Ipv4Addr], ttl_secs: u32) {
        let IpAddr::V4(src) = src else { return };
        let until = Instant::now() + MIN_LIFE.max(Duration::from_secs(ttl_secs as u64));
        let mut all = self.inner.lock().unwrap();
        let mine = all.entry(src).or_default();
        if mine.len() >= PER_VM {
            let now = Instant::now();
            mine.retain(|_, (_, exp)| *exp > now);
            if mine.len() >= PER_VM {
                return;
            }
        }
        for a in addrs {
            mine.insert(*a, (name.to_string(), until));
        }
    }

    /// The name `src` resolved `dst` from, if it did and the entry lives.
    pub fn name_for(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Option<String> {
        let all = self.inner.lock().unwrap();
        let (name, until) = all.get(&src)?.get(&dst)?;
        (*until > Instant::now()).then(|| name.clone())
    }

    /// Everything a VM resolved, when the VM is gone.
    pub fn forget(&self, src: Ipv4Addr) {
        self.inner.lock().unwrap().remove(&src);
    }

    /// Forget what a VM resolved whenever `cp` releases its slot. `addr` is a
    /// slot's VM-side (`vp`) address, the source the DNS server sees.
    pub fn forget_released<N, S, R>(
        self: &Arc<Self>,
        cp: &ControlPlane<N, S, R>,
        addr: impl Fn(SlotId) -> Ipv4Addr + Send + Sync + 'static,
    ) where
        N: NetworkManager,
        S: StorageManager,
        R: VmRuntime,
    {
        let memory = self.clone();
        cp.on_slot_released(move |slot| memory.forget(addr(slot)));
    }
}

impl iso_dns_server::Observer for DnsMemory {
    fn answered(&self, src: IpAddr, name: &str, addrs: &[Ipv4Addr], ttl_secs: u32) {
        self.record(src, name, addrs, ttl_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_per_vm_and_only_what_was_resolved() {
        let m = DnsMemory::default();
        let vm = Ipv4Addr::new(172, 21, 0, 1);
        let other = Ipv4Addr::new(172, 21, 0, 3);
        let a = Ipv4Addr::new(93, 184, 216, 34);
        m.record(vm.into(), "example.test", &[a], 5);
        assert_eq!(m.name_for(vm, a).as_deref(), Some("example.test"));
        assert_eq!(m.name_for(other, a), None, "another VM never resolved it");
        assert_eq!(m.name_for(vm, Ipv4Addr::new(1, 1, 1, 1)), None, "never resolved");
        m.record(vm.into(), "other.test", &[a], 5);
        assert_eq!(m.name_for(vm, a).as_deref(), Some("other.test"), "the latest answer wins");
        m.forget(vm);
        assert_eq!(m.name_for(vm, a), None);
    }

    /// Nothing called `forget`, so a VM placed on a freed slot inherited what
    /// the slot's last VM resolved, for at least `MIN_LIFE`.
    #[tokio::test]
    async fn a_vm_leaving_its_slot_takes_what_it_resolved_with_it() {
        use iso_control_plane::CreateVm;
        let cp = crate::testing::control_plane(&["base"]);
        let m = Arc::new(DnsMemory::default());
        let addr = |slot: SlotId| Ipv4Addr::new(172, 21, 0, slot.get() as u8 * 2 + 1);
        m.forget_released(&cp, addr);
        let a = cp.create_vm(CreateVm::new("base")).await.unwrap();
        let b = cp.create_vm(CreateVm::new("base")).await.unwrap();
        let at = |id| addr(cp.get_vm(id).unwrap().unwrap().slot.unwrap());
        let (va, vb) = (at(a), at(b));
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        m.record(va.into(), "a.test", &[dst], 5);
        m.record(vb.into(), "b.test", &[dst], 5);

        cp.destroy_vm(a).await.unwrap();
        assert_eq!(m.name_for(va, dst), None, "gone with its VM");
        assert_eq!(m.name_for(vb, dst).as_deref(), Some("b.test"));
    }
}
