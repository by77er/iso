//! What each VM resolved, recently: `(vm address, answered address)` to the
//! name asked for. A guest that dials an address on a port with no SNI can
//! only have got that address from here (the host's DNS is the only
//! resolver it can reach), so the name it resolved is the name a
//! `tunnel tcp://name:port` rule is matched against. An address a VM never
//! resolved has no name and is refused.
//!
//! Entries live for the answer's TTL, floored generously: a connection pool
//! dials long after the lookup.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Below this, an answer's TTL is not trusted to bound when the guest dials.
const MIN_LIFE: Duration = Duration::from_secs(600);
/// Entries per VM, so a guest resolving forever cannot grow this without bound.
const PER_VM: usize = 4096;

#[derive(Default)]
pub struct DnsMemory {
    inner: Mutex<HashMap<Ipv4Addr, HashMap<Ipv4Addr, (String, Instant)>>>,
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
}
