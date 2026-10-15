//! Who may have what resolved upstream: the [`iso_dns_server::Gate`] the
//! daemon hands its DNS server. A forwarded query is data leaving the host
//! (the name is the payload), so a VM has resolved exactly the names its
//! egress could reach:
//!
//! - `deny`: none.
//! - `proxy`: the names some `allow` or `tunnel` rule's host matches, as the
//!   proxy matches an SNI or a resolved name against them (`*.x` is any name
//!   under `x`, `*` any name at all: `allow https://*/**` is the open policy).
//!   A `deny` rule takes no name away: it refuses requests or ports on a
//!   host the proxy still talks to.
//! - No VM on the address's slot: none, unless the slot is where template
//!   bakes run their builder. A builder is host tooling with no VM record and
//!   no policy; it egresses directly, and `--provision` needs names.
//!
//! A slot's answer is kept for [`TTL`] (a guest asks A and AAAA, often for
//! several names, per connection), and dropped as soon as the control plane
//! releases the slot: the next VM placed there has the same address, and
//! must not be judged by its predecessor's policy.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iso_common::{EgressMode, NetworkManager, SlotId, StorageManager, VmRuntime};
use iso_control_plane::{ControlPlane, VmRecord};
use iso_policy::{Action, HostPattern, RuleSet};

/// How long a slot's answer is kept. As long as `iso-proxyd` keeps an
/// `identify` answer by default, so a policy change reaches DNS no later
/// than it reaches the proxy.
const TTL: Duration = Duration::from_secs(1);

/// The names a slot may have resolved upstream.
#[derive(Debug)]
enum Reach {
    /// None: a `deny` VM, or a slot no VM and no builder holds.
    Nothing,
    /// Those these hosts match: a `proxy` VM's allow and tunnel rules.
    Hosts(Vec<HostPattern>),
    /// Any: a bake's builder.
    Anything,
}

impl Reach {
    fn of(vm: &VmRecord) -> Self {
        match vm.egress {
            EgressMode::Deny => Reach::Nothing,
            EgressMode::Proxy => match RuleSet::from_record(&vm.allow, &vm.rules) {
                Ok(rules) => Reach::Hosts(
                    rules
                        .rules()
                        .iter()
                        .filter(|r| r.action != Action::Deny)
                        .map(|r| r.host.clone())
                        .collect(),
                ),
                // `identify` serves such a record as no rules, which the
                // proxy denies everything under.
                Err(e) => {
                    eprintln!("iso-controld: dns: vm {} has an invalid policy: {e}", vm.id);
                    Reach::Nothing
                }
            },
        }
    }

    fn allows(&self, name: &str) -> bool {
        match self {
            Reach::Nothing => false,
            Reach::Hosts(hosts) => hosts.iter().any(|h| h.matches(name)),
            Reach::Anything => true,
        }
    }
}

#[derive(Default)]
struct Cache {
    /// Each slot's reach, and when it was looked up.
    slots: HashMap<SlotId, (Instant, Reach)>,
    /// Bumped by every release, so that a lookup a release overtook is not
    /// kept: it may have found the VM that just left.
    releases: u64,
}

pub struct DnsGate<N, S, R> {
    cp: Arc<ControlPlane<N, S, R>>,
    /// The network manager's address -> slot arithmetic.
    slot_of: Box<dyn Fn(Ipv4Addr) -> Option<SlotId> + Send + Sync>,
    /// The slots template bakes run their builder on, which no VM is placed on.
    builders: Vec<SlotId>,
    cache: Arc<Mutex<Cache>>,
}

impl<N, S, R> DnsGate<N, S, R>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    /// The gate over `cp`'s VMs. `slot_of` maps a query's source (a VM's
    /// `vp`, after the in-netns SNAT) to its slot, as the network manager
    /// does; `builders` are the slots bakes use.
    pub fn new(
        cp: Arc<ControlPlane<N, S, R>>,
        slot_of: impl Fn(Ipv4Addr) -> Option<SlotId> + Send + Sync + 'static,
        builders: Vec<SlotId>,
    ) -> Self {
        let cache = Arc::new(Mutex::new(Cache::default()));
        let released = cache.clone();
        cp.on_slot_released(move |slot| {
            let mut c = released.lock().unwrap();
            c.slots.remove(&slot);
            c.releases += 1;
        });
        Self {
            cp,
            slot_of: Box::new(slot_of),
            builders,
            cache,
        }
    }

    /// May the VM (or builder) on `slot` have `name` resolved upstream?
    fn slot_may_resolve(&self, slot: SlotId, name: &str) -> bool {
        let releases = {
            let c = self.cache.lock().unwrap();
            if let Some((at, reach)) = c.slots.get(&slot)
                && at.elapsed() < TTL
            {
                return reach.allows(name);
            }
            c.releases
        };
        // The VM on the slot, found as `ControlPlane::identify` finds it.
        let reach = match self.cp.list_vms() {
            Ok(vms) => match vms.iter().find(|v| v.slot == Some(slot)) {
                Some(vm) => Reach::of(vm),
                None if self.builders.contains(&slot) => Reach::Anything,
                None => Reach::Nothing,
            },
            // Refused, and not kept: the store may answer the next query.
            Err(e) => {
                eprintln!("iso-controld: dns: no VM record for slot {slot}: {e}");
                return false;
            }
        };
        let allowed = reach.allows(name);
        let mut c = self.cache.lock().unwrap();
        if c.releases == releases {
            c.slots.insert(slot, (Instant::now(), reach));
        }
        allowed
    }
}

impl<N, S, R> iso_dns_server::Gate for DnsGate<N, S, R>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    fn may_resolve(&self, src: IpAddr, name: &str) -> bool {
        let IpAddr::V4(ip) = src else { return false };
        match (self.slot_of)(ip) {
            Some(slot) => self.slot_may_resolve(slot, name),
            // Not a slot's address, so not a VM's.
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use iso_control_plane::CreateVm;
    use iso_dns_server::Gate;

    use crate::testing::{MNet, MRun, MStore};

    /// The daemon's own slot <-> address arithmetic.
    fn net() -> iso_network_manager::Manager {
        iso_network_manager::Manager::default()
    }

    /// The address a VM's queries come from.
    fn vp(slot: SlotId) -> IpAddr {
        net().fixture(slot).vp_ip.into()
    }

    const BUILDER: u16 = 32766;

    type Cp = Arc<ControlPlane<MNet, MStore, MRun>>;

    fn gate(cp: &Cp) -> DnsGate<MNet, MStore, MRun> {
        DnsGate::new(
            cp.clone(),
            |ip| net().address_to_slot(ip),
            vec![SlotId::new(BUILDER).unwrap()],
        )
    }

    /// A running VM's address, under `egress` with `allow` and `rules`.
    async fn vm(
        cp: &Cp,
        egress: EgressMode,
        allow: &[&str],
        rules: &[&str],
    ) -> (iso_common::VmId, IpAddr) {
        let id = cp
            .create_vm(CreateVm {
                egress,
                allow: allow.iter().map(|s| s.to_string()).collect(),
                rules: rules.iter().map(|s| s.to_string()).collect(),
                ..CreateVm::new("base")
            })
            .await
            .unwrap();
        (id, vp(cp.get_vm(id).unwrap().unwrap().slot.unwrap()))
    }

    #[tokio::test]
    async fn a_deny_vm_resolves_nothing() {
        let cp = crate::testing::control_plane(&["base"]);
        let g = gate(&cp);
        // Rules a deny VM keeps for later do not reach anything now.
        let (_, ip) = vm(
            &cp,
            EgressMode::Deny,
            &["api.allowed.test"],
            &["allow https://*/**"],
        )
        .await;
        for name in [
            "api.allowed.test",
            "anything.example",
            "c2VjcmV0.exfil.example",
        ] {
            assert!(!g.may_resolve(ip, name), "{name}");
        }
    }

    #[tokio::test]
    async fn a_proxy_vm_resolves_what_its_rules_name_and_nothing_else() {
        let cp = crate::testing::control_plane(&["base"]);
        let g = gate(&cp);
        let (_, ip) = vm(
            &cp,
            EgressMode::Proxy,
            &["api.allowed.test"],
            &[
                "allow https://*.cdn.allowed.test/**",
                "tunnel tcp://db.allowed.test:5432",
                "deny https://api.allowed.test/admin/**",
                "deny tcp://smtp.denied.test:25",
            ],
        )
        .await;
        for name in [
            "api.allowed.test",
            "img.cdn.allowed.test",
            "a.b.cdn.allowed.test",
            "db.allowed.test",
        ] {
            assert!(g.may_resolve(ip, name), "{name}");
        }
        for name in [
            "allowed.test",
            "cdn.allowed.test", // `*.` is never the apex
            "c2VjcmV0.api.allowed.test",
            "smtp.denied.test",
            "c2VjcmV0.exfil.example",
            "",
        ] {
            assert!(!g.may_resolve(ip, name), "{name}");
        }
        // Another VM is judged by its own policy.
        let (_, other) = vm(&cp, EgressMode::Deny, &[], &[]).await;
        assert!(!g.may_resolve(other, "api.allowed.test"));
    }

    #[tokio::test]
    async fn the_open_policy_resolves_any_name() {
        let cp = crate::testing::control_plane(&["base"]);
        let g = gate(&cp);
        let (_, ip) = vm(&cp, EgressMode::Proxy, &[], &["allow https://*/**"]).await;
        assert!(g.may_resolve(ip, "anything.example"));
        assert!(g.may_resolve(ip, "c2VjcmV0.exfil.example"));
    }

    #[tokio::test]
    async fn an_address_no_vm_holds_resolves_nothing_but_the_builders() {
        let cp = crate::testing::control_plane(&["base"]);
        let g = gate(&cp);
        let empty = vp(SlotId::new(5).unwrap());
        assert!(
            !g.may_resolve(empty, "anything.example"),
            "a slot no VM holds"
        );
        for stranger in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            "::1".parse().unwrap(),
        ] {
            assert!(!g.may_resolve(stranger, "anything.example"), "{stranger}");
        }
        let builder = vp(SlotId::new(BUILDER).unwrap());
        assert!(g.may_resolve(builder, "deb.debian.org"));
        assert!(g.may_resolve(builder, "anything.example"));
    }

    /// The answer for a slot was kept for its TTL whoever came next, so a VM
    /// placed on a slot an open VM just left resolved anything for a while.
    #[tokio::test]
    async fn a_released_slot_forgets_its_vm_at_once() {
        let cp = crate::testing::control_plane(&["base"]);
        let g = gate(&cp);
        let (id, ip) = vm(&cp, EgressMode::Proxy, &[], &["allow https://*/**"]).await;
        assert!(g.may_resolve(ip, "anything.example"));
        cp.destroy_vm(id).await.unwrap();
        assert!(
            !g.may_resolve(ip, "anything.example"),
            "the slot is empty now"
        );
    }
}
