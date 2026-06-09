//! The [`Manager`]: implements [`iso_common::NetworkManager`] natively over
//! netlink + nftables (no subprocesses). Pure planning lives in [`crate::plan`];
//! execution in [`crate::netlink`] / [`crate::nft`].

use iso_common::{
    Error, HostNetwork, NetworkFixture, NetworkManager, NetworkPolicy, Result, SlotId,
};

use crate::config::Config;
use crate::plan::Plan;
use crate::{fixture, netlink, plan};

/// Manages per-VM network resources on a single host.
#[derive(Clone, Debug)]
pub struct Manager {
    cfg: Config,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Manager {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The slot-derived fixture (pure).
    pub fn fixture(&self, slot: SlotId) -> NetworkFixture {
        fixture::derive(slot, &self.cfg)
    }

    /// Build the declarative plan for `slot`/`policy` (pure; no side effects).
    pub fn plan(&self, slot: SlotId, policy: &NetworkPolicy) -> Result<Plan> {
        Self::validate(policy)?;
        let fx = self.fixture(slot);
        Ok(plan::build(&fx, policy, &self.cfg))
    }

    fn validate(policy: &NetworkPolicy) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for f in &policy.ingress {
            if !seen.insert((f.host_port, f.proto)) {
                return Err(Error::DuplicatePortForward {
                    host_port: f.host_port,
                    proto: f.proto,
                });
            }
        }
        Ok(())
    }

}

/// Run blocking netlink/nft work off the async executor and flatten the join.
async fn spawn_blocking<F>(f: F) -> Result<()>
where
    F: FnOnce() -> Result<()> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Backend(format!("blocking task panicked: {e}")))?
}

impl NetworkManager for Manager {
    /// One-time host setup (forwarding, uplink RPF, services dummy). Idempotent.
    async fn init(&self) -> Result<HostNetwork> {
        let cfg = self.cfg.clone();
        spawn_blocking(move || netlink::host_init(&cfg)).await?;
        Ok(HostNetwork {
            services_addr: self.cfg.services,
            proxy_port: self.cfg.proxy_port,
        })
    }

    async fn apply(&self, slot: SlotId, policy: &NetworkPolicy) -> Result<NetworkFixture> {
        let plan = self.plan(slot, policy)?;
        let fx = plan.fixture.clone();
        let cfg = self.cfg.clone();
        spawn_blocking(move || netlink::converge(&plan, &cfg)).await?;
        Ok(fx)
    }

    async fn teardown(&self, slot: SlotId) -> Result<()> {
        let fx = self.fixture(slot);
        spawn_blocking(move || netlink::destroy(&fx)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iso_common::{EgressMode, PortForward, Protocol};

    fn slot(n: u16) -> SlotId {
        SlotId::new(n).unwrap()
    }

    #[test]
    fn duplicate_forward_is_rejected_at_plan_time() {
        let m = Manager::default();
        let f = PortForward {
            host_port: 8080,
            vm_port: 80,
            proto: Protocol::Tcp,
        };
        let policy = NetworkPolicy {
            egress: EgressMode::Allow,
            ingress: vec![f, f],
        };
        assert!(matches!(
            m.plan(slot(1), &policy),
            Err(Error::DuplicatePortForward { host_port: 8080, .. })
        ));
    }

    #[test]
    fn distinct_forwards_are_accepted() {
        let m = Manager::default();
        let policy = NetworkPolicy {
            egress: EgressMode::Allow,
            ingress: vec![
                PortForward {
                    host_port: 8080,
                    vm_port: 80,
                    proto: Protocol::Tcp,
                },
                PortForward {
                    host_port: 8080,
                    vm_port: 80,
                    proto: Protocol::Udp,
                },
            ],
        };
        assert!(m.plan(slot(1), &policy).is_ok());
    }

    #[test]
    fn plan_carries_slot_derived_fixture() {
        let m = Manager::default();
        let p = m.plan(slot(1), &NetworkPolicy::default()).unwrap();
        assert_eq!(p.fixture.netns, "vm0001");
        assert_eq!(p.host.table, "iso_vm0001");
    }

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    /// The default-route interface (parsed from `/proc/net/route`), so the live
    /// test runs on whatever uplink this host actually has.
    fn default_uplink() -> Option<String> {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in table.lines().skip(1) {
            let mut f = line.split_whitespace();
            let iface = f.next()?;
            let dest = f.next()?;
            if dest == "00000000" {
                return Some(iface.to_string());
            }
        }
        None
    }

    /// Verify table state independently of our implementation, via the `nft`
    /// CLI (test-only; the implementation itself never shells out).
    fn host_table_exists(name: &str) -> bool {
        std::process::Command::new("nft")
            .args(["list", "table", "inet", name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Dump rules via the `nft`/`ip` CLI (test-only). `args` starting with `-n`
    /// run `ip netns exec <ns> nft ...`.
    fn nft_dump(args: &[&str]) -> String {
        let out = if args.first() == Some(&"-n") {
            std::process::Command::new("ip")
                .args(["netns", "exec", args[1]])
                .args(&args[3..])
                .output()
        } else {
            std::process::Command::new("nft").args(args).output()
        }
        .expect("nft/ip dump");
        // include stderr so a failed query is visible in assertion messages.
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// End-to-end against a real kernel. Self-skips unless run as root (so a
    /// plain `cargo test` on a dev box / CI sandbox passes), exercises the full
    /// netlink + nftables + TAP path on a root host.
    #[tokio::test]
    async fn live_apply_then_teardown() {
        if !is_root() {
            eprintln!("skipping live_apply_then_teardown: requires root + netns/nftables");
            return;
        }

        let uplink = default_uplink().expect("a default-route uplink");
        let m = Manager::new(Config {
            uplink,
            ..Config::default()
        });
        m.init().await.expect("host init");

        let s = slot(4242); // -> vm1092 / iso_vm1092
        let policy = NetworkPolicy {
            egress: EgressMode::Allow,
            ingress: vec![PortForward {
                host_port: 18080,
                vm_port: 80,
                proto: Protocol::Tcp,
            }],
        };

        let fx = m.apply(s, &policy).await.expect("apply");
        assert_eq!(fx.netns, "vm1092");
        assert!(
            netns_rs::NetNs::get(&fx.netns).is_ok(),
            "netns should exist"
        );
        assert!(host_table_exists("iso_vm1092"), "host table should exist");

        // host ruleset: masquerade for the unique vp + the inbound DNAT.
        let vp = fx.vp_ip.to_string();
        let host = nft_dump(&["list", "table", "inet", "iso_vm1092"]);
        assert!(host.contains("masquerade"), "host:\n{host}");
        assert!(host.contains("dport 18080"), "host:\n{host}");
        assert!(host.contains(&format!("to {vp}:80")), "host:\n{host}");

        // netns ruleset: SNAT inner -> unique vp, and the inner DNAT.
        let inner = nft_dump(&["-n", "vm1092", "--", "nft", "list", "table", "inet", "iso"]);
        assert!(inner.contains(&format!("snat ip to {vp}")), "netns:\n{inner}");
        assert!(inner.contains("dnat ip to 172.20.0.1"), "netns:\n{inner}");

        // the TAP exists inside the netns.
        assert!(
            std::process::Command::new("ip")
                .args(["-n", "vm1092", "link", "show", "tap1092"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
            "tap1092 should exist in the netns"
        );

        // idempotent re-apply must succeed unchanged.
        m.apply(s, &policy).await.expect("re-apply is idempotent");
        assert!(host_table_exists("iso_vm1092"));

        m.teardown(s).await.expect("teardown");
        assert!(
            netns_rs::NetNs::get(&fx.netns).is_err(),
            "netns should be gone"
        );
        assert!(!host_table_exists("iso_vm1092"), "host table should be gone");

        // idempotent teardown of an absent slot.
        m.teardown(s).await.expect("teardown is idempotent");
    }
}
