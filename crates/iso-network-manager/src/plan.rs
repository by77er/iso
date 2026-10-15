//! Pure, declarative description of what a slot's network should look like.
//!
//! `build` turns `(fixture, policy, config)` into an abstract [`Plan`] — links,
//! addresses, routes, sysctls and nftables rulesets — with **no side effects**.
//! The executors (`netlink`, `nft`) render this plan against the kernel. Keeping
//! the decision logic here makes it fully unit-testable without root.

use std::net::Ipv4Addr;

use iso_common::{EgressMode, NetworkFixture, NetworkPolicy, Protocol};

use crate::config::Config;

/// Which netfilter chain a rule belongs to. Maps to (type, hook, priority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainKind {
    Prerouting,
    Forward,
    Input,
    Output,
    Postrouting,
}

/// An abstract nftables rule. Rendered to `rustables` expressions in `nft.rs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NftRule {
    /// `ct state established,related accept`
    AcceptEstablished,
    /// `ct state new iifname <iif> oifname <oif> accept` (inbound port-forwards)
    AcceptInbound { iif: String, oif: String },
    /// `iifname <iif> oifname <oif> accept` (direct egress, the bake's builder only)
    AcceptEgress { iif: String, oif: String },
    /// `iifname <iif> ip daddr <daddr> <proto> dport <dport> accept` (services baseline, input)
    AcceptService {
        iif: String,
        daddr: Ipv4Addr,
        proto: Protocol,
        dport: u16,
    },
    /// `iifname <iif> ip daddr <net>/<prefix> drop` (lateral movement)
    DropToNet {
        iif: String,
        net: Ipv4Addr,
        prefix: u8,
    },
    /// `iifname <iif> drop` (per-VM default deny, forward and input)
    DropFrom { iif: String },
    /// `ip saddr <saddr> oifname <oif> masquerade`
    Masquerade { saddr: Ipv4Addr, oif: String },
    /// `oifname <oif> snat to <to>` (in-netns: inner -> unique vp)
    Snat { oif: String, to: Ipv4Addr },
    /// `iifname <iif> <proto> dport <dport> dnat to <to>:<to_port>` (host inbound)
    Dnat {
        iif: String,
        proto: Protocol,
        dport: u16,
        to: Ipv4Addr,
        to_port: u16,
    },
    /// `iifname <iif> ip daddr <daddr> <proto> dport <dport> dnat to <to>` (in-netns inbound)
    DnatInner {
        iif: String,
        daddr: Ipv4Addr,
        proto: Protocol,
        dport: u16,
        to: Ipv4Addr,
    },
    /// `ip daddr <host_addr> <proto> dport <host_port> dnat to <to>:<to_port>`
    /// (host-local hairpin for an ingress forward, in OUTPUT).
    DnatHairpin {
        host_addr: Ipv4Addr,
        proto: Protocol,
        host_port: u16,
        to: Ipv4Addr,
        to_port: u16,
    },
    /// `iifname <iif> ip daddr != <except> <proto> ... dnat to <to>:<to_port>` (Proxy intercept)
    RedirectProxy {
        iif: String,
        except: Ipv4Addr,
        proto: Protocol,
        to: Ipv4Addr,
        to_port: u16,
    },
}

/// A chain and its ordered rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSpec {
    pub kind: ChainKind,
    pub rules: Vec<NftRule>,
}

/// A complete nftables table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ruleset {
    pub table: String,
    pub chains: Vec<ChainSpec>,
}

/// An in-netns route. `dest == None` is the default route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub dest: Option<(Ipv4Addr, u8)>,
    pub gateway: Ipv4Addr,
}

/// The full converged state for a slot (pure data).
#[derive(Clone, Debug)]
pub struct Plan {
    pub fixture: NetworkFixture,
    pub host: Ruleset,
    pub netns: Ruleset,
    /// Routes installed inside the netns.
    pub routes: Vec<Route>,
    /// sysctls set inside the netns (`key`, `value`).
    pub sysctls: Vec<(String, String)>,
    pub inner_tap: Ipv4Addr,
}

/// Build the full plan for `policy` on `slot`'s `fixture`.
pub fn build(fx: &NetworkFixture, policy: &NetworkPolicy, cfg: &Config) -> Plan {
    Plan {
        fixture: fx.clone(),
        host: host_ruleset(fx, policy, cfg),
        netns: netns_ruleset(fx, policy, cfg),
        routes: routes(fx, policy, cfg),
        sysctls: sysctls(),
        inner_tap: cfg.inner_tap,
    }
}

/// The slot's host-side table name.
pub fn table_name(slot: iso_common::SlotId) -> String {
    format!("iso_vm{:04x}", slot.get())
}

fn host_ruleset(fx: &NetworkFixture, policy: &NetworkPolicy, cfg: &Config) -> Ruleset {
    let vh = &fx.veth_host;
    let up = &cfg.uplink;

    let mut prerouting = Vec::new();
    for f in &policy.ingress {
        prerouting.push(NftRule::Dnat {
            iif: up.clone(),
            proto: f.proto,
            dport: f.host_port,
            to: fx.vp_ip,
            to_port: f.vm_port,
        });
    }
    if policy.egress == EgressMode::Proxy && !policy.direct {
        // intercept after the in-netns SNAT (source is vp_ip). tcp+udp.
        for proto in [Protocol::Tcp, Protocol::Udp] {
            prerouting.push(NftRule::RedirectProxy {
                iif: vh.clone(),
                except: cfg.services,
                proto,
                to: cfg.services,
                to_port: cfg.proxy_port,
            });
        }
    }

    let mut forward = vec![
        NftRule::AcceptEstablished,
        NftRule::AcceptInbound {
            iif: up.clone(),
            oif: vh.clone(),
        },
        NftRule::DropToNet {
            iif: vh.clone(),
            net: cfg.veth_net,
            prefix: 16,
        },
    ];
    if policy.direct && policy.egress != EgressMode::Deny {
        forward.push(NftRule::AcceptEgress {
            iif: vh.clone(),
            oif: up.clone(),
        });
    }
    forward.push(NftRule::DropFrom { iif: vh.clone() });

    // What this VM may open to the host itself: the ports iso serves on the
    // services address, in every level. Replies to flows the host started
    // (an inbound forward's hairpin, an operator dialling the VM) ride
    // `established`. Anything else ends here, so a host listener on all
    // interfaces (sshd, a database) is not the VM's to reach, on the
    // services address or the veth's own; the chain's `accept` policy is
    // left to the host's own traffic.
    let mut input = vec![NftRule::AcceptEstablished];
    let proxy = (Protocol::Tcp, cfg.proxy_port);
    for (proto, dport) in cfg.service_ports.iter().copied().chain([proxy]) {
        input.push(NftRule::AcceptService {
            iif: vh.clone(),
            daddr: cfg.services,
            proto,
            dport,
        });
    }
    input.push(NftRule::DropFrom { iif: vh.clone() });
    let postrouting = vec![NftRule::Masquerade {
        saddr: fx.vp_ip,
        oif: up.clone(),
    }];

    // Host-local hairpin: let processes on the host (e.g. an orchestrator) reach a VM's
    // forwarded ports via the host's own primary IP (locally-originated traffic
    // skips the uplink prerouting hook, so DNAT in OUTPUT).
    let mut chains = vec![
        ChainSpec {
            kind: ChainKind::Prerouting,
            rules: prerouting,
        },
        ChainSpec {
            kind: ChainKind::Forward,
            rules: forward,
        },
        ChainSpec {
            kind: ChainKind::Input,
            rules: input,
        },
        ChainSpec {
            kind: ChainKind::Postrouting,
            rules: postrouting,
        },
    ];
    if let Some(host_addr) = cfg.host_addr {
        let output: Vec<NftRule> = policy
            .ingress
            .iter()
            .map(|f| NftRule::DnatHairpin {
                host_addr,
                proto: f.proto,
                host_port: f.host_port,
                to: fx.vp_ip,
                to_port: f.vm_port,
            })
            .collect();
        if !output.is_empty() {
            chains.push(ChainSpec {
                kind: ChainKind::Output,
                rules: output,
            });
        }
    }

    Ruleset {
        table: table_name(fx.slot),
        chains,
    }
}

fn netns_ruleset(fx: &NetworkFixture, policy: &NetworkPolicy, cfg: &Config) -> Ruleset {
    let vp = &fx.veth_netns;
    let postrouting = vec![NftRule::Snat {
        oif: vp.clone(),
        to: fx.vp_ip,
    }];
    let prerouting = policy
        .ingress
        .iter()
        .map(|f| NftRule::DnatInner {
            iif: vp.clone(),
            daddr: fx.vp_ip,
            proto: f.proto,
            dport: f.vm_port,
            to: cfg.inner_vm,
        })
        .collect();

    Ruleset {
        table: "iso".to_string(),
        chains: vec![
            ChainSpec {
                kind: ChainKind::Postrouting,
                rules: postrouting,
            },
            ChainSpec {
                kind: ChainKind::Prerouting,
                rules: prerouting,
            },
        ],
    }
}

fn routes(fx: &NetworkFixture, policy: &NetworkPolicy, cfg: &Config) -> Vec<Route> {
    // services (DNS) reachable in every level; default route only when not Deny
    // (fail-closed backstop).
    let mut routes = vec![Route {
        dest: Some((cfg.services, 32)),
        gateway: fx.vh_ip,
    }];
    if policy.egress != EgressMode::Deny {
        routes.push(Route {
            dest: None,
            gateway: fx.vh_ip,
        });
    }
    routes
}

fn sysctls() -> Vec<(String, String)> {
    vec![
        ("net.ipv4.ip_forward".to_string(), "1".to_string()),
        ("net.ipv4.conf.all.rp_filter".to_string(), "2".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use iso_common::{PortForward, SlotId};

    fn ctx() -> Config {
        Config::default()
    }
    fn fx(slot: u16) -> NetworkFixture {
        fixture::derive(SlotId::new(slot).unwrap(), &ctx())
    }
    fn policy(egress: EgressMode, ingress: Vec<PortForward>) -> NetworkPolicy {
        NetworkPolicy {
            egress,
            ingress,
            direct: false,
        }
    }
    fn forward_chain(rs: &Ruleset) -> &Vec<NftRule> {
        &rs.chains
            .iter()
            .find(|c| c.kind == ChainKind::Forward)
            .unwrap()
            .rules
    }
    fn prerouting(rs: &Ruleset) -> &Vec<NftRule> {
        &rs.chains
            .iter()
            .find(|c| c.kind == ChainKind::Prerouting)
            .unwrap()
            .rules
    }
    fn input_chain(rs: &Ruleset) -> &Vec<NftRule> {
        &rs.chains
            .iter()
            .find(|c| c.kind == ChainKind::Input)
            .unwrap()
            .rules
    }

    /// A packet as the host's `input` hook sees it, after prerouting's NAT.
    #[derive(Clone, Copy, Debug)]
    struct Pkt {
        iif: &'static str,
        daddr: Ipv4Addr,
        /// Protocol and destination port; `None` for one without ports (ICMP).
        l4: Option<(Protocol, u16)>,
        /// `ct state established,related`: part of a flow the host started.
        reply: bool,
    }

    /// The verdict `rules` give `p`, walked as the kernel walks a chain: the
    /// first rule that matches decides, and none matching leaves it to the
    /// chain's policy, `accept`.
    fn input_verdict(rules: &[NftRule], p: Pkt) -> &'static str {
        for r in rules {
            let hit = match r {
                NftRule::AcceptEstablished => p.reply,
                NftRule::AcceptService {
                    iif,
                    daddr,
                    proto,
                    dport,
                } => *iif == p.iif && *daddr == p.daddr && p.l4 == Some((*proto, *dport)),
                NftRule::DropFrom { iif } => *iif == p.iif,
                other => panic!("unexpected rule in input: {other:?}"),
            };
            if hit {
                return match r {
                    NftRule::DropFrom { .. } => "drop",
                    _ => "accept",
                };
            }
        }
        "accept"
    }

    #[test]
    fn deny_has_no_egress_accept_no_default_route_no_redirect() {
        let f = fx(1);
        let cfg = ctx();
        let p = policy(EgressMode::Deny, vec![]);
        let host = host_ruleset(&f, &p, &cfg);

        // forward: established, inbound, lateral-drop, drop — but NO egress accept.
        let fwd = forward_chain(&host);
        assert!(
            !fwd.iter()
                .any(|r| matches!(r, NftRule::AcceptEgress { .. }))
        );
        assert!(matches!(fwd.last(), Some(NftRule::DropFrom { .. })));

        // no redirect in prerouting
        assert!(prerouting(&host).is_empty());

        // routes: services only, no default
        let routes = routes(&f, &p, &cfg);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].dest, Some((cfg.services, 32)));
    }

    #[test]
    fn direct_permits_egress_and_routes_default_without_intercept() {
        let f = fx(1);
        let cfg = ctx();
        let p = NetworkPolicy {
            direct: true,
            ..policy(EgressMode::Proxy, vec![])
        };
        let host = host_ruleset(&f, &p, &cfg);
        assert!(prerouting(&host).is_empty(), "nothing intercepted");

        assert!(forward_chain(&host).iter().any(|r| matches!(
            r,
            NftRule::AcceptEgress { iif, oif } if iif == "vm0001" && oif == "eth0"
        )));
        // masquerade present in postrouting with the unique vp source.
        let post = &host
            .chains
            .iter()
            .find(|c| c.kind == ChainKind::Postrouting)
            .unwrap()
            .rules;
        assert!(post.iter().any(|r| matches!(
            r,
            NftRule::Masquerade { saddr, .. } if *saddr == f.vp_ip
        )));

        let routes = routes(&f, &p, &cfg);
        assert!(routes.iter().any(|r| r.dest.is_none()), "default route");
    }

    #[test]
    fn proxy_intercepts_tcp_and_udp_but_no_egress_accept() {
        let f = fx(1);
        let cfg = ctx();
        let p = policy(EgressMode::Proxy, vec![]);
        let host = host_ruleset(&f, &p, &cfg);

        let redirects: Vec<_> = prerouting(&host)
            .iter()
            .filter(|r| matches!(r, NftRule::RedirectProxy { .. }))
            .collect();
        assert_eq!(redirects.len(), 2, "tcp + udp intercept");
        assert!(matches!(
            redirects[0],
            NftRule::RedirectProxy { to, to_port, except, .. }
                if *to == cfg.services && *to_port == cfg.proxy_port && *except == cfg.services
        ));
        // proxy still needs a default route to reach the host, but no egress accept.
        assert!(routes(&f, &p, &cfg).iter().any(|r| r.dest.is_none()));
        assert!(
            !forward_chain(&host)
                .iter()
                .any(|r| matches!(r, NftRule::AcceptEgress { .. }))
        );
    }

    #[test]
    fn ingress_generates_two_layer_dnat() {
        let f = fx(1); // vp_ip = 172.21.0.3
        let cfg = ctx();
        let pf = PortForward {
            host_port: 8080,
            vm_port: 80,
            proto: Protocol::Tcp,
        };
        let p = policy(EgressMode::Deny, vec![pf]);

        // host: uplink dport 8080 -> vp:80
        assert!(
            prerouting(&host_ruleset(&f, &p, &cfg))
                .iter()
                .any(|r| matches!(
                    r,
                    NftRule::Dnat { iif, dport, to, to_port, .. }
                        if iif == "eth0" && *dport == 8080 && *to == f.vp_ip && *to_port == 80
                ))
        );
        // netns: vp:80 -> inner
        assert!(prerouting(&netns_ruleset(&f, &p, &cfg)).iter().any(|r| matches!(
            r,
            NftRule::DnatInner { iif, daddr, dport, to, .. }
                if iif == "vp0001" && *daddr == f.vp_ip && *dport == 80 && *to == cfg.inner_vm
        )));
    }

    #[test]
    fn netns_always_snats_to_unique_vp() {
        let f = fx(5);
        let cfg = ctx();
        for mode in [EgressMode::Proxy, EgressMode::Deny] {
            let rs = netns_ruleset(&f, &policy(mode, vec![]), &cfg);
            let post = &rs
                .chains
                .iter()
                .find(|c| c.kind == ChainKind::Postrouting)
                .unwrap()
                .rules;
            assert_eq!(
                post,
                &vec![NftRule::Snat {
                    oif: "vp0005".to_string(),
                    to: f.vp_ip
                }]
            );
        }
    }

    #[test]
    fn services_baseline_is_always_present() {
        let f = fx(1);
        let cfg = ctx();
        for mode in [EgressMode::Proxy, EgressMode::Deny] {
            let host = host_ruleset(&f, &policy(mode, vec![]), &cfg);
            let input = input_chain(&host);
            for (proto, port) in [
                (Protocol::Udp, 53),
                (Protocol::Tcp, 53),
                (Protocol::Tcp, 80),
                (Protocol::Tcp, cfg.proxy_port),
            ] {
                assert!(input.iter().any(|r| matches!(
                    r,
                    NftRule::AcceptService { iif, daddr, proto: p, dport }
                        if iif == "vm0001" && *daddr == cfg.services && *p == proto && *dport == port
                )), "{mode:?}: {proto} {port}");
            }
            // ...and the VM's own default deny ends the chain.
            assert_eq!(
                input.last(),
                Some(&NftRule::DropFrom {
                    iif: "vm0001".to_string()
                })
            );
            // and the services route exists in every mode.
            assert!(
                routes(&f, &policy(mode, vec![]), &cfg)
                    .iter()
                    .any(|r| r.dest == Some((cfg.services, 32)))
            );
        }
    }

    #[test]
    fn vm_reaches_only_the_ports_iso_serves_on_the_host() {
        let f = fx(1);
        let cfg = ctx();
        let svc = cfg.services;
        let new = |daddr, l4| Pkt {
            iif: "vm0001",
            daddr,
            l4,
            reply: false,
        };
        let builder = NetworkPolicy {
            direct: true,
            ..policy(EgressMode::Proxy, vec![])
        };
        for p in [
            policy(EgressMode::Proxy, vec![]),
            policy(EgressMode::Deny, vec![]),
            builder,
        ] {
            let host = host_ruleset(&f, &p, &cfg);
            let v = |pkt| input_verdict(input_chain(&host), pkt);

            // What iso serves on the services address (in Proxy, every
            // intercepted TCP flow arrives here as the proxy port).
            assert_eq!(
                v(new(svc, Some((Protocol::Udp, 53)))),
                "accept",
                "{p:?}: dns"
            );
            assert_eq!(
                v(new(svc, Some((Protocol::Tcp, 53)))),
                "accept",
                "{p:?}: dns/tcp"
            );
            assert_eq!(
                v(new(svc, Some((Protocol::Tcp, 80)))),
                "accept",
                "{p:?}: metadata"
            );
            let proxy = Some((Protocol::Tcp, cfg.proxy_port));
            assert_eq!(v(new(svc, proxy)), "accept", "{p:?}: proxy");

            // Any other host listener is not the VM's to reach, on the
            // services address or the veth's own.
            assert_eq!(
                v(new(svc, Some((Protocol::Tcp, 22)))),
                "drop",
                "{p:?}: sshd"
            );
            assert_eq!(
                v(new(svc, Some((Protocol::Tcp, 5432)))),
                "drop",
                "{p:?}: a database"
            );
            assert_eq!(
                v(new(svc, Some((Protocol::Udp, 80)))),
                "drop",
                "{p:?}: wrong protocol"
            );
            assert_eq!(
                v(new(svc, Some((Protocol::Udp, cfg.proxy_port)))),
                "drop",
                "{p:?}: udp intercept"
            );
            assert_eq!(v(new(svc, None)), "drop", "{p:?}: icmp");
            assert_eq!(
                v(new(f.vh_ip, Some((Protocol::Tcp, 22)))),
                "drop",
                "{p:?}: sshd on vh"
            );
            assert_eq!(
                v(new(f.vh_ip, Some((Protocol::Udp, 53)))),
                "drop",
                "{p:?}: dns on vh"
            );

            // The reply leg of a flow the host started still comes home.
            let reply = Pkt {
                reply: true,
                ..new(f.vh_ip, Some((Protocol::Tcp, 40000)))
            };
            assert_eq!(v(reply), "accept", "{p:?}: reply");

            // Traffic from any other interface is left to the host's own
            // policy (another slot's is judged by that slot's table).
            for iif in ["eth0", "lo", "vm0002"] {
                let other = Pkt {
                    iif,
                    ..new(svc, Some((Protocol::Tcp, 22)))
                };
                assert_eq!(v(other), "accept", "{p:?}: from {iif}");
            }
        }
    }
}
