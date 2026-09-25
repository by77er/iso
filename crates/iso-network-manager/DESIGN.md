# iso-network-manager — Network Design

This document describes the per-VM network topology, addressing scheme, NAT
strategy, inbound port forwarding, and egress firewall policy implemented by the
network manager.

## Goals & guiding principles

- **Byte-identical guest config.** Every VM sees the same network configuration
  so the golden image needs zero per-VM customization.
- **Per-host uniqueness without guest involvement.** VMs are distinguished on the
  host by a deterministic per-host **Slot ID**, never by anything baked into the
  guest.
- **Stateless, idempotent network manager.** All fixtures derive from the slot,
  so `apply`/`teardown` are pure functions of the slot and its policy, and can be
  re-driven for reconciliation/crash recovery.
- **Guest-tamper-proof enforcement.** Policy lives in namespaces and the host
  root namespace, both of which the guest cannot reach.

## Identity vs. placement

Two distinct concepts, owned by different layers:

| Concept     | Owner          | Lifetime          | Used for                                    |
| ----------- | -------------- | ----------------- | ------------------------------------------- |
| **UUID**    | control plane  | durable, global   | identity: APIs, logs, cross-host references |
| **Slot ID** | control plane  | per-host, recycled | placement: all deterministic net fixtures   |

The network manager is a **pure function of the Slot ID**. It is *not* given the
UUID — identity is not its concern, and keying network state by UUID would
reintroduce stateful coupling. UUID↔slot binding is owned solely by the control
plane.

For log/trace correlation, the UUID is carried in the **tracing span context** at
the call site, not as a function argument:

```text
apply(slot: SlotId, policy: &NetworkPolicy) -> Result<NetworkFixture>
teardown(slot: SlotId)                      -> Result<()>
```

### Slot allocator

The Slot ID *is* the address allocation, so there is no separate IPAM. The only
persisted state is the control plane's UUID↔slot binding in SQLite; the slot
bitmap (`0..32767`) is rebuilt from it on startup. Slots are returned to the
free pool **only after teardown fully completes** (netns gone, conntrack
flushed), and allocation rotates from a cursor, so a freed slot is not reused
straight away and cannot resurrect stale neighbor/conntrack state. A template
bake borrows a slot the daemon doesn't know about (`isoctl bake --slot`,
default 0, so pick a high one on a busy host; `dev-up.sh` uses 32767 and
builds through the API use 32766).

## Topology

Each VM runs in its own network namespace with a TAP device, linked to the host
root namespace by a veth pair.

```text
        guest                netns "vm<slot>"                 host root ns
   ┌───────────┐      ┌──────────────────────────┐      ┌──────────────────┐
   │  VM        │      │                          │      │                  │
   │ 172.20.0.1 ├─TAP──┤ 172.20.0.0   vp ─────────┼─veth─┤ vh         eth0  ├── uplink
   │ (constant) │      │ (constant)   172.21.x.x+1 │      │ 172.21.x.x       │
   └───────────┘      └──────────────────────────┘      │ dummy0           │
                                                          │ 172.22.0.1/32    │
                                                          └──────────────────┘
```

### Addressing

| Element          | Address              | Scope                         |
| ---------------- | -------------------- | ----------------------------- |
| TAP / VM gateway | `172.20.0.0/31`      | **constant** for every VM     |
| VM               | `172.20.0.1`         | **constant** for every VM     |
| veth host (`vh`) | `172.21.x.x/31`      | unique, derived from slot     |
| veth netns (`vp`)| `172.21.x.x+1/31`    | unique, derived from slot     |
| dummy (services) | `172.22.0.1/32`      | host-local, shared anycast    |

- All point-to-point links are **/31** (RFC 3021) — no network/broadcast waste.
  The TAP/VM pair uses the constant `172.20.0.0/31`; pick an aligned pair (`.0`/`.1`).
- The veth space `172.21.0.0/16` yields **2^15 = 32768** slots per host.
- **MAC is identical across all VMs.** This is safe because the datapath is
  routed (L3), never bridged. *Do not ever bridge these interfaces together* —
  L2 isolation via separate namespaces is load-bearing.

> ⚠️ **Prefixes must be configurable.** `172.21.0.0/16` sits inside RFC 1918
> `172.16.0.0/12` and can collide with a host LAN/VPC. `172.20.0.0/31` and
> `172.22.0.1/32` are likewise defaults, not constants. Do not hard-code them.

### Slot → fixture derivation (pure)

Given `slot ∈ 0..32767`:

```text
netns      = "vm<slot:04x>"            # e.g. vm7fff
tap        = "tap0"                    # CONSTANT across all netns (see below)
veth_host  = "vm<slot:04x>"            # host side
veth_netns = "vp<slot:04x>"            # netns side
vh_ip      = 172.21.(slot >> 7).((slot & 0x7f) << 1)        # /31 base
vp_ip      = vh_ip + 1
mac        = 02:00:00:00:00:01         # guest, constant
tap_mac    = 02:00:00:00:00:00         # gateway (the TAP), constant
```

> **The TAP's MAC is constant too.** A resumed snapshot restores the guest's
> ARP cache, which holds the gateway's MAC from bake time. With a random MAC
> per TAP, every clone would spend its first ~30 seconds sending frames to a
> MAC nobody answers for, until Linux times the stale entry out and re-ARPs.

> **The TAP name is constant**, not slot-derived. The TAP lives inside the
> isolated per-VM netns, so an identical name in every namespace is safe — and
> it means a Firecracker memory snapshot's frozen network config
> (`host_dev_name=tap0`) is valid for *every* clone with zero per-VM override.
> This is the same "identical inner config" principle that lets one snapshot
> resume across many VMs; the veth stays unique because it lives in the shared
> root namespace.

> **Reverse lookup:** `address_to_slot(vp_ip|vh_ip) -> slot` inverts the veth
> derivation (`slot = (addr - veth_net) / 2`), letting host-local services (the
> metadata endpoint) identify a caller by its post-SNAT source address.

> Linux caps interface names at 15 chars (`IFNAMSIZ-1`). Use the compact **hex**
> scheme above (`vm7fff`, `vp7fff`) so the high end of the slot range never
> truncates or collides.

### Kernel prerequisites

- `net.ipv4.ip_forward = 1` in **both** the host and each netns.
- `rp_filter = 2` (loose) on the uplink and inside each netns — strict RPF
  drops the asymmetric-looking replies created by NAT and policy routing.

## NAT strategy

The constant inner IP means a VM's flows are **indistinguishable** until made
unique. Uniqueness must be established *before* traffic reaches any shared
conntrack table. That work is the **in-netns SNAT** (`172.20.0.1 → vp`), and it
is load-bearing — it cannot be replaced by marks (see below).

### Egress: internal (to `172.22.0.1`) — single NAT

```text
inner 172.20.0.1 ──[netns SNAT → vp]──► host routes to dummy0 ──► local service
```

- netns SNATs to the unique `vp` IP; the host performs **no NAT**, only routing.
- The local service (proxy/DNS on `172.22.0.1`) identifies the VM directly by its
  unique source IP and replies normally; the kernel routes the reply back into
  the correct netns via the `/31`.

### Egress: external (internet) — double NAT (unavoidable)

```text
inner 172.20.0.1 ──[netns SNAT → vp]──► host ──[masquerade → public]──► uplink
```

A VM's own traffic never takes this path: in `Proxy` mode it terminates at the
proxy on `172.22.0.1`, which opens its own upstream connection from the host.
Only the bake's builder VM (`direct`, below) routes out this way. The masquerade
rule is still part of every slot's table, so the path is there when it is
needed.

- The in-netns SNAT makes the source unique; the host masquerade gives it a
  public source. Both are required.
- This double-NAT is **forced** by the constant-inner-IP design and is cheap:
  one extra conntrack entry per flow plus a fast-path rewrite (µs). We accept it
  to keep the byte-identical golden image.

### Why marks cannot replace the SNAT

Conntrack entries are keyed on **tuple + zone**; the mark/connmark is metadata,
**not** part of the key. With identical inner IPs this yields a circular
dependency:

1. Identical original tuples across VMs collide on insert within a single zone.
2. Zones (per-veth on ingress) fix the insert, but the reply arrives on `eth0`
   with no field to recover the zone → lookup misses → no un-NAT.
3. connmark-based return needs a single zone; a single zone needs unique original
   tuples; unique tuples need a unique source IP — i.e. the SNAT.

So the SNAT *creates* the L3 uniqueness that both insertion and return steering
depend on. Marks are used for what they're good at (return/policy routing), not
as a substitute for the SNAT. Performance-wise marks buy nothing here: the host
masquerade is still required, conntrack NAT is a flow-setup cost, and large
`ip rule` lists are slower than a fast-path rewrite.

> The only genuine single-NAT-external option is 1:1 SNAT to a **per-slot public
> IP** pool (reply `daddr` then identifies the VM, so the zone can be set on the
> reply). Out of scope unless a public IP per concurrent VM is available.

## Inbound: opening host ports that DNAT to a VM — two-layer DNAT

The network manager can expose a port on the **main host** that forwards to a
port on a VM (the `ingress` list of the slot's `NetworkPolicy`). A single DNAT straight
to the constant inner IP cannot work: the host has no
unambiguous route to deliver the constant address to the right netns. The
destination must be the **unique `vp`** at the point host routing decides. This
mirrors the egress double-NAT:

```text
client ─► host pub:Pport ──[host DNAT → vp:port]──► netns ──[netns DNAT → 172.20.0.1:port]──► VM
```

```nft
# host root ns
chain prerouting {
  type nat hook prerouting priority dstnat;
  iifname "eth0" tcp dport <Pport> dnat to <vp_ip>:<port>
}
# netns vm<slot>
chain prerouting {
  type nat hook prerouting priority dstnat;
  iifname "vp<slot>" dnat to 172.20.0.1:<port>
}
```

- Both rules are pure functions of the slot; conntrack reverses the entire chain
  on replies (we never author the return direction).
- Only the **destination** is rewritten, so the VM sees the **real client IP**.
  (If proxy-terminated inbound is desired instead, client IP becomes an
  `X-Forwarded-For`-style concern at `iso-proxy` — a separate decision.)

The single-layer alternative (DNAT to the constant IP + per-slot
`ip rule`/policy-route steering) is rejected: it trades a cheap conntrack rewrite
for the `ip rule` linear-scan scaling footgun plus a routing table per slot.

## Egress modes

Each VM's egress is one of **two levels**, set declaratively via the `egress`
field of its [`NetworkPolicy`] and reconciled on `apply`. The levels govern only
**external** traffic; access to the host's internal services on `172.22.0.1`
(DNS, metadata, the proxy) is an **always-on baseline** in every level.

| Level   | Behaviour                                                              |
| ------- | ---------------------------------------------------------------------- |
| `Proxy` | every flow bound beyond `172.22.0.1` is **transparently intercepted** to the proxy on `172.22.0.1:<proxyport>` |
| `Deny`  | **no external egress** (internal-services baseline still applies)      |

There is no direct mode. Every byte a VM sends outward goes through the proxy,
where its rules decide and the access log records it. How wide a VM's access is
(`allow https://*/**`, `tunnel tcp://host:port`) is the rules' business, not the
mode's; see `crates/iso-proxy/DESIGN.md`. The proxy port is manager
configuration, not per-VM policy.

`NetworkPolicy` also carries `direct: bool`, which only `isoctl bake` sets, for
the builder VM that runs `--provision` commands. The builder is host tooling on
a slot no VM occupies, with no policy and no proxy identity, so it gets a
forward accept out the uplink instead of the intercept. No VM is ever `direct`.

Each slot's rules live in a table of their own (`iso_vm<slot>` in the host root
namespace, `iso` inside the netns), and `apply` resets the whole table in one
atomic batch, so converging a VM to a new level is a single table replace.
Because NAT and filtering decisions apply to the first packet of a flow, a level
change affects **NEW connections only**; flush the VM's conntrack entries
(matched by the `vp` source) if in-flight flows must re-evaluate immediately.
(Rule changes inside `Proxy` are the proxy's business, and it closes
connections admitted under an older policy generation itself.)

### `Proxy` level (transparent proxy intercept)

`Proxy` transparently DNATs VM egress to a proxy port on `172.22.0.1` —
crucially **after the first NAT**. The in-netns SNAT has already rewritten the
source to the unique `vp`, so the proxy sees a source IP that identifies the VM,
and recovers the intended destination via `SO_ORIGINAL_DST`.

```nft
# host root ns, table iso_vm<slot> — nat prerouting, after the in-netns SNAT
chain prerouting {
  type nat hook prerouting priority dstnat;
  iifname "vm<slot>" ip daddr != 172.22.0.1 tcp dnat to 172.22.0.1:<proxyport>
  iifname "vm<slot>" ip daddr != 172.22.0.1 udp dnat to 172.22.0.1:<proxyport>
}
```

- The `ip daddr != 172.22.0.1` guard leaves traffic to the host's own services
  (DNS, metadata) alone and prevents redirect loops.
- DNAT to a **local** address routes the flow to the host `input` hook (not
  `forward`), terminating at the proxy.
- The proxy speaks TCP only, so intercepted UDP (anything but DNS to
  `172.22.0.1`) reaches no listener and goes nowhere.
- Source remains the unique `vp` end-to-end, so the proxy can map
  connection → VM with no extra signalling.

## Egress firewall policy

Forwarded traffic is filtered in the **host `forward` chain, matched on the
ingress veth** — the host-controlled trust boundary and the routing fork.
(`Proxy` traffic never reaches `forward`; it is DNAT'd to the local dummy in
prerouting and handled in `input`.) Filtering is *not* enforced on the dummy
interface (that only protects the service, not lateral movement).

**Filter on connection origin/state, never on `ip daddr` alone.** Destination is
the wrong axis: the egress (reply) leg of an inbound-initiated flow has
`daddr = client`, so a daddr test would wrongly drop it.

```nft
# host root ns, table iso_vm<slot>
chain forward {
  type filter hook forward priority filter; policy accept;

  # reply leg of ANY permitted flow (inbound- OR outbound-initiated)
  ct state established,related accept

  # inbound-initiated NEW (port-forwards) — let it into the VM
  ct state new iifname "eth0" oifname "vm<slot>" accept

  # lateral movement: nothing from this VM to any other veth (ip_forward is on)
  iifname "vm<slot>" ip daddr 172.21.0.0/16 drop

  # direct only (the bake's builder): out the uplink
  iifname "vm<slot>" oifname "eth0" accept

  # everything else this VM starts
  iifname "vm<slot>" drop
}

chain input {
  type filter hook input priority filter; policy accept;
  iifname "vm<slot>" ip daddr 172.22.0.1 accept   # services baseline
}

chain postrouting {
  type nat hook postrouting priority srcnat;
  ip saddr <vp_ip> oifname "eth0" masquerade
}
```

- `established,related accept` first means the drops only ever see **new**
  packets. Reply legs of both inbound- and outbound-initiated flows are accepted
  before reaching them.
- This yields the intended asymmetry: a `Deny` VM is **reachable inbound** (its
  reply leg rides `established`) while unable to **initiate** anything past the
  internal-services baseline.
- The chains' `accept` policy only matters for traffic that isn't this VM's;
  every packet this VM starts ends at an explicit verdict.
- The explicit `172.21.0.0/16` drop blocks **lateral movement** between VMs
  (necessary because `ip_forward` is on and all veths live in the root
  namespace).
- If policies grow complex enough that "who initiated this" isn't obvious from
  the interface, stamp origin onto the conntrack at creation
  (`ct mark set <vm-initiated|inbound>`) and key policy on the mark — immune to
  which leg is being inspected.

### Defense in depth: netns routing as fail-closed backstop

`Deny` VMs get **no default route** in their netns — only a route to
`172.22.0.1`. A missing/botched host rule then still cannot leak: an
internet-bound packet reaches the netns and dies for lack of a route. The netns
routing table is host-controlled (not guest-reachable), so this is a legitimate
control. `Proxy` VMs need the default route, since the intercept happens on the
host. The host rules remain the authoritative enforcement; netns routing is the
backstop.

## Interface contract summary

The interface is **declarative**: the caller states the complete desired network
state for a slot, and the manager diffs it against reality and converges (egress
mode + the full ingress set). Re-applying the same policy is a no-op; applying a
changed policy reconciles only the difference. This avoids add/remove ordering
bugs and makes crash recovery a matter of re-applying.

```text
apply(slot: SlotId, policy: &NetworkPolicy)          -> Result<NetworkFixture>  # converge to present
reapply_policy(slot: SlotId, policy: &NetworkPolicy) -> Result<()>              # nft only, for a running VM
teardown(slot: SlotId)                               -> Result<()>              # converge to absent
```

`reapply_policy` re-renders only the two nftables tables and leaves the
interfaces alone, because a full `apply` on a running VM fails on the TAP the
VMM holds open (`TUNSETIFF ... busy`).

```text
struct NetworkPolicy {
  egress:  EgressMode,        # Proxy | Deny
  ingress: Vec<PortForward>,  # full desired set; (host_port, proto) unique
  direct:  bool,              # the bake's builder only; never a VM
}
# Default = deny-by-default: Deny, no ingress.
struct PortForward { host_port: u16, vm_port: u16, proto: Protocol }
```

`NetworkFixture` carries only the slot-derived names/addresses needed by callers
(netns, tap, vh/vp + IPs, mac). The constant inner addressing is a compile-time
constant, not part of the fixture. The network manager holds no per-VM state and
never sees the UUID.
