# iso on DigitalOcean, distributed

An [inframe](https://github.com/by77er/inframe) stack that provisions a test
rig for the distributed deployment, and a script that installs iso on it:

| Droplet | Runs | Holds |
| --- | --- | --- |
| `iso-control` | `iso-fleetd` (:7080, the one API clients use), `iso-proxyd --role proxy` (the tier), `iso-cad`, `iso-secretsd` | the CA key, the leaf keys, the secret values |
| `iso-host-a`, `iso-host-b` | `iso-controld`, `iso-proxyd --role edge`, one baked Debian template | nothing a guest's traffic could be read or forged with |

The three sit on one VPC in `nyc3`. Only SSH and the fleet API (mutual TLS)
are open to the internet; every other port is reachable from the VPC alone.
The stack's policies, proved when it compiles, hold it to exactly that:
`lean/IsoFleet/Policies.lean`.

**Nested virtualization.** DigitalOcean droplets expose `/dev/kvm` but do not
recommend nested virtualization; guests will be slow. Cloud-init on the hosts
leaves `/var/lib/iso-no-kvm` if a droplet has none and `deploy.sh` stops
there. This is a rig for testing the distributed control plane and proxy,
not a place to run a fleet for real.

## Provision

You need the inframe CLI (`cargo build -p inframe-cli` in its checkout),
OpenTofu, Lean 4 via elan, a DigitalOcean token, and an SSH key already in
your account. Set its name in `lean/IsoFleet/Stack.lean` (`adminKeyName`).

```bash
export DIGITALOCEAN_TOKEN='…'
inframe provider generate            # the typed DigitalOcean adapters, once
inframe build --stack do             # renders the graph
inframe test --stack do              # the policy executable (also runs before plan/apply)
inframe plan --stack do
inframe apply --stack do             # three droplets, a VPC, a firewall: billable
inframe output --stack do
```

`inframe.toml` points `[lean.core]` at the inframe repository on GitHub; for
a local checkout, use `core = { path = "/path/to/inframe/lean" }` and the
matching `[[require]]` in `lean/lakefile.toml`.

## Install iso

Build iso on your machine, then let the script do the rest over SSH as root:

```bash
cargo build --release -p iso-controld -p iso-cli -p iso-ca -p iso-secrets -p iso-proxy -p iso-fleet
cp secrets.example.toml secrets.toml && $EDITOR secrets.toml   # real credentials, control host only
SECRETS_TOML=./secrets.toml ./deploy.sh
```

What it does, in order:

1. **Control host.** Ships the binaries. Mints one admin CA for every host and
   the identities each service presents: the fleet's client identity, the
   control host's service identity, one edge identity per host, and an
   operator client for the fleet's own CA. Writes the tier and fleet
   configs and starts `iso-cad`, `iso-secretsd`, `iso-proxyd --role proxy`
   and `iso-fleetd` as systemd units. Fetches the tier CA (for the guests),
   the host admin CA (for the hosts) and your operator credentials into
   `.deploy/`.
2. **Each host.** Ships the binaries, the guest kernel and static agent
   (`nix build .#kernel .#iso-guest-agent-static`), the `image/` tree with
   the tier CA in it, and the edge identity. Installs the shared admin CA
   before `iso-controld` first starts, so the host adopts it instead of
   generating its own. Starts controld on the private address and the edge
   pointed at the tier, bakes a Debian template that trusts the tier CA, and
   registers it.
3. **You.** The exports it prints at the end make `isoctl vm …` talk to the
   fleet: create places on a host with a free slot, `exec` is routed by id,
   and a proxied request to `api.github.com` comes back with the token
   injected on the control host.

## Tear down

```bash
inframe destroy --stack do
rm -rf .deploy
```

`.deploy/` holds the host admin CA key and your operator key; it is ignored
by git. Do not commit it.
