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
   the identities each party presents: the fleet's client identity, the
   control host's service identity, one identity per host (its controld
   server certificate and its edge's client certificate are the same one),
   and an operator client for the fleet's own CA. The CA key stays here.
   Writes the tier and fleet configs and starts `iso-cad` and `iso-secretsd`
   (answering the control identity by name and nothing else), `iso-fleetd`
   (which mints its policy signing key on first start) and then
   `iso-proxyd --role proxy` with the fleet's public key, so the tier serves
   only policies the fleet signed. Fetches the tier CA (for the guests), the
   admin CA certificate, the host identities and your operator credentials
   into `.deploy/`.
2. **Each host.** Ships the binaries, the guest kernel and static agent
   (`nix build .#kernel .#iso-guest-agent-static`), the `image/` tree with
   the tier CA in it, and the host's identity: as the edge's credentials and
   as `iso-controld`'s server certificate under `/var/lib/iso/admin-pki`,
   with the CA certificate beside it and no CA key. Puts the tier CA where
   `isoctl bake` reads the CA a guest must trust (`/var/lib/iso/ca/ca.crt`,
   the spot `iso-cad` fills on a single host). Starts controld on the private
   address and the edge pointed at the tier, bakes a Debian template, and
   registers it.
3. **You.** The exports it prints at the end make `isoctl vm …` talk to the
   fleet: create places on a host with a free slot, `exec` is routed by id,
   and a proxied request to `api.github.com` comes back with the token
   injected on the control host.

## Reading the access log

The tier writes one JSON line per request and per tunnel (`ISO_LOG_FORMAT=json`
in its unit), so a VM's traffic is one filter away:

```bash
ssh root@<control> "journalctl -u iso-proxyd -o cat | grep '\"target\":\"iso_proxy::access\"' | grep '\"vm\":\"<id>\"'"
```

Each line names the edge the request came through, the VM and principal,
the method, scheme, host and path, the decision and rule, the names of the
injected headers, the status and the latency. Query strings and header
values are never logged.

## Check it end to end

```bash
./e2e.sh
```

With the exports from `deploy.sh` set, `e2e.sh` drives the rig through the
fleet API alone: two healthy hosts with the template; a VM placed by the
fleet whose agent answers and whose clock was set on resume; a request to
`postman-echo.com` that comes back with the headers from `secrets.toml`
injected on the control host; a URI rule that turns a path into a 403
naming the rule; a host no rule names refused at SNI time; a WebSocket
upgrade tunnelled through to a 101; a policy change that bumps the
generation and closes the old connections; then, from host-a with its own
identity, an unsigned policy refused by the tier, the secrets service
refusing that identity by name, and no CA key on the host; a second VM
landing on the other host; and a clean destroy. It ran green
against `nyc3` on 2026-09-14, about 90 seconds end to end, with the guest
agent answering roughly two seconds after `vm create` on nested KVM.

## Tear down

```bash
inframe destroy --stack do -- -auto-approve
rm -rf .deploy
```

Then confirm nothing is left billing: `curl -H "Authorization: Bearer
$DIGITALOCEAN_TOKEN" https://api.digitalocean.com/v2/droplets` should list
no droplets tagged `iso`.

`.deploy/` holds the host identities' keys and your operator key; it is
ignored by git. Do not commit it.
