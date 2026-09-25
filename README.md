# iso

Fast, isolated Firecracker microVMs for coding agents and other untrusted code,
on your own Linux machines.

iso runs a daemon, `iso-controld`, that creates, snapshots, suspends, and
destroys microVMs on a Linux host. Each VM gets its own kernel, its own network
namespace, and its own copy-on-write disk. A new VM resumes from a snapshot of
an already-booted template, so it skips booting entirely.

You control VMs through an HTTP API or the `isoctl` command line. You can run
commands and read or write files inside a VM without SSH, and without giving it
any network access. The host talks to a small agent inside the guest over
vsock.

## How it works

- **Templates.** A template is a disk image plus a memory snapshot of a VM that
  has already booted. Build one from the bundled NixOS or Debian image, or from
  any OCI image, such as `python:3.12-slim`.
- **VMs.** Each VM gets a thin LVM snapshot of its template's disk and resumes
  from the template's memory snapshot. Every VM sees the same IP address and
  MAC inside its own network namespace, which is why one snapshot works for all
  of them.
- **Guest agent.** A small service in every VM runs programs and moves files
  for the host. It works even when the VM has no network.
- **Network.** VMs have no network access by default. In `proxy` mode, all of
  a VM's traffic goes through a proxy on the host that enforces rules you set
  for that VM, and you can change them while it runs.
- **Isolation.** Every VM runs under Firecracker's jailer, in its own chroot,
  as an unprivileged user.
- **Lifecycle.** VMs can be stopped, started, suspended, and resumed. Durable
  VMs keep their disk when stopped. Ephemeral ones don't.

## Quick start

You need an x86_64 Linux host with KVM, root access, and Nix with flakes.

```bash
nix develop                                  # nightly Rust and Firecracker
cargo build
nix build .#kernel .#iso-guest-agent-static
sudo scripts/dev-up.sh
```

`dev-up.sh` sets up everything else. It installs the host packages it needs
(on Debian or Ubuntu), starts the daemon and the proxy with state under
`./state`, puts a client certificate in `~/.iso/creds`, and builds a Debian
template named `debian`. You can safely run it again. It looks for
`firecracker`, `jailer`, and `nix` on root's `PATH` or in `~/.nix-profile`
(`nix profile install .#firecracker` puts the first two there).

Then create a VM and use it:

```bash
export PATH=$PWD/target/debug:$PATH
export ISO_SERVER=https://127.0.0.1:7070 ISO_CREDS=~/.iso/creds ISO_CLIENT=$USER

id=$(isoctl vm create --template debian --quiet)
isoctl vm exec "$id" -- uname -a
isoctl vm put "$id" /home/coder/hello.txt --content "hi"
isoctl vm cat "$id" /home/coder/hello.txt
isoctl vm rm "$id"
```

That VM has no network. To let one reach the internet through the proxy:

```bash
id=$(isoctl vm create --template debian --egress proxy --rule 'allow https://*/**' --quiet)
isoctl vm exec "$id" -- curl -sI https://example.com
```

To let the daemon build templates from OCI images on request, point
`ISO_BAKE_KERNEL` and `ISO_BAKE_AGENT_BIN` at the kernel and guest agent from
the `nix build` above. Then:

```bash
isoctl template build --name py312 --image python:3.12-slim --wait
```

## API

The daemon serves one HTTP API in two places: a Unix socket that only root can
use, and port 7070 with mutual TLS for everyone else. It covers creating and
managing VMs, running commands and moving files inside them, changing their
network rules, forwarding ports, and building templates. `isoctl` and the Rust
client in `crates/iso-client` are both built on it, and the daemon serves its
OpenAPI document at `/openapi.json`.

See [docs/admin-api.md](docs/admin-api.md) for authentication, the client, and
the guest agent.

## Also included

- **Egress proxy** (`iso-proxyd`, `iso-cad`, `iso-secretsd`): lets a VM reach
  only the hosts and paths you allow, logs every request, and adds real API
  keys to requests on the way out, so secrets never enter the VM.
  [Design](crates/iso-proxy/DESIGN.md).
- **Fleet** (`iso-fleetd`): one API across many hosts. It places each VM on a
  host and routes later calls to it. [docs/fleet.md](docs/fleet.md).
- **Master** (`iso-master`): a web app for chatting with pi coding agents, each
  in its own VM. It puts idle agents to sleep and can run swarms of planners
  and workers. [contrib/master](contrib/master/README.md).
- **pi extension** (`contrib/pi/iso.ts`): runs the tools of the
  [pi](https://github.com/badlogic/pi-mono) coding agent inside a fresh VM
  while pi itself stays on your machine.
- **Harbor environment**: runs [Harbor](https://github.com/laude-institute/harbor)
  agent evaluations with one VM per trial.
  [contrib/harbor](contrib/harbor/README.md).
- **DigitalOcean test rig**: an [inframe](https://github.com/by77er/inframe)
  stack that deploys a three-machine fleet, with an end-to-end test.
  [contrib/inframe/digitalocean](contrib/inframe/digitalocean/README.md).

## Status

iso is a working prototype, not a hardened product.

- Any client certificate from the admin CA has full control of every VM. There
  are no roles.
- x86_64 only.

## Development

```bash
cargo test
```

Most tests run without root. The integration tests in `iso-controld` and
`iso-firecracker` need root and KVM, and skip themselves otherwise. For design
notes, see [the network design](crates/iso-network-manager/DESIGN.md) and
[the proxy design](crates/iso-proxy/DESIGN.md).
