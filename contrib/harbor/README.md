# Harbor on iso

An environment for the [Harbor](https://github.com/laude-institute/harbor)
agent evaluation framework that runs each trial in a Firecracker microVM on
an iso host or fleet, behind iso's egress proxy.

What happens per trial:

1. The task's image (its `Dockerfile`, built and pushed to a registry the
   hosts can reach, or its prebuilt `docker_image`) becomes an iso template:
   `POST /templates/build` pulls the image on every host and bakes it with
   the guest agent as init. One build per task per fleet; later trials find
   the template.
2. A VM is cloned from the template with the task's network policy as iso
   rules: `no-network` is `deny`, `public` is `allow https://*/**`, an
   allowlist is one `allow` per host (leading `*.` wildcards work). Every
   byte out goes through the proxy, which can inject credentials the VM
   never holds.
3. Harbor's `exec`, uploads and downloads go through the host's guest agent
   over vsock, as the user Harbor asks for.
4. `stop` deletes the VM. The template stays for the next trial.

## Use

```bash
pip install ./contrib/harbor          # or: uv pip install ./contrib/harbor
export ISO_SERVER=https://<fleet>:7080 ISO_CREDS=/path/to/creds ISO_CLIENT=operator
export ISO_HARBOR_REGISTRY=ghcr.io/acme/harbor-envs   # where built images are pushed
harbor run --dataset terminal-bench@2.0 --agent claude-code \
  --model anthropic/claude-opus-4-1 --env harbor_iso:IsoEnvironment
```

Kwargs (`--ek key=value`) override the environment: `server`, `creds`,
`client`, `registry`, `template_prefix` (default `hb-`), `vcpus`,
`mem_mib`, `rootfs_size` (default `16G`), `principal` (the iso principal
whose credentials the proxy injects), `build_timeout_sec`,
`boot_timeout_sec`.

The credentials directory is what `isoctl admin issue-client --out` writes
(`ca.crt`, `<client>.crt`, `<client>.key`); the DigitalOcean rig's
`deploy.sh` leaves an operator's in `.deploy/creds`.

## Limits

- Images must have gzip layers (the usual) and target linux/amd64.
- Allowlists take hostnames, not addresses or CIDRs; that is what iso's rules
  name.
- Plain TCP (ssh to a git host, say) needs a `tunnel tcp://host:port` rule,
  which Harbor's policy model has no word for; pass extra rules through a
  task-level iso principal and policy if you need them.
- Directory transfers use `tar` inside the image when it is there and fall
  back to one file at a time when it is not.

## Test

```bash
uv venv && uv pip install -e '.[test]'
.venv/bin/pytest
```
