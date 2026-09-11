# iso master

An **agent-first web UI** for a fleet of iso control planes. Users create an agent
and chat; the master allocates an isolated microVM, starts **headless pi**, routes
tools into that VM, and sleeps/resumes the workspace automatically.

- **Rust / Axum / Tokio**: web API, authentication, placement, persistent session
  state machine, idle timers and pi subprocess supervision.
- **`iso-client`**: independent mTLS connection to each control plane.
- **React / TypeScript / Vite**: component-based chat, incremental responses,
  collapsible tool activity, recovery controls and an operator fleet view.
- **SQLite + pi JSONL**: durable browser history, session-to-VM assignment and full
  pi conversation/context. The guest disk is durable too.

The Python prototype is not part of this implementation.

## Try it without infrastructure

From the **repository root**, with Rust stable and Node.js **24+** on `PATH`:

```sh
cd contrib/master
npm ci --ignore-scripts
npm run build
cd ../..
cargo +stable build -p iso-master

# Set MASTER_PASSWORD through your shell's protected input or service secret store.
# It must contain at least 16 characters. MASTER_USER defaults to admin.
./target/debug/iso-master contrib/master/demo.json
```

Open **http://127.0.0.1:8080**. Create an agent, send a message, and inspect tool-free
demo responses. Under **Workspace details**, choose **Sleep now**, then send another
message to wake the same workspace. Otherwise sessions sleep after 15 minutes.
The demo does not run a model, execute commands, or contact real iso hosts.

Demo VM records exist only in memory; after restarting the demo master, old demo
sessions cannot resume their simulated VMs. Close those sessions and create new
ones, or use a fresh demo data directory. Real VMs persist independently of the master.

## Connect real control planes

1. On each iso host, bake/register a template and issue a master client identity:

   ```sh
   isoctl admin issue-client --name orchestrator --out ./creds
   ```

   Follow the [admin API documentation](../../docs/admin-api.md). Securely copy
   `ca.crt`, `orchestrator.crt`, and `orchestrator.key` to a separate master-side
   directory for each plane. These are full-admin credentials; never place them
   in guests or the frontend.

2. Copy [`master.example.json`](master.example.json) to a protected deployment
   config and edit its planes. Paths are relative to the **master's launch cwd**,
   not the config file. Keep plane IDs stable: persisted sessions reference them.
   A plane specifies its own template, credential principal, egress policy,
   domain allow-list, and maximum VM count. Restart the master to reload config.

3. Configure the model used by headless pi via `pi_model`. Pinning pi to `0.85.1`
   keeps the RPC protocol and extension APIs reproducible.
   `pi_env_file` points to a protected JSON object of provider environment variables,
   e.g. keys named `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`, populated by your secret
   manager. It is read when a pi worker starts; values are **never** sent to guests
   or returned to the browser. Do not put real values in tracked example files.
   With no explicit model, pi selects its configured default.

   **LLM traffic originates on the master.** Guest egress credential injection does
   not automatically authenticate the master-side pi process. Use master-side
   provider credentials or an authenticated model gateway. The plane's `principal`
   controls **guest** API attribution only. This version has one operator identity;
   it does not implement per-user provider credential selection.

4. Build the frontend as above and start `iso-master /path/to/master.json` with
   `MASTER_PASSWORD` configured. Put a TLS reverse proxy in front of the loopback
   listener. Set `public_origin` to the exact browser origin (no trailing slash)
   and leave `secure_cookie: true` for HTTPS. Forward `/api/*` and static assets
   to the master. Provider/mTLS credentials must remain outside the public UI dir.

The CLI validates all plane credentials at startup; later connectivity failures
are reported per plane. Placement probes reachable planes concurrently, chooses
the least populated with capacity, and serializes creation. It counts all VMs on
that plane, including ones created outside the master. It is **not** a CPU/RAM-aware
scheduler. There is no cross-plane migration of a sleeping or failed session.

## Models and swarms

`pi_models` is the operator-controlled list of `provider/model` IDs offered in
the UI. `pi_model`, when configured, is also included and is the default. These
must be models supported by the installed pi version and authenticated on the
master. For example:

```json
{
  "pi_model": "openai-codex/gpt-5.5",
  "pi_models": ["openai-codex/gpt-5.5", "openai-codex/gpt-5.6-sol"],
  "swarm_max_depth": 4,
  "swarm_max_agents": 16
}
```

New agent offers a model dropdown. An existing standalone session can change
models while idle, asleep, or interrupted; the choice persists across restarts.
An idle worker switches through pi's model RPC without losing its conversation.

Enable **Swarm mode** when creating an agent to select separate **Planner model**
and **Worker model** values. The root is a planner. Every sub-planner inherits the
planner model and every worker inherits the worker model. These role settings are
fixed for that tree; create a new swarm to use a different pair.

Planners have only `read` and `list` for workspace inspection, plus `swarm_spawn`,
`swarm_send`, and `swarm_status` for coordination. They cannot use shell commands,
write, or edit. Workers get the normal remote read/write/edit/bash tools and
messaging/status, but cannot spawn children. These restrictions are implemented
in the tool registrations and checked by the master for scheduling; they are not
just prompt instructions. Each node has its own VM: disks are not shared, so
tasks should include repository/setup instructions and report patches or results
back to their parent.

The sidebar displays the swarm hierarchy with collapsible branches, roles, and
phases. Click a node to inspect its chat and model. Parent/child messages appear
as distinct cards identifying the sender. Planners can schedule children
themselves, or the operator can open **Coordination** and use **Schedule child**.
The default maximum is four edges from root
to leaf and 16 total nodes per tree (including closed nodes), additionally bounded
by `max_agents` and control-plane capacity. Scheduling returns a capacity error
when a limit is reached; it does not silently create a second workspace or retry.
Close descendants before closing their planner.

Messages only travel between direct parents and children. They are stored in
SQLite, queued while the recipient works, and delivered as a new turn when idle
or asleep. Sleeping recipients wake automatically. Interrupted recipients require
explicit recovery. A delivery interrupted before acknowledgment is marked
`uncertain` and never automatically replayed. The panel shows mailbox status;
inspect the conversation before manually repeating an uncertain message. Workers
are instructed to send results to their parent, and waiting planners should end
their turn so incoming reports can wake them.

Coordination uses a `0600` Unix socket at `<data_dir>/swarm.sock`, with a separate
session token for each pi process. Tokens are revoked when a worker stops and
rotated on recovery; these endpoints are not served on the browser's TCP listener.
No master or provider credentials are passed into guests.

Demo mode supports manually building and inspecting trees without model calls.
It does not simulate autonomous planner decisions.

## Session lifecycle

```text
allocating → starting → idle ⇄ working
                         ↓
                      sleeping → asleep → waking → idle

uncertain create → allocation_unknown → reconcile → interrupted
uncertain live operation / master restart → interrupted → recover → starting
idle / working / asleep / interrupted → closing → closed
```

Transitions are persisted before external side effects and validated in Rust.
A per-session async lock serializes prompt, wake, sleep, recover and close; a
process-wide file lock prevents two masters from using the same SQLite database.

| Operation    | Behavior                                                                                                                                              |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| New agent    | Persist session, create a **durable** VM, wait for its guest agent, start pi and require a remote-tool readiness handshake.                           |
| Prompt       | One in flight per session. Conversation events are journaled and delivered to React using durable sequence cursors.                                   |
| Idle timeout | Default 900 seconds, checked at most every 30 seconds. Only fully settled (`agent_settled`) sessions sleep. Browser polling does not keep them awake. |
| Sleep        | Close the idle pi worker; ask iso to **suspend** the VM. Preserve disk, VM ID, history and assignment.                                                |
| Wake         | Start the same VM and a fresh pi process with the same `--session` JSONL file, then send the new message.                                             |
| Stop agent   | Terminate pi and **halt the VM**, preserving its durable disk. Mark the session interrupted; recovery is explicit.                                    |
| Recover      | Stop any previous pi worker, halt/reboot the durable VM to fence off old guest commands, restore pi history. **Never replay a prompt.**               |
| Close        | Delete the VM/disk. Retain read-only conversation history. Failed deletes can be retried; an authoritative fleet listing confirms prior deletion.     |

**Sleep is suspension, not necessarily resource reclamation.** iso's suspend API
pauses/snapshots the VM in place; its slot and potentially its memory remain
allocated. This version does not evict suspended VMs to cold storage.

### Interrupted operations

- VM creation has no upstream idempotency key. An ambiguous create is **never
  automatically retried or failed over**. The VM carries a `master-session` label.
  **Reconcile** adopts it only if exactly one VM has that label on the assigned
  plane. Zero/multiple matches require operator inspection; the record remains
  blocked rather than allocating a replacement or guessing.
- HTTP disconnection does not prove an iso guest `exec` stopped. Recovery reboots
  the workspace; simply restarting pi could otherwise overlap old/new commands.
  Unsaved guest RAM state is lost during recovery, but disk files survive.
- Master restart preserves `asleep`, `closed`, and ambiguous-allocation states;
  formerly live sessions become `interrupted`. The operator reviews history and
  explicitly recovers them. A disconnected browser can reconnect without stopping
  the agent or restarting any prompt.
- Prompt rejection/timeout is surfaced; retry is a user decision. No exactly-once
  claim is made across an RPC/HTTP failure. Inspect history before resending.

## Security boundaries and current scope

This is a **single-operator prototype**, not a hardened multi-tenant or HA service.
All authenticated browser sessions can manage all agents and see their histories.
Keep the master private until you add your application's identity provider, per-user
ownership/authorization and audit policy.

- Login exchanges `MASTER_USER` / `MASTER_PASSWORD` for an opaque random cookie:
  HttpOnly, SameSite=Strict, Secure by default, expires after eight hours.
  Cookie tokens are stored hashed in memory; restart revokes browser sessions.
  Login attempts are rate-limited (ten per minute across this single-operator server).
- Mutations require a custom CSRF header and matching Origin when present; CORS is
  not enabled. Browser requests also reject `Sec-Fetch-Site: cross-site`.
- Master state is placed in a `0700` directory. Protect configs, provider secrets,
  certificates, SQLite/WAL files, pi session files and backups using OS permissions.
  Model messages and tool output may contain sensitive data.
- The pi process uses a cleared environment plus explicitly configured provider
  values. It does not inherit `MASTER_PASSWORD` or ambient GitHub credentials.
- The dedicated pi extension exposes remote `read`, `write`, `edit`, and
  `bash` for standalone agents/workers; swarm planners get read-only inspection
  and coordination tools as described above. There is **no local fallback**. Built-in tools, auto-discovered extensions,
  skills, prompt templates and context files are disabled; startup requires a
  readiness notification from the explicit remote extension.
- The browser cannot send arbitrary pi RPC commands, load extensions, select a
  credential principal, or supply a control-plane URL. `/` and `!` harness command
  input is disabled. Trusted operator config still has full authority.
- mTLS certificate verification is mandatory for live planes. Rust admin requests
  ignore ambient HTTP proxies and do not follow redirects. The extension uses
  direct HTTPS with the plane's CA and client identity too.
- Tool requests still have guest privileges, including passwordless sudo. Configure
  iso's jailer, egress policy and VPC isolation according to your threat model.

Limits: `max_agents` defaults to 16 live pi processes. Tool exec is capped at ten
minutes and 256 KiB per stdout/stderr stream. Browser events are capped at 256 KiB;
oversized events are replaced with a notice (full pi history remains on disk).
The read tool is text-only in this version; use shell tools for search. No file
uploads, interactive extension dialogs, conversation branching, runtime plane
registration, transcript deletion/retention job, or per-user RBAC yet. Plan storage
retention externally. SQLite calls are short synchronous operations; this is not
a high-throughput scheduler.

## Development and checks

```sh
cd contrib/master
npm ci --ignore-scripts
npm run dev
```

Vite proxies `/api` to `127.0.0.1:8080`. For development, set the master config's
`public_origin` to `http://localhost:5173` (or your exact Vite origin) and
`secure_cookie` to false. Do not use that cookie setting for remote deployments.

From the repository root:

```sh
scripts/check-master.sh
```

This checks rustfmt, **Clippy with `-D warnings`**, Rust tests, **ESLint with zero
warnings**, Prettier, TypeScript, Vitest, production build, and a **real pi RPC
smoke test against a mock mTLS server**. Requires OpenSSL on PATH for test-only
certificates. It never contacts a model or real iso host.

For the complete browser flow (login → create → chat → sleep → wake → fleet → close):

```sh
cd contrib/master
npx playwright install --with-deps chromium
cd ../..
RUN_BROWSER_TESTS=1 scripts/check-master.sh
```

Browser tests use a temporary database and two mock planes; they also check
transcript replay, no client-side exceptions and mobile horizontal overflow.
