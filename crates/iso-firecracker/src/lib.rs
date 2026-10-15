//! Firecracker backend implementing [`iso_common::VmRuntime`].
//!
//! Each microVM is a detached `firecracker` process launched **inside the VM's
//! netns** (via `setns` in a `pre_exec` hook — no `ip netns exec`), configured
//! over its API unix socket. Socket/pid/snapshot paths derive deterministically
//! from `(config, VmId)`, so the control plane re-adopts instances after a
//! restart via [`VmRuntime::status`].
//!
//! With [`Config::jailer`] set, the process is Firecracker's `jailer` instead:
//! a chroot per VM, an unprivileged uid and gid per VM, the netns joined by
//! the jailer, cgroup limits sized to the VM. See [`jail`] for the layout.
//!
//! Every freshly booted VM (so every template baked from now on, and its
//! clones) gets a virtio entropy device and, unless [`Config::rate_limits`]
//! is `None`, token-bucket limits on its disk, NIC and entropy device.

mod client;
pub mod jail;
mod pidfile;

pub use jail::JailerConfig;

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use iso_common::{Error, InstanceSpec, Result, SnapshotRef, VmId, VmRuntime, VmStatus};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The vsock unix socket, relative to the VMM's working directory. Relative on
/// purpose: a snapshot records the path, so every clone resumed from it must
/// resolve the same string to its *own* socket, which a per-VM cwd provides.
pub const VSOCK_UDS: &str = "v.sock";

/// How long a guest-channel `CONNECT` may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn be<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

/// Firecracker backend configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// `firecracker` binary.
    pub bin: PathBuf,
    /// Directory for per-VM API sockets.
    pub socket_dir: PathBuf,
    /// Directory for per-VM pidfiles, logs, and suspend snapshots.
    pub state_dir: PathBuf,
    /// Where named netns live (matches the network manager / `ip netns`).
    pub netns_dir: PathBuf,
    /// How long to wait for the API socket to appear after spawn.
    pub boot_timeout: Duration,
    /// Run every VM under `jailer` with these settings; `None` runs
    /// `firecracker` directly as the daemon's own user.
    pub jailer: Option<JailerConfig>,
    /// Limits Firecracker enforces on each VM's devices; `None` for none.
    /// Set at boot, so a snapshot carries the limits of the VM it was taken
    /// from: a template's clones get the bake's.
    pub rate_limits: Option<RateLimits>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bin: PathBuf::from("firecracker"),
            socket_dir: PathBuf::from("/run/iso/fc"),
            state_dir: PathBuf::from("/var/lib/iso/fc"),
            netns_dir: PathBuf::from("/var/run/netns"),
            boot_timeout: Duration::from_secs(10),
            jailer: None,
            rate_limits: Some(RateLimits::default()),
        }
    }
}

/// Per-VM device limits, each a token bucket refilled every second. The
/// defaults are generous on purpose: well above what one sandbox needs, low
/// enough that one VM cannot take a host's whole disk or uplink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimits {
    /// Root disk throughput, reads and writes together (default 1 GiB/s).
    pub disk_bytes_per_sec: u64,
    /// Root disk requests (default 50 000/s).
    pub disk_ops_per_sec: u64,
    /// NIC throughput in each direction (default 2 Gbit/s).
    pub net_bytes_per_sec: u64,
    /// Entropy device output (default 64 KiB/s): the guest kernel reads a
    /// few dozen bytes at a time.
    pub entropy_bytes_per_sec: u64,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            disk_bytes_per_sec: 1 << 30,
            disk_ops_per_sec: 50_000,
            net_bytes_per_sec: 250_000_000,
            entropy_bytes_per_sec: 64 << 10,
        }
    }
}

/// A Firecracker `rate_limiter` object: a bandwidth bucket of `bytes` per
/// second and, when given, an operations bucket of `ops` per second.
fn rate_limiter(bytes: u64, ops: Option<u64>) -> serde_json::Value {
    let mut v = json!({ "bandwidth": { "size": bytes, "refill_time": 1000 } });
    if let Some(ops) = ops {
        v["ops"] = json!({ "size": ops, "refill_time": 1000 });
    }
    v
}

/// What Firecracker's API is told about a VM's files: host paths when it runs
/// directly, jail-relative constants when it runs jailed.
struct ApiPaths {
    kernel: String,
    rootfs: String,
    snapshot_mem: String,
    snapshot_vmstate: String,
}

/// Move a file the jailed VMM just wrote out of the jail. `rename` first (both
/// sides normally live under the same state dir); fall back to copy+unlink when
/// they are on different filesystems.
fn move_out(src: &Path, dst: &Path) -> Result<()> {
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(src, dst).map_err(|e| Error::Backend(format!("copy {}: {e}", src.display())))?;
    let _ = std::fs::remove_file(src);
    Ok(())
}

pub struct FirecrackerRuntime {
    cfg: Config,
    /// `cfg.bin` resolved to the canonical file, which is what the jailer
    /// names jails after (it follows symlinks). Falls back to `cfg.bin` when
    /// resolution fails; spawning then reports why.
    fc_bin: PathBuf,
    /// Children spawned this process lifetime (for reaping). Re-adopted VMs
    /// after a restart aren't here; they're handled via pidfile + socket.
    children: Mutex<HashMap<VmId, Child>>,
}

impl FirecrackerRuntime {
    pub fn new(cfg: Config) -> Self {
        let fc_bin = jail::resolve_bin(&cfg.bin).unwrap_or_else(|_| cfg.bin.clone());
        Self {
            cfg,
            fc_bin,
            children: Mutex::new(HashMap::new()),
        }
    }

    /// The jail root for `vm`, when jailing is on.
    fn jail_root(&self, vm: VmId) -> Option<PathBuf> {
        self.cfg
            .jailer
            .as_ref()
            .map(|j| j.jail_dir(&self.fc_bin, vm).join("root"))
    }

    fn socket(&self, vm: VmId) -> PathBuf {
        match self.jail_root(vm) {
            Some(root) => root.join("run/firecracker.socket"),
            None => self.cfg.socket_dir.join(format!("{vm}.sock")),
        }
    }
    fn pidfile(&self, vm: VmId) -> PathBuf {
        self.cfg.state_dir.join(format!("{vm}.pid"))
    }
    /// The VM's own directory: the VMM's working directory (so relative paths
    /// in its API, like the vsock socket, land here) and where `suspend` writes
    /// its snapshot.
    fn snap_dir(&self, vm: VmId) -> PathBuf {
        self.cfg.state_dir.join(vm.to_string())
    }

    /// Where a snapshot taken by [`VmRuntime::suspend`] lands: `mem` and
    /// `vmstate` files in this directory.
    ///
    /// The same place whether or not the VM is jailed. A jailed VMM writes into
    /// its own `snapshot/out` because it cannot write anywhere else, but
    /// `suspend` moves the result here before returning — the jail is torn down
    /// on the next spawn, so nothing may be left inside it.
    pub fn snapshot_dir(&self, vm: VmId) -> PathBuf {
        self.snap_dir(vm)
    }

    fn vsock_path(&self, vm: VmId) -> PathBuf {
        match self.jail_root(vm) {
            Some(root) => root.join(VSOCK_UDS),
            None => self.snap_dir(vm).join(VSOCK_UDS),
        }
    }

    /// Spawn the VM through `jailer`: build the jail on disk, then run the
    /// jailer (which joins the netns, drops privileges and execs Firecracker
    /// in place, so the child pid is the VMM's). Returns the API-side paths.
    fn spawn_jailed(&self, jailer: &JailerConfig, spec: &InstanceSpec) -> Result<ApiPaths> {
        std::fs::create_dir_all(&self.cfg.state_dir).map_err(be)?;
        let fc = jail::resolve_bin(&self.cfg.bin)?;
        let plan = jail::plan(jailer, &fc, &self.cfg.netns_dir.join(&spec.netns), spec);
        if plan.root != self.jail_root(spec.vm).expect("jailer is configured") {
            return Err(Error::Backend(
                "jail path changed since the runtime was built".into(),
            ));
        }
        jail::teardown(&plan.jail_dir);
        jail::materialize(&plan, jailer, &spec.rootfs_device)?;
        if !spec.tap.is_empty() {
            jail::give_tap(
                &self.cfg.netns_dir.join(&spec.netns),
                &spec.tap,
                plan.uid,
                plan.gid,
            )?;
        }

        let mut cmd = Command::new(&jailer.bin);
        cmd.args(&plan.args)
            .arg("--")
            .arg("--api-sock")
            .arg(jail::GUEST_API_SOCKET)
            .stdin(Stdio::null());
        if let Ok(log) = std::fs::File::create(self.cfg.state_dir.join(format!("{}.log", spec.vm)))
            && let Ok(log2) = log.try_clone()
        {
            cmd.stdout(log).stderr(log2);
        }
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let child = cmd
            .spawn()
            .map_err(|e| Error::Backend(format!("spawn {}: {e}", jailer.bin.display())))?;
        self.write_pidfile(spec.vm, &child)?;
        self.children.lock().unwrap().insert(spec.vm, child);
        Ok(ApiPaths {
            kernel: jail::GUEST_KERNEL.into(),
            rootfs: jail::GUEST_ROOTFS.into(),
            snapshot_mem: jail::GUEST_SNAPSHOT_IN_MEM.into(),
            snapshot_vmstate: jail::GUEST_SNAPSHOT_IN_VMSTATE.into(),
        })
    }

    /// Stop the VMM and remove its per-process scratch. `keep_snapshot` spares
    /// the state dir, which is where [`VmRuntime::suspend`] leaves the memory
    /// and vmstate a later start resumes from: a durable VM that stops has not
    /// thrown that away, only a destroyed one has.
    async fn teardown_vmm(&self, vm: VmId, keep_snapshot: bool) {
        self.kill(vm);
        let own_child = self.children.lock().unwrap().remove(&vm);
        match own_child {
            // our own child: reap it.
            Some(mut child) => {
                let _ = child.wait();
            }
            // VM re-adopted across a restart (no Child handle): wait for the
            // SIGKILL'd process to actually exit so its rootfs LV is released
            // before storage teardown (else lvremove fails on an open device).
            None => self.wait_dead(vm, Duration::from_secs(5)).await,
        }
        let _ = std::fs::remove_file(self.socket(vm));
        let _ = std::fs::remove_file(self.pidfile(vm));
        if !keep_snapshot {
            let _ = std::fs::remove_dir_all(self.snap_dir(vm));
        }
        // The jail always goes: its snapshot/in links are rebuilt from the
        // resume source on the next spawn, and spawn_jailed tears it down
        // anyway.
        if let Some(j) = &self.cfg.jailer {
            jail::teardown(&j.jail_dir(&self.fc_bin, vm));
            // Empty once the VMM is gone; a VMM still in it keeps it.
            let _ = std::fs::remove_dir(jail::cgroup_dir(&self.fc_bin, vm));
        }
    }

    /// Record `child` as `vm`'s VMM: its pid and start time, so a later
    /// daemon can tell it from whatever reuses the pid (see [`pidfile`]).
    fn write_pidfile(&self, vm: VmId, child: &Child) -> Result<()> {
        std::fs::write(self.pidfile(vm), pidfile::format(child.id())).map_err(be)
    }

    fn recorded(&self, vm: VmId) -> Option<pidfile::Recorded> {
        pidfile::parse(&std::fs::read_to_string(self.pidfile(vm)).ok()?)
    }

    /// Whether `args` are those of a VMM launched for `vm`: the jailer, and
    /// Firecracker once the jailer has exec'd it, carry `--id <vm>`; an
    /// unjailed Firecracker carries its own API socket. Both forms are
    /// accepted whatever the current config says, so a VM started under the
    /// other setting is still recognized (and stopped) as this VM's.
    fn names_vm(&self, vm: VmId, args: &[Vec<u8>]) -> bool {
        let unjailed_socket = self.cfg.socket_dir.join(format!("{vm}.sock"));
        pidfile::has_pair(args, "--id", vm.to_string().as_bytes())
            || pidfile::has_pair(args, "--api-sock", unjailed_socket.as_os_str().as_bytes())
    }

    /// Whether `vm`'s VMM is alive. Our own child is trusted (its pid cannot be
    /// reused before we reap it); a pidfile's pid only once it checks out.
    fn pid_alive(&self, vm: VmId) -> bool {
        if let Some(c) = self.children.lock().unwrap().get(&vm) {
            return unsafe { libc::kill(c.id() as i32, 0) == 0 };
        }
        self.recorded(vm)
            .is_some_and(|rec| pidfile::is_live(rec, |args| self.names_vm(vm, args)))
    }

    fn kill(&self, vm: VmId) {
        if let Some(c) = self.children.lock().unwrap().get(&vm) {
            unsafe { libc::kill(c.id() as i32, libc::SIGKILL) };
            return;
        }
        if let Some(rec) = self.recorded(vm) {
            pidfile::signal_if(rec.pid, libc::SIGKILL, || {
                pidfile::is_live(rec, |args| self.names_vm(vm, args))
            });
        }
    }

    /// Poll until `vm`'s process is gone (or `timeout` elapses).
    async fn wait_dead(&self, vm: VmId, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while self.pid_alive(vm) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Spawn a detached firecracker in `netns`, writing its pidfile.
    ///
    /// `rootfs_bind` is `Some((device, baked_path))` on snapshot resume: the
    /// snapshot reopens `baked_path` (the template's base device), so we redirect
    /// it to this VM's CoW `device` with a bind mount inside a fresh, private
    /// mount namespace. Without it every clone would write the shared template.
    fn spawn(&self, vm: VmId, netns: &str, rootfs_bind: Option<(&Path, &Path)>) -> Result<()> {
        std::fs::create_dir_all(&self.cfg.socket_dir).map_err(be)?;
        std::fs::create_dir_all(&self.cfg.state_dir).map_err(be)?;
        let vm_dir = self.snap_dir(vm);
        std::fs::create_dir_all(&vm_dir).map_err(be)?;
        let socket = self.socket(vm);
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(self.vsock_path(vm));

        let ns_path = self.cfg.netns_dir.join(netns);
        // Owned, so that every return from here on, a failed spawn included,
        // closes it. The hook below uses the raw number in the child.
        let ns: OwnedFd = std::fs::File::open(&ns_path)
            .map_err(|e| Error::Backend(format!("open netns {ns_path:?}: {e}")))?
            .into();
        let nsfd = ns.as_raw_fd();

        // Prepare the bind paths as CStrings up front (no allocation in the
        // post-fork pre_exec hook, which must stay async-signal-safe).
        let bind = match rootfs_bind {
            Some((dev, baked)) => {
                let d = std::ffi::CString::new(dev.as_os_str().as_bytes()).map_err(be)?;
                let b = std::ffi::CString::new(baked.as_os_str().as_bytes()).map_err(be)?;
                Some((d, b))
            }
            None => None,
        };

        let mut cmd = Command::new(&self.cfg.bin);
        cmd.arg("--api-sock")
            .arg(&socket)
            .current_dir(&vm_dir)
            .stdin(Stdio::null());
        if let Ok(log) = std::fs::File::create(self.cfg.state_dir.join(format!("{vm}.log")))
            && let Ok(log2) = log.try_clone()
        {
            cmd.stdout(log).stderr(log2);
        }
        // Enter the netns, redirect the rootfs (resume only), and start a new
        // session (detach) before exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setns(nsfd, libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some((dev, baked)) = &bind {
                    // Private mount ns so the bind never leaks to the host.
                    if libc::unshare(libc::CLONE_NEWNS) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let root = c"/".as_ptr();
                    if libc::mount(
                        std::ptr::null(),
                        root,
                        std::ptr::null(),
                        libc::MS_REC | libc::MS_PRIVATE,
                        std::ptr::null(),
                    ) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    // Bind this VM's CoW device over the baked template path.
                    if libc::mount(
                        dev.as_ptr(),
                        baked.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    ) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                libc::setsid();
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(be)?;
        drop(ns);
        self.write_pidfile(vm, &child)?;
        self.children.lock().unwrap().insert(vm, child);
        Ok(())
    }

    /// The API calls that define a freshly booted VM, in order: `(path, body)`
    /// for a `PUT` each. `kernel` and `rootfs` are the paths as the VMM sees
    /// them. A resumed VM gets none of this: its snapshot carries the devices
    /// (and limits) of the VM it was taken from.
    fn boot_config(
        &self,
        spec: &InstanceSpec,
        kernel: &str,
        rootfs: &str,
    ) -> Vec<(&'static str, serde_json::Value)> {
        let limits = self.cfg.rate_limits;
        let mut calls = vec![
            (
                "/machine-config",
                json!({ "vcpu_count": spec.vcpus, "mem_size_mib": spec.mem_mib }),
            ),
            (
                "/boot-source",
                json!({ "kernel_image_path": kernel, "boot_args": spec.boot_args }),
            ),
        ];
        let mut drive = json!({
            "drive_id": "rootfs",
            "path_on_host": rootfs,
            "is_root_device": true,
            "is_read_only": false,
            // Honor guest flush/FUA so ext4 journaling is actually durable.
            // The Firecracker default ("Unsafe") silently drops flushes;
            // combined with snapshot-then-SIGKILL (no clean unmount), that
            // left the baked rootfs — notably a freshly-seeded `.git` — with
            // torn metadata on the LV, so every CoW clone read a corrupt repo.
            // Baked into the vmstate, so resumed clones inherit it too.
            "cache_type": "Writeback",
        });
        if let Some(l) = limits {
            drive["rate_limiter"] = rate_limiter(l.disk_bytes_per_sec, Some(l.disk_ops_per_sec));
        }
        calls.push(("/drives/rootfs", drive));
        if !spec.tap.is_empty() {
            let mut nic = json!({ "iface_id": "eth0", "host_dev_name": spec.tap, "guest_mac": spec.mac.to_string() });
            if let Some(l) = limits {
                nic["rx_rate_limiter"] = rate_limiter(l.net_bytes_per_sec, None);
                nic["tx_rate_limiter"] = rate_limiter(l.net_bytes_per_sec, None);
            }
            calls.push(("/network-interfaces/eth0", nic));
        }
        if let Some(cid) = spec.vsock_cid {
            // Relative path: resolved against the VMM's cwd (this VM's dir), and
            // recorded as-is in any snapshot so clones get their own socket.
            calls.push(("/vsock", json!({ "guest_cid": cid, "uds_path": VSOCK_UDS })));
        }
        // virtio-rng, fed from the host's getrandom. A clone resumes with the
        // kernel RNG state of the snapshot it came from, the same in every
        // clone; this is fresh host entropy for the guest to reseed from
        // (`iso-guest-agent --reseed`, see `iso_guest_agent::reseed`).
        let mut entropy = json!({});
        if let Some(l) = limits {
            entropy["rate_limiter"] = rate_limiter(l.entropy_bytes_per_sec, None);
        }
        calls.push(("/entropy", entropy));
        calls
    }

    async fn wait_socket(&self, vm: VmId) -> Result<()> {
        let socket = self.socket(vm);
        let deadline = Instant::now() + self.cfg.boot_timeout;
        let mut last_err = String::from("socket not present yet");
        while Instant::now() < deadline {
            if socket.exists() {
                match client::connect(&socket).await {
                    Ok(_) => return Ok(()),
                    Err(e) => last_err = e.to_string(),
                }
            }
            if !self.pid_alive(vm) {
                return Err(Error::Backend(
                    "firecracker exited before its API socket was ready".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Say what was waited for: with the jailer the path depends on how the
        // jailer named the jail, which is the first thing to check.
        let mut listing = String::new();
        if let Some(root) = self.jail_root(vm) {
            match std::fs::read_dir(&root) {
                Ok(rd) => {
                    let names: Vec<String> = rd
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    listing = format!("; jail root {} holds {names:?}", root.display());
                }
                Err(e) => listing = format!("; jail root {} unreadable: {e}", root.display()),
            }
        }
        Err(Error::Backend(format!(
            "timed out waiting for firecracker API socket {} (exists: {}; last connect error: {last_err}){listing}",
            socket.display(),
            socket.exists()
        )))
    }
}

impl VmRuntime for FirecrackerRuntime {
    async fn create(&self, spec: &InstanceSpec) -> Result<()> {
        let paths = match &self.cfg.jailer {
            Some(jailer) => self.spawn_jailed(jailer, spec)?,
            None => {
                // On resume, redirect the snapshot's baked rootfs path to this
                // VM's CoW device (see `spawn`); a fresh boot attaches
                // `rootfs_device` directly.
                let rootfs_bind = spec
                    .rootfs_backing
                    .as_deref()
                    .map(|baked| (spec.rootfs_device.as_path(), baked));
                self.spawn(spec.vm, &spec.netns, rootfs_bind)?;
                ApiPaths {
                    kernel: spec.kernel.to_string_lossy().into_owned(),
                    rootfs: spec.rootfs_device.to_string_lossy().into_owned(),
                    snapshot_mem: spec
                        .resume_from
                        .as_ref()
                        .map(|s| s.mem_file.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    snapshot_vmstate: spec
                        .resume_from
                        .as_ref()
                        .map(|s| s.vmstate.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                }
            }
        };
        self.wait_socket(spec.vm).await?;
        let socket = self.socket(spec.vm);

        if spec.resume_from.is_some() {
            // Load (paused). The TAP name is constant across netns, so the
            // snapshot's frozen network config is valid here without override.
            client::put(
                &socket,
                "/snapshot/load",
                json!({
                    "snapshot_path": paths.snapshot_vmstate,
                    "mem_backend": { "backend_type": "File", "backend_path": paths.snapshot_mem },
                    "enable_diff_snapshots": false,
                    "resume_vm": false,
                }),
            )
            .await?;
            return Ok(());
        }

        for (path, body) in self.boot_config(spec, &paths.kernel, &paths.rootfs) {
            client::put(&socket, path, body).await?;
        }
        Ok(())
    }

    async fn start(&self, vm: VmId) -> Result<()> {
        let socket = self.socket(vm);
        // resumed-from-snapshot instances are Paused; fresh ones are Not started.
        if client::state(&socket).await? == "Paused" {
            client::patch(&socket, "/vm", json!({ "state": "Resumed" })).await
        } else {
            client::put(
                &socket,
                "/actions",
                json!({ "action_type": "InstanceStart" }),
            )
            .await
        }
    }

    async fn suspend(&self, vm: VmId) -> Result<SnapshotRef> {
        let socket = self.socket(vm);
        // Firecracker refuses to snapshot a running microVM.
        client::patch(&socket, "/vm", json!({ "state": "Paused" })).await?;
        let dir = self.snap_dir(vm);
        std::fs::create_dir_all(&dir).map_err(be)?;
        let out = SnapshotRef {
            mem_file: dir.join("mem"),
            vmstate: dir.join("vmstate"),
        };

        // Jailed, the VMM writes into its own `snapshot/out` — never over the
        // `snapshot/in` links, which share the template's inode with every
        // other clone. Unjailed, it writes straight to the destination.
        let jail_root = self.jail_root(vm);
        let (vmstate, mem) = match &jail_root {
            Some(_) => (
                jail::GUEST_SNAPSHOT_OUT_VMSTATE.to_string(),
                jail::GUEST_SNAPSHOT_OUT_MEM.to_string(),
            ),
            None => (
                out.vmstate.to_string_lossy().into_owned(),
                out.mem_file.to_string_lossy().into_owned(),
            ),
        };
        client::put(
            &socket,
            "/snapshot/create",
            json!({ "snapshot_type": "Full", "snapshot_path": vmstate, "mem_file_path": mem }),
        )
        .await?;

        // Move it out of the jail: the next `spawn_jailed` tears the jail dir
        // down wholesale, so anything left inside is lost on the next start —
        // which is exactly the state we would want to resume from.
        if let Some(root) = jail_root {
            let snap_out = root.join("snapshot/out");
            move_out(&snap_out.join("vmstate"), &out.vmstate)?;
            move_out(&snap_out.join("mem"), &out.mem_file)?;
            // The VMM's own uid created them; every VM resuming them has
            // another, and none may write them.
            jail::seal_snapshot_file(&out.vmstate)?;
            jail::seal_snapshot_file(&out.mem_file)?;
        }
        Ok(out)
    }

    async fn stop(&self, vm: VmId) -> Result<()> {
        // graceful: guest ACPI shutdown; firecracker then exits.
        client::put(
            &self.socket(vm),
            "/actions",
            json!({ "action_type": "SendCtrlAltDel" }),
        )
        .await
    }

    async fn halt(&self, vm: VmId) -> Result<()> {
        self.kill(vm);
        Ok(())
    }

    async fn release(&self, vm: VmId) -> Result<()> {
        self.teardown_vmm(vm, true).await;
        Ok(())
    }

    async fn destroy(&self, vm: VmId) -> Result<()> {
        self.teardown_vmm(vm, false).await;
        Ok(())
    }

    /// Firecracker's host-initiated vsock handshake: connect to the VM's vsock
    /// unix socket, write `CONNECT <port>\n`, and read the `OK <port>\n` line;
    /// the stream is then the raw guest connection.
    async fn guest_channel(&self, vm: VmId, port: u32) -> Result<OwnedFd> {
        let path = self.vsock_path(vm);
        let connect = async {
            let mut s = client::connect(&path).await.map_err(|e| {
                Error::Backend(format!(
                    "connect to vsock socket {}: {e} (a template baked without a vsock device has none)",
                    path.display()
                ))
            })?;
            s.write_all(format!("CONNECT {port}\n").as_bytes())
                .await
                .map_err(be)?;
            let mut line = Vec::with_capacity(16);
            let mut b = [0u8; 1];
            loop {
                if s.read(&mut b).await.map_err(be)? == 0 {
                    return Err(Error::Backend(format!(
                        "vsock CONNECT {port} refused: nothing is listening on that guest port"
                    )));
                }
                if b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
                if line.len() > 32 {
                    return Err(Error::Backend("malformed vsock CONNECT reply".into()));
                }
            }
            let reply = String::from_utf8_lossy(&line);
            if !reply.starts_with("OK ") {
                return Err(Error::Backend(format!(
                    "vsock CONNECT {port} failed: {reply}"
                )));
            }
            let std = s.into_std().map_err(be)?;
            std.set_nonblocking(false).map_err(be)?;
            Ok(OwnedFd::from(std))
        };
        tokio::time::timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| Error::Backend(format!("vsock CONNECT {port} timed out")))?
    }

    async fn status(&self, vm: VmId) -> Result<VmStatus> {
        // reap if our own child has exited
        {
            let mut map = self.children.lock().unwrap();
            if let Some(child) = map.get_mut(&vm)
                && child.try_wait().map_err(be)?.is_some()
            {
                map.remove(&vm);
                return Ok(VmStatus::Stopped);
            }
        }
        let socket = self.socket(vm);
        if !socket.exists() {
            return Ok(if self.pid_alive(vm) {
                VmStatus::Created
            } else {
                VmStatus::Absent
            });
        }
        match client::state(&socket).await {
            Ok(s) if s == "Running" => Ok(VmStatus::Running),
            Ok(s) if s == "Paused" => Ok(VmStatus::Suspended),
            Ok(_) => Ok(VmStatus::Created),
            // The process is there but its API did not answer in time: wedged,
            // or busy (a snapshot of a large guest holds the API for minutes).
            // It is alive, so report it as running, not as `Created` (never
            // started) and never as `Stopped`/`Absent`, the two states the
            // supervisor takes for an exit and restarts. The next poll asks
            // again; only a process that is gone (or not this VM's) is
            // `Stopped`.
            Err(_) => Ok(if self.pid_alive(vm) {
                VmStatus::Running
            } else {
                VmStatus::Stopped
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iso_common::{MacAddr, SnapshotRef};
    use std::process::Command as P;

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn sh(args: &[&str]) -> bool {
        P::new(args[0])
            .args(&args[1..])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// A fresh scratch directory for one test.
    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("iso-fc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// An unjailed runtime rooted in `base`, whose `firecracker` does not exist.
    fn unjailed(base: &Path) -> FirecrackerRuntime {
        let rt = FirecrackerRuntime::new(Config {
            bin: base.join("no-such-firecracker"),
            socket_dir: base.join("sock"),
            state_dir: base.join("state"),
            netns_dir: base.join("netns"),
            boot_timeout: Duration::from_secs(1),
            jailer: None,
            ..Config::default()
        });
        for d in [&rt.cfg.socket_dir, &rt.cfg.state_dir, &rt.cfg.netns_dir] {
            std::fs::create_dir_all(d).unwrap();
        }
        rt
    }

    /// A live process whose command line names `socket` the way an unjailed
    /// VMM's does, in a process group of its own so the test can reap it whole.
    fn fake_vmm(socket: &Path) -> std::process::Child {
        let child = P::new("sh")
            .args(["-c", "sleep 30; exit 0", "firecracker", "--api-sock"])
            .arg(socket)
            .process_group(0)
            .spawn()
            .unwrap();
        // `spawn` can return before the exec: wait for the command line.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pidfile::args(child.id() as i32)
            .is_some_and(|a| pidfile::has_pair(&a, "--api-sock", socket.as_os_str().as_bytes()))
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        child
    }

    fn reap_group(mut child: std::process::Child) {
        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        let _ = child.wait();
    }

    /// A VMM that is alive but whose API does not answer (wedged, or busy
    /// writing a large snapshot) has not "never started": reporting `Created`
    /// made the supervisor restart it as if it had died.
    #[tokio::test]
    async fn a_live_vmm_whose_api_does_not_answer_is_still_running() {
        let base = scratch("status");
        let rt = unjailed(&base);
        let vm = VmId::from_u128(0x5747);
        let socket = rt.socket(vm);
        // Accepts, reads nothing, answers nothing.
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let vmm = fake_vmm(&socket);
        std::fs::write(rt.pidfile(vm), vmm.id().to_string()).unwrap();

        assert_eq!(rt.status(vm).await.unwrap(), VmStatus::Running);

        // Once the process is gone, an API that does not answer means it exited.
        reap_group(vmm);
        hold.abort();
        let _ = hold.await;
        assert_eq!(rt.status(vm).await.unwrap(), VmStatus::Stopped);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// After a daemon restart the pidfile is all there is, and its pid may
    /// since have been reused: whatever lives there now must not be killed.
    #[tokio::test]
    async fn a_pidfile_naming_another_process_kills_nothing() {
        let base = scratch("pidreuse");
        let rt = unjailed(&base);
        let vm = VmId::from_u128(0x9e5);
        let mut other = P::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(rt.pidfile(vm), other.id().to_string()).unwrap();

        rt.halt(vm).await.unwrap();
        // SIGKILL is not synchronous: give a wrongly signalled process time to die.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            other.try_wait().unwrap().is_none(),
            "halt killed the unrelated process"
        );
        assert_eq!(
            rt.status(vm).await.unwrap(),
            VmStatus::Absent,
            "an unrelated process is not this VM"
        );
        rt.destroy(vm).await.unwrap();
        assert!(
            other.try_wait().unwrap().is_none(),
            "destroy killed the unrelated process"
        );
        let _ = other.kill();
        let _ = other.wait();
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The check does not stop the runtime from stopping a VMM it re-adopted:
    /// one that is this VM's by start time and arguments is still killed, and
    /// one with this VM's arguments but another start time (its pid reused by
    /// a later VMM for the same VM, say) is not.
    #[tokio::test]
    async fn a_readopted_vmm_is_killed_only_if_it_is_the_one_recorded() {
        let base = scratch("readopt");
        let rt = unjailed(&base);
        let vm = VmId::from_u128(0xad0);
        let vmm = fake_vmm(&rt.socket(vm));
        let pid = vmm.id() as i32;
        let rec = pidfile::parse(&pidfile::format(vmm.id())).unwrap();

        let stale = format!("{pid} {}\n", rec.start.unwrap() + 1);
        std::fs::write(rt.pidfile(vm), stale).unwrap();
        assert_eq!(rt.status(vm).await.unwrap(), VmStatus::Absent);
        rt.halt(vm).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            pidfile::start_time(pid).is_some(),
            "killed a process the pidfile did not record"
        );

        std::fs::write(rt.pidfile(vm), pidfile::format(vmm.id())).unwrap();
        assert_eq!(
            rt.status(vm).await.unwrap(),
            VmStatus::Created,
            "alive, no API socket yet"
        );
        rt.destroy(vm).await.unwrap();
        assert!(
            pidfile::start_time(pid).is_none(),
            "destroy left the VMM running"
        );
        reap_group(vmm);
        let _ = std::fs::remove_dir_all(&base);
    }

    fn boot_spec() -> InstanceSpec {
        InstanceSpec {
            vm: VmId::from_u128(0xb007),
            netns: "vm0001".into(),
            tap: "tap0".into(),
            mac: MacAddr([0x02, 0, 0, 0, 0, 1]),
            rootfs_device: "/dev/iso/vm_b007".into(),
            vcpus: 2,
            mem_mib: 1024,
            kernel: "/k/vmlinux".into(),
            boot_args: "console=ttyS0".into(),
            resume_from: None,
            rootfs_backing: None,
            vsock_cid: Some(3),
        }
    }

    /// Every fresh VM gets a virtio entropy device (so a clone has host
    /// randomness to reseed from), and its disk, NIC and entropy device are
    /// rate limited unless the limits are turned off.
    #[test]
    fn boot_config_has_an_entropy_device_and_rate_limits() {
        let base = scratch("bootcfg");
        let rt = unjailed(&base);
        let calls = rt.boot_config(&boot_spec(), "/k/vmlinux", "/rootfs");
        let paths: Vec<&str> = calls.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            paths,
            [
                "/machine-config",
                "/boot-source",
                "/drives/rootfs",
                "/network-interfaces/eth0",
                "/vsock",
                "/entropy"
            ]
        );
        let body = |p: &str| calls.iter().find(|(q, _)| *q == p).unwrap().1.clone();
        let l = RateLimits::default();
        assert_eq!(
            body("/entropy")["rate_limiter"]["bandwidth"]["size"],
            l.entropy_bytes_per_sec
        );
        assert_eq!(
            body("/drives/rootfs")["rate_limiter"]["bandwidth"]["size"],
            l.disk_bytes_per_sec
        );
        assert_eq!(
            body("/drives/rootfs")["rate_limiter"]["ops"]["size"],
            l.disk_ops_per_sec
        );
        assert_eq!(body("/drives/rootfs")["cache_type"], "Writeback");
        for dir in ["rx_rate_limiter", "tx_rate_limiter"] {
            assert_eq!(
                body("/network-interfaces/eth0")[dir]["bandwidth"]["refill_time"],
                1000
            );
        }

        let unlimited = FirecrackerRuntime::new(Config {
            rate_limits: None,
            ..rt.cfg.clone()
        });
        let calls = unlimited.boot_config(
            &InstanceSpec {
                tap: String::new(),
                vsock_cid: None,
                ..boot_spec()
            },
            "/k",
            "/r",
        );
        let paths: Vec<&str> = calls.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            paths,
            [
                "/machine-config",
                "/boot-source",
                "/drives/rootfs",
                "/entropy"
            ]
        );
        assert!(calls.iter().all(|(_, b)| b.get("rate_limiter").is_none()));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A spawn that fails after the netns was opened must not leave the
    /// namespace fd open in the daemon.
    #[test]
    fn a_failed_spawn_does_not_leak_the_netns_fd() {
        let base = scratch("nsfd");
        let rt = unjailed(&base);
        // A regular file: it opens, and `setns` on it then fails in the child.
        let ns = rt.cfg.netns_dir.join("leak");
        std::fs::write(&ns, b"").unwrap();

        assert!(rt.spawn(VmId::from_u128(0x1ea4), "leak", None).is_err());
        let still_open = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .any(|target| target == ns);
        assert!(!still_open, "the netns fd outlived the failed spawn");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A Firecracker-compatible uncompressed guest kernel, from env or the nix store.
    fn find_kernel() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("ISO_TEST_KERNEL") {
            return Some(p.into());
        }
        for e in std::fs::read_dir("/nix/store").ok()?.flatten() {
            if e.file_name()
                .to_string_lossy()
                .contains("firecracker-vmlinux")
            {
                let k = e.path().join("vmlinux");
                if k.exists() {
                    return Some(k);
                }
            }
        }
        None
    }

    /// A netns with a TAP. `owner` is the jail uid/gid: attaching to a TAP
    /// without CAP_NET_ADMIN is only allowed to its owner, and a jailed
    /// Firecracker has neither the capability nor root.
    fn setup_netns(name: &str, owner: Option<(u32, u32)>) {
        let _ = sh(&["ip", "netns", "del", name]);
        assert!(sh(&["ip", "netns", "add", name]));
        let (uid, gid) = owner
            .map(|(u, g)| (u.to_string(), g.to_string()))
            .unwrap_or_default();
        let mut add = vec![
            "ip", "netns", "exec", name, "ip", "tuntap", "add", "dev", "tap0", "mode", "tap",
        ];
        if owner.is_some() {
            add.extend(["user", uid.as_str(), "group", gid.as_str()]);
        }
        assert!(sh(&add));
        assert!(sh(&[
            "ip", "netns", "exec", name, "ip", "link", "set", "tap0", "up"
        ]));
        let _ = sh(&["ip", "netns", "exec", name, "ip", "link", "set", "lo", "up"]);
    }

    fn make_rootfs(path: &str) {
        let _ = std::fs::remove_file(path);
        assert!(sh(&["truncate", "-s", "64M", path]));
        assert!(sh(&["mkfs.ext4", "-F", "-q", path]));
    }

    /// The guest agent binary: `ISO_TEST_AGENT`, or the workspace's debug build.
    fn find_agent() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("ISO_TEST_AGENT") {
            return Some(p.into());
        }
        let p =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/iso-guest-agent");
        p.exists().then_some(p)
    }

    /// An ext4 rootfs whose `/init` is the guest agent, with the shared
    /// libraries it links and an `/etc/hostname`. Populated with
    /// `mkfs.ext4 -d`, so it needs no mount. The kernel mounts devtmpfs on the
    /// empty `/dev` before running init, which gives the agent a console.
    fn make_agent_rootfs(path: &str, agent: &Path) {
        let stage = PathBuf::from(format!("{path}.stage"));
        let _ = std::fs::remove_dir_all(&stage);
        for d in [
            "etc",
            "tmp",
            "dev",
            "proc",
            "sys",
            "lib64",
            "lib/x86_64-linux-gnu",
        ] {
            std::fs::create_dir_all(stage.join(d)).unwrap();
        }
        std::fs::copy(agent, stage.join("init")).expect("copy agent");
        let libs = P::new("ldd").arg(agent).output().expect("ldd");
        for line in String::from_utf8_lossy(&libs.stdout).lines() {
            let lib = line.split_whitespace().find(|w| w.starts_with('/'));
            if let Some(lib) = lib {
                let dst = stage.join(lib.trim_start_matches('/'));
                std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
                std::fs::copy(lib, &dst).unwrap_or_else(|e| panic!("copy {lib}: {e}"));
            }
        }
        std::fs::write(stage.join("etc/hostname"), "fctest\n").unwrap();
        let _ = std::fs::remove_file(path);
        assert!(sh(&["truncate", "-s", "256M", path]));
        assert!(sh(&[
            "mkfs.ext4",
            "-F",
            "-q",
            "-d",
            stage.to_str().unwrap(),
            path
        ]));
        let _ = std::fs::remove_dir_all(&stage);
    }

    /// Open the guest agent through the VMM's channel.
    async fn agent_client(
        rt: &FirecrackerRuntime,
        vm: VmId,
    ) -> Result<iso_guest_proto::GuestClient<tokio::net::UnixStream>> {
        let fd = rt.guest_channel(vm, iso_guest_proto::DEFAULT_PORT).await?;
        let std = std::os::unix::net::UnixStream::from(fd);
        std.set_nonblocking(true).map_err(be)?;
        Ok(iso_guest_proto::GuestClient::new(
            tokio::net::UnixStream::from_std(std).map_err(be)?,
        ))
    }

    /// Poll until the agent inside `vm` answers a ping.
    async fn wait_agent(rt: &FirecrackerRuntime, vm: VmId) -> iso_guest_proto::AgentInfo {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last = String::new();
        while Instant::now() < deadline {
            match agent_client(rt, vm).await {
                Ok(mut c) => match c.ping().await {
                    Ok(info) => return info,
                    Err(e) => last = e.to_string(),
                },
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("guest agent in {vm} never answered: {last}");
    }

    /// A stock Debian rootfs built by image/debian/build-rootfs.sh, packed
    /// with `mkfs.ext4 -d`. Needs mmdebstrap, root, network, and the static
    /// agent (`ISO_TEST_AGENT_STATIC`, or `nix build .#iso-guest-agent-static`).
    fn make_debian_rootfs(path: &str, agent: &Path) -> bool {
        if P::new("mmdebstrap")
            .arg("--version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!("skipping: mmdebstrap not on PATH");
            return false;
        }
        let stage = PathBuf::from(format!("{path}.stage"));
        let _ = std::fs::remove_dir_all(&stage);
        let script =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../image/debian/build-rootfs.sh");
        let ok = P::new("bash")
            .arg(&script)
            .env("ROOTFS_DIR", &stage)
            .env("AGENT_BIN", agent)
            .env("MODE", "root")
            .env(
                "SUITE",
                std::env::var("ISO_TEST_DEBIAN_SUITE").unwrap_or_else(|_| "trixie".into()),
            )
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "build-rootfs.sh failed");
        let _ = std::fs::remove_file(path);
        assert!(sh(&["truncate", "-s", "2G", path]));
        assert!(sh(&[
            "mkfs.ext4",
            "-F",
            "-q",
            "-d",
            stage.to_str().unwrap(),
            path
        ]));
        let _ = std::fs::remove_dir_all(&stage);
        true
    }

    /// Boot a stock Debian guest on the flake's kernel, with systemd as init
    /// and the agent as a unit, and use it the way an agent would: run apt,
    /// read os-release, write a file. Self-skips unless root with a kernel,
    /// mmdebstrap and the static agent.
    #[tokio::test]
    async fn live_debian_guest_runs_apt_through_the_agent() {
        if !is_root() {
            eprintln!("skipping live_debian_guest_runs_apt_through_the_agent: requires root + KVM");
            return;
        }
        let Some(kernel) = find_kernel() else {
            eprintln!("skipping: no firecracker vmlinux found (set ISO_TEST_KERNEL)");
            return;
        };
        let Ok(agent) = std::env::var("ISO_TEST_AGENT_STATIC").map(PathBuf::from) else {
            eprintln!(
                "skipping: set ISO_TEST_AGENT_STATIC to a static iso-guest-agent (nix build .#iso-guest-agent-static)"
            );
            return;
        };

        let netns = "fcdebian";
        let base = PathBuf::from("/var/tmp/iso-fc-debian");
        let rootfs = "/var/tmp/iso-fc-debian/rootfs.ext4";
        let cfg = Config {
            bin: std::env::var("ISO_TEST_FC")
                .unwrap_or_else(|_| "firecracker".into())
                .into(),
            socket_dir: base.join("sock"),
            state_dir: base.join("state"),
            netns_dir: "/var/run/netns".into(),
            boot_timeout: Duration::from_secs(10),
            jailer: JailerConfig::from_env(&base),
            ..Config::default()
        };
        let rt = FirecrackerRuntime::new(cfg.clone());
        let vm = VmId::from_u128(0xdeb);
        let _ = rt.destroy(vm).await;
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        setup_netns(netns, cfg.jailer.as_ref().map(|j| (j.uid, j.gid)));
        if !make_debian_rootfs(rootfs, &agent) {
            return;
        }

        let spec = InstanceSpec {
            vm,
            netns: netns.into(),
            tap: "tap0".into(),
            mac: MacAddr([0x02, 0, 0, 0, 0xde, 0xb1]),
            rootfs_device: rootfs.into(),
            vcpus: 2,
            mem_mib: 1024,
            kernel,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/init"
                .into(),
            resume_from: None,
            rootfs_backing: None,
            vsock_cid: Some(3),
        };
        rt.create(&spec).await.expect("create");
        rt.start(vm).await.expect("start");
        let info = wait_agent(&rt, vm).await;
        assert_eq!(info.hostname, "iso-guest");
        assert_eq!(info.uid, 1000, "the unit runs the agent as coder");

        let mut c = agent_client(&rt, vm).await.unwrap();
        let run = |cmd: &str| iso_guest_proto::ExecRequest {
            cmd: "sh".into(),
            args: vec!["-c".into(), cmd.into()],
            timeout_ms: Some(60_000),
            ..Default::default()
        };
        let r = c
            .exec(run(
                ". /etc/os-release; echo $ID; systemctl is-system-running || true; whoami",
            ))
            .await
            .unwrap();
        assert_eq!(r.exit_code, Some(0), "{r:?}");
        let out: Vec<&str> = r.stdout.lines().collect();
        assert_eq!(out[0], "debian");
        assert!(
            matches!(out[1], "running" | "degraded" | "starting"),
            "systemd state: {}",
            out[1]
        );
        assert_eq!(out[2], "coder");
        // apt itself works offline; installing needs egress this test has none of.
        let r = c.exec(run("sudo -n apt-get --version | head -1 && test -f /etc/apt/sources.list && grep -c https /etc/apt/sources.list")).await.unwrap();
        assert_eq!(r.exit_code, Some(0), "{r:?}");
        assert!(r.stdout.starts_with("apt "), "{r:?}");
        let r = c
            .exec(run(
                "cat /etc/resolv.conf; test -f /etc/iso/AGENTS.md && echo notes",
            ))
            .await
            .unwrap();
        assert!(
            r.stdout.contains("172.22.0.1") && r.stdout.contains("notes"),
            "{r:?}"
        );
        assert_eq!(
            c.write_file("/home/coder/hello.txt", "aGk=".into(), None, false)
                .await
                .unwrap(),
            2
        );
        drop(c);

        rt.destroy(vm).await.expect("destroy");
        let _ = std::fs::remove_dir_all(&base);
        let _ = sh(&["ip", "netns", "del", netns]);
    }

    /// Boot a rootfs whose init is the guest agent, talk to it over vsock,
    /// snapshot, resume a clone under a different VM id, and talk to the clone:
    /// the relative `v.sock` path recorded in the snapshot must resolve to the
    /// clone's own socket. `ISO_JAILER=1` runs the same flow under the jailer.
    /// Self-skips unless root with a guest kernel and a built agent.
    #[tokio::test]
    async fn live_guest_agent_over_vsock_survives_snapshot_clone() {
        if !is_root() {
            eprintln!(
                "skipping live_guest_agent_over_vsock_survives_snapshot_clone: requires root + KVM"
            );
            return;
        }
        let Some(kernel) = find_kernel() else {
            eprintln!("skipping: no firecracker vmlinux found (set ISO_TEST_KERNEL)");
            return;
        };
        let Some(agent) = find_agent() else {
            eprintln!(
                "skipping: no guest agent binary (cargo build -p iso-guest-agent, or set ISO_TEST_AGENT)"
            );
            return;
        };

        let netns = "fcvsock";
        // /var/tmp, not /tmp: a jail needs device nodes, and /tmp is often a
        // tmpfs mounted nodev, where opening one fails with EACCES. Keeping the
        // rootfs images beside the jail also lets them be hard-linked in.
        let base = PathBuf::from("/var/tmp/iso-fc-vsock");
        let rootfs = "/var/tmp/iso-fc-vsock/rootfs.ext4";
        let rootfs2 = "/var/tmp/iso-fc-vsock/rootfs-clone.ext4";
        let cfg = Config {
            bin: std::env::var("ISO_TEST_FC")
                .unwrap_or_else(|_| "firecracker".into())
                .into(),
            socket_dir: base.join("sock"),
            state_dir: base.join("state"),
            netns_dir: "/var/run/netns".into(),
            boot_timeout: Duration::from_secs(10),
            jailer: JailerConfig::from_env(&base),
            ..Config::default()
        };
        eprintln!("jailer: {}", cfg.jailer.is_some());
        let rt = FirecrackerRuntime::new(cfg.clone());
        let vm1 = VmId::from_u128(0xa1);
        let vm2 = VmId::from_u128(0xa2);
        // A previous run that panicked left its VMs running: their pidfiles are
        // still in `base`, so destroy by id before wiping it.
        let _ = rt.destroy(vm1).await;
        let _ = rt.destroy(vm2).await;
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        setup_netns(netns, cfg.jailer.as_ref().map(|j| (j.uid, j.gid)));
        make_agent_rootfs(rootfs, &agent);

        // --- fresh boot with a vsock device ---
        let spec = InstanceSpec {
            vm: vm1,
            netns: netns.into(),
            tap: "tap0".into(),
            mac: MacAddr([0x02, 0, 0, 0, 0, 0xa1]),
            rootfs_device: rootfs.into(),
            vcpus: 1,
            mem_mib: 256,
            kernel: kernel.clone(),
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/init".into(),
            resume_from: None,
            rootfs_backing: None,
            vsock_cid: Some(3),
        };
        rt.create(&spec).await.expect("create vm1");
        rt.start(vm1).await.expect("start vm1");
        let info = wait_agent(&rt, vm1).await;
        assert_eq!(info.hostname, "fctest");
        assert_eq!(info.agent, "iso-guest-agent");

        // --- files through the agent ---
        {
            let mut c = agent_client(&rt, vm1).await.unwrap();
            assert_eq!(
                c.write_file("/tmp/hello", "aGk=".into(), Some(0o600), false)
                    .await
                    .unwrap(),
                2
            );
            let f = c.read_file("/tmp/hello", None).await.unwrap();
            assert_eq!(f.content_b64, "aGk=");
            let names: Vec<String> = c
                .list_dir("/")
                .await
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
            assert!(names.contains(&"init".to_string()), "{names:?}");
            // closed before the snapshot: Firecracker wants no live vsock connections then.
        }

        // --- snapshot, keep it, drop vm1 ---
        rt.suspend(vm1).await.expect("suspend vm1");
        let snap = rt.snapshot_dir(vm1);
        let tpl = base.join("tpl");
        std::fs::create_dir_all(&tpl).unwrap();
        std::fs::copy(snap.join("mem"), tpl.join("mem")).expect("copy mem");
        std::fs::copy(snap.join("vmstate"), tpl.join("vmstate")).expect("copy vmstate");
        rt.destroy(vm1).await.expect("destroy vm1");
        assert_eq!(rt.status(vm1).await.unwrap(), VmStatus::Absent);

        // --- a clone: its own rootfs copy behind the baked path, its own v.sock ---
        std::fs::copy(rootfs, rootfs2).unwrap();
        let clone = InstanceSpec {
            vm: vm2,
            rootfs_device: rootfs2.into(),
            rootfs_backing: Some(rootfs.into()),
            resume_from: Some(SnapshotRef {
                mem_file: tpl.join("mem"),
                vmstate: tpl.join("vmstate"),
            }),
            ..spec.clone()
        };
        rt.create(&clone).await.expect("create vm2 (load snapshot)");
        rt.start(vm2).await.expect("resume vm2");
        let info2 = wait_agent(&rt, vm2).await;
        assert_eq!(info2.hostname, "fctest");
        assert!(
            rt.vsock_path(vm2).exists(),
            "the resumed VM re-bound its vsock under its own directory"
        );
        {
            // the clone still has the file the template wrote, and writes go to its own copy
            let mut c = agent_client(&rt, vm2).await.unwrap();
            assert_eq!(
                c.read_file("/tmp/hello", None).await.unwrap().content_b64,
                "aGk="
            );
            c.write_file("/tmp/clone-only", "eA==".into(), None, false)
                .await
                .unwrap();
        }
        rt.destroy(vm2).await.expect("destroy vm2");

        // cleanup
        let _ = std::fs::remove_dir_all(&base);
        let _ = sh(&["ip", "netns", "del", netns]);
    }

    /// Full lifecycle against real Firecracker + KVM: fresh boot, suspend +
    /// snapshot, then resume a *fresh clone* from that snapshot reusing the
    /// constant TAP. Self-skips unless root with a guest kernel available.
    #[tokio::test]
    async fn live_boot_suspend_resume_clone() {
        if !is_root() {
            eprintln!("skipping live_boot_suspend_resume_clone: requires root + KVM");
            return;
        }
        let Some(kernel) = find_kernel() else {
            eprintln!("skipping: no firecracker vmlinux found");
            return;
        };

        let netns = "fctest";
        let rootfs = "/tmp/iso-fc-test.ext4";
        let base = PathBuf::from("/tmp/iso-fc-test");
        let _ = std::fs::remove_dir_all(&base);
        setup_netns(netns, None);
        make_rootfs(rootfs);

        let cfg = Config {
            bin: std::env::var("ISO_TEST_FC")
                .unwrap_or_else(|_| "firecracker".into())
                .into(),
            socket_dir: base.join("sock"),
            state_dir: base.join("state"),
            netns_dir: "/var/run/netns".into(),
            boot_timeout: Duration::from_secs(10),
            jailer: None,
            ..Config::default()
        };
        let rt = FirecrackerRuntime::new(cfg.clone());

        // --- fresh boot ---
        let vm1 = VmId::from_u128(0xf1);
        let spec = InstanceSpec {
            vm: vm1,
            netns: netns.into(),
            tap: "tap0".into(),
            mac: MacAddr([0x02, 0, 0, 0, 0, 1]),
            rootfs_device: rootfs.into(),
            vcpus: 1,
            mem_mib: 128,
            kernel: kernel.clone(),
            boot_args: "console=ttyS0 reboot=k pci=off".into(),
            resume_from: None,
            rootfs_backing: None,
            vsock_cid: None,
        };
        rt.create(&spec).await.expect("create vm1");
        rt.start(vm1).await.expect("start vm1");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            rt.status(vm1).await.unwrap(),
            VmStatus::Running,
            "vm1 running"
        );

        // --- suspend + snapshot ---
        rt.suspend(vm1).await.expect("suspend vm1");
        assert_eq!(rt.status(vm1).await.unwrap(), VmStatus::Suspended);
        let snap_src = cfg.state_dir.join(vm1.to_string());
        assert!(snap_src.join("mem").exists() && snap_src.join("vmstate").exists());

        // copy the snapshot to a template-like location that survives vm1's destroy
        let tpl = base.join("tpl");
        std::fs::create_dir_all(&tpl).unwrap();
        std::fs::copy(snap_src.join("mem"), tpl.join("mem")).unwrap();
        std::fs::copy(snap_src.join("vmstate"), tpl.join("vmstate")).unwrap();

        // free the tap by destroying vm1
        rt.destroy(vm1).await.expect("destroy vm1");
        assert_eq!(rt.status(vm1).await.unwrap(), VmStatus::Absent);

        // --- resume a fresh clone from the snapshot, reusing tap0 ---
        let vm2 = VmId::from_u128(0xf2);
        let clone = InstanceSpec {
            vm: vm2,
            resume_from: Some(SnapshotRef {
                mem_file: tpl.join("mem"),
                vmstate: tpl.join("vmstate"),
            }),
            ..spec.clone()
        };
        rt.create(&clone).await.expect("create vm2 (load snapshot)");
        rt.start(vm2).await.expect("resume vm2");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            rt.status(vm2).await.unwrap(),
            VmStatus::Running,
            "clone resumed from snapshot should be running"
        );

        rt.destroy(vm2).await.expect("destroy vm2");

        // cleanup
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_file(rootfs);
        let _ = sh(&["ip", "netns", "del", netns]);
    }
}
