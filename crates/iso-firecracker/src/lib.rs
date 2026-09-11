//! Firecracker backend implementing [`iso_common::VmRuntime`].
//!
//! Each microVM is a detached `firecracker` process launched **inside the VM's
//! netns** (via `setns` in a `pre_exec` hook — no `ip netns exec`), configured
//! over its API unix socket. Socket/pid/snapshot paths derive deterministically
//! from `(config, VmId)`, so the control plane re-adopts instances after a
//! restart via [`VmRuntime::status`].
//!
//! With [`Config::jailer`] set, the process is Firecracker's `jailer` instead:
//! a chroot per VM, an unprivileged uid, the netns joined by the jailer. See
//! [`jail`] for the layout.

mod client;
pub mod jail;

pub use jail::JailerConfig;

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use iso_common::{Error, InstanceSpec, Result, VmId, VmRuntime, VmStatus};
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
        }
    }
}

/// What Firecracker's API is told about a VM's files: host paths when it runs
/// directly, jail-relative constants when it runs jailed.
struct ApiPaths {
    kernel: String,
    rootfs: String,
    snapshot_mem: String,
    snapshot_vmstate: String,
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
        self.cfg.jailer.as_ref().map(|j| j.jail_dir(&self.fc_bin, vm).join("root"))
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
    /// `vmstate` files in this directory (inside the jail when jailed).
    pub fn snapshot_dir(&self, vm: VmId) -> PathBuf {
        match self.jail_root(vm) {
            Some(root) => root.join("snapshot"),
            None => self.snap_dir(vm),
        }
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
            return Err(Error::Backend("jail path changed since the runtime was built".into()));
        }
        jail::teardown(&plan.jail_dir);
        jail::materialize(&plan, jailer, &spec.rootfs_device)?;

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
        let child = cmd.spawn().map_err(|e| Error::Backend(format!("spawn {}: {e}", jailer.bin.display())))?;
        std::fs::write(self.pidfile(spec.vm), child.id().to_string()).map_err(be)?;
        self.children.lock().unwrap().insert(spec.vm, child);
        Ok(ApiPaths {
            kernel: jail::GUEST_KERNEL.into(),
            rootfs: jail::GUEST_ROOTFS.into(),
            snapshot_mem: jail::GUEST_SNAPSHOT_MEM.into(),
            snapshot_vmstate: jail::GUEST_SNAPSHOT_VMSTATE.into(),
        })
    }

    fn pid_of(&self, vm: VmId) -> Option<i32> {
        if let Some(c) = self.children.lock().unwrap().get(&vm) {
            return Some(c.id() as i32);
        }
        std::fs::read_to_string(self.pidfile(vm))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    fn pid_alive(&self, vm: VmId) -> bool {
        self.pid_of(vm)
            .map(|pid| unsafe { libc::kill(pid, 0) == 0 })
            .unwrap_or(false)
    }

    fn kill(&self, vm: VmId) {
        if let Some(pid) = self.pid_of(vm) {
            unsafe { libc::kill(pid, libc::SIGKILL) };
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
        let cpath = std::ffi::CString::new(ns_path.as_os_str().as_bytes()).map_err(be)?;
        let nsfd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if nsfd < 0 {
            return Err(Error::Backend(format!(
                "open netns {ns_path:?}: {}",
                std::io::Error::last_os_error()
            )));
        }

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
        unsafe { libc::close(nsfd) };
        std::fs::write(self.pidfile(vm), child.id().to_string()).map_err(be)?;
        self.children.lock().unwrap().insert(vm, child);
        Ok(())
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
                return Err(Error::Backend("firecracker exited before its API socket was ready".into()));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Say what was waited for: with the jailer the path depends on how the
        // jailer named the jail, which is the first thing to check.
        let mut listing = String::new();
        if let Some(root) = self.jail_root(vm) {
            match std::fs::read_dir(&root) {
                Ok(rd) => {
                    let names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
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
                    snapshot_mem: spec.resume_from.as_ref().map(|s| s.mem_file.to_string_lossy().into_owned()).unwrap_or_default(),
                    snapshot_vmstate: spec.resume_from.as_ref().map(|s| s.vmstate.to_string_lossy().into_owned()).unwrap_or_default(),
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

        client::put(
            &socket,
            "/machine-config",
            json!({ "vcpu_count": spec.vcpus, "mem_size_mib": spec.mem_mib }),
        )
        .await?;
        client::put(
            &socket,
            "/boot-source",
            json!({ "kernel_image_path": paths.kernel, "boot_args": spec.boot_args }),
        )
        .await?;
        client::put(
            &socket,
            "/drives/rootfs",
            json!({
                "drive_id": "rootfs",
                "path_on_host": paths.rootfs,
                "is_root_device": true,
                "is_read_only": false,
                // Honor guest flush/FUA so ext4 journaling is actually durable.
                // The Firecracker default ("Unsafe") silently drops flushes;
                // combined with snapshot-then-SIGKILL (no clean unmount), that
                // left the baked rootfs — notably a freshly-seeded `.git` — with
                // torn metadata on the LV, so every CoW clone read a corrupt repo.
                // Baked into the vmstate, so resumed clones inherit it too.
                "cache_type": "Writeback",
            }),
        )
        .await?;
        if !spec.tap.is_empty() {
            client::put(
                &socket,
                "/network-interfaces/eth0",
                json!({ "iface_id": "eth0", "host_dev_name": spec.tap, "guest_mac": spec.mac.to_string() }),
            )
            .await?;
        }
        if let Some(cid) = spec.vsock_cid {
            // Relative path: resolved against the VMM's cwd (this VM's dir), and
            // recorded as-is in any snapshot so clones get their own socket.
            client::put(&socket, "/vsock", json!({ "guest_cid": cid, "uds_path": VSOCK_UDS }))
                .await?;
        }
        Ok(())
    }

    async fn start(&self, vm: VmId) -> Result<()> {
        let socket = self.socket(vm);
        // resumed-from-snapshot instances are Paused; fresh ones are Not started.
        if client::state(&socket).await? == "Paused" {
            client::patch(&socket, "/vm", json!({ "state": "Resumed" })).await
        } else {
            client::put(&socket, "/actions", json!({ "action_type": "InstanceStart" })).await
        }
    }

    async fn suspend(&self, vm: VmId) -> Result<()> {
        let socket = self.socket(vm);
        client::patch(&socket, "/vm", json!({ "state": "Paused" })).await?;
        let (vmstate, mem) = if self.jail_root(vm).is_some() {
            (jail::GUEST_SNAPSHOT_VMSTATE.to_string(), jail::GUEST_SNAPSHOT_MEM.to_string())
        } else {
            let dir = self.snap_dir(vm);
            std::fs::create_dir_all(&dir).map_err(be)?;
            (
                dir.join("vmstate").to_string_lossy().into_owned(),
                dir.join("mem").to_string_lossy().into_owned(),
            )
        };
        client::put(
            &socket,
            "/snapshot/create",
            json!({ "snapshot_type": "Full", "snapshot_path": vmstate, "mem_file_path": mem }),
        )
        .await
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

    async fn destroy(&self, vm: VmId) -> Result<()> {
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
        let _ = std::fs::remove_dir_all(self.snap_dir(vm));
        if let Some(j) = &self.cfg.jailer {
            jail::teardown(&j.jail_dir(&self.fc_bin, vm));
        }
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
            s.write_all(format!("CONNECT {port}\n").as_bytes()).await.map_err(be)?;
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
                return Err(Error::Backend(format!("vsock CONNECT {port} failed: {reply}")));
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
            Err(_) => Ok(if self.pid_alive(vm) {
                VmStatus::Created
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

    /// A Firecracker-compatible uncompressed guest kernel, from env or the nix store.
    fn find_kernel() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("ISO_TEST_KERNEL") {
            return Some(p.into());
        }
        for e in std::fs::read_dir("/nix/store").ok()?.flatten() {
            if e.file_name().to_string_lossy().contains("firecracker-vmlinux") {
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
        let (uid, gid) = owner.map(|(u, g)| (u.to_string(), g.to_string())).unwrap_or_default();
        let mut add = vec!["ip", "netns", "exec", name, "ip", "tuntap", "add", "dev", "tap0", "mode", "tap"];
        if owner.is_some() {
            add.extend(["user", uid.as_str(), "group", gid.as_str()]);
        }
        assert!(sh(&add));
        assert!(sh(&["ip", "netns", "exec", name, "ip", "link", "set", "tap0", "up"]));
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
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/iso-guest-agent");
        p.exists().then_some(p)
    }

    /// An ext4 rootfs whose `/init` is the guest agent, with the shared
    /// libraries it links and an `/etc/hostname`. Populated with
    /// `mkfs.ext4 -d`, so it needs no mount. The kernel mounts devtmpfs on the
    /// empty `/dev` before running init, which gives the agent a console.
    fn make_agent_rootfs(path: &str, agent: &Path) {
        let stage = PathBuf::from(format!("{path}.stage"));
        let _ = std::fs::remove_dir_all(&stage);
        for d in ["etc", "tmp", "dev", "proc", "sys", "lib64", "lib/x86_64-linux-gnu"] {
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
        assert!(sh(&["mkfs.ext4", "-F", "-q", "-d", stage.to_str().unwrap(), path]));
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
        Ok(iso_guest_proto::GuestClient::new(tokio::net::UnixStream::from_std(std).map_err(be)?))
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

    /// Boot a rootfs whose init is the guest agent, talk to it over vsock,
    /// snapshot, resume a clone under a different VM id, and talk to the clone:
    /// the relative `v.sock` path recorded in the snapshot must resolve to the
    /// clone's own socket. `ISO_JAILER=1` runs the same flow under the jailer.
    /// Self-skips unless root with a guest kernel and a built agent.
    #[tokio::test]
    async fn live_guest_agent_over_vsock_survives_snapshot_clone() {
        if !is_root() {
            eprintln!("skipping live_guest_agent_over_vsock_survives_snapshot_clone: requires root + KVM");
            return;
        }
        let Some(kernel) = find_kernel() else {
            eprintln!("skipping: no firecracker vmlinux found (set ISO_TEST_KERNEL)");
            return;
        };
        let Some(agent) = find_agent() else {
            eprintln!("skipping: no guest agent binary (cargo build -p iso-guest-agent, or set ISO_TEST_AGENT)");
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
            bin: std::env::var("ISO_TEST_FC").unwrap_or_else(|_| "firecracker".into()).into(),
            socket_dir: base.join("sock"),
            state_dir: base.join("state"),
            netns_dir: "/var/run/netns".into(),
            boot_timeout: Duration::from_secs(10),
            jailer: JailerConfig::from_env(&base),
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
            assert_eq!(c.write_file("/tmp/hello", "aGk=".into(), Some(0o600), false).await.unwrap(), 2);
            let f = c.read_file("/tmp/hello", None).await.unwrap();
            assert_eq!(f.content_b64, "aGk=");
            let names: Vec<String> = c.list_dir("/").await.unwrap().into_iter().map(|e| e.name).collect();
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
            resume_from: Some(SnapshotRef { mem_file: tpl.join("mem"), vmstate: tpl.join("vmstate") }),
            ..spec.clone()
        };
        rt.create(&clone).await.expect("create vm2 (load snapshot)");
        rt.start(vm2).await.expect("resume vm2");
        let info2 = wait_agent(&rt, vm2).await;
        assert_eq!(info2.hostname, "fctest");
        assert!(rt.vsock_path(vm2).exists(), "the resumed VM re-bound its vsock under its own directory");
        {
            // the clone still has the file the template wrote, and writes go to its own copy
            let mut c = agent_client(&rt, vm2).await.unwrap();
            assert_eq!(c.read_file("/tmp/hello", None).await.unwrap().content_b64, "aGk=");
            c.write_file("/tmp/clone-only", "eA==".into(), None, false).await.unwrap();
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
            bin: std::env::var("ISO_TEST_FC").unwrap_or_else(|_| "firecracker".into()).into(),
            socket_dir: base.join("sock"),
            state_dir: base.join("state"),
            netns_dir: "/var/run/netns".into(),
            boot_timeout: Duration::from_secs(10),
            jailer: None,
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
        assert_eq!(rt.status(vm1).await.unwrap(), VmStatus::Running, "vm1 running");

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
