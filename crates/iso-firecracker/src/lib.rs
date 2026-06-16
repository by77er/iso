//! Firecracker backend implementing [`iso_common::VmRuntime`].
//!
//! Each microVM is a detached `firecracker` process launched **inside the VM's
//! netns** (via `setns` in a `pre_exec` hook — no `ip netns exec`), configured
//! over its API unix socket. Socket/pid/snapshot paths derive deterministically
//! from `(config, VmId)`, so the control plane re-adopts instances after a
//! restart via [`VmRuntime::status`].

mod client;

use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use iso_common::{Error, InstanceSpec, Result, VmId, VmRuntime, VmStatus};
use serde_json::json;

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bin: PathBuf::from("firecracker"),
            socket_dir: PathBuf::from("/run/iso/fc"),
            state_dir: PathBuf::from("/var/lib/iso/fc"),
            netns_dir: PathBuf::from("/var/run/netns"),
            boot_timeout: Duration::from_secs(10),
        }
    }
}

pub struct FirecrackerRuntime {
    cfg: Config,
    /// Children spawned this process lifetime (for reaping). Re-adopted VMs
    /// after a restart aren't here; they're handled via pidfile + socket.
    children: Mutex<HashMap<VmId, Child>>,
}

impl FirecrackerRuntime {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            children: Mutex::new(HashMap::new()),
        }
    }

    fn socket(&self, vm: VmId) -> PathBuf {
        self.cfg.socket_dir.join(format!("{vm}.sock"))
    }
    fn pidfile(&self, vm: VmId) -> PathBuf {
        self.cfg.state_dir.join(format!("{vm}.pid"))
    }
    fn snap_dir(&self, vm: VmId) -> PathBuf {
        self.cfg.state_dir.join(vm.to_string())
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
    fn spawn(&self, vm: VmId, netns: &str) -> Result<()> {
        std::fs::create_dir_all(&self.cfg.socket_dir).map_err(be)?;
        std::fs::create_dir_all(&self.cfg.state_dir).map_err(be)?;
        let socket = self.socket(vm);
        let _ = std::fs::remove_file(&socket);

        let ns_path = self.cfg.netns_dir.join(netns);
        let cpath = std::ffi::CString::new(ns_path.as_os_str().as_bytes()).map_err(be)?;
        let nsfd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if nsfd < 0 {
            return Err(Error::Backend(format!(
                "open netns {ns_path:?}: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut cmd = Command::new(&self.cfg.bin);
        cmd.arg("--api-sock").arg(&socket).stdin(Stdio::null());
        if let Ok(log) = std::fs::File::create(self.cfg.state_dir.join(format!("{vm}.log")))
            && let Ok(log2) = log.try_clone()
        {
            cmd.stdout(log).stderr(log2);
        }
        // Enter the netns and start a new session (detach) before exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setns(nsfd, libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
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
        while Instant::now() < deadline {
            if socket.exists() && tokio::net::UnixStream::connect(&socket).await.is_ok() {
                return Ok(());
            }
            if !self.pid_alive(vm) {
                return Err(Error::Backend("firecracker exited before its API socket was ready".into()));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Err(Error::Backend("timed out waiting for firecracker API socket".into()))
    }
}

impl VmRuntime for FirecrackerRuntime {
    async fn create(&self, spec: &InstanceSpec) -> Result<()> {
        self.spawn(spec.vm, &spec.netns)?;
        self.wait_socket(spec.vm).await?;
        let socket = self.socket(spec.vm);

        if let Some(snap) = &spec.resume_from {
            // Load (paused). The TAP name is constant across netns, so the
            // snapshot's frozen network config is valid here without override.
            client::put(
                &socket,
                "/snapshot/load",
                json!({
                    "snapshot_path": snap.vmstate.to_string_lossy(),
                    "mem_backend": { "backend_type": "File", "backend_path": snap.mem_file.to_string_lossy() },
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
            json!({ "kernel_image_path": spec.kernel.to_string_lossy(), "boot_args": spec.boot_args }),
        )
        .await?;
        client::put(
            &socket,
            "/drives/rootfs",
            json!({
                "drive_id": "rootfs",
                "path_on_host": spec.rootfs_device.to_string_lossy(),
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
        let dir = self.snap_dir(vm);
        std::fs::create_dir_all(&dir).map_err(be)?;
        client::put(
            &socket,
            "/snapshot/create",
            json!({
                "snapshot_type": "Full",
                "snapshot_path": dir.join("vmstate").to_string_lossy(),
                "mem_file_path": dir.join("mem").to_string_lossy(),
            }),
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
        Ok(())
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

    fn setup_netns(name: &str) {
        let _ = sh(&["ip", "netns", "del", name]);
        assert!(sh(&["ip", "netns", "add", name]));
        assert!(sh(&["ip", "netns", "exec", name, "ip", "tuntap", "add", "dev", "tap0", "mode", "tap"]));
        assert!(sh(&["ip", "netns", "exec", name, "ip", "link", "set", "tap0", "up"]));
        let _ = sh(&["ip", "netns", "exec", name, "ip", "link", "set", "lo", "up"]);
    }

    fn make_rootfs(path: &str) {
        let _ = std::fs::remove_file(path);
        assert!(sh(&["truncate", "-s", "64M", path]));
        assert!(sh(&["mkfs.ext4", "-F", "-q", path]));
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
        setup_netns(netns);
        make_rootfs(rootfs);

        let cfg = Config {
            bin: std::env::var("ISO_TEST_FC").unwrap_or_else(|_| "firecracker".into()).into(),
            socket_dir: base.join("sock"),
            state_dir: base.join("state"),
            netns_dir: "/var/run/netns".into(),
            boot_timeout: Duration::from_secs(10),
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
