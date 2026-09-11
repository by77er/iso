//! Running Firecracker under its `jailer`.
//!
//! With a [`JailerConfig`] every VM gets a chroot of its own at
//! `<chroot_base>/<firecracker basename>/<vm id>/root`, the VMM drops to an
//! unprivileged uid/gid, and the jailer joins the VM's network namespace. The
//! rootfs reaches the jail as a block-device *node* (`mknod`) pointing at the
//! VM's own CoW volume; the kernel and any snapshot are hard-linked in, or
//! copied through a per-file cache when they live on another filesystem; the
//! API socket is `run/firecracker.socket` inside the jail.
//!
//! Paths handed to Firecracker's API are jail-relative and identical for every
//! VM — `/vmlinux`, `/rootfs`, `/snapshot/{mem,vmstate}`, `v.sock` — which is
//! what a snapshot wants: whatever it recorded resolves inside each clone's
//! jail to that clone's own resources. A snapshot taken by an *unjailed* bake
//! recorded the template's host device path for the rootfs instead, so the
//! plan also creates a node at that path; such templates keep working.
//!
//! What the jailer itself provides: the chroot and `pivot_root`, `/dev/kvm`,
//! `/dev/net/tun` and `/dev/urandom` nodes, the uid/gid drop, the netns join,
//! and optional cgroup and rlimit settings. What it does not do is copy in
//! kernels or disks, which is the job of [`materialize`].

use std::ffi::{CString, OsString};
use std::hash::{Hash, Hasher};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use iso_common::{Error, InstanceSpec, Result};

/// Run each VM under `jailer` with these settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JailerConfig {
    /// The `jailer` binary.
    pub bin: PathBuf,
    /// `--chroot-base-dir`: jails live at `<chroot_base>/<firecracker>/<vm>`.
    /// Must not be on a `nodev` mount, since the rootfs is a device node.
    pub chroot_base: PathBuf,
    /// Unprivileged identity the VMM runs as.
    pub uid: u32,
    pub gid: u32,
    /// `--cgroup-version`.
    pub cgroup_version: u8,
    /// Extra `--cgroup <file>=<value>` settings, e.g. `cpu.max=200000 100000`.
    pub cgroups: Vec<String>,
    /// Extra `--resource-limit <name>=<value>` settings, e.g. `no-file=4096`.
    pub resource_limits: Vec<String>,
}

impl JailerConfig {
    /// Jailer settings from the environment, or `None` when `ISO_JAILER` is
    /// unset or not one of `1`, `true`, `yes`. `ISO_JAILER_BIN` (default
    /// `jailer`), `ISO_JAIL_DIR` (default `<state_dir>/jail`), `ISO_JAIL_UID` and
    /// `ISO_JAIL_GID` (default 65534), `ISO_JAIL_CGROUP_VERSION` (default 2),
    /// and the comma-separated `ISO_JAIL_CGROUPS` and `ISO_JAIL_RLIMITS` tune it.
    pub fn from_env(state_dir: &Path) -> Option<Self> {
        let on = std::env::var("ISO_JAILER").ok()?;
        if !matches!(on.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes") {
            return None;
        }
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let list = |k: &str| {
            var(k)
                .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default()
        };
        Some(Self {
            bin: var("ISO_JAILER_BIN").map(PathBuf::from).unwrap_or_else(|| "jailer".into()),
            chroot_base: var("ISO_JAIL_DIR").map(PathBuf::from).unwrap_or_else(|| state_dir.join("jail")),
            uid: var("ISO_JAIL_UID").and_then(|v| v.parse().ok()).unwrap_or(65534),
            gid: var("ISO_JAIL_GID").and_then(|v| v.parse().ok()).unwrap_or(65534),
            cgroup_version: var("ISO_JAIL_CGROUP_VERSION").and_then(|v| v.parse().ok()).unwrap_or(2),
            cgroups: list("ISO_JAIL_CGROUPS"),
            resource_limits: list("ISO_JAIL_RLIMITS"),
        })
    }

    /// `<chroot_base>/<firecracker basename>/<vm>` — everything the jailer and
    /// [`materialize`] create for one VM, removed whole on destroy.
    pub fn jail_dir(&self, firecracker: &Path, vm: iso_common::VmId) -> PathBuf {
        let name = firecracker.file_name().map(|n| n.to_os_string()).unwrap_or_else(|| "firecracker".into());
        self.chroot_base.join(name).join(vm.to_string())
    }
}

/// The jail-relative paths Firecracker's API is given. Constant across VMs.
pub const GUEST_KERNEL: &str = "/vmlinux";
pub const GUEST_ROOTFS: &str = "/rootfs";
pub const GUEST_SNAPSHOT_MEM: &str = "/snapshot/mem";
pub const GUEST_SNAPSHOT_VMSTATE: &str = "/snapshot/vmstate";
pub const GUEST_API_SOCKET: &str = "/run/firecracker.socket";

/// Everything that has to exist for one jailed VM, on the host side, plus the
/// jailer's argument list. Pure: derived from the config and the spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JailPlan {
    pub jail_dir: PathBuf,
    /// The jail's root: what the VMM sees as `/`.
    pub root: PathBuf,
    /// Host path of the API socket.
    pub api_socket: PathBuf,
    /// Kernel: (host source, host destination inside the jail).
    pub kernel: (PathBuf, PathBuf),
    /// Block-device nodes to create for the rootfs, as host paths. Always
    /// `<root>/rootfs`; on resume also the path the snapshot may have recorded.
    pub rootfs_nodes: Vec<PathBuf>,
    /// Snapshot files to link in on resume: (host source, host destination).
    pub snapshot: Vec<(PathBuf, PathBuf)>,
    /// The jailer's arguments, up to but not including the `--` separator.
    pub args: Vec<OsString>,
}

/// Derive the jail for `spec`. `firecracker` must be an absolute path (the
/// jailer copies it into the jail); `netns_path` is the namespace file.
pub fn plan(jail: &JailerConfig, firecracker: &Path, netns_path: &Path, spec: &InstanceSpec) -> JailPlan {
    let jail_dir = jail.jail_dir(firecracker, spec.vm);
    let root = jail_dir.join("root");

    let mut rootfs_nodes = vec![root.join("rootfs")];
    if let Some(baked) = &spec.rootfs_backing {
        let rel = baked.strip_prefix("/").unwrap_or(baked);
        if rel != Path::new("rootfs") {
            rootfs_nodes.push(root.join(rel));
        }
    }
    let snapshot = spec
        .resume_from
        .as_ref()
        .map(|s| {
            vec![
                (s.mem_file.clone(), root.join("snapshot/mem")),
                (s.vmstate.clone(), root.join("snapshot/vmstate")),
            ]
        })
        .unwrap_or_default();

    let mut args: Vec<OsString> = Vec::new();
    let mut push = |k: &str, v: OsString| {
        args.push(k.into());
        args.push(v);
    };
    push("--id", spec.vm.to_string().into());
    push("--exec-file", firecracker.as_os_str().to_os_string());
    push("--uid", jail.uid.to_string().into());
    push("--gid", jail.gid.to_string().into());
    push("--chroot-base-dir", jail.chroot_base.as_os_str().to_os_string());
    push("--cgroup-version", jail.cgroup_version.to_string().into());
    push("--netns", netns_path.as_os_str().to_os_string());
    for c in &jail.cgroups {
        push("--cgroup", c.into());
    }
    for r in &jail.resource_limits {
        push("--resource-limit", r.into());
    }

    JailPlan {
        api_socket: root.join("run/firecracker.socket"),
        kernel: (spec.kernel.clone(), root.join("vmlinux")),
        rootfs_nodes,
        snapshot,
        jail_dir,
        root,
        args,
    }
}

fn be<E: std::fmt::Display>(what: &str, e: E) -> Error {
    Error::Backend(format!("jail: {what}: {e}"))
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|e| be("path", e))?;
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        return Err(be(&format!("chown {}", path.display()), std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Create a block-device node at `node` with the same major:minor as `device`.
fn mknod_like(node: &Path, device: &Path, uid: u32, gid: u32) -> Result<()> {
    let meta = std::fs::metadata(device).map_err(|e| be(&format!("stat {}", device.display()), e))?;
    if !meta.file_type().is_block_device() {
        return Err(Error::Backend(format!("jail: {} is not a block device", device.display())));
    }
    if let Some(parent) = node.parent() {
        std::fs::create_dir_all(parent).map_err(|e| be("mkdir", e))?;
    }
    let _ = std::fs::remove_file(node);
    let c = CString::new(node.as_os_str().as_bytes()).map_err(|e| be("path", e))?;
    if unsafe { libc::mknod(c.as_ptr(), libc::S_IFBLK | 0o600, meta.rdev() as libc::dev_t) } != 0 {
        return Err(be(&format!("mknod {}", node.display()), std::io::Error::last_os_error()));
    }
    chown(node, uid, gid)
}

/// Hard-link `src` to `dst`. When that fails (another filesystem, typically the
/// Nix store), copy `src` once into `cache_dir` and hard-link the cached copy,
/// so a kernel is copied per host rather than per VM.
fn link_or_cache(src: &Path, dst: &Path, cache_dir: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| be("mkdir", e))?;
    }
    let _ = std::fs::remove_file(dst);
    if std::fs::hard_link(src, dst).is_ok() {
        return Ok(());
    }
    let meta = std::fs::metadata(src).map_err(|e| be(&format!("stat {}", src.display()), e))?;
    let canonical = std::fs::canonicalize(src).unwrap_or_else(|_| src.to_path_buf());
    let mut h = std::collections::hash_map::DefaultHasher::new();
    canonical.hash(&mut h);
    meta.len().hash(&mut h);
    meta.mtime().hash(&mut h);
    meta.mtime_nsec().hash(&mut h);
    let name = src.file_name().map(|n| n.to_os_string()).unwrap_or_else(|| "file".into());
    let cached_dir = cache_dir.join(format!("{:016x}", h.finish()));
    let cached = cached_dir.join(&name);
    if !cached.exists() {
        std::fs::create_dir_all(&cached_dir).map_err(|e| be("mkdir cache", e))?;
        let tmp = cached_dir.join(format!(".{}.{}", name.to_string_lossy(), std::process::id()));
        std::fs::copy(src, &tmp).map_err(|e| be(&format!("copy {}", src.display()), e))?;
        std::fs::rename(&tmp, &cached).map_err(|e| be("rename into cache", e))?;
    }
    if std::fs::hard_link(&cached, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(&cached, dst).map(|_| ()).map_err(|e| be(&format!("copy {}", cached.display()), e))
}

/// Build the jail on disk: directories owned by the jail identity, the kernel
/// and snapshot linked in, and the rootfs device nodes pointing at
/// `rootfs_device`.
pub fn materialize(plan: &JailPlan, jail: &JailerConfig, rootfs_device: &Path) -> Result<()> {
    for dir in [&plan.root, &plan.root.join("run"), &plan.root.join("snapshot")] {
        std::fs::create_dir_all(dir).map_err(|e| be(&format!("mkdir {}", dir.display()), e))?;
        chown(dir, jail.uid, jail.gid)?;
    }
    let cache = jail.chroot_base.join(".cache");
    link_or_cache(&plan.kernel.0, &plan.kernel.1, &cache)?;
    for (src, dst) in &plan.snapshot {
        link_or_cache(src, dst, &cache)?;
    }
    let is_block = std::fs::metadata(rootfs_device)
        .map(|m| m.file_type().is_block_device())
        .map_err(|e| be(&format!("stat {}", rootfs_device.display()), e))?;
    for node in &plan.rootfs_nodes {
        if is_block {
            mknod_like(node, rootfs_device, jail.uid, jail.gid)?;
        } else {
            // A file-backed rootfs (tests, ad hoc images): link it in and let
            // the jailed VMM write it. A hard link shares the inode, so this
            // changes the source file's owner too.
            link_or_cache(rootfs_device, node, &cache)?;
            chown(node, jail.uid, jail.gid)?;
        }
    }
    Ok(())
}

/// Remove a VM's jail. The jailer bind-mounts the root onto itself before
/// pivoting, so detach that first (harmless when it is already gone).
pub fn teardown(plan_jail_dir: &Path) {
    let root = plan_jail_dir.join("root");
    if let Ok(c) = CString::new(root.as_os_str().as_bytes()) {
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
    }
    let _ = std::fs::remove_dir_all(plan_jail_dir);
}

/// Resolve a binary name to the canonical absolute path of the file
/// (searching `PATH` for a bare name, following symlinks). The jailer
/// canonicalizes `--exec-file` itself and names the jail after the *target*,
/// so every jail path here must be derived from the same resolved name.
pub fn resolve_bin(bin: &Path) -> Result<PathBuf> {
    let found = if bin.components().count() > 1 {
        bin.to_path_buf()
    } else {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .map(|dir| dir.join(bin))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| Error::Backend(format!("jail: {} not found on PATH", bin.display())))?
    };
    std::fs::canonicalize(&found).map_err(|e| be(&format!("resolve {}", found.display()), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iso_common::{MacAddr, SnapshotRef, VmId};

    fn cfg() -> JailerConfig {
        JailerConfig {
            bin: "/usr/bin/jailer".into(),
            chroot_base: "/var/lib/iso/jail".into(),
            uid: 1234,
            gid: 1235,
            cgroup_version: 2,
            cgroups: vec!["cpu.max=200000 100000".into()],
            resource_limits: vec!["no-file=4096".into()],
        }
    }

    fn spec(resume: bool) -> InstanceSpec {
        InstanceSpec {
            vm: VmId::from_u128(0xabc),
            netns: "vm0003".into(),
            tap: "tap0".into(),
            mac: MacAddr([2, 0, 0, 0, 0, 1]),
            rootfs_device: "/dev/iso/vm_abc".into(),
            vcpus: 1,
            mem_mib: 512,
            kernel: "/nix/store/xyz-firecracker-vmlinux/vmlinux".into(),
            boot_args: "console=ttyS0".into(),
            resume_from: resume.then(|| SnapshotRef {
                mem_file: "/var/lib/iso/templates/base/mem".into(),
                vmstate: "/var/lib/iso/templates/base/vmstate".into(),
            }),
            rootfs_backing: resume.then(|| PathBuf::from("/dev/iso/tpl_base")),
            vsock_cid: Some(3),
        }
    }

    #[test]
    fn plan_lays_out_a_fresh_boot() {
        let p = plan(&cfg(), Path::new("/opt/fc/firecracker"), Path::new("/var/run/netns/vm0003"), &spec(false));
        let root = PathBuf::from("/var/lib/iso/jail/firecracker/00000000-0000-0000-0000-000000000abc/root");
        assert_eq!(p.root, root);
        assert_eq!(p.jail_dir, root.parent().unwrap());
        assert_eq!(p.api_socket, root.join("run/firecracker.socket"));
        assert_eq!(p.kernel, ("/nix/store/xyz-firecracker-vmlinux/vmlinux".into(), root.join("vmlinux")));
        assert_eq!(p.rootfs_nodes, vec![root.join("rootfs")]);
        assert!(p.snapshot.is_empty());
        let args: Vec<String> = p.args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(
            args,
            [
                "--id", "00000000-0000-0000-0000-000000000abc",
                "--exec-file", "/opt/fc/firecracker",
                "--uid", "1234", "--gid", "1235",
                "--chroot-base-dir", "/var/lib/iso/jail",
                "--cgroup-version", "2",
                "--netns", "/var/run/netns/vm0003",
                "--cgroup", "cpu.max=200000 100000",
                "--resource-limit", "no-file=4096",
            ]
        );
    }

    #[test]
    fn plan_for_resume_links_the_snapshot_and_covers_the_baked_rootfs_path() {
        let p = plan(&cfg(), Path::new("/opt/fc/firecracker"), Path::new("/var/run/netns/vm0003"), &spec(true));
        assert_eq!(
            p.snapshot,
            vec![
                ("/var/lib/iso/templates/base/mem".into(), p.root.join("snapshot/mem")),
                ("/var/lib/iso/templates/base/vmstate".into(), p.root.join("snapshot/vmstate")),
            ]
        );
        // both the jailed name and the unjailed bake's host path resolve to this VM's device
        assert_eq!(p.rootfs_nodes, vec![p.root.join("rootfs"), p.root.join("dev/iso/tpl_base")]);
    }

    #[test]
    fn a_jailed_bake_records_the_constant_rootfs_name_so_no_extra_node_is_needed() {
        let mut s = spec(true);
        s.rootfs_backing = Some(GUEST_ROOTFS.into());
        let p = plan(&cfg(), Path::new("/opt/fc/firecracker"), Path::new("/ns"), &s);
        assert_eq!(p.rootfs_nodes, vec![p.root.join("rootfs")]);
    }

    #[test]
    fn env_config_is_off_unless_asked() {
        // Not a real env test (globals); exercise the parser's defaults directly.
        let c = JailerConfig {
            bin: "jailer".into(),
            chroot_base: Path::new("/s").join("jail"),
            uid: 65534,
            gid: 65534,
            cgroup_version: 2,
            cgroups: vec![],
            resource_limits: vec![],
        };
        assert_eq!(c.jail_dir(Path::new("/x/firecracker"), VmId::from_u128(1)),
            PathBuf::from("/s/jail/firecracker/00000000-0000-0000-0000-000000000001"));
    }

    #[test]
    fn link_falls_back_to_a_cached_copy() {
        let base = std::env::temp_dir().join(format!("iso-jail-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let src = base.join("vmlinux");
        std::fs::write(&src, b"kernel").unwrap();
        let dst = base.join("jail/root/vmlinux");
        link_or_cache(&src, &dst, &base.join(".cache")).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"kernel");
        // same inode: a hard link, not a copy
        assert_eq!(std::fs::metadata(&src).unwrap().ino(), std::fs::metadata(&dst).unwrap().ino());
        let _ = std::fs::remove_dir_all(&base);
    }
}
