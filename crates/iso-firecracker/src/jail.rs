//! Running Firecracker under its `jailer`.
//!
//! With a [`JailerConfig`] every VM gets a chroot of its own at
//! `<chroot_base>/<firecracker basename>/<vm id>/root`, the VMM drops to an
//! unprivileged uid and gid of its own (see [`JailerConfig::identity`]), and
//! the jailer joins the VM's network namespace. The
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
//! and cgroup and rlimit settings ([`limits`] derives defaults from the VM's
//! size, cgroup ones where the host offers their controllers). With any
//! cgroup setting the jailer moves the VMM into a cgroup of its own (see
//! [`cgroup_dir`]), out of the daemon's: a VMM there outlives the daemon's
//! service being stopped, and the next daemon re-adopts it. What it does
//! not do is copy in kernels or disks, which is the job of
//! [`materialize`], or hand the VM's TAP to its identity, which is
//! [`give_tap`]'s.

use std::ffi::{CString, OsString};
use std::hash::{Hash, Hasher};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use iso_common::{Error, InstanceSpec, Result, SlotId};

/// The first per-VM uid and gid by default: slot `s` runs as `65536 + s`, so
/// every slot falls in `65536..=98303`. That is above every 16-bit id (system
/// and login users, systemd's dynamic users, `nobody`) and below `100000`,
/// where `/etc/subuid` ranges for rootless containers begin by default. A
/// kernel compares ids, not names, so a range shared with another user's
/// containers would let their processes signal VMMs.
pub const DEFAULT_ID_BASE: u32 = 65536;

/// Run each VM under `jailer` with these settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JailerConfig {
    /// The `jailer` binary.
    pub bin: PathBuf,
    /// `--chroot-base-dir`: jails live at `<chroot_base>/<firecracker>/<vm>`.
    /// Must not be on a `nodev` mount, since the rootfs is a device node.
    pub chroot_base: PathBuf,
    /// The identity a VMM runs as when VMs do not get their own (`id_base`
    /// is `None`), and for a VM whose slot cannot be told from its netns.
    pub uid: u32,
    pub gid: u32,
    /// Give every VM a uid and gid of its own, `id_base + slot`: a VMM that
    /// escapes Firecracker then cannot signal, trace or open the files of
    /// its neighbours, as it could when they all shared one uid.
    pub id_base: Option<u32>,
    /// `--cgroup-version`.
    pub cgroup_version: u8,
    /// Derive per-VM cgroup and rlimit settings from the VM's size (see
    /// [`limits`]). `cgroups` and `resource_limits` override them key by key.
    pub default_limits: bool,
    /// The cgroup v2 controllers the host offers (the `cgroup.controllers` of
    /// [`CGROUP_ROOT`]), as [`Self::from_env`] found them. A derived cgroup
    /// default whose controller is not among them is left out: the jailer
    /// refuses a setting it has no controller for, which would fail every
    /// VM. `None` when not looked up, and every controller is assumed.
    pub cgroup_controllers: Option<Vec<String>>,
    /// `--cgroup <file>=<value>` settings, e.g. `cpu.max=200000 100000`.
    pub cgroups: Vec<String>,
    /// `--resource-limit <name>=<value>` settings, e.g. `no-file=4096`.
    pub resource_limits: Vec<String>,
}

impl JailerConfig {
    /// Jailer settings from the environment, or `None` when `ISO_JAILER` is
    /// one of `0`, `false`, `no`, `off`: jailed unless explicitly turned off.
    /// `ISO_JAILER_BIN` (default `jailer`), `ISO_JAIL_DIR` (default
    /// `<state_dir>/jail`), `ISO_JAIL_CGROUP_VERSION` (default 2), and the
    /// comma-separated `ISO_JAIL_CGROUPS` and `ISO_JAIL_RLIMITS` tune it.
    ///
    /// Each VM runs as uid and gid `ISO_JAIL_ID_BASE + slot` (default
    /// [`DEFAULT_ID_BASE`]). Setting `ISO_JAIL_UID` or `ISO_JAIL_GID` (default
    /// 65534) instead pins one identity for every VM, as does
    /// `ISO_JAIL_ID_BASE=off`; with `ISO_JAIL_ID_BASE` set as well, VMs keep
    /// their own ids and the pinned one serves only a VM whose netns is not
    /// a slot's.
    ///
    /// cgroup (v2) and rlimit defaults come from each VM's size, see
    /// [`limits`]; `ISO_JAIL_CGROUPS` and `ISO_JAIL_RLIMITS` entries replace
    /// the default for the same key, and `ISO_JAIL_LIMITS=off` drops the
    /// defaults, leaving only those entries. The cgroup defaults apply only
    /// where the host offers their controllers, read here once from
    /// [`CGROUP_ROOT`]; a default left out is logged, with why. Entries in
    /// `ISO_JAIL_CGROUPS` are passed on whatever the host offers.
    ///
    /// The default is the safe one: a VMM that is a direct child of root is
    /// the exception, and has to be asked for. `None` therefore means "the
    /// operator opted out", never "we could not work out how to jail" — the
    /// daemon resolves the jailer binary at startup and refuses to run if the
    /// jail is on but unusable, rather than quietly dropping the isolation.
    pub fn from_env(state_dir: &Path) -> Option<Self> {
        if let Ok(v) = std::env::var("ISO_JAILER")
            && matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        {
            return None;
        }
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let list = |k: &str| {
            var(k)
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default()
        };
        let pinned = var("ISO_JAIL_UID").is_some() || var("ISO_JAIL_GID").is_some();
        let id_base = id_base(var("ISO_JAIL_ID_BASE").as_deref(), pinned);
        let cgroup_version = var("ISO_JAIL_CGROUP_VERSION")
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        let default_limits = !var("ISO_JAIL_LIMITS").is_some_and(|v| is_off(&v));
        // Only the derived cgroup defaults depend on what the host offers.
        let cgroup_controllers = (default_limits && cgroup_version == 2).then(|| {
            let (offered, skipped) = offered_controllers(Path::new(CGROUP_ROOT));
            if let Some(why) = skipped {
                eprintln!("jailer: {why}");
            }
            offered
        });
        Some(Self {
            bin: var("ISO_JAILER_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| "jailer".into()),
            chroot_base: var("ISO_JAIL_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| state_dir.join("jail")),
            uid: var("ISO_JAIL_UID")
                .and_then(|v| v.parse().ok())
                .unwrap_or(65534),
            gid: var("ISO_JAIL_GID")
                .and_then(|v| v.parse().ok())
                .unwrap_or(65534),
            id_base,
            cgroup_version,
            default_limits,
            cgroup_controllers,
            cgroups: list("ISO_JAIL_CGROUPS"),
            resource_limits: list("ISO_JAIL_RLIMITS"),
        })
    }

    /// The uid and gid `netns`'s VM runs as: `id_base + slot`, with the slot
    /// read from the network manager's netns name (`vm` and four hex digits),
    /// or the shared `uid`/`gid` when per-VM ids are off or the name is not a
    /// slot's. Slots are unique among a host's running VMs, so no two of them
    /// share an id, and the id is the same every time the VM is started in
    /// the same slot, which is all a re-adopted VMM's files need.
    pub fn identity(&self, netns: &str) -> (u32, u32) {
        match (self.id_base, slot_of(netns)) {
            (Some(base), Some(slot)) => {
                let id = base.saturating_add(slot as u32);
                (id, id)
            }
            _ => (self.uid, self.gid),
        }
    }

    /// Whether the host offers cgroup `controller` (see
    /// [`Self::cgroup_controllers`]).
    fn offers(&self, controller: &str) -> bool {
        self.cgroup_controllers
            .as_ref()
            .is_none_or(|offered| offered.iter().any(|c| c == controller))
    }

    /// `<chroot_base>/<firecracker basename>/<vm>` — everything the jailer and
    /// [`materialize`] create for one VM, removed whole on destroy.
    pub fn jail_dir(&self, firecracker: &Path, vm: iso_common::VmId) -> PathBuf {
        let name = firecracker
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| "firecracker".into());
        self.chroot_base.join(name).join(vm.to_string())
    }
}

fn is_off(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// `ISO_JAIL_ID_BASE` (`setting`) read: off, a base (one that leaves room
/// for every slot, else the default), or, unset, the default unless the
/// operator pinned an identity with `ISO_JAIL_UID`/`ISO_JAIL_GID`.
fn id_base(setting: Option<&str>, pinned: bool) -> Option<u32> {
    match setting {
        Some(v) if is_off(v) => None,
        Some(v) => Some(
            v.trim()
                .parse()
                .ok()
                .filter(|b: &u32| b.checked_add(SlotId::MAX as u32).is_some())
                .unwrap_or(DEFAULT_ID_BASE),
        ),
        None if pinned => None,
        None => Some(DEFAULT_ID_BASE),
    }
}

/// The slot a netns belongs to, from the name the network manager gives it
/// (`vm{slot:04x}`, see its `fixture::derive`).
fn slot_of(netns: &str) -> Option<u16> {
    let hex = netns.strip_prefix("vm")?;
    if hex.len() != 4 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(hex, 16)
        .ok()
        .filter(|s| *s <= SlotId::MAX)
}

/// Where the host's cgroup v2 hierarchy is mounted. The jailer makes each
/// VM's cgroup under it (see [`cgroup_dir`]), and refuses a setting whose
/// controller its root's `cgroup.controllers` does not list.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The cgroup files [`limits`] derives a default for.
const DERIVED_CGROUPS: [&str; 3] = ["cpu.max", "memory.max", "pids.max"];

/// The controller a cgroup setting belongs to: its file name up to the first
/// `.`, as the jailer reads it (`cpu.max=…` is `cpu`'s).
fn controller(setting: &str) -> &str {
    setting.split(['.', '=']).next().unwrap_or(setting)
}

/// The controllers the cgroup v2 hierarchy at `root` offers, and, when that
/// leaves out any of the derived defaults, a line saying which and why. No
/// readable `cgroup.controllers` (cgroup v1, or a hybrid host's v2 mounted
/// elsewhere) offers none.
fn offered_controllers(root: &Path) -> (Vec<String>, Option<String>) {
    let file = root.join("cgroup.controllers");
    let read = std::fs::read_to_string(&file);
    let offered: Vec<String> = match &read {
        Ok(s) => s.split_whitespace().map(String::from).collect(),
        Err(_) => Vec::new(),
    };
    let skipped: Vec<&str> = DERIVED_CGROUPS
        .into_iter()
        .filter(|c| !offered.iter().any(|o| o == controller(c)))
        .collect();
    if skipped.is_empty() {
        return (offered, None);
    }
    let why = match &read {
        Ok(_) => {
            let missing: Vec<&str> = skipped.iter().map(|c| controller(c)).collect();
            format!(
                "the host offers no {} controller ({} lists {:?})",
                missing.join(", "),
                file.display(),
                offered.join(" ")
            )
        }
        Err(e) => format!("no cgroup v2 controllers at {} ({e})", file.display()),
    };
    let note = format!(
        "leaving out the default cgroup limits {}: {why}",
        skipped.join(", ")
    );
    (offered, Some(note))
}

/// The cgroup and rlimit settings for `spec`, as `(cgroups, rlimits)`:
/// derived defaults (when `jail.default_limits`) with `jail.cgroups` and
/// `jail.resource_limits` layered over them key by key.
///
/// The defaults, cgroup v2 only (v1 names the files differently), each where
/// the host offers its controller (`jail.cgroup_controllers`):
/// - `cpu.max`: one CPU more than the VM has vCPUs. The vCPU threads cannot
///   use more than one each anyway; the spare is for the VMM's own threads
///   (device emulation, the API).
/// - `memory.max`: guest memory plus an eighth of it, at least 256 MiB, for
///   the VMM, KVM's page tables and the page cache of the snapshot and disk
///   I/O it does (which is reclaimable, so it is throttled, not killed).
/// - `pids.max`: 64 plus the vCPU count. Firecracker runs a handful of
///   threads; this only stops an escaped VMM from forking without bound.
/// - `no-file=2048` (rlimit): the jailer's own default, made explicit.
///
/// No `fsize` limit by default: the VMM writes snapshots as large as guest
/// memory, and a file-backed rootfs is written under the same limit, so any
/// value safe for both bounds nothing a disk quota would not.
pub fn limits(jail: &JailerConfig, spec: &InstanceSpec) -> (Vec<String>, Vec<String>) {
    let mut cgroups = Vec::new();
    let mut rlimits = Vec::new();
    if jail.default_limits {
        if jail.cgroup_version == 2 {
            let mem = spec.mem_mib as u64;
            let headroom = (mem / 8).max(256);
            let derived = [
                format!(
                    "cpu.max={} 100000",
                    (spec.vcpus.max(1) as u64 + 1) * 100_000
                ),
                format!("memory.max={}", (mem + headroom) * 1024 * 1024),
                format!("pids.max={}", 64 + spec.vcpus),
            ];
            // A setting for a controller the host lacks fails the jailer,
            // and with it the VM: leave it out rather than fail every VM.
            cgroups.extend(derived.into_iter().filter(|c| jail.offers(controller(c))));
        }
        rlimits.push("no-file=2048".to_string());
    }
    (
        overlay(cgroups, &jail.cgroups),
        overlay(rlimits, &jail.resource_limits),
    )
}

/// `base` with every `key=value` in `over` replacing the entry for its key.
fn overlay(mut base: Vec<String>, over: &[String]) -> Vec<String> {
    let key = |s: &str| {
        s.split_once('=')
            .map(|(k, _)| k.trim().to_string())
            .unwrap_or_else(|| s.trim().to_string())
    };
    for o in over {
        base.retain(|b| key(b) != key(o));
    }
    base.extend(over.iter().cloned());
    base
}

/// The jail-relative paths Firecracker's API is given. Constant across VMs.
pub const GUEST_KERNEL: &str = "/vmlinux";
pub const GUEST_ROOTFS: &str = "/rootfs";
/// Resume inputs: hard links to the template's snapshot, shared with every
/// other clone and with the golden copy itself. **Read-only by contract** —
/// writing here would corrupt the snapshot every other VM resumes from.
pub const GUEST_SNAPSHOT_IN_MEM: &str = "/snapshot/in/mem";
pub const GUEST_SNAPSHOT_IN_VMSTATE: &str = "/snapshot/in/vmstate";
/// Suspend outputs: an empty directory owned by the jail identity, so the
/// dropped-privilege VMM can create its own files instead of being handed
/// root-owned ones it cannot open for write.
pub const GUEST_SNAPSHOT_OUT_MEM: &str = "/snapshot/out/mem";
pub const GUEST_SNAPSHOT_OUT_VMSTATE: &str = "/snapshot/out/vmstate";
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
    /// The identity the VMM drops to, which owns the jail's files.
    pub uid: u32,
    pub gid: u32,
    /// The jailer's arguments, up to but not including the `--` separator.
    pub args: Vec<OsString>,
}

/// Derive the jail for `spec`. `firecracker` must be an absolute path (the
/// jailer copies it into the jail); `netns_path` is the namespace file.
pub fn plan(
    jail: &JailerConfig,
    firecracker: &Path,
    netns_path: &Path,
    spec: &InstanceSpec,
) -> JailPlan {
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
                (s.mem_file.clone(), root.join("snapshot/in/mem")),
                (s.vmstate.clone(), root.join("snapshot/in/vmstate")),
            ]
        })
        .unwrap_or_default();

    let (uid, gid) = jail.identity(&spec.netns);
    let (cgroups, rlimits) = limits(jail, spec);
    let mut args: Vec<OsString> = Vec::new();
    let mut push = |k: &str, v: OsString| {
        args.push(k.into());
        args.push(v);
    };
    push("--id", spec.vm.to_string().into());
    push("--exec-file", firecracker.as_os_str().to_os_string());
    push("--uid", uid.to_string().into());
    push("--gid", gid.to_string().into());
    push(
        "--chroot-base-dir",
        jail.chroot_base.as_os_str().to_os_string(),
    );
    push("--cgroup-version", jail.cgroup_version.to_string().into());
    push("--netns", netns_path.as_os_str().to_os_string());
    for c in cgroups {
        push("--cgroup", c.into());
    }
    for r in rlimits {
        push("--resource-limit", r.into());
    }

    JailPlan {
        api_socket: root.join("run/firecracker.socket"),
        kernel: (spec.kernel.clone(), root.join("vmlinux")),
        rootfs_nodes,
        snapshot,
        uid,
        gid,
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
        return Err(be(
            &format!("chown {}", path.display()),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Create a block-device node at `node` with the same major:minor as `device`.
fn mknod_like(node: &Path, device: &Path, uid: u32, gid: u32) -> Result<()> {
    let meta =
        std::fs::metadata(device).map_err(|e| be(&format!("stat {}", device.display()), e))?;
    if !meta.file_type().is_block_device() {
        return Err(Error::Backend(format!(
            "jail: {} is not a block device",
            device.display()
        )));
    }
    if let Some(parent) = node.parent() {
        std::fs::create_dir_all(parent).map_err(|e| be("mkdir", e))?;
    }
    let _ = std::fs::remove_file(node);
    let c = CString::new(node.as_os_str().as_bytes()).map_err(|e| be("path", e))?;
    if unsafe {
        libc::mknod(
            c.as_ptr(),
            libc::S_IFBLK | 0o600,
            meta.rdev() as libc::dev_t,
        )
    } != 0
    {
        return Err(be(
            &format!("mknod {}", node.display()),
            std::io::Error::last_os_error(),
        ));
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
    let name = src
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "file".into());
    let cached_dir = cache_dir.join(format!("{:016x}", h.finish()));
    let cached = cached_dir.join(&name);
    if !cached.exists() {
        std::fs::create_dir_all(&cached_dir).map_err(|e| be("mkdir cache", e))?;
        let tmp = cached_dir.join(format!(
            ".{}.{}",
            name.to_string_lossy(),
            std::process::id()
        ));
        std::fs::copy(src, &tmp).map_err(|e| be(&format!("copy {}", src.display()), e))?;
        std::fs::rename(&tmp, &cached).map_err(|e| be("rename into cache", e))?;
    }
    if std::fs::hard_link(&cached, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(&cached, dst)
        .map(|_| ())
        .map_err(|e| be(&format!("copy {}", cached.display()), e))
}

/// Build the jail on disk: directories owned by the jail identity, the kernel
/// and snapshot linked in, and the rootfs device nodes pointing at
/// `rootfs_device`.
pub fn materialize(plan: &JailPlan, jail: &JailerConfig, rootfs_device: &Path) -> Result<()> {
    let (uid, gid) = (plan.uid, plan.gid);
    // `snapshot/in` holds links to the shared template snapshot; `snapshot/out`
    // is where suspend writes. They are separate directories because the same
    // path cannot be both: the inputs are hard links to a root-owned inode that
    // other VMs resume from, so a suspend writing over them would both fail
    // (the VMM is uid `plan.uid`, the file is root's) and, if it succeeded,
    // rewrite the golden snapshot through the shared inode.
    for dir in [
        &plan.root,
        &plan.root.join("run"),
        &plan.root.join("snapshot"),
        &plan.root.join("snapshot/in"),
        &plan.root.join("snapshot/out"),
    ] {
        std::fs::create_dir_all(dir).map_err(|e| be(&format!("mkdir {}", dir.display()), e))?;
        chown(dir, uid, gid)?;
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
            mknod_like(node, rootfs_device, uid, gid)?;
        } else {
            // A file-backed rootfs (tests, ad hoc images): link it in and let
            // the jailed VMM write it. A hard link shares the inode, so this
            // changes the source file's owner too.
            link_or_cache(rootfs_device, node, &cache)?;
            chown(node, uid, gid)?;
        }
    }
    Ok(())
}

/// Make the TAP `tap`, in the network namespace at `netns_path`, attachable
/// by `uid`/`gid`: without CAP_NET_ADMIN, which a jailed VMM does not have,
/// only a TAP's owner may attach to it. The network manager creates TAPs with
/// one owner for every slot; with an identity per VM, each VM's own has to be
/// set before its VMM starts. A TAP that does not exist is left to
/// Firecracker to report.
pub fn give_tap(netns_path: &Path, tap: &str, uid: u32, gid: u32) -> Result<()> {
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const TUNSETOWNER: libc::c_ulong = 0x4004_54cc;
    const TUNSETGROUP: libc::c_ulong = 0x4004_54ce;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;
    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    if tap.is_empty() || tap.len() >= libc::IFNAMSIZ {
        return Err(Error::Backend(format!("jail: bad tap name {tap:?}")));
    }
    let ns = std::fs::File::open(netns_path)
        .map_err(|e| be(&format!("open netns {}", netns_path.display()), e))?;
    let name = CString::new(tap).map_err(|e| be("tap name", e))?;
    // A thread of its own, which ends right after: `setns` moves only the
    // calling thread, and no other work may run in the VM's namespace.
    let work = move || -> Result<()> {
        let last = || std::io::Error::last_os_error();
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(be("setns", last()));
        }
        // Without this, TUNSETIFF would create a new (non-persistent) TAP.
        if unsafe { libc::if_nametoindex(name.as_ptr()) } == 0 {
            return Ok(());
        }
        // Opened after `setns`: the tun device resolves names in the
        // namespace it was opened in.
        let tun: OwnedFd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| be("open /dev/net/tun", e))?
            .into();
        let mut req = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TAP | IFF_NO_PI,
            _pad: [0; 22],
        };
        for (dst, b) in req.name.iter_mut().zip(name.as_bytes()) {
            *dst = *b as libc::c_char;
        }
        // Attaching to the persistent TAP, then dropping the fd, leaves it as
        // it was apart from its owner.
        if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &req) } < 0 {
            return Err(be(&format!("attach to {}", name.to_string_lossy()), last()));
        }
        if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETOWNER, uid as libc::c_int) } < 0 {
            return Err(be("TUNSETOWNER", last()));
        }
        if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETGROUP, gid as libc::c_int) } < 0 {
            return Err(be("TUNSETGROUP", last()));
        }
        Ok(())
    };
    std::thread::spawn(work)
        .join()
        .unwrap_or_else(|_| Err(Error::Backend("jail: give_tap panicked".into())))
}

/// Hand a snapshot file the jailed VMM wrote over to root, readable by all:
/// every VM identity has to be able to resume it (a template's by any clone,
/// a VM's own after it comes back in another slot), and none may write it,
/// since clones resume from it through hard links that share its inode.
pub fn seal_snapshot_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    chown(path, 0, 0)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| be(&format!("chmod {}", path.display()), e))
}

/// The cgroup (v2) the jailer creates for `vm`: `<mount>/<parent>/<vm>`, the
/// parent being the Firecracker binary's name. Nothing removes it when the
/// VMM exits, so teardown does.
pub fn cgroup_dir(firecracker: &Path, vm: iso_common::VmId) -> PathBuf {
    let name = firecracker
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "firecracker".into());
    Path::new(CGROUP_ROOT).join(name).join(vm.to_string())
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
            id_base: Some(70000),
            cgroup_version: 2,
            default_limits: true,
            cgroup_controllers: Some(
                ["cpuset", "cpu", "io", "memory", "pids"]
                    .map(String::from)
                    .to_vec(),
            ),
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
        let p = plan(
            &cfg(),
            Path::new("/opt/fc/firecracker"),
            Path::new("/var/run/netns/vm0003"),
            &spec(false),
        );
        let root = PathBuf::from(
            "/var/lib/iso/jail/firecracker/00000000-0000-0000-0000-000000000abc/root",
        );
        assert_eq!(p.root, root);
        assert_eq!(p.jail_dir, root.parent().unwrap());
        assert_eq!(p.api_socket, root.join("run/firecracker.socket"));
        assert_eq!(
            p.kernel,
            (
                "/nix/store/xyz-firecracker-vmlinux/vmlinux".into(),
                root.join("vmlinux")
            )
        );
        assert_eq!(p.rootfs_nodes, vec![root.join("rootfs")]);
        assert!(p.snapshot.is_empty());
        assert_eq!((p.uid, p.gid), (70003, 70003), "slot 3's own identity");
        let args: Vec<String> = p
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "--id",
                "00000000-0000-0000-0000-000000000abc",
                "--exec-file",
                "/opt/fc/firecracker",
                "--uid",
                "70003",
                "--gid",
                "70003",
                "--chroot-base-dir",
                "/var/lib/iso/jail",
                "--cgroup-version",
                "2",
                "--netns",
                "/var/run/netns/vm0003",
                "--cgroup",
                "memory.max=805306368",
                "--cgroup",
                "pids.max=65",
                "--cgroup",
                "cpu.max=200000 100000",
                "--resource-limit",
                "no-file=4096",
            ]
        );
    }

    #[test]
    fn every_slot_runs_as_its_own_uid_and_gid() {
        let c = cfg();
        assert_eq!(c.identity("vm0000"), (70000, 70000));
        assert_eq!(c.identity("vm0003"), (70003, 70003));
        assert_eq!(c.identity("vm7fff"), (70000 + 32767, 70000 + 32767));
        assert_ne!(c.identity("vm0001"), c.identity("vm0002"));
        // Not a slot's netns (a test's, say): the shared identity.
        assert_eq!(c.identity("fcvsock"), (1234, 1235));
        assert_eq!(c.identity("vm8000"), (1234, 1235), "past SlotId::MAX");
        assert_eq!(c.identity("vm003"), (1234, 1235));
        // Per-VM ids off: everyone shares the configured one.
        let shared = JailerConfig {
            id_base: None,
            ..cfg()
        };
        assert_eq!(shared.identity("vm0003"), (1234, 1235));
        // How the environment chooses.
        assert_eq!(id_base(None, false), Some(DEFAULT_ID_BASE));
        assert_eq!(
            id_base(None, true),
            None,
            "ISO_JAIL_UID/GID pin one identity"
        );
        assert_eq!(id_base(Some("200000"), true), Some(200_000));
        assert_eq!(id_base(Some("off"), false), None);
        assert_eq!(id_base(Some("0"), false), None, "never root + slot");
        assert_eq!(
            id_base(Some("4294967295"), false),
            Some(DEFAULT_ID_BASE),
            "no room for the slots"
        );
        // The default range sits between the 16-bit ids and the subuid ranges.
        let top = DEFAULT_ID_BASE + SlotId::MAX as u32;
        assert!(
            DEFAULT_ID_BASE > 65535 && top < 100_000,
            "{DEFAULT_ID_BASE}..={top}"
        );
    }

    #[test]
    fn limits_follow_the_vm_size_and_explicit_settings_win_per_key() {
        let mut s = spec(false);
        s.vcpus = 4;
        s.mem_mib = 4096;
        let none = JailerConfig {
            cgroups: vec![],
            resource_limits: vec![],
            ..cfg()
        };
        let (cg, rl) = limits(&none, &s);
        assert_eq!(
            cg,
            [
                "cpu.max=500000 100000",
                "memory.max=4831838208",
                "pids.max=68"
            ]
        );
        assert_eq!(rl, ["no-file=2048"]);
        // Small guests still get 256 MiB of headroom.
        s.mem_mib = 512;
        assert!(
            limits(&none, &s)
                .0
                .contains(&format!("memory.max={}", 768u64 << 20))
        );

        let (cg, rl) = limits(&cfg(), &s);
        assert_eq!(
            cg.iter()
                .filter(|c| c.starts_with("cpu.max="))
                .collect::<Vec<_>>(),
            ["cpu.max=200000 100000"]
        );
        assert_eq!(rl, ["no-file=4096"]);

        let off = JailerConfig {
            default_limits: false,
            ..cfg()
        };
        assert_eq!(
            limits(&off, &s),
            (
                vec!["cpu.max=200000 100000".to_string()],
                vec!["no-file=4096".to_string()]
            )
        );
        let v1 = JailerConfig {
            cgroup_version: 1,
            ..none
        };
        assert!(limits(&v1, &s).0.is_empty(), "the defaults name v2 files");
    }

    /// On a host whose cgroup v2 root lacks a default's controller the jailer
    /// refused the setting, and every VM failed to start. Only the defaults
    /// the host can enforce are derived; what the operator set passes as is.
    #[test]
    fn defaults_are_left_out_where_the_host_offers_no_controller() {
        let s = spec(false);
        let only = |offered: &[&str]| JailerConfig {
            cgroup_controllers: Some(offered.iter().map(|c| c.to_string()).collect()),
            cgroups: vec![],
            resource_limits: vec![],
            ..cfg()
        };
        assert_eq!(
            limits(&only(&["io", "memory"]), &s).0,
            ["memory.max=805306368"]
        );
        let (cg, rl) = limits(&only(&[]), &s);
        assert!(cg.is_empty(), "no cgroup v2 at all: {cg:?}");
        assert_eq!(rl, ["no-file=2048"], "rlimits are not cgroups");
        let asked = JailerConfig {
            cgroups: vec!["cpu.max=200000 100000".into()],
            ..only(&[])
        };
        assert_eq!(limits(&asked, &s).0, ["cpu.max=200000 100000"]);

        // Nothing for a missing controller reaches the jailer's arguments.
        let p = plan(
            &only(&["memory"]),
            Path::new("/opt/fc/firecracker"),
            Path::new("/var/run/netns/vm0003"),
            &s,
        );
        let cgroup_args: Vec<String> = p
            .args
            .windows(2)
            .filter(|w| w[0] == "--cgroup")
            .map(|w| w[1].to_string_lossy().into_owned())
            .collect();
        assert_eq!(cgroup_args, ["memory.max=805306368"]);
    }

    /// What the host offers is read from its cgroup root, and every default
    /// that leaves out is named, with why.
    #[test]
    fn the_hosts_controllers_come_from_its_cgroup_root() {
        let root = std::env::temp_dir().join(format!("iso-jail-cgroup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let controllers = root.join("cgroup.controllers");

        // A systemd host offers them all: nothing to say.
        std::fs::write(
            &controllers,
            "cpuset cpu io memory hugetlb pids rdma misc\n",
        )
        .unwrap();
        let (offered, note) = offered_controllers(&root);
        assert_eq!(offered.len(), 8);
        assert_eq!(note, None);

        let config = |offered| JailerConfig {
            cgroup_controllers: Some(offered),
            cgroups: vec![],
            ..cfg()
        };
        assert_eq!(limits(&config(offered), &spec(false)).0.len(), 3);

        // Some missing.
        std::fs::write(&controllers, "cpuset io memory\n").unwrap();
        let (offered, note) = offered_controllers(&root);
        assert_eq!(offered, ["cpuset", "io", "memory"]);
        let note = note.unwrap();
        assert!(
            note.starts_with("leaving out the default cgroup limits cpu.max, pids.max: "),
            "{note}"
        );
        assert!(note.contains("no cpu, pids controller"), "{note}");
        assert!(note.contains("\"cpuset io memory\""), "{note}");

        // No cgroup v2 there: a v1 host, or a hybrid one's v2 mounted below.
        std::fs::remove_file(&controllers).unwrap();
        let (offered, note) = offered_controllers(&root);
        assert!(offered.is_empty());
        let note = note.unwrap();
        assert!(note.contains("cpu.max, memory.max, pids.max"), "{note}");
        assert!(
            note.contains(&format!(
                "no cgroup v2 controllers at {}",
                controllers.display()
            )),
            "{note}"
        );
        assert!(limits(&config(offered), &spec(false)).0.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The TAP handed to a VM's identity: that uid can attach without
    /// CAP_NET_ADMIN, another cannot. Needs root, `unshare` and /dev/net/tun.
    #[test]
    fn give_tap_lets_the_vm_identity_and_no_other_attach() {
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
        const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
        #[repr(C)]
        struct IfReq {
            name: [libc::c_char; libc::IFNAMSIZ],
            flags: libc::c_short,
            _pad: [u8; 22],
        }
        fn req() -> IfReq {
            let mut r = IfReq {
                name: [0; libc::IFNAMSIZ],
                flags: 0x0002 | 0x1000,
                _pad: [0; 22],
            };
            for (d, b) in r.name.iter_mut().zip(b"tap0") {
                *d = *b as libc::c_char;
            }
            r
        }
        /// In `ns`, as `uid` (this thread only; raw syscalls, since libc's
        /// wrappers change every thread), try to attach to tap0.
        fn attach(ns: &Path, uid: Option<u32>, persist: bool) -> std::io::Result<()> {
            let ns = std::fs::File::open(ns)?;
            std::thread::spawn(move || {
                if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let tun = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/net/tun")?;
                if let Some(id) = uid {
                    unsafe {
                        libc::syscall(libc::SYS_setresgid, id, id, id);
                        libc::syscall(libc::SYS_setresuid, id, id, id);
                    }
                }
                if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &req()) } < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if persist && unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETPERSIST, 1) } < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .join()
            .unwrap()
        }

        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping give_tap test: requires root");
            return;
        }
        let Ok(mut holder) = std::process::Command::new("unshare")
            .args(["-n", "sleep", "30"])
            .spawn()
        else {
            eprintln!("skipping give_tap test: no unshare");
            return;
        };
        std::thread::sleep(std::time::Duration::from_millis(200));
        let ns = PathBuf::from(format!("/proc/{}/ns/net", holder.id()));
        if let Err(e) = attach(&ns, None, true) {
            eprintln!("skipping give_tap test: cannot create a TAP here: {e}");
            let _ = holder.kill();
            let _ = holder.wait();
            return;
        }

        give_tap(&ns, "tap0", 70003, 70003).unwrap();
        attach(&ns, Some(70003), false).expect("the VM's identity attaches");
        let other = attach(&ns, Some(70004), false).unwrap_err();
        assert_eq!(other.raw_os_error(), Some(libc::EPERM), "{other}");
        // A TAP that is not there is left alone (and not created).
        give_tap(&ns, "tap9", 70003, 70003).unwrap();
        let _ = holder.kill();
        let _ = holder.wait();
    }

    #[test]
    fn a_sealed_snapshot_is_roots_and_readable_by_every_vm() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: chown needs root");
            return;
        }
        let base = std::env::temp_dir().join(format!("iso-jail-seal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let f = base.join("mem");
        std::fs::write(&f, b"guest").unwrap();
        chown(&f, 70003, 70003).unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        seal_snapshot_file(&f).unwrap();
        let m = std::fs::metadata(&f).unwrap();
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o777), (0, 0, 0o644));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn plan_for_resume_links_the_snapshot_and_covers_the_baked_rootfs_path() {
        let p = plan(
            &cfg(),
            Path::new("/opt/fc/firecracker"),
            Path::new("/var/run/netns/vm0003"),
            &spec(true),
        );
        assert_eq!(
            p.snapshot,
            vec![
                (
                    "/var/lib/iso/templates/base/mem".into(),
                    p.root.join("snapshot/in/mem")
                ),
                (
                    "/var/lib/iso/templates/base/vmstate".into(),
                    p.root.join("snapshot/in/vmstate")
                ),
            ]
        );
        // both the jailed name and the unjailed bake's host path resolve to this VM's device
        assert_eq!(
            p.rootfs_nodes,
            vec![p.root.join("rootfs"), p.root.join("dev/iso/tpl_base")]
        );
    }

    #[test]
    fn a_jailed_bake_records_the_constant_rootfs_name_so_no_extra_node_is_needed() {
        let mut s = spec(true);
        s.rootfs_backing = Some(GUEST_ROOTFS.into());
        let p = plan(
            &cfg(),
            Path::new("/opt/fc/firecracker"),
            Path::new("/ns"),
            &s,
        );
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
            id_base: Some(DEFAULT_ID_BASE),
            cgroup_version: 2,
            default_limits: true,
            cgroup_controllers: None,
            cgroups: vec![],
            resource_limits: vec![],
        };
        assert_eq!(
            c.jail_dir(Path::new("/x/firecracker"), VmId::from_u128(1)),
            PathBuf::from("/s/jail/firecracker/00000000-0000-0000-0000-000000000001")
        );
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
        assert_eq!(
            std::fs::metadata(&src).unwrap().ino(),
            std::fs::metadata(&dst).unwrap().ino()
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
