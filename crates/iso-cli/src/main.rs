//! `isoctl` — the iso command line: bake "warm" templates, manage the admin
//! CA, and drive VMs through the admin API (`isoctl vm …`, see `vm.rs`).
//!
//! A warm template is a *resume point*: a rootfs LV plus a Firecracker memory
//! snapshot taken once the guest has fully booted. The control plane then clones
//! VMs by thin-snapshotting the rootfs and resuming the shared memory snapshot —
//! millisecond boots. This keeps that one-shot, privileged flow out of the
//! long-running daemon.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod oci;
mod template;
mod vm;

use clap::{Parser, Subcommand};
use iso_common::{
    EgressMode, InstanceSpec, NetworkManager, NetworkPolicy, SlotId, SnapshotRef, StorageManager,
    VmId, VmRuntime,
};

type R<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(name = "isoctl", about = "iso out-of-band setup")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build a warm template: bake the rootfs, boot it once, snapshot it.
    Bake(Bake),
    /// The admin API's certificate authority: issue client certificates.
    Admin(Admin),
    /// Create, inspect and use VMs through the admin API.
    Vm(vm::Vm),
    /// Templates: list them, build one from an OCI image, follow a build.
    Template(template::Template),
}

#[derive(Parser)]
struct Admin {
    /// Directory holding the admin CA (the daemon's `ISO_ADMIN_TLS_DIR`).
    #[arg(long, default_value = "/var/lib/iso/admin-pki")]
    pki_dir: PathBuf,
    #[command(subcommand)]
    cmd: AdminCmd,
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Mint a client certificate signed by the admin CA and write
    /// `<name>.crt`, `<name>.key` and `ca.crt` into `--out`.
    IssueClient {
        /// Common name of the client, e.g. `orchestrator` or `alice@laptop`.
        #[arg(long)]
        name: String,
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// Mint a service identity (server + client auth) signed by the admin CA,
    /// for a proxy edge, a proxy replica, the CA service or the secrets
    /// service. Writes `<name>.crt`, `<name>.key` and `ca.crt` into `--out`.
    IssueServer {
        /// Common name, e.g. `proxy-1` or `edge-hostA`.
        #[arg(long)]
        name: String,
        /// DNS names or IPs the certificate is valid for as a server (repeatable).
        #[arg(long = "san")]
        sans: Vec<String>,
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// Print the admin CA certificate (PEM).
    Ca,
}

#[derive(Parser)]
struct Bake {
    /// Template name (rootfs LV `tpl_<name>` + snapshot dir).
    #[arg(long)]
    name: String,
    /// What fills the rootfs: `nixos` (the flake's image), `debian` (a stock
    /// Debian built by image/debian/build-rootfs.sh with mmdebstrap; agents get
    /// apt), or `oci` (an OCI image, see --image and --oci-tar; implied by
    /// either). All boot the flake's kernel and run the guest agent.
    #[arg(long, default_value = "nixos", value_parser = ["nixos", "debian", "oci"])]
    distro: String,
    /// Pull this OCI image from its registry and make it the rootfs, e.g.
    /// `python:3.12-slim`, `ghcr.io/acme/tool:v3`, `localhost:5000/x@sha256:…`.
    /// Anonymous, or `ISO_REGISTRY_AUTH=user:password` for a private
    /// registry. The image has no init; the guest agent is one.
    #[arg(long, conflicts_with = "oci_tar")]
    image: Option<String>,
    /// Like --image, from a tarball on disk: `docker save`, an OCI image
    /// layout, or a bare `docker export` rootfs.
    #[arg(long)]
    oci_tar: Option<PathBuf>,
    /// Debian suite for `--distro debian`.
    #[arg(long, default_value = "trixie")]
    debian_suite: String,
    /// Pin `--distro debian` to a snapshot.debian.org timestamp (e.g.
    /// 20260901T000000Z) for reproducible bytes.
    #[arg(long)]
    debian_snapshot: Option<String>,
    /// Extra Debian packages, comma-separated.
    #[arg(long)]
    debian_packages: Option<String>,
    /// Use this uncompressed guest kernel instead of building `#kernel` from
    /// the flake (for hosts without Nix, or to keep Nix out of a root shell).
    #[arg(long)]
    kernel: Option<PathBuf>,
    /// With `--distro debian`, use this static guest agent instead of building
    /// `#iso-guest-agent-static`.
    #[arg(long)]
    agent_bin: Option<PathBuf>,
    /// With `--distro debian`, the ssh public keys baked in for the coder user
    /// (default: <flake>/image/keys/authorized_keys).
    #[arg(long)]
    authorized_keys: Option<PathBuf>,
    /// The flake providing #kernel, #toplevel and #nixos-install-tools: this
    /// repository. Given as a plain path, so a git checkout contributes only
    /// its tracked files (a new module must be `git add`ed to be seen).
    #[arg(long, default_value = ".")]
    flake: String,
    /// State root (must match the control plane's ISO_STATE_DIR).
    #[arg(long, default_value = "/var/lib/iso")]
    state: PathBuf,
    /// LVM volume group (must match the control plane's).
    #[arg(long, default_value = "iso")]
    vg: String,
    /// Host uplink (for the builder's transient network namespace).
    #[arg(long, default_value = "eth0")]
    uplink: String,
    /// Rootfs LV virtual size.
    #[arg(long, default_value = "8G")]
    size: String,
    #[arg(long, default_value_t = 1)]
    vcpus: u32,
    #[arg(long, default_value_t = 512)]
    mem_mib: u32,
    /// Transient placement slot used for the builder VM.
    #[arg(long, default_value_t = 0)]
    slot: u16,
    /// Seconds to wait for the guest to come up before snapshotting.
    #[arg(long, default_value_t = 90)]
    boot_timeout: u64,
    /// Skip rebuilding the rootfs (mkfs + nixos-install) and re-snapshot the
    /// existing `tpl_<name>` instead. Use after editing/injecting a template.
    #[arg(long, default_value_t = false)]
    skip_install: bool,
    /// Extra nix store closures to copy into the rootfs and expose on the
    /// `coder` PATH (`~/.nix-profile/bin/<bin>`), e.g. the `pi` agent. Done
    /// BEFORE the snapshot so warm-resumed clones can see them. Repeatable.
    #[arg(long)]
    inject: Vec<String>,
    /// Seed a git repo into the rootfs as `src:dest`, e.g.
    /// `/srv/myrepo:/home/coder/myrepo`. Cloned single-branch from
    /// the local `main` (fast, no network), with the remote reset to `src`'s
    /// origin and a single-branch fetch refspec; owned by `coder`. CoW-shared
    /// across every VM cloned from the template. Repeatable.
    #[arg(long)]
    seed_repo: Vec<String>,
    /// Commands to run inside the builder through the guest agent (as the
    /// agent's user: `coder` on the Debian and NixOS images, the image's
    /// USER or root on an OCI image) AFTER boot and BEFORE the snapshot, e.g.
    /// to warm a toolchain once so it's CoW-shared across all VMs. Gives the
    /// builder direct egress. Non-fatal. Repeatable.
    #[arg(long)]
    provision: Vec<String>,
    /// Guest CID of the vsock device baked into the template, which is what the
    /// host's guest channel (exec, file access) rides on. Must match the
    /// control plane's `vsock_cid`.
    #[arg(long, default_value_t = 3)]
    vsock_cid: u32,
}

fn run(args: &[&str]) -> R<()> {
    let st = Command::new(args[0]).args(&args[1..]).status()?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("command failed ({st}): {}", args.join(" ")).into())
    }
}

fn run_out(args: &[&str]) -> R<String> {
    let out = Command::new(args[0]).args(&args[1..]).output()?;
    if !out.status.success() {
        return Err(format!(
            "command failed: {}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn nix_build(flake: &str, attr: &str) -> R<String> {
    let flake_abs = std::fs::canonicalize(flake)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| flake.to_string());
    run_out(&[
        "nix",
        "build",
        &format!("{flake_abs}#{attr}"),
        "--no-link",
        "--print-out-paths",
    ])
}

/// Copy nix closures into a (currently unmounted) rootfs LV and symlink each
/// closure's `bin/*` onto the `coder` user's PATH.
fn inject_closures(dev: &str, paths: &[String]) -> R<()> {
    let mnt = run_out(&["mktemp", "-d"])?;
    run(&["mount", dev, &mnt])?;
    let res = (|| -> R<()> {
        let bindir = format!("{mnt}/home/coder/.nix-profile/bin");
        run(&["install", "-d", "-o", "1000", "-g", "1000", &bindir])?;
        for path in paths {
            eprintln!("[bake] inject {path}");
            run(&["nix", "copy", "--no-check-sigs", "--to", &format!("local?root={mnt}"), path])?;
            for entry in std::fs::read_dir(format!("{path}/bin"))?.flatten() {
                let target = entry.path();
                let link = format!("{bindir}/{}", entry.file_name().to_string_lossy());
                let _ = std::fs::remove_file(&link);
                std::os::unix::fs::symlink(&target, &link)?;
                run(&["chown", "-h", "1000:1000", &link])?;
            }
        }
        Ok(())
    })();
    run(&["sync"]).ok();
    let _ = run(&["umount", "-R", &mnt]);
    res
}

/// Clone repos (single-branch `main`) into a rootfs LV, owned by `coder`.
fn seed_repos(dev: &str, specs: &[String]) -> R<()> {
    let mnt = run_out(&["mktemp", "-d"])?;
    run(&["mount", dev, &mnt])?;
    let res = (|| -> R<()> {
        for spec in specs {
            let (src, dest) = spec
                .split_once(':')
                .ok_or("--seed-repo must be src:dest")?;
            let target = format!("{mnt}{dest}");
            eprintln!("[bake] seed-repo {src} (main) -> {dest}");
            // Real remote to leave configured in the guest (so it fetches GitHub).
            let origin = run_out(&[
                "git", "-C", src, "-c", "safe.directory=*", "remote", "get-url", "origin",
            ])
            .unwrap_or_default();
            run(&[
                "git", "-c", "safe.directory=*", "clone", "--single-branch", "--branch", "main",
                "--no-tags", "--no-hardlinks", &format!("file://{src}"), &target,
            ])?;
            if !origin.is_empty() {
                run(&["git", "-C", &target, "remote", "set-url", "origin", &origin])?;
            }
            // Fetch only `main` going forward.
            run(&[
                "git", "-C", &target, "config", "remote.origin.fetch",
                "+refs/heads/main:refs/remotes/origin/main",
            ])?;
            run(&["chown", "-R", "1000:1000", &target])?;
        }
        Ok(())
    })();
    run(&["sync"]).ok();
    let _ = run(&["umount", "-R", &mnt]);
    res
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> R<()> {
    match Cli::parse().cmd {
        Cmd::Bake(b) => bake(b).await,
        Cmd::Admin(a) => admin(a),
        Cmd::Vm(v) => vm::run(v).await,
        Cmd::Template(t) => template::run(t).await,
    }
}

fn admin(a: Admin) -> R<()> {
    // Loading with no SANs never reissues an existing server certificate; a
    // missing CA is generated here exactly as the daemon would generate it.
    let pki = iso_admin_pki::AdminPki::load_or_generate(&a.pki_dir, &[])?;
    match a.cmd {
        AdminCmd::Ca => {
            print!("{}", pki.ca_cert_pem());
            Ok(())
        }
        AdminCmd::IssueServer { name, sans, out } => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let id = pki.issue_server(&name, &sans)?;
            std::fs::create_dir_all(&out)?;
            let crt = out.join(format!("{name}.crt"));
            let key = out.join(format!("{name}.key"));
            let ca = out.join("ca.crt");
            std::fs::write(&crt, &id.cert_pem)?;
            let _ = std::fs::remove_file(&key);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key)?
                .write_all(id.key_pem.as_bytes())?;
            std::fs::write(&ca, pki.ca_cert_pem())?;
            eprintln!(
                "issued service identity {name}: {} {} (CA: {})\n  ISO_TLS_CA={} ISO_TLS_CERT={} ISO_TLS_KEY={}",
                crt.display(),
                key.display(),
                ca.display(),
                ca.display(),
                crt.display(),
                key.display()
            );
            Ok(())
        }
        AdminCmd::IssueClient { name, out } => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let id = pki.issue_client(&name)?;
            std::fs::create_dir_all(&out)?;
            let crt = out.join(format!("{name}.crt"));
            let key = out.join(format!("{name}.key"));
            let ca = out.join("ca.crt");
            std::fs::write(&crt, &id.cert_pem)?;
            let _ = std::fs::remove_file(&key);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key)?
                .write_all(id.key_pem.as_bytes())?;
            std::fs::write(&ca, pki.ca_cert_pem())?;
            eprintln!(
                "issued {name}: {} {} (CA: {})\n  curl --cert {} --key {} --cacert {} https://<host>:7070/vms",
                crt.display(),
                key.display(),
                ca.display(),
                crt.display(),
                key.display(),
                ca.display()
            );
            Ok(())
        }
    }
}

async fn bake(b: Bake) -> R<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("bake must run as root (LVM, netns, KVM)".into());
    }

    let oci = b.distro == "oci" || b.image.is_some() || b.oci_tar.is_some();
    if oci && b.image.is_none() && b.oci_tar.is_none() {
        return Err("--distro oci needs --image or --oci-tar".into());
    }
    eprintln!("[bake] building {} image from flake {}", if oci { "oci" } else { &b.distro }, b.flake);
    let kernel = match &b.kernel {
        Some(k) => k.clone(),
        None => PathBuf::from(nix_build(&b.flake, "kernel")?).join("vmlinux"),
    };
    let debian = b.distro == "debian" && !oci;
    // NixOS: the system closure and the installer. Debian and OCI: the static
    // agent copied into the rootfs.
    let (toplevel, nixos_install, agent) = if debian || oci {
        let agent = match &b.agent_bin {
            Some(a) => a.to_string_lossy().into_owned(),
            None => format!("{}/bin/iso-guest-agent", nix_build(&b.flake, "iso-guest-agent-static")?),
        };
        (String::new(), String::new(), agent)
    } else {
        let toplevel = nix_build(&b.flake, "toplevel")?;
        let nixos_install = format!("{}/bin/nixos-install", nix_build(&b.flake, "nixos-install-tools")?);
        (toplevel, nixos_install, String::new())
    };
    eprintln!("[bake] kernel={}", kernel.display());

    // --- storage: backing pool + rootfs LV, install the system into it ---
    let scfg = iso_storage_manager::Config {
        image_path: b.state.join("storage.img"),
        image_size: 100 * 1024 * 1024 * 1024,
        vg: b.vg.clone(),
        ..Default::default()
    };
    let storage = iso_storage_manager::Manager::new(
        scfg,
        Arc::new(iso_storage_manager::command::SystemRunner),
    );
    storage.init().await?;
    let tpl_lv = storage.template_lv(&b.name);
    let dev = storage.dev_path(&tpl_lv);
    if b.skip_install {
        eprintln!("[bake] --skip-install: re-using existing rootfs {}", dev.display());
    } else {
        storage.create_template(&b.name, &b.size).await?;
        eprintln!(
            "[bake] mkfs + {} onto {}",
            if oci { "the image's layers" } else if debian { "mmdebstrap" } else { "nixos-install" },
            dev.display()
        );
        run(&["mkfs.ext4", "-F", "-q", &dev.to_string_lossy()])?;
        let mnt = run_out(&["mktemp", "-d"])?;
        run(&["mount", &dev.to_string_lossy(), &mnt])?;
        let install = if oci {
            oci_rootfs(&b, &mnt, &agent).await
        } else if debian {
            debian_rootfs(&b, &mnt, &agent)
        } else {
            run(&[
                &nixos_install, "--root", &mnt, "--system", &toplevel,
                "--no-bootloader", "--no-root-passwd", "--no-channel-copy",
            ])
        };
        run(&["sync"]).ok();
        let _ = run(&["umount", "-R", &mnt]);
        install?;
    }

    // Inject extra closures (e.g. `pi`) into the rootfs BEFORE booting/snapshotting:
    // warm-resumed clones restore a frozen page cache, so files added to the
    // template *after* the snapshot are invisible to them. Idempotent.
    if !b.inject.is_empty() {
        inject_closures(&dev.to_string_lossy(), &b.inject)?;
    }
    if !b.seed_repo.is_empty() {
        seed_repos(&dev.to_string_lossy(), &b.seed_repo)?;
    }

    // --- network: transient netns/veth/tap for the builder ---
    let jailer = iso_firecracker::JailerConfig::from_env(&b.state);
    let ncfg = iso_network_manager::Config {
        uplink: b.uplink.clone(),
        tap_owner: jailer.as_ref().map(|j| (j.uid, j.gid)),
        veth_net: std::env::var("ISO_VETH_NET")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(iso_network_manager::Config::default().veth_net),
        ..Default::default()
    };
    let net = iso_network_manager::Manager::new(ncfg.clone());
    net.init().await?;
    let slot = SlotId::new(b.slot)?;
    // Provisioning needs network; otherwise the builder needs no egress. The
    // builder is host tooling on a slot no VM occupies: it has no policy and
    // no proxy identity, so it goes out directly. Every VM goes through the
    // proxy.
    let policy = if b.provision.is_empty() {
        NetworkPolicy::default()
    } else {
        NetworkPolicy {
            egress: EgressMode::Proxy,
            ingress: Vec::new(),
            direct: true,
        }
    };
    let fixture = net.apply(slot, &policy).await?;

    // --- runtime: boot the builder VM directly on the rootfs LV ---
    // Honors ISO_JAILER / ISO_FIRECRACKER_BIN like the daemon, so a jailed host
    // bakes jailed: the snapshot then records the jail-relative `/rootfs` and
    // `v.sock` paths every clone resolves to its own resources.
    let fcfg = iso_firecracker::Config {
        bin: std::env::var("ISO_FIRECRACKER_BIN").map(PathBuf::from).unwrap_or_else(|_| "firecracker".into()),
        socket_dir: b.state.join("fc/sock"),
        state_dir: b.state.join("fc/state"),
        jailer,
        ..Default::default()
    };
    let rt = iso_firecracker::FirecrackerRuntime::new(fcfg.clone());
    let builder = VmId::from_u128(0xba6e_0000_0000_0000_0000_0000_0000_0001);
    let inner_vm = ncfg.inner_vm;
    let gw = ncfg.inner_tap;
    // An OCI image has no init: the agent is one when it finds itself PID 1.
    let init = if oci {
        "/usr/local/bin/iso-guest-agent"
    } else if debian {
        "/sbin/init"
    } else {
        "/nix/var/nix/profiles/system/init"
    };
    let boot_args = format!(
        "console=ttyS0 reboot=k panic=1 acpi=off quiet loglevel=3 \
         root=/dev/vda rootfstype=ext4 rw ip={inner_vm}::{gw}:255.255.255.254::eth0:off \
         init={init}"
    );
    let spec = InstanceSpec {
        vm: builder,
        netns: fixture.netns.clone(),
        tap: fixture.tap.clone(),
        mac: fixture.mac,
        rootfs_device: dev.clone(),
        vcpus: b.vcpus,
        mem_mib: b.mem_mib,
        kernel: kernel.clone(),
        boot_args: boot_args.clone(),
        resume_from: None,
        rootfs_backing: None,
        vsock_cid: Some(b.vsock_cid),
    };

    let result = bake_inner(&rt, &fixture.netns, builder, &spec, b.boot_timeout, &b.state, &b.name, &b.provision, b.vsock_cid).await;

    // always tear the builder down (keep the rootfs LV + the snapshot)
    let _ = rt.destroy(builder).await;
    let _ = net.teardown(slot).await;
    let (snap_mem, snap_vmstate) = result?;

    // --- emit the template registration (POST this to controld /templates) ---
    let reg = serde_json::json!({
        "name": b.name,
        "rootfs_template": b.name,
        "snapshot_mem": snap_mem.to_string_lossy(),
        "snapshot_vmstate": snap_vmstate.to_string_lossy(),
        "vcpus": b.vcpus,
        "mem_mib": b.mem_mib,
        "kernel": kernel.to_string_lossy(),
        "boot_args": boot_args,
    });
    // sanity: the SnapshotRef shape the control plane consumes.
    let _ = SnapshotRef { mem_file: snap_mem.clone(), vmstate: snap_vmstate.clone() };

    // Keep the registration beside the snapshot: iso-up.sh posts it on boot.
    let saved = b.state.join("templates").join(&b.name).join("template.json");
    std::fs::write(&saved, serde_json::to_string_pretty(&reg)?)?;
    eprintln!("[bake] registration saved to {}", saved.display());

    println!("{}", serde_json::to_string_pretty(&reg)?);
    eprintln!(
        "[bake] done. Register with:\n  curl -s --unix-socket {}/control.sock \
         -H 'content-type: application/json' -d @- http://x/templates <<'JSON'\n{}\nJSON",
        b.state.display(),
        serde_json::to_string_pretty(&reg)?
    );
    Ok(())
}

/// Fill a mounted volume with an OCI image's filesystem plus what a guest
/// needs on top: the agent (as init), the image's config for it, the
/// resolver, and the proxy's CA in every trust store.
async fn oci_rootfs(b: &Bake, mnt: &str, agent: &str) -> R<()> {
    let dest = Path::new(mnt);
    let boxed = |e: Box<dyn std::error::Error + Send + Sync>| -> Box<dyn std::error::Error> { e };
    let config = if let Some(image) = &b.image {
        oci::pull(image, dest).await.map_err(boxed)?
    } else if let Some(tar) = &b.oci_tar {
        oci::from_archive(tar, dest).map_err(boxed)?
    } else {
        return Err("--distro oci needs --image or --oci-tar".into());
    };
    if let Some(u) = &config.user {
        eprintln!("[bake] image user {u}, workdir {}", config.workdir.as_deref().unwrap_or("/"));
    }
    let ca = std::fs::read_to_string(b.state.join("ca/ca.crt")).ok();
    if ca.is_none() {
        eprintln!("[bake] warning: no {} on this host; guests will not trust the egress proxy", b.state.join("ca/ca.crt").display());
    }
    oci::install(dest, Path::new(agent), config, ca.as_deref()).map_err(boxed)?;
    Ok(())
}

/// Fill a mounted volume with a stock Debian through image/debian/build-rootfs.sh,
/// found next to the flake. The script needs mmdebstrap on PATH.
fn debian_rootfs(b: &Bake, mnt: &str, agent: &str) -> R<()> {
    let flake_abs = std::fs::canonicalize(&b.flake).unwrap_or_else(|_| PathBuf::from(&b.flake));
    let script = flake_abs.join("image/debian/build-rootfs.sh");
    if !script.exists() {
        return Err(format!("{} not found (is --flake the repository?)", script.display()).into());
    }
    let mut cmd = Command::new("bash");
    cmd.arg(&script)
        .env("ROOTFS_DIR", mnt)
        .env("AGENT_BIN", agent)
        .env("SUITE", &b.debian_suite)
        .env("MODE", "root");
    let keys = b.authorized_keys.clone().unwrap_or_else(|| flake_abs.join("image/keys/authorized_keys"));
    if keys.exists() {
        cmd.env("AUTHORIZED_KEYS", &keys);
    }
    // Trust this host's egress-proxy CA when it exists, as the NixOS image does
    // with image/ca.crt.
    let ca = b.state.join("ca/ca.crt");
    if ca.exists() {
        cmd.env("CA_CERT", &ca);
    }
    if let Some(snap) = &b.debian_snapshot {
        cmd.env("SNAPSHOT", snap);
    }
    if let Some(extra) = &b.debian_packages {
        cmd.env("EXTRA_PACKAGES", extra);
    }
    let st = cmd.status()?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("build-rootfs.sh failed ({st})").into())
    }
}

/// The guest agent inside the builder, over the VMM's vsock channel: how
/// the bake knows the guest is up, runs provisioning, and flushes the
/// filesystem, whatever the image is (an OCI image has no sshd).
async fn builder_agent(
    rt: &iso_firecracker::FirecrackerRuntime,
    vm: VmId,
) -> R<iso_guest_proto::GuestClient<tokio::net::UnixStream>> {
    use iso_common::runtime::VmRuntime as _;
    let fd = rt.guest_channel(vm, iso_guest_proto::DEFAULT_PORT).await?;
    let std = std::os::unix::net::UnixStream::from(fd);
    std.set_nonblocking(true)?;
    Ok(iso_guest_proto::GuestClient::new(tokio::net::UnixStream::from_std(std)?))
}

/// `sh -c cmd` in the builder, as the agent's user; the command is never
/// echoed (it may carry a secret). Returns whether it exited 0.
async fn builder_exec(rt: &iso_firecracker::FirecrackerRuntime, vm: VmId, cmd: &str, timeout_ms: u64) -> R<bool> {
    let mut agent = builder_agent(rt, vm).await?;
    let out = agent
        .exec(iso_guest_proto::ExecRequest {
            cmd: "sh".into(),
            args: vec!["-c".into(), cmd.into()],
            timeout_ms: Some(timeout_ms),
            max_output_bytes: Some(64 * 1024),
            ..Default::default()
        })
        .await?;
    for line in out.stderr.lines().chain(out.stdout.lines()).rev().take(20).collect::<Vec<_>>().into_iter().rev() {
        eprintln!("[bake]   | {line}");
    }
    Ok(out.exit_code == Some(0))
}

#[allow(clippy::too_many_arguments)]
async fn bake_inner(
    rt: &iso_firecracker::FirecrackerRuntime,
    netns: &str,
    builder: VmId,
    spec: &InstanceSpec,
    boot_timeout: u64,
    state: &Path,
    name: &str,
    provision: &[String],
    _vsock_cid: u32,
) -> R<(PathBuf, PathBuf)> {
    eprintln!("[bake] booting builder VM in netns {netns}");
    rt.create(spec).await?;
    rt.start(builder).await?;

    // The guest is up when its agent answers on vsock.
    eprintln!("[bake] waiting for the guest agent (<= {boot_timeout}s)");
    let deadline = Instant::now() + Duration::from_secs(boot_timeout);
    let mut up = false;
    while Instant::now() < deadline {
        if let Ok(mut agent) = builder_agent(rt, builder).await
            && tokio::time::timeout(Duration::from_secs(2), agent.ping()).await.is_ok_and(|r| r.is_ok())
        {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    if !up {
        return Err("the guest agent never answered within the boot timeout".into());
    }
    eprintln!("[bake] guest up");

    // Run provisioning commands inside the builder before snapshotting, so
    // any warmed state is CoW-shared. Non-fatal. The command is never logged:
    // `--provision` is how a caller ships secrets into the builder, so echoing
    // it puts live credentials in the bake output.
    let total = provision.len();
    for (i, cmd) in provision.iter().enumerate() {
        eprintln!("[bake] provision {}/{total}", i + 1);
        match builder_exec(rt, builder, cmd, 3_600_000).await {
            Ok(true) => {}
            Ok(false) => eprintln!("[bake] provision {}/{total} failed (continuing)", i + 1),
            Err(e) => eprintln!("[bake] provision {}/{total} could not run: {e} (continuing)", i + 1),
        }
    }

    // Flush the guest fs to the backing LV before snapshotting. With the rootfs
    // drive in Writeback mode this becomes a host fsync, so the on-disk template
    // is byte-consistent with the frozen page cache. Without it, dirty ext4
    // metadata (e.g. the seeded `.git`, written by git/direnv activity during
    // boot) never reaches the LV and every CoW clone reads a torn repo.
    eprintln!("[bake] sync guest fs before snapshot");
    if !matches!(builder_exec(rt, builder, "sync", 60_000).await, Ok(true)) {
        eprintln!("[bake] warning: guest sync before snapshot failed (rootfs may be inconsistent)");
    }

    eprintln!("[bake] pausing + snapshotting");
    // suspend = pause + CreateSnapshot into the runtime's per-vm dir.
    rt.suspend(builder).await?;

    // copy the snapshot to a stable, template-scoped location that survives the
    // builder's teardown.
    let src = rt.snapshot_dir(builder);
    let dst = state.join("templates").join(name);
    std::fs::create_dir_all(&dst)?;
    let mem = dst.join("mem");
    let vmstate = dst.join("vmstate");
    std::fs::copy(src.join("mem"), &mem)?;
    std::fs::copy(src.join("vmstate"), &vmstate)?;
    eprintln!("[bake] snapshot written to {}", dst.display());
    Ok((mem, vmstate))
}
