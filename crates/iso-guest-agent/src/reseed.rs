//! Making a resumed clone its own machine again.
//!
//! Every clone of a template resumes the same memory image, so every clone
//! starts with the same kernel RNG state and the same SSH host keys. The
//! kernel keeps gathering input after the resume (interrupt timing, and the
//! virtio entropy device the host gives every VM), but it reseeds the
//! generator that `getrandom` and `/dev/urandom` read only about once a
//! minute, so until then clones hand out the same "random" bytes. And a
//! tenant who reads the generator's state from its own clone's memory can
//! predict another clone's output from the same snapshot.
//!
//! [`reseed_kernel_rng`] mixes fresh randomness in (bytes from the host and
//! from the entropy device) and forces the reseed; [`regenerate_ssh_host_keys`]
//! gives a clone host keys of its own. Both need root (`CAP_SYS_ADMIN` for the
//! ioctls), which the agent on the NixOS and Debian images is not: the host
//! runs them as `sudo -n iso-guest-agent --reseed [--ssh-host-keys]` through
//! `exec`, with base64 random bytes on stdin (see [`reseed_command`]). After a
//! `set_clock`, which the host sends on every resume, the agent also tries the
//! RNG half itself, which succeeds where it runs as root (an OCI template).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine as _;
use serde::Serialize;

/// The virtio entropy device, fed from the host's `getrandom`.
pub const HWRNG: &str = "/dev/hwrng";
/// Where bytes are mixed into the kernel's pool.
pub const RANDOM: &str = "/dev/urandom";
/// Where sshd's host keys live.
pub const SSH_DIR: &str = "/etc/ssh";

/// Bytes taken from the entropy device per reseed.
const HWRNG_BYTES: usize = 64;
/// Host bytes beyond this are ignored: 4096 bits is far past what a reseed
/// can use.
pub const MAX_HOST_BYTES: usize = 512;

// <linux/random.h>; the same numbers on x86_64 and aarch64.
const RNDADDENTROPY: libc::c_ulong = 0x4008_5203;
const RNDRESEEDCRNG: libc::c_ulong = 0x5207;

/// What [`reseed_kernel_rng`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Reseeded {
    /// Bytes mixed into the kernel's pool, the host's and the device's.
    pub mixed: usize,
    /// They were credited as entropy (`RNDADDENTROPY`, root only); otherwise
    /// they were only written to the pool, which mixes them without credit.
    pub credited: bool,
    /// The generator was reseeded there and then (`RNDRESEEDCRNG`, root
    /// only); otherwise the fresh input reaches it at the next scheduled
    /// reseed, within a minute.
    pub reseeded: bool,
}

/// Mix `host` (random bytes the host sent) and a read of the entropy device
/// into the kernel's pool, then reseed its generator.
pub fn reseed_kernel_rng(host: &[u8]) -> Result<Reseeded, String> {
    reseed_with(Path::new(HWRNG), Path::new(RANDOM), host)
}

/// [`reseed_kernel_rng`] against other device paths, for tests.
pub fn reseed_with(hwrng: &Path, random: &Path, host: &[u8]) -> Result<Reseeded, String> {
    let mut bytes = host[..host.len().min(MAX_HOST_BYTES)].to_vec();
    bytes.extend(read_hwrng(hwrng));
    let dev = OpenOptions::new()
        .write(true)
        .open(random)
        .map_err(|e| format!("open {}: {e}", random.display()))?;
    let mut done = Reseeded {
        mixed: bytes.len(),
        ..Default::default()
    };
    if !bytes.is_empty() {
        done.credited = add_entropy(&dev, &bytes);
        if !done.credited {
            (&dev)
                .write_all(&bytes)
                .map_err(|e| format!("write {}: {e}", random.display()))?;
        }
    }
    done.reseeded = unsafe { libc::ioctl(dev.as_raw_fd(), RNDRESEEDCRNG) } == 0;
    Ok(done)
}

/// Up to [`HWRNG_BYTES`] from the entropy device; nothing when there is no
/// device, no permission, or nothing ready (never blocks a resume on it).
fn read_hwrng(path: &Path) -> Vec<u8> {
    let Ok(mut f) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    else {
        return Vec::new();
    };
    let mut buf = vec![0u8; HWRNG_BYTES];
    match f.read(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            buf
        }
        Err(_) => Vec::new(),
    }
}

/// `RNDADDENTROPY`: mix `bytes` in and credit them in full. They come from
/// the host's CSPRNG, directly or through the entropy device.
fn add_entropy(dev: &File, bytes: &[u8]) -> bool {
    // struct rand_pool_info { int entropy_count; int buf_size; __u32 buf[]; }
    let mut info = vec![0u32; 2 + bytes.len().div_ceil(4)];
    info[0] = (bytes.len() * 8) as u32;
    info[1] = bytes.len() as u32;
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            info.as_mut_ptr().add(2) as *mut u8,
            bytes.len(),
        );
        libc::ioctl(dev.as_raw_fd(), RNDADDENTROPY, info.as_ptr()) == 0
    }
}

/// Replace every SSH host key in `dir` (`ssh_host_<type>_key` and its
/// `.pub`) with a new key of the same type, so the set sshd is configured for
/// stays the same. Returns the types replaced: none when there are no host
/// keys (no sshd in the image, or none generated yet).
pub fn regenerate_ssh_host_keys(dir: &Path) -> Result<Vec<String>, String> {
    regenerate_with(dir, || find_tool("ssh-keygen"))
}

fn regenerate_with(
    dir: &Path,
    keygen: impl FnOnce() -> Option<PathBuf>,
) -> Result<Vec<String>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("list {}: {e}", dir.display())),
    };
    let mut types: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            Some(
                name.strip_prefix("ssh_host_")?
                    .strip_suffix("_key")?
                    .to_string(),
            )
        })
        .collect();
    types.sort();
    if types.is_empty() {
        return Ok(types);
    }
    let keygen = keygen().ok_or("ssh-keygen not found")?;
    for t in &types {
        let key = dir.join(format!("ssh_host_{t}_key"));
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(dir.join(format!("ssh_host_{t}_key.pub")));
        let status = Command::new(&keygen)
            .args(["-q", "-t", t, "-N", "", "-f"])
            .arg(&key)
            .stdin(Stdio::null())
            .status()
            .map_err(|e| format!("run {}: {e}", keygen.display()))?;
        if !status.success() {
            return Err(format!("ssh-keygen -t {t} -f {}: {status}", key.display()));
        }
    }
    Ok(types)
}

/// Have a running sshd pick up new host keys. `sshd.service` is the unit on
/// NixOS and an alias of Debian's `ssh.service`; nothing happens if it is not
/// running, or if there is no systemd.
pub fn restart_sshd() {
    if let Some(systemctl) = find_tool("systemctl") {
        let _ = Command::new(systemctl)
            .args(["try-restart", "sshd.service"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// `name` on `PATH`, else in the usual system directories: under `sudo` the
/// `PATH` may be a minimal one, and NixOS keeps its tools elsewhere.
fn find_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(
            [
                "/run/current-system/sw/bin",
                "/usr/sbin",
                "/usr/bin",
                "/sbin",
                "/bin",
            ]
            .map(PathBuf::from),
        )
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// `iso-guest-agent --reseed [--ssh-host-keys]`: `stdin` is base64 random
/// bytes from the host (may be empty). Returns the JSON report to print and
/// whether everything asked for was done: the generator reseeded and, with
/// `ssh_host_keys`, the keys replaced and sshd told.
pub fn reseed_command(stdin: &str, ssh_host_keys: bool) -> (serde_json::Value, bool) {
    let host = match base64::engine::general_purpose::STANDARD.decode(stdin.trim()) {
        Ok(b) => b,
        Err(e) => {
            return (
                serde_json::json!({ "error": format!("stdin is not base64: {e}") }),
                false,
            );
        }
    };
    let mut ok = true;
    let rng = match reseed_kernel_rng(&host) {
        Ok(r) => {
            ok &= r.reseeded;
            serde_json::to_value(&r).unwrap_or_default()
        }
        Err(e) => {
            ok = false;
            serde_json::json!({ "error": e })
        }
    };
    let mut report = serde_json::json!({ "rng": rng });
    if ssh_host_keys {
        report["ssh_host_keys"] = match regenerate_ssh_host_keys(Path::new(SSH_DIR)) {
            Ok(types) => {
                if !types.is_empty() {
                    restart_sshd();
                }
                serde_json::json!(types)
            }
            Err(e) => {
                ok = false;
                serde_json::json!({ "error": e })
            }
        };
    }
    (report, ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("iso-agent-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Without the ioctls (here, regular files stand in for the devices) the
    /// host's bytes and the entropy device's are still written to the pool,
    /// and the report says the reseed did not happen.
    #[test]
    fn host_and_device_bytes_reach_the_pool() {
        let d = scratch("reseed");
        let (hwrng, random) = (d.join("hwrng"), d.join("random"));
        std::fs::write(&hwrng, b"from-the-device").unwrap();
        std::fs::write(&random, b"").unwrap();
        let r = reseed_with(&hwrng, &random, b"from-the-host").unwrap();
        assert_eq!(
            r,
            Reseeded {
                mixed: 28,
                credited: false,
                reseeded: false
            }
        );
        assert_eq!(
            std::fs::read(&random).unwrap(),
            b"from-the-hostfrom-the-device"
        );

        // No device and no host bytes: nothing to mix, still no error.
        std::fs::write(&random, b"").unwrap();
        let r = reseed_with(&d.join("missing"), &random, &[]).unwrap();
        assert_eq!(r.mixed, 0);
        assert!(std::fs::read(&random).unwrap().is_empty());

        // Host bytes are capped.
        let r = reseed_with(&d.join("missing"), &random, &[7u8; 4096]).unwrap();
        assert_eq!(r.mixed, MAX_HOST_BYTES);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The real thing, as root: the kernel takes the bytes and reseeds.
    /// (Harmless on the machine running the tests: it only adds randomness.)
    #[test]
    fn as_root_the_kernel_generator_is_reseeded() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: RNDADDENTROPY and RNDRESEEDCRNG need root");
            return;
        }
        // No made-up host bytes: crediting those would be a lie to this
        // machine's kernel. Whatever the entropy device gives is real.
        let r = reseed_kernel_rng(&[]).unwrap();
        assert!(r.reseeded, "{r:?}");
        assert_eq!(r.credited, r.mixed > 0, "{r:?}");
    }

    #[test]
    fn ssh_host_keys_are_replaced_type_for_type() {
        let d = scratch("sshkeys");
        // Nothing to do without keys, and no ssh-keygen needed for that.
        assert_eq!(regenerate_with(&d, || None).unwrap(), Vec::<String>::new());
        assert_eq!(
            regenerate_with(&d.join("absent"), || None).unwrap(),
            Vec::<String>::new()
        );

        for t in ["ed25519", "rsa"] {
            std::fs::write(d.join(format!("ssh_host_{t}_key")), "template").unwrap();
            std::fs::write(d.join(format!("ssh_host_{t}_key.pub")), "template").unwrap();
        }
        std::fs::write(d.join("sshd_config"), "keep").unwrap();
        let err = regenerate_with(&d, || None).unwrap_err();
        assert!(err.contains("ssh-keygen"), "{err}");

        // A stand-in ssh-keygen that writes what it was asked for.
        let keygen = d.join("fake-ssh-keygen");
        std::fs::write(
            &keygen,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do case $1 in -t) t=$2; shift;; -f) f=$2; shift;; esac; shift; done\n\
             echo \"new $t\" > \"$f\"; echo \"new $t pub\" > \"$f.pub\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&keygen, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let ssh = d.join("etc-ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        for f in [
            "ssh_host_ed25519_key",
            "ssh_host_ed25519_key.pub",
            "ssh_host_rsa_key",
            "ssh_host_rsa_key.pub",
            "sshd_config",
        ] {
            std::fs::copy(d.join(f), ssh.join(f)).unwrap();
        }
        assert_eq!(
            regenerate_with(&ssh, || Some(keygen.clone())).unwrap(),
            ["ed25519", "rsa"]
        );
        assert_eq!(
            std::fs::read_to_string(ssh.join("ssh_host_ed25519_key")).unwrap(),
            "new ed25519\n"
        );
        assert_eq!(
            std::fs::read_to_string(ssh.join("ssh_host_rsa_key.pub")).unwrap(),
            "new rsa pub\n"
        );
        assert_eq!(
            std::fs::read_to_string(ssh.join("sshd_config")).unwrap(),
            "keep"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_command_rejects_stdin_that_is_not_base64() {
        let (report, ok) = reseed_command("not base64!", false);
        assert!(!ok);
        assert!(
            report["error"].as_str().unwrap().contains("base64"),
            "{report}"
        );
    }
}
