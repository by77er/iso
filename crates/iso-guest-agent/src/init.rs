//! The agent as PID 1.
//!
//! A template built from an OCI image is the image's filesystem and nothing
//! more: no systemd, often no shell worth the name. The kernel boots it with
//! `init=/usr/local/bin/iso-guest-agent`, and the agent, finding itself PID
//! 1, does what an init must and no more: mounts the pseudo filesystems,
//! reads the image's environment, working directory and user from
//! `/etc/iso/image.json` (written at bake time from the image config),
//! runs the agent proper as a child with that environment, reaps every
//! orphan, restarts the agent if it dies, and powers off on SIGINT, which
//! is what Ctrl-Alt-Del from the host becomes once CAD is disabled.
//!
//! The kernel's `ip=` argument has configured eth0 before this runs, and
//! `/etc/resolv.conf` was baked in, so there is no network to bring up.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;

/// What the bake wrote from the image's config.
#[derive(Debug, Default, Deserialize)]
pub struct ImageConfig {
    /// `KEY=VALUE` entries, as the image config carries them.
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub workdir: Option<String>,
    /// The image's `USER`, the default for `exec`.
    #[serde(default)]
    pub user: Option<String>,
}

pub const IMAGE_CONFIG: &str = "/etc/iso/image.json";

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn log(msg: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "iso-init: {msg}");
}

fn mount(src: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) {
    let _ = std::fs::create_dir_all(target);
    let (s, t, f, d) = (
        std::ffi::CString::new(src).unwrap(),
        std::ffi::CString::new(target).unwrap(),
        std::ffi::CString::new(fstype).unwrap(),
        std::ffi::CString::new(data).unwrap(),
    );
    let rc = unsafe { libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), flags, d.as_ptr() as *const libc::c_void) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        // Already mounted (the kernel mounted devtmpfs, say) is fine.
        if e.raw_os_error() != Some(libc::EBUSY) {
            log(&format!("mount {fstype} on {target}: {e}"));
        }
    }
}

/// Run as init. Never returns.
pub fn run(agent_args: &[String]) -> ! {
    log("running as PID 1");
    mount("proc", "/proc", "proc", libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV, "");
    mount("sysfs", "/sys", "sysfs", libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV, "");
    mount("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, "mode=0755");
    mount("devpts", "/dev/pts", "devpts", libc::MS_NOSUID | libc::MS_NOEXEC, "gid=5,mode=620,ptmxmode=666");
    mount("tmpfs", "/dev/shm", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, "mode=1777");
    mount("tmpfs", "/run", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, "mode=0755");
    mount("tmpfs", "/tmp", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, "mode=1777");
    let _ = std::fs::create_dir_all("/run/lock");
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim();
        if !h.is_empty() {
            unsafe { libc::sethostname(h.as_ptr() as *const libc::c_char, h.len()) };
        }
    }
    // Ctrl-Alt-Del (the host's graceful stop) becomes SIGINT to us.
    unsafe {
        libc::reboot(libc::LINUX_REBOOT_CMD_CAD_OFF);
        let handler = on_stop as extern "C" fn(libc::c_int) as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }

    let image: ImageConfig = std::fs::read_to_string(IMAGE_CONFIG)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let exe = std::env::current_exe().unwrap_or_else(|_| "/usr/local/bin/iso-guest-agent".into());

    loop {
        if STOP.load(Ordering::SeqCst) {
            power_off();
        }
        let mut cmd = std::process::Command::new(&exe);
        cmd.args(agent_args).env_clear();
        cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        cmd.env("HOME", "/root").env("USER", "root").env("LOGNAME", "root").env("TERM", "xterm");
        for kv in &image.env {
            if let Some((k, v)) = kv.split_once('=') {
                cmd.env(k, v);
            }
        }
        if let Some(u) = &image.user {
            if !u.is_empty() && u != "root" && u != "0" {
                cmd.env("ISO_DEFAULT_USER", u);
            }
        }
        if let Some(w) = image.workdir.as_deref().filter(|w| !w.is_empty()) {
            let _ = std::fs::create_dir_all(w);
            cmd.current_dir(w);
        }
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                log(&format!("spawning the agent: {e}"));
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };
        let agent = child.id() as libc::pid_t;
        // Reap everything; notice when the agent itself is what died.
        loop {
            if STOP.load(Ordering::SeqCst) {
                unsafe { libc::kill(agent, libc::SIGTERM) };
                power_off();
            }
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid == agent {
                log(&format!("agent exited ({status}); restarting"));
                std::thread::sleep(std::time::Duration::from_secs(1));
                break;
            }
            if pid <= 0 {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        // `child` is already reaped by the loop above; forget it quietly.
        std::mem::forget(child);
    }
}

fn power_off() -> ! {
    log("powering off");
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    std::process::exit(0)
}
