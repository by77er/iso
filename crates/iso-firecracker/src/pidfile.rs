//! Pidfiles that are checked before they are believed.
//!
//! A pidfile outlives the process it names. After a daemon restart it is all
//! the runtime has to find a VMM by, and by then the pid may have been handed
//! to any other process: signalling it as root on the pidfile's word kills
//! whatever got the number next. So the pidfile records the process's start
//! time beside its pid, and a pid is only acted on once the process behind it
//! started at that time and was launched with this VM's arguments.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// What a pidfile says: the pid, and the start time recorded with it (absent
/// in a pidfile written before start times were).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Recorded {
    pub pid: i32,
    pub start: Option<u64>,
}

/// The pidfile line for `pid`: `<pid> <start time>`.
pub(crate) fn format(pid: u32) -> String {
    match start_time(pid as i32) {
        Some(start) => format!("{pid} {start}\n"),
        None => format!("{pid}\n"),
    }
}

pub(crate) fn parse(s: &str) -> Option<Recorded> {
    let mut words = s.split_whitespace();
    let pid = words.next()?.parse().ok().filter(|p: &i32| *p > 0)?;
    let start = words.next().and_then(|w| w.parse().ok());
    Some(Recorded { pid, start })
}

/// When `pid` started, in clock ticks since boot (field 22 of
/// `/proc/<pid>/stat`). `None` when there is no such process, or only its
/// zombie: an exited VMM is not a live one.
pub(crate) fn start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` is parenthesized and may itself hold spaces or parentheses, so
    // fields are counted from the last `)`. The first after it is field 3.
    let rest = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if matches!(fields.first(), Some(&"Z") | Some(&"X")) {
        return None;
    }
    fields.get(22 - 3)?.parse().ok()
}

/// The process's arguments, `argv[0]` included.
pub(crate) fn args(pid: i32) -> Option<Vec<Vec<u8>>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        raw.split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
    )
}

/// Whether `args` hold `flag` immediately followed by `value`.
pub(crate) fn has_pair(args: &[Vec<u8>], flag: &str, value: &[u8]) -> bool {
    args.windows(2)
        .any(|w| w[0] == flag.as_bytes() && w[1] == value)
}

/// Whether `rec` names a live process that started when the pidfile says and
/// whose arguments pass `names_vm`.
pub(crate) fn is_live(rec: Recorded, names_vm: impl FnOnce(&[Vec<u8>]) -> bool) -> bool {
    let Some(started) = start_time(rec.pid) else {
        return false;
    };
    if rec.start.is_some_and(|s| s != started) {
        return false;
    }
    args(rec.pid).is_some_and(|a| names_vm(&a))
}

/// Send `sig` to `pid` if `check` holds for it, with no window for the pid to
/// be reused in between: the pidfd pins one process, `check` reads `/proc`,
/// and the signal goes through the pidfd. Should the pinned process exit and
/// its pid be reused while `check` runs, the signal fails with `ESRCH`
/// rather than reaching the newcomer. Returns whether a signal was sent.
pub(crate) fn signal_if(pid: i32, sig: i32, check: impl FnOnce() -> bool) -> bool {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        // A kernel before 5.3 has no pidfds: checked, then signalled by pid.
        // The window is the time between the two, not since the pidfile.
        let nosys = std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS);
        return nosys && check() && unsafe { libc::kill(pid, sig) } == 0;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    check()
        && unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfiles_round_trip_and_old_ones_still_parse() {
        let me = std::process::id();
        let rec = parse(&format(me)).unwrap();
        assert_eq!(rec.pid, me as i32);
        assert_eq!(rec.start, start_time(me as i32));
        assert!(rec.start.is_some());
        assert_eq!(
            parse("1234\n"),
            Some(Recorded {
                pid: 1234,
                start: None
            })
        );
        assert_eq!(parse(""), None);
        assert_eq!(parse("-1 5"), None);
    }

    #[test]
    fn a_process_is_known_by_its_start_time_and_arguments() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30; exit 0", "sh", "--marker"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let rec = parse(&format(child.id())).unwrap();
        // `spawn` can return before the child has exec'd: until then its
        // command line is still this test's.
        let marked = |a: &[Vec<u8>]| a.iter().any(|w| w == b"--marker");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !args(pid).is_some_and(|a| marked(&a)) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(is_live(rec, marked));
        assert!(
            !is_live(rec, |_| false),
            "arguments that do not name the VM"
        );
        let stale = Recorded {
            start: rec.start.map(|s| s + 1),
            ..rec
        };
        assert!(
            !is_live(stale, |_| true),
            "a pid reused since the pidfile was written"
        );
        assert!(!signal_if(pid, libc::SIGKILL, || false));
        assert!(child.try_wait().unwrap().is_none());
        assert!(signal_if(pid, libc::SIGKILL, || true));
        let _ = child.wait();
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        assert!(!is_live(rec, |_| true), "a reaped process is gone");
    }

    #[test]
    fn has_pair_wants_the_value_right_after_the_flag() {
        let args: Vec<Vec<u8>> = ["fc", "--id", "a", "--api-sock", "/s"]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        assert!(has_pair(&args, "--id", b"a"));
        assert!(has_pair(&args, "--api-sock", b"/s"));
        assert!(!has_pair(&args, "--id", b"/s"));
    }
}
