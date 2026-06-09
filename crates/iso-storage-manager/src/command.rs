//! Command execution abstraction for the LVM/loop tools.
//!
//! LVM has no idiomatic native binding, so the storage backend drives the
//! `lvm2` + `losetup` CLIs. Commands are built as pure [`Cmd`] values (testable)
//! and run through a [`CommandRunner`]; [`RecordingRunner`] captures and scripts
//! them in tests without touching the system.

use std::sync::Mutex;

use iso_common::{Error, Result};

/// A command to execute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cmd {
    pub argv: Vec<String>,
    /// If true, a non-zero exit is reported (`CmdOut::ok == false`) instead of
    /// being turned into an error — used for probes and idempotent removes.
    pub ignore_err: bool,
}

impl Cmd {
    pub fn new(argv: &[&str]) -> Self {
        Self {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            ignore_err: false,
        }
    }

    /// A command whose non-zero exit is tolerated (probe / idempotent remove).
    pub fn lenient(argv: &[&str]) -> Self {
        Self {
            ignore_err: true,
            ..Self::new(argv)
        }
    }

    pub fn display(&self) -> String {
        self.argv.join(" ")
    }
}

/// Result of running a command.
#[derive(Clone, Debug, Default)]
pub struct CmdOut {
    /// Whether the process exited successfully.
    pub ok: bool,
    /// Captured stdout (trimmed of nothing; callers trim as needed).
    pub stdout: String,
}

/// Runs [`Cmd`]s. `Send + Sync` so a [`crate::Manager`] can run them from
/// `spawn_blocking`.
pub trait CommandRunner: Send + Sync {
    fn run(&self, cmd: &Cmd) -> Result<CmdOut>;
}

/// Runs commands against the host via `std::process::Command`.
#[derive(Clone, Debug, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, cmd: &Cmd) -> Result<CmdOut> {
        let out = std::process::Command::new(&cmd.argv[0])
            .args(&cmd.argv[1..])
            .output()
            .map_err(|e| Error::Backend(format!("spawn `{}`: {e}", cmd.display())))?;
        let ok = out.status.success();
        if !ok && !cmd.ignore_err {
            return Err(Error::Backend(format!(
                "`{}` failed: {}",
                cmd.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(CmdOut {
            ok,
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        })
    }
}

/// Captures commands and returns scripted responses. For tests.
pub struct RecordingRunner {
    calls: Mutex<Vec<Cmd>>,
    responder: Box<dyn Fn(&Cmd) -> CmdOut + Send + Sync>,
}

impl RecordingRunner {
    /// Every command "succeeds" with empty output.
    pub fn new() -> Self {
        Self::with_responder(|_| CmdOut {
            ok: true,
            stdout: String::new(),
        })
    }

    /// Script responses as a function of the command.
    pub fn with_responder(f: impl Fn(&Cmd) -> CmdOut + Send + Sync + 'static) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responder: Box::new(f),
        }
    }

    /// Snapshot of the commands run so far.
    pub fn calls(&self) -> Vec<Cmd> {
        self.calls.lock().unwrap().clone()
    }
}

impl Default for RecordingRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&self, cmd: &Cmd) -> Result<CmdOut> {
        self.calls.lock().unwrap().push(cmd.clone());
        Ok((self.responder)(cmd))
    }
}
