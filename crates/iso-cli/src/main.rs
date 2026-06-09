//! `isoctl` — out-of-band setup/admin actions for iso (template baking, host
//! setup, ...). Deliberately kept separate from the control-plane core so these
//! one-shot, privileged operations aren't intermingled with the long-running
//! service, and can be replaced by an external process later.
//!
//! Intentionally minimal for now.

fn main() {
    eprintln!("isoctl: not yet implemented");
    std::process::exit(1);
}
