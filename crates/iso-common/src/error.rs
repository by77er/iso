//! Shared error type for the iso contracts.

use std::fmt;

/// Convenience alias used throughout the contracts.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can surface across a component boundary.
///
/// Backends translate their internal failures (netlink, nftables, filesystem,
/// …) into these variants; the [`Error::Backend`] catch-all carries a
/// human-readable description for anything not worth modelling explicitly.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A [`crate::SlotId`] outside the valid range was supplied.
    SlotOutOfRange(u16),
    /// The resource for this key was expected to be absent but already exists.
    AlreadyProvisioned,
    /// The resource for this key was expected to exist but does not.
    NotProvisioned,
    /// A network policy listed the same `(host_port, proto)` more than once.
    DuplicatePortForward {
        host_port: u16,
        proto: crate::network::Protocol,
    },
    /// Backend-specific failure with a human-readable description.
    Backend(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SlotOutOfRange(v) => {
                write!(f, "slot {v} is out of range (max {})", crate::SlotId::MAX)
            }
            Error::AlreadyProvisioned => write!(f, "resource already provisioned"),
            Error::NotProvisioned => write!(f, "resource not provisioned"),
            Error::DuplicatePortForward { host_port, proto } => {
                write!(f, "duplicate port forward for {proto}/{host_port}")
            }
            Error::Backend(msg) => write!(f, "backend error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}
