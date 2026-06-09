//! Control-plane error type.

use iso_common::VmId;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// No free placement slots remain.
    SlotsExhausted,
    /// No free host ports remain for ingress forwards.
    PortsExhausted,
    /// No VM with this id is known.
    UnknownVm(VmId),
    /// No template registered under this name.
    UnknownTemplate(String),
    /// The backing pool is too full to provision into.
    PoolFull {
        data_percent: f64,
        metadata_percent: f64,
    },
    /// The operation isn't valid in the VM's current state.
    InvalidState {
        vm: VmId,
        state: &'static str,
        op: &'static str,
    },
    /// Persistence-layer failure.
    Store(String),
    /// A subsystem (network / storage / runtime) failed.
    Component(iso_common::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SlotsExhausted => write!(f, "no free slots remain"),
            Error::PortsExhausted => write!(f, "no free forward ports remain"),
            Error::UnknownVm(id) => write!(f, "unknown vm {id}"),
            Error::UnknownTemplate(n) => write!(f, "unknown template '{n}'"),
            Error::PoolFull {
                data_percent,
                metadata_percent,
            } => write!(
                f,
                "backing pool too full (data {data_percent:.1}%, metadata {metadata_percent:.1}%)"
            ),
            Error::InvalidState { vm, state, op } => {
                write!(f, "cannot {op} vm {vm} in state {state}")
            }
            Error::Store(m) => write!(f, "store error: {m}"),
            Error::Component(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<iso_common::Error> for Error {
    fn from(e: iso_common::Error) -> Self {
        Error::Component(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Store(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Store(format!("json: {e}"))
    }
}
