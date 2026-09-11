//! iso-controld library: the axum admin API and daemon settings, kept as a lib
//! so integration tests (and the binary) can share them.

pub mod http;
pub mod identify;
pub mod metadata;
pub mod settings;
pub mod tls;
