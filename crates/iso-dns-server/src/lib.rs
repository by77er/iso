//! iso-dns-server: a **dual-horizon** DNS server built on hickory-dns.
//!
//! - An authoritative local zone `iso.internal` answers `metadata.iso.internal`
//!   with the services dummy IP, so guests can reach the metadata server by name.
//!   (`.internal` avoids the `.local` mDNS reservation entirely.)
//! - Everything else is forwarded to upstream resolvers.
//!
//! The control plane binds it on the dummy address (e.g. `172.22.0.1:53`), which
//! the guest image uses as its nameserver.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_server::proto::rr::rdata::{A, SOA};
use hickory_server::proto::rr::{LowerName, Name, RData, Record};
use hickory_server::resolver::config::NameServerConfig;
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneHandler, ZoneType};
use hickory_server::Server;
use tokio::net::{TcpListener, UdpSocket};

/// The internal zone and the metadata name within it.
pub const LOCAL_ZONE: &str = "iso.internal.";
pub const METADATA_NAME: &str = "metadata.iso.internal.";

#[derive(Clone, Debug)]
pub struct Config {
    /// Address to bind UDP + TCP on (the dummy address, port 53).
    pub bind: SocketAddr,
    /// Upstream resolvers for the forward horizon.
    pub upstreams: Vec<IpAddr>,
    /// The services dummy IP that `metadata.iso.local` resolves to.
    pub metadata_ip: Ipv4Addr,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "172.22.0.1:53".parse().unwrap(),
            upstreams: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
            metadata_ip: Ipv4Addr::new(172, 22, 0, 1),
        }
    }
}

/// The authoritative `iso.local` zone with the metadata A record.
fn local_zone(metadata_ip: Ipv4Addr) -> Result<InMemoryZoneHandler, String> {
    let origin: Name = LOCAL_ZONE.parse().map_err(|e| format!("zone name: {e}"))?;
    let meta: Name = METADATA_NAME.parse().map_err(|e| format!("metadata name: {e}"))?;
    let serial = 1;

    let mut zone = InMemoryZoneHandler::empty(origin.clone(), ZoneType::Primary, AxfrPolicy::Deny);

    // a zone must carry an SOA
    let mname: Name = format!("ns.{LOCAL_ZONE}").parse().map_err(|e| format!("{e}"))?;
    let rname: Name = format!("admin.{LOCAL_ZONE}").parse().map_err(|e| format!("{e}"))?;
    let soa = Record::from_rdata(
        origin.clone(),
        60,
        RData::SOA(SOA::new(mname, rname, serial, 3600, 600, 86400, 60)),
    );
    zone.upsert_mut(soa, serial);

    let a = Record::from_rdata(meta, 60, RData::A(A(metadata_ip)));
    zone.upsert_mut(a, serial);
    Ok(zone)
}

/// Build the dual-horizon catalog: local `iso.local` zone + root forward zone.
fn build_catalog(cfg: &Config) -> Result<Catalog, String> {
    let forward = ForwardConfig {
        name_servers: cfg
            .upstreams
            .iter()
            .map(|ip| NameServerConfig::udp_and_tcp(*ip))
            .collect(),
        options: None,
    };
    let fwd = ForwardZoneHandler::builder_tokio(forward).build()?;

    let mut catalog = Catalog::new();
    // forward horizon (least specific)
    catalog.upsert(
        LowerName::from(Name::root()),
        vec![Arc::new(fwd) as Arc<dyn ZoneHandler>],
    );
    // internal horizon (more specific → wins for *.iso.local)
    let zone = local_zone(cfg.metadata_ip)?;
    catalog.upsert(
        zone.origin().clone(),
        vec![Arc::new(zone) as Arc<dyn ZoneHandler>],
    );
    Ok(catalog)
}

/// Run the dual-horizon DNS server until shutdown.
pub async fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let catalog = build_catalog(&cfg)?;
    let mut server = Server::new(catalog);
    server.register_socket(UdpSocket::bind(cfg.bind).await?);
    server.register_listener(TcpListener::bind(cfg.bind).await?, Duration::from_secs(5), 4096);
    server.block_until_done().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dual_horizon_catalog_builds() {
        assert!(build_catalog(&Config::default()).is_ok());
    }
}
