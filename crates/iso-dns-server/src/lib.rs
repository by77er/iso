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

use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{Header, HeaderCounts, Metadata};
use hickory_server::proto::rr::rdata::{A, SOA};
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_server::resolver::config::NameServerConfig;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, MessageResponseBuilder, ZoneHandler, ZoneType};
use hickory_server::Server;
use tokio::net::{TcpListener, UdpSocket};

/// Decides whether a query should be steered to the egress proxy. Lets `Allow`
/// VMs route their proxied domains (per-VM `allow`-list) to the proxy for
/// credential injection while everything else resolves normally.
pub trait RedirectResolver: Send + Sync + Unpin + 'static {
    /// `Some(proxy_ip)` if `name` (queried by `src`) should resolve to the proxy.
    fn redirect(&self, src: IpAddr, name: &str) -> Option<Ipv4Addr>;
}

/// Wraps the dual-horizon [`Catalog`] with per-source redirect-to-proxy.
struct RedirectHandler {
    catalog: Catalog,
    resolver: Arc<dyn RedirectResolver>,
}

#[async_trait::async_trait]
impl RequestHandler for RedirectHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        if let Ok(info) = request.request_info() {
            let qtype = info.query.query_type();
            if matches!(qtype, RecordType::A | RecordType::AAAA) {
                let name = info.query.name().to_string();
                let domain = name.trim_end_matches('.');
                if let Some(ip) = self.resolver.redirect(info.src.ip(), domain) {
                    // A -> proxy; AAAA -> NODATA so the client falls back to A.
                    let mut answers = Vec::new();
                    if qtype == RecordType::A {
                        let rec_name = Name::from(info.query.name().clone());
                        answers.push(Record::from_rdata(rec_name, 5, RData::A(A(ip))));
                    }
                    let mut meta = Metadata::response_from_request(&request.metadata);
                    meta.authoritative = true;
                    meta.recursion_available = true;
                    let err_meta = meta; // Metadata: Copy
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.build(
                        meta,
                        &answers,
                        std::iter::empty::<&Record>(),
                        std::iter::empty::<&Record>(),
                        std::iter::empty::<&Record>(),
                    );
                    return match response_handle.send_response(response).await {
                        Ok(info) => info,
                        Err(error) => {
                            tracing::error!(%error, "dns: send redirect response failed");
                            ResponseInfo::from(Header {
                                metadata: err_meta,
                                counts: HeaderCounts::default(),
                            })
                        }
                    };
                }
            }
        }
        self.catalog
            .handle_request::<R, T>(request, response_handle)
            .await
    }
}

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

/// Run the dual-horizon DNS server with per-source redirect-to-proxy, until shutdown.
pub async fn run(
    cfg: Config,
    resolver: Arc<dyn RedirectResolver>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let catalog = build_catalog(&cfg)?;
    let handler = RedirectHandler { catalog, resolver };
    let mut server = Server::new(handler);
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
