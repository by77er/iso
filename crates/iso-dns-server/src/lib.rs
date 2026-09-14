//! iso-dns-server: a **dual-horizon** DNS server built on hickory-dns.
//!
//! - An authoritative local zone `iso.internal` answers `metadata.iso.internal`
//!   with the services dummy IP, so guests can reach the metadata server by name.
//!   (`.internal` avoids the `.local` mDNS reservation entirely.)
//! - Everything else is forwarded to upstream resolvers; A answers are
//!   reported to an [`Observer`], the control plane's memory of what each VM
//!   resolved, which is how a plain TCP connection gets a name.
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

/// Told what a VM resolved: the A answers handed to `src` for `name`, and
/// how long they are good for. The control plane keeps that memory so the
/// proxy can put a name to an address a VM dials on a port that carries no
/// SNI, and match it against `tunnel tcp://name:port` rules.
pub trait Observer: Send + Sync + Unpin + 'static {
    fn answered(&self, src: IpAddr, name: &str, addrs: &[Ipv4Addr], ttl_secs: u32);
}

/// Answers A queries itself, through the upstream resolvers, so every
/// answer can be observed; AAAA is NODATA (guests have no IPv6 route, and a
/// passthrough needs the A answer we saw); everything else goes to the
/// dual-horizon [`Catalog`].
struct ObservedHandler {
    catalog: Catalog,
    resolver: hickory_resolver::TokioResolver,
    observer: Arc<dyn Observer>,
}

#[async_trait::async_trait]
impl RequestHandler for ObservedHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        if let Ok(info) = request.request_info() {
            let qtype = info.query.query_type();
            let name = info.query.name().to_string();
            let internal = name.to_ascii_lowercase().ends_with(LOCAL_ZONE);
            if matches!(qtype, RecordType::A | RecordType::AAAA) && !internal {
                let domain = name.trim_end_matches('.').to_ascii_lowercase();
                let rec_name = Name::from(info.query.name().clone());
                let mut answers = Vec::new();
                if qtype == RecordType::A {
                    match self.resolver.lookup(domain.as_str(), RecordType::A).await {
                        Ok(lookup) => {
                            let a_records: Vec<(Ipv4Addr, u32)> = lookup
                                .answers()
                                .iter()
                                .filter_map(|r| match &r.data {
                                    RData::A(A(ip)) => Some((*ip, r.ttl)),
                                    _ => None,
                                })
                                .collect();
                            let ttl = a_records.iter().map(|(_, t)| *t).min().unwrap_or(60);
                            let addrs: Vec<Ipv4Addr> = a_records.iter().map(|(ip, _)| *ip).collect();
                            self.observer.answered(info.src.ip(), &domain, &addrs, ttl);
                            for ip in addrs {
                                answers.push(Record::from_rdata(rec_name.clone(), ttl, RData::A(A(ip))));
                            }
                        }
                        Err(e) => {
                            tracing::debug!("dns: {domain}: {e}");
                            // NXDOMAIN and the like: let the catalog answer
                            // as it would have, so the client sees the same
                            // error it always did.
                            return self.catalog.handle_request::<R, T>(request, response_handle).await;
                        }
                    }
                }
                let mut meta = Metadata::response_from_request(&request.metadata);
                meta.recursion_available = true;
                let err_meta = meta;
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
                        tracing::error!(%error, "dns: send response failed");
                        ResponseInfo::from(Header {
                            metadata: err_meta,
                            counts: HeaderCounts::default(),
                        })
                    }
                };
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

/// The resolver A queries go through, so their answers can be observed.
fn build_resolver(cfg: &Config) -> Result<hickory_resolver::TokioResolver, String> {
    use hickory_resolver::config::ResolverConfig;
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    let rc = ResolverConfig::from_parts(
        None,
        Vec::new(),
        cfg.upstreams.iter().map(|ip| NameServerConfig::udp_and_tcp(*ip)).collect(),
    );
    hickory_resolver::TokioResolver::builder_with_config(rc, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| e.to_string())
}

/// Run the dual-horizon DNS server, telling `observer` what every VM
/// resolved, until shutdown.
pub async fn run(
    cfg: Config,
    observer: Arc<dyn Observer>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let catalog = build_catalog(&cfg)?;
    let resolver = build_resolver(&cfg)?;
    let handler = ObservedHandler { catalog, resolver, observer };
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
