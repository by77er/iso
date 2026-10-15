//! iso-dns-server: a **dual-horizon** DNS server built on hickory-dns.
//!
//! - An authoritative local zone `iso.internal` answers `metadata.iso.internal`
//!   with the services dummy IP, so guests can reach the metadata server by name.
//!   (`.internal` avoids the `.local` mDNS reservation entirely.)
//! - Everything else is forwarded to upstream resolvers, for the VMs and the
//!   names a [`Gate`] allows (a forwarded query is data leaving the host, so
//!   a VM with no egress has nothing resolved upstream); A answers are
//!   reported to an [`Observer`], the control plane's memory of what each VM
//!   resolved, which is how a plain TCP connection gets a name.
//!
//! The control plane binds it on the dummy address (e.g. `172.22.0.1:53`), which
//! the guest image uses as its nameserver.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_server::Server;
use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_server::proto::rr::rdata::{A, SOA};
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_server::resolver::config::NameServerConfig;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{
    AxfrPolicy, Catalog, MessageResponseBuilder, ZoneHandler, ZoneType,
};
use tokio::net::{TcpListener, UdpSocket};

/// Told what a VM resolved: the A answers handed to `src` for `name`, and
/// how long they are good for. The control plane keeps that memory so the
/// proxy can put a name to an address a VM dials on a port that carries no
/// SNI, and match it against `tunnel tcp://name:port` rules.
pub trait Observer: Send + Sync + Unpin + 'static {
    fn answered(&self, src: IpAddr, name: &str, addrs: &[Ipv4Addr], ttl_secs: u32);
}

/// Who may have what resolved upstream: the control plane's view of each
/// VM's egress policy, keyed like the [`Observer`] by the address a query
/// comes from (the VM's veth address after the in-netns SNAT). A query the
/// server forwards is data leaving the host, encoded in the name, so a VM
/// whose policy allows no egress must have nothing forwarded, and one with
/// rules only the names they could reach; the proxy refuses the rest anyway.
pub trait Gate: Send + Sync + 'static {
    /// May `src` have `name` (lowercase, no trailing dot) resolved upstream?
    fn may_resolve(&self, src: IpAddr, name: &str) -> bool;
}

/// Answers A queries itself, through the upstream resolvers, so every
/// answer can be observed; AAAA is NODATA (guests have no IPv6 route, and a
/// passthrough needs the A answer we saw); everything else goes to the
/// dual-horizon [`Catalog`]. A name outside the internal zone that the
/// [`Gate`] does not allow its asker is REFUSED, whatever the query type,
/// before anything is forwarded.
struct ObservedHandler {
    catalog: Catalog,
    resolver: hickory_resolver::TokioResolver,
    observer: Arc<dyn Observer>,
    gate: Option<Arc<dyn Gate>>,
    local_zone: LowerName,
}

impl ObservedHandler {
    /// The handler for `cfg`, forwarding to its upstreams on `upstream_port`.
    fn new(cfg: &Config, observer: Arc<dyn Observer>, upstream_port: u16) -> Result<Self, String> {
        let upstreams = name_servers(cfg, upstream_port);
        Ok(Self {
            catalog: build_catalog(cfg, upstreams.clone())?,
            resolver: build_resolver(upstreams)?,
            observer,
            gate: cfg.gate.clone(),
            local_zone: LowerName::from(
                Name::from_ascii(LOCAL_ZONE).map_err(|e| format!("zone name: {e}"))?,
            ),
        })
    }

    /// Refuse a query the asker may not have resolved.
    async fn refuse<R: ResponseHandler>(request: &Request, mut response_handle: R) -> ResponseInfo {
        let response = MessageResponseBuilder::from_message_request(request)
            .error_msg(&request.metadata, ResponseCode::Refused);
        let metadata = *response.metadata();
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(error) => {
                tracing::error!(%error, "dns: send response failed");
                ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                })
            }
        }
    }
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
            // By labels: `x.eviliso.internal` is not ours, and goes upstream.
            let internal = self.local_zone.zone_of(info.query.name());
            let domain = info
                .query
                .name()
                .to_string()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let src = info.src.ip();
            if !internal
                && !self
                    .gate
                    .as_ref()
                    .is_some_and(|g| g.may_resolve(src, &domain))
            {
                tracing::debug!("dns: {src} may not resolve {domain}: refused");
                return Self::refuse(request, response_handle).await;
            }
            if matches!(qtype, RecordType::A | RecordType::AAAA) && !internal {
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
                            let addrs: Vec<Ipv4Addr> =
                                a_records.iter().map(|(ip, _)| *ip).collect();
                            self.observer.answered(src, &domain, &addrs, ttl);
                            for ip in addrs {
                                answers.push(Record::from_rdata(
                                    rec_name.clone(),
                                    ttl,
                                    RData::A(A(ip)),
                                ));
                            }
                        }
                        Err(e) => {
                            tracing::debug!("dns: {domain}: {e}");
                            // NXDOMAIN and the like: let the catalog answer
                            // as it would have, so the client sees the same
                            // error it always did.
                            return self
                                .catalog
                                .handle_request::<R, T>(request, response_handle)
                                .await;
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

#[derive(Clone)]
pub struct Config {
    /// Address to bind UDP + TCP on (the dummy address, port 53).
    pub bind: SocketAddr,
    /// Upstream resolvers for the forward horizon.
    pub upstreams: Vec<IpAddr>,
    /// The services dummy IP that `metadata.iso.local` resolves to.
    pub metadata_ip: Ipv4Addr,
    /// Who may have what resolved through `upstreams`. `None` forwards
    /// nothing for anyone: only the internal zone answers, so a server that
    /// was never told the VMs' policies leaks nothing for them.
    pub gate: Option<Arc<dyn Gate>>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("upstreams", &self.upstreams)
            .field("metadata_ip", &self.metadata_ip)
            .field("gate", &self.gate.as_ref().map(|_| "Gate"))
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "172.22.0.1:53".parse().unwrap(),
            upstreams: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
            metadata_ip: Ipv4Addr::new(172, 22, 0, 1),
            gate: None,
        }
    }
}

/// The authoritative `iso.local` zone with the metadata A record.
fn local_zone(metadata_ip: Ipv4Addr) -> Result<InMemoryZoneHandler, String> {
    let origin: Name = LOCAL_ZONE.parse().map_err(|e| format!("zone name: {e}"))?;
    let meta: Name = METADATA_NAME
        .parse()
        .map_err(|e| format!("metadata name: {e}"))?;
    let serial = 1;

    let mut zone = InMemoryZoneHandler::empty(origin.clone(), ZoneType::Primary, AxfrPolicy::Deny);

    // a zone must carry an SOA
    let mname: Name = format!("ns.{LOCAL_ZONE}")
        .parse()
        .map_err(|e| format!("{e}"))?;
    let rname: Name = format!("admin.{LOCAL_ZONE}")
        .parse()
        .map_err(|e| format!("{e}"))?;
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

/// The upstream resolvers, over UDP and TCP on `port` (53, but in tests).
fn name_servers(cfg: &Config, port: u16) -> Vec<NameServerConfig> {
    cfg.upstreams
        .iter()
        .map(|ip| {
            let mut ns = NameServerConfig::udp_and_tcp(*ip);
            for c in &mut ns.connections {
                c.port = port;
            }
            ns
        })
        .collect()
}

/// Build the dual-horizon catalog: local `iso.local` zone + root forward zone.
fn build_catalog(cfg: &Config, upstreams: Vec<NameServerConfig>) -> Result<Catalog, String> {
    let forward = ForwardConfig {
        name_servers: upstreams,
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
fn build_resolver(
    upstreams: Vec<NameServerConfig>,
) -> Result<hickory_resolver::TokioResolver, String> {
    use hickory_resolver::config::ResolverConfig;
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    let rc = ResolverConfig::from_parts(None, Vec::new(), upstreams);
    hickory_resolver::TokioResolver::builder_with_config(rc, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| e.to_string())
}

/// Run the dual-horizon DNS server, telling `observer` what every VM
/// resolved, until shutdown. Only what `cfg.gate` allows is resolved
/// upstream.
pub async fn run(
    cfg: Config,
    observer: Arc<dyn Observer>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let handler = ObservedHandler::new(&cfg, observer, 53)?;
    let mut server = Server::new(handler);
    server.register_socket(UdpSocket::bind(cfg.bind).await?);
    server.register_listener(
        TcpListener::bind(cfg.bind).await?,
        Duration::from_secs(5),
        4096,
    );
    server.block_until_done().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use hickory_server::proto::op::{Message, MessageType, OpCode, Query};

    #[tokio::test]
    async fn dual_horizon_catalog_builds() {
        let cfg = Config::default();
        assert!(build_catalog(&cfg, name_servers(&cfg, 53)).is_ok());
    }

    /// One VM per loopback address, each with its own policy.
    const DENY: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
    const RULES: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
    const OPEN: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
    /// What the stand-in upstream answers every A query with.
    const UPSTREAM_ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);

    /// `DENY` has no egress, `RULES` reaches `api.allowed.test` and
    /// `*.cdn.allowed.test`, `OPEN` anything; nobody else is a VM.
    struct Policies;
    impl Gate for Policies {
        fn may_resolve(&self, src: IpAddr, name: &str) -> bool {
            match src {
                IpAddr::V4(ip) if ip == RULES => {
                    name == "api.allowed.test" || name.ends_with(".cdn.allowed.test")
                }
                IpAddr::V4(ip) if ip == OPEN => true,
                _ => false,
            }
        }
    }

    #[derive(Default)]
    struct Seen(Mutex<Vec<(IpAddr, String)>>);
    impl Observer for Seen {
        fn answered(&self, src: IpAddr, name: &str, _: &[Ipv4Addr], _: u32) {
            self.0.lock().unwrap().push((src, name.to_string()));
        }
    }

    /// A stand-in upstream resolver on loopback: answers every A query with
    /// [`UPSTREAM_ANSWER`] and anything else with NODATA, and logs every
    /// name it is asked, which is every name that left the host.
    async fn upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = asked.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(q) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let Some(query) = q.queries.first().cloned() else {
                    continue;
                };
                log.lock().unwrap().push(query.name().to_string());
                let mut r = Message::response(q.metadata.id, q.metadata.op_code);
                r.metadata.recursion_desired = q.metadata.recursion_desired;
                r.metadata.recursion_available = true;
                if query.query_type() == RecordType::A {
                    r.add_answer(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::A(A(UPSTREAM_ANSWER)),
                    ));
                }
                r.add_query(query);
                let _ = sock.send_to(&r.to_vec().unwrap(), from).await;
            }
        });
        (port, asked)
    }

    /// The server on loopback, forwarding to a stand-in upstream; returns
    /// where it listens, what the upstream was asked and what was observed.
    async fn server(
        gate: Option<Arc<dyn Gate>>,
    ) -> (SocketAddr, Arc<Mutex<Vec<String>>>, Arc<Seen>) {
        let (upstream_port, asked) = upstream().await;
        let cfg = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            upstreams: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            gate,
            ..Config::default()
        };
        let seen = Arc::new(Seen::default());
        let handler = ObservedHandler::new(&cfg, seen.clone(), upstream_port).unwrap();
        let sock = UdpSocket::bind(cfg.bind).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let mut server = Server::new(handler);
        server.register_socket(sock);
        tokio::spawn(async move { server.block_until_done().await });
        (addr, asked, seen)
    }

    /// Ask `server`, from the VM at `src`, for `name`'s `qtype` records.
    async fn ask(server: SocketAddr, src: Ipv4Addr, name: &str, qtype: RecordType) -> Message {
        let sock = UdpSocket::bind((src, 0)).await.unwrap();
        let mut q = Message::new(7, MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        q.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        sock.send_to(&q.to_vec().unwrap(), server).await.unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("an answer")
            .unwrap();
        Message::from_vec(&buf[..n]).unwrap()
    }

    fn addrs(m: &Message) -> Vec<Ipv4Addr> {
        m.answers
            .iter()
            .filter_map(|r| match r.data {
                RData::A(A(ip)) => Some(ip),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn a_vm_with_no_egress_has_nothing_resolved_upstream() {
        let (srv, asked, seen) = server(Some(Arc::new(Policies))).await;
        for (name, qtype) in [
            ("api.allowed.test.", RecordType::A),
            ("c2VjcmV0.exfil.example.", RecordType::A),
            ("c2VjcmV0.exfil.example.", RecordType::TXT),
            ("c2VjcmV0.exfil.example.", RecordType::AAAA),
            // looks like the internal zone, but is not under it
            ("c2VjcmV0.eviliso.internal.", RecordType::A),
        ] {
            let r = ask(srv, DENY, name, qtype).await;
            assert_eq!(
                r.metadata.response_code,
                ResponseCode::Refused,
                "{name} {qtype}"
            );
            assert!(r.answers.is_empty(), "{name} {qtype}");
        }
        // The internal zone still answers: metadata is the baseline.
        let r = ask(srv, DENY, METADATA_NAME, RecordType::A).await;
        assert_eq!(addrs(&r), [Ipv4Addr::new(172, 22, 0, 1)]);
        assert_eq!(
            *asked.lock().unwrap(),
            Vec::<String>::new(),
            "nothing left the host"
        );
        assert!(seen.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_vm_with_rules_has_only_their_names_resolved() {
        let (srv, asked, seen) = server(Some(Arc::new(Policies))).await;
        let r = ask(srv, RULES, "API.allowed.test.", RecordType::A).await;
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(addrs(&r), [UPSTREAM_ANSWER]);
        let r = ask(srv, RULES, "img.cdn.allowed.test.", RecordType::A).await;
        assert_eq!(addrs(&r), [UPSTREAM_ANSWER]);
        for (name, qtype) in [
            ("c2VjcmV0.exfil.example.", RecordType::A),
            ("c2VjcmV0.exfil.example.", RecordType::TXT),
            ("allowed.test.", RecordType::A),
            ("c2VjcmV0.api.allowed.test.", RecordType::A),
        ] {
            let r = ask(srv, RULES, name, qtype).await;
            assert_eq!(
                r.metadata.response_code,
                ResponseCode::Refused,
                "{name} {qtype}"
            );
        }
        assert_eq!(
            *asked.lock().unwrap(),
            ["api.allowed.test.", "img.cdn.allowed.test."]
        );
        let rules = IpAddr::V4(RULES);
        assert_eq!(
            *seen.0.lock().unwrap(),
            [
                (rules, "api.allowed.test".to_string()),
                (rules, "img.cdn.allowed.test".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn an_open_vm_resolves_anything_and_strangers_nothing() {
        let (srv, asked, _) = server(Some(Arc::new(Policies))).await;
        let r = ask(srv, OPEN, "anything.example.", RecordType::A).await;
        assert_eq!(addrs(&r), [UPSTREAM_ANSWER]);
        let r = ask(srv, Ipv4Addr::LOCALHOST, "anything.example.", RecordType::A).await;
        assert_eq!(
            r.metadata.response_code,
            ResponseCode::Refused,
            "not a VM the gate knows"
        );
        assert_eq!(*asked.lock().unwrap(), ["anything.example."]);
    }

    #[tokio::test]
    async fn without_a_gate_nothing_is_resolved_upstream() {
        let (srv, asked, _) = server(None).await;
        let r = ask(srv, OPEN, "anything.example.", RecordType::A).await;
        assert_eq!(r.metadata.response_code, ResponseCode::Refused);
        let r = ask(srv, OPEN, METADATA_NAME, RecordType::A).await;
        assert_eq!(addrs(&r), [Ipv4Addr::new(172, 22, 0, 1)]);
        assert!(asked.lock().unwrap().is_empty());
    }
}
