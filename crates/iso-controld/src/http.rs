//! axum admin API over the (transport-agnostic) control-plane core.
//!
//! Admin-only: host-global stats live here, never on a VM-facing surface.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use iso_common::{
    EgressMode, NetworkManager, PortForward, Protocol, SnapshotRef, StorageManager, VmId,
    VmRuntime,
};
use iso_control_plane::types::{egress_parse, egress_str, TemplateDef};
use iso_control_plane::{ControlPlane, CreateVm, Error as CpError, VmRecord};
use iso_guest_proto::{AgentInfo, ClientError, DirEntry, ExecRequest, ExecResult, FileContent, GuestClient};
use serde::{Deserialize, Serialize};

type Cp<N, S, R> = Arc<ControlPlane<N, S, R>>;

// ---- error mapping ----

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<CpError> for ApiError {
    fn from(e: CpError) -> Self {
        let code = match &e {
            CpError::UnknownVm(_)
            | CpError::UnknownTemplate(_)
            | CpError::UnknownForward { .. } => StatusCode::NOT_FOUND,
            CpError::SlotsExhausted
            | CpError::PortsExhausted
            | CpError::PoolFull { .. }
            | CpError::InvalidState { .. } => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(code, e.to_string())
    }
}

fn parse_id(s: &str) -> Result<VmId, ApiError> {
    VmId::parse(s).ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "invalid vm id".into()))
}

impl From<ClientError> for ApiError {
    fn from(e: ClientError) -> Self {
        // The agent refusing an operation (a missing path, a bad program) is
        // the caller's problem; not reaching the agent at all is the host's.
        let code = match &e {
            ClientError::Agent(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::BAD_GATEWAY,
        };
        ApiError(code, e.to_string())
    }
}

/// Bound on one guest file operation, and the slack added to an `exec`'s own
/// timeout so a wedged agent can't hold the request forever.
const GUEST_IO_TIMEOUT: Duration = Duration::from_secs(60);
const EXEC_SLACK: Duration = Duration::from_secs(15);

// ---- DTOs ----

#[derive(Serialize, Deserialize)]
struct PortForwardDto {
    /// Allocated by the control plane; omit on create, reported on read.
    #[serde(default)]
    host_port: u16,
    vm_port: u16,
    proto: String,
}

#[derive(Deserialize)]
struct CreateReq {
    template: String,
    #[serde(default)]
    egress: String,
    #[serde(default)]
    ingress: Vec<PortForwardDto>,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default)]
    lifecycle: String,
    #[serde(default)]
    restart: String,
    #[serde(default)]
    vcpus: Option<u32>,
    #[serde(default)]
    mem_mib: Option<u32>,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Serialize)]
struct IdResp {
    id: String,
}

/// Body for `POST /vms/{id}/forwards`: open a new ingress forward. The host
/// port is allocated by the control plane and returned in the response.
#[derive(Deserialize)]
struct AddForwardReq {
    vm_port: u16,
    /// `"tcp"` (default) or `"udp"`.
    #[serde(default)]
    proto: String,
}

/// Query for `DELETE /vms/{id}/forwards/{host_port}`: which protocol's forward
/// to remove (defaults to tcp, matching `AddForwardReq`).
#[derive(Deserialize)]
struct ProtoQuery {
    #[serde(default)]
    proto: Option<String>,
}

#[derive(Serialize)]
struct VmResp {
    id: String,
    slot: Option<u16>,
    template: String,
    state: String,
    egress: String,
    lifecycle: String,
    restart: String,
    labels: HashMap<String, String>,
    ingress: Vec<PortForwardDto>,
    tap: Option<String>,
    rootfs_device: Option<String>,
    principal: Option<String>,
    allow: Vec<String>,
}

#[derive(Deserialize)]
struct PolicyReq {
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    allow: Option<Vec<String>>,
    /// `"allow" | "proxy" | "deny"`; invalid/absent leaves it unchanged.
    #[serde(default)]
    egress: Option<String>,
}

/// Query for the guest file endpoints.
#[derive(Deserialize)]
struct PathQuery {
    path: String,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    recursive: bool,
}

/// Body for `PUT /vms/{id}/files`: one of `content` (UTF-8 text) or
/// `content_b64` (arbitrary bytes).
#[derive(Deserialize)]
struct WriteFileReq {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    content_b64: Option<String>,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    mkdir: bool,
}

#[derive(Serialize)]
struct WrittenResp {
    bytes: u64,
}

#[derive(Serialize)]
struct DirResp {
    entries: Vec<DirEntry>,
}

#[derive(Serialize)]
struct StatsResp {
    data_percent: f64,
    metadata_percent: f64,
    slots_used: usize,
    slots_total: usize,
    vms: usize,
}

#[derive(Deserialize)]
struct TemplateReq {
    name: String,
    rootfs_template: String,
    #[serde(default)]
    snapshot_mem: Option<String>,
    #[serde(default)]
    snapshot_vmstate: Option<String>,
    vcpus: u32,
    mem_mib: u32,
    kernel: String,
    #[serde(default)]
    boot_args: String,
}

// ---- conversions ----

fn proto_to(p: Protocol) -> String {
    match p {
        Protocol::Tcp => "tcp".into(),
        Protocol::Udp => "udp".into(),
    }
}
fn proto_from(s: &str) -> Protocol {
    if s.eq_ignore_ascii_case("udp") {
        Protocol::Udp
    } else {
        Protocol::Tcp
    }
}
fn egress_from(s: &str) -> EgressMode {
    match s {
        "allow" => EgressMode::Allow,
        "proxy" => EgressMode::Proxy,
        _ => EgressMode::Deny,
    }
}
fn lifecycle_from(s: &str) -> iso_control_plane::Lifecycle {
    match s {
        "durable" => iso_control_plane::Lifecycle::Durable,
        _ => iso_control_plane::Lifecycle::Ephemeral,
    }
}
fn restart_from(s: &str) -> iso_control_plane::RestartPolicy {
    match s {
        "always" => iso_control_plane::RestartPolicy::Always,
        "on_failure" => iso_control_plane::RestartPolicy::OnFailure,
        _ => iso_control_plane::RestartPolicy::Never,
    }
}

fn to_req(r: CreateReq) -> CreateVm {
    CreateVm {
        template: r.template,
        egress: egress_from(&r.egress),
        ingress: r
            .ingress
            .into_iter()
            .map(|f| PortForward {
                host_port: 0, // control plane allocates
                vm_port: f.vm_port,
                proto: proto_from(&f.proto),
            })
            .collect(),
        labels: r.labels,
        lifecycle: lifecycle_from(&r.lifecycle),
        restart: restart_from(&r.restart),
        vcpus: r.vcpus,
        mem_mib: r.mem_mib,
        principal: r.principal,
        allow: r.allow,
    }
}

fn vm_resp(r: &VmRecord) -> VmResp {
    VmResp {
        id: r.id.to_string(),
        slot: r.slot.map(|s| s.get()),
        template: r.template.clone(),
        state: r.state.as_str().into(),
        egress: egress_str(r.egress).into(),
        lifecycle: r.lifecycle.as_str().into(),
        restart: r.restart.as_str().into(),
        labels: r.labels.clone(),
        ingress: r
            .ingress
            .iter()
            .map(|f| PortForwardDto {
                host_port: f.host_port,
                vm_port: f.vm_port,
                proto: proto_to(f.proto),
            })
            .collect(),
        tap: r.tap.clone(),
        rootfs_device: r.rootfs_device.as_ref().map(|p| p.to_string_lossy().into_owned()),
        principal: r.principal.clone(),
        allow: r.allow.clone(),
    }
}

// ---- handlers ----

async fn create<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Json(req): Json<CreateReq>,
) -> Result<Json<IdResp>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let id = cp.create_vm(to_req(req)).await?;
    Ok(Json(IdResp { id: id.to_string() }))
}

async fn list<N, S, R>(State(cp): State<Cp<N, S, R>>) -> Result<Json<Vec<VmResp>>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    Ok(Json(cp.list_vms()?.iter().map(vm_resp).collect()))
}

async fn get_one<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
) -> Result<Json<VmResp>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let id = parse_id(&id)?;
    let rec = cp.get_vm(id)?.ok_or(ApiError(StatusCode::NOT_FOUND, "no such vm".into()))?;
    Ok(Json(vm_resp(&rec)))
}

macro_rules! lifecycle_handler {
    ($name:ident, $method:ident) => {
        async fn $name<N, S, R>(
            State(cp): State<Cp<N, S, R>>,
            Path(id): Path<String>,
        ) -> Result<StatusCode, ApiError>
        where
            N: NetworkManager + Send + Sync + 'static,
            S: StorageManager + Send + Sync + 'static,
            R: VmRuntime + Send + Sync + 'static,
        {
            cp.$method(parse_id(&id)?).await?;
            Ok(StatusCode::NO_CONTENT)
        }
    };
}
lifecycle_handler!(start, start_vm);
lifecycle_handler!(stop, stop_vm);
lifecycle_handler!(suspend, suspend_vm);
lifecycle_handler!(halt, halt_vm);
lifecycle_handler!(destroy, destroy_vm);

async fn register_template<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Json(t): Json<TemplateReq>,
) -> Result<StatusCode, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let snapshot = match (t.snapshot_mem, t.snapshot_vmstate) {
        (Some(m), Some(v)) => Some(SnapshotRef {
            mem_file: PathBuf::from(m),
            vmstate: PathBuf::from(v),
        }),
        _ => None,
    };
    cp.register_template(&TemplateDef {
        name: t.name,
        rootfs_template: t.rootfs_template,
        snapshot,
        vcpus: t.vcpus,
        mem_mib: t.mem_mib,
        kernel: PathBuf::from(t.kernel),
        boot_args: t.boot_args,
    })?;
    Ok(StatusCode::CREATED)
}

async fn set_policy<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Json(req): Json<PolicyReq>,
) -> Result<StatusCode, ApiError>
where
    N: iso_common::network::NetworkManager + Send + Sync + 'static,
    S: iso_common::storage::StorageManager + Send + Sync + 'static,
    R: iso_common::runtime::VmRuntime + Send + Sync + 'static,
{
    let egress = req.egress.as_deref().and_then(egress_parse);
    cp.set_policy(parse_id(&id)?, req.principal, req.allow, egress)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_forward<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Json(req): Json<AddForwardReq>,
) -> Result<Json<PortForwardDto>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let fwd = cp
        .add_forward(parse_id(&id)?, req.vm_port, proto_from(&req.proto))
        .await?;
    Ok(Json(PortForwardDto {
        host_port: fwd.host_port,
        vm_port: fwd.vm_port,
        proto: proto_to(fwd.proto),
    }))
}

async fn remove_forward<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path((id, host_port)): Path<(String, u16)>,
    Query(q): Query<ProtoQuery>,
) -> Result<StatusCode, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let proto = proto_from(q.proto.as_deref().unwrap_or("tcp"));
    cp.remove_forward(parse_id(&id)?, host_port, proto).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn stats<N, S, R>(State(cp): State<Cp<N, S, R>>) -> Result<Json<StatsResp>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let s = cp.stats().await?;
    Ok(Json(StatsResp {
        data_percent: s.pool.data_percent,
        metadata_percent: s.pool.metadata_percent,
        slots_used: s.slots_used,
        slots_total: s.slots_total,
        vms: s.vms,
    }))
}

// ---- guest agent (exec and files inside the VM) ----

/// Open the guest agent inside `id` over the VMM's channel.
async fn guest<N, S, R>(
    cp: &Cp<N, S, R>,
    id: &str,
) -> Result<GuestClient<tokio::net::UnixStream>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let fd = cp.guest_channel(parse_id(id)?, None).await?;
    let std = std::os::unix::net::UnixStream::from(fd);
    let io = |e: std::io::Error| ApiError(StatusCode::BAD_GATEWAY, format!("guest channel: {e}"));
    std.set_nonblocking(true).map_err(io)?;
    Ok(GuestClient::new(tokio::net::UnixStream::from_std(std).map_err(io)?))
}

async fn bounded<T>(limit: Duration, f: impl std::future::Future<Output = Result<T, ClientError>>) -> Result<T, ApiError> {
    match tokio::time::timeout(limit, f).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(ApiError(StatusCode::GATEWAY_TIMEOUT, "guest agent did not answer in time".into())),
    }
}

async fn agent_info<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
) -> Result<Json<AgentInfo>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let mut g = guest(&cp, &id).await?;
    Ok(Json(bounded(GUEST_IO_TIMEOUT, g.ping()).await?))
}

async fn exec<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Json(req): Json<ExecRequest>,
) -> Result<Json<ExecResult>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    if req.cmd.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "cmd is required".into()));
    }
    let limit = Duration::from_millis(req.timeout_ms.unwrap_or(iso_guest_proto::DEFAULT_EXEC_TIMEOUT_MS)) + EXEC_SLACK;
    let mut g = guest(&cp, &id).await?;
    Ok(Json(bounded(limit, g.exec(req)).await?))
}

async fn read_file<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<FileContent>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let mut g = guest(&cp, &id).await?;
    Ok(Json(bounded(GUEST_IO_TIMEOUT, g.read_file(&q.path, q.max_bytes)).await?))
}

async fn write_file<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
    Json(req): Json<WriteFileReq>,
) -> Result<Json<WrittenResp>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    use base64::Engine as _;
    let content_b64 = match (req.content, req.content_b64) {
        (Some(text), None) => base64::engine::general_purpose::STANDARD.encode(text.as_bytes()),
        (None, Some(b64)) => b64,
        (None, None) => return Err(ApiError(StatusCode::BAD_REQUEST, "one of content or content_b64 is required".into())),
        (Some(_), Some(_)) => return Err(ApiError(StatusCode::BAD_REQUEST, "give content or content_b64, not both".into())),
    };
    let mut g = guest(&cp, &id).await?;
    let bytes = bounded(GUEST_IO_TIMEOUT, g.write_file(&q.path, content_b64, req.mode, req.mkdir)).await?;
    Ok(Json(WrittenResp { bytes }))
}

async fn remove_path<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<StatusCode, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let mut g = guest(&cp, &id).await?;
    bounded(GUEST_IO_TIMEOUT, g.remove(&q.path, q.recursive)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_dir<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<DirResp>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let mut g = guest(&cp, &id).await?;
    let entries = bounded(GUEST_IO_TIMEOUT, g.list_dir(&q.path)).await?;
    Ok(Json(DirResp { entries }))
}

/// Build the admin router over a control plane.
pub fn router<N, S, R>(cp: Cp<N, S, R>) -> Router
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    Router::new()
        .route("/vms", post(create::<N, S, R>).get(list::<N, S, R>))
        .route("/vms/{id}", get(get_one::<N, S, R>).delete(destroy::<N, S, R>))
        .route("/vms/{id}/start", post(start::<N, S, R>))
        .route("/vms/{id}/stop", post(stop::<N, S, R>))
        .route("/vms/{id}/suspend", post(suspend::<N, S, R>))
        .route("/vms/{id}/halt", post(halt::<N, S, R>))
        .route("/vms/{id}/policy", patch(set_policy::<N, S, R>))
        .route("/vms/{id}/forwards", post(add_forward::<N, S, R>))
        .route(
            "/vms/{id}/forwards/{host_port}",
            delete(remove_forward::<N, S, R>),
        )
        .route("/vms/{id}/agent", get(agent_info::<N, S, R>))
        .route("/vms/{id}/exec", post(exec::<N, S, R>))
        .route(
            "/vms/{id}/files",
            get(read_file::<N, S, R>).put(write_file::<N, S, R>).delete(remove_path::<N, S, R>),
        )
        .route("/vms/{id}/dir", get(list_dir::<N, S, R>))
        .route("/templates", post(register_template::<N, S, R>))
        .route("/stats", get(stats::<N, S, R>))
        .with_state(cp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use iso_common::{
        HostNetwork, InstanceSpec, MacAddr, NetworkFixture, NetworkPolicy, PoolStats,
        Result as IRes, SlotId, StorageHandle, VmStatus, VolumeSpec,
    };
    use iso_control_plane::Config;
    use std::net::Ipv4Addr;
    use tower::ServiceExt;

    struct MNet;
    impl NetworkManager for MNet {
        async fn init(&self) -> IRes<HostNetwork> {
            Ok(HostNetwork { services_addr: Ipv4Addr::new(172, 22, 0, 1), proxy_port: 3128 })
        }
        async fn apply(&self, slot: SlotId, _p: &NetworkPolicy) -> IRes<NetworkFixture> {
            Ok(NetworkFixture {
                slot,
                netns: format!("vm{:04x}", slot.get()),
                tap: "tap0".into(),
                veth_host: format!("vm{:04x}", slot.get()),
                veth_netns: format!("vp{:04x}", slot.get()),
                vh_ip: Ipv4Addr::new(172, 21, 0, 0),
                vp_ip: Ipv4Addr::new(172, 21, 0, 1),
                mac: MacAddr([2, 0, 0, 0, 0, 1]),
            })
        }
        async fn reapply_policy(&self, _slot: SlotId, _p: &NetworkPolicy) -> IRes<()> {
            Ok(())
        }
        async fn teardown(&self, _slot: SlotId) -> IRes<()> {
            Ok(())
        }
        fn address_to_slot(&self, _a: Ipv4Addr) -> Option<SlotId> {
            None
        }
    }

    struct MStore;
    impl StorageManager for MStore {
        async fn init(&self) -> IRes<()> {
            Ok(())
        }
        async fn provision(&self, vm: VmId, _s: &VolumeSpec) -> IRes<StorageHandle> {
            Ok(StorageHandle {
                vm,
                device_path: "/dev/iso/x".into(),
                backing_device: Some("/dev/iso/tpl_x".into()),
            })
        }
        async fn teardown(&self, _vm: VmId) -> IRes<()> {
            Ok(())
        }
        async fn pool_stats(&self) -> IRes<PoolStats> {
            Ok(PoolStats { data_percent: 10.0, metadata_percent: 5.0 })
        }
    }

    struct MRun(Mutex<std::collections::HashMap<VmId, VmStatus>>);
    impl VmRuntime for MRun {
        async fn create(&self, s: &InstanceSpec) -> IRes<()> {
            self.0.lock().unwrap().insert(s.vm, VmStatus::Created);
            Ok(())
        }
        async fn start(&self, vm: VmId) -> IRes<()> {
            self.0.lock().unwrap().insert(vm, VmStatus::Running);
            Ok(())
        }
        async fn suspend(&self, vm: VmId) -> IRes<()> {
            self.0.lock().unwrap().insert(vm, VmStatus::Suspended);
            Ok(())
        }
        async fn stop(&self, vm: VmId) -> IRes<()> {
            self.0.lock().unwrap().insert(vm, VmStatus::Stopped);
            Ok(())
        }
        async fn halt(&self, vm: VmId) -> IRes<()> {
            self.0.lock().unwrap().insert(vm, VmStatus::Stopped);
            Ok(())
        }
        async fn destroy(&self, vm: VmId) -> IRes<()> {
            self.0.lock().unwrap().remove(&vm);
            Ok(())
        }
        async fn status(&self, vm: VmId) -> IRes<VmStatus> {
            Ok(self.0.lock().unwrap().get(&vm).copied().unwrap_or(VmStatus::Absent))
        }
        /// The real guest agent on the far end of a socketpair: the handlers
        /// under test speak to it exactly as they would to a VM.
        async fn guest_channel(&self, _vm: VmId, _port: u32) -> IRes<std::os::fd::OwnedFd> {
            let (host, guest) = std::os::unix::net::UnixStream::pair().map_err(|e| iso_common::Error::Backend(e.to_string()))?;
            guest.set_nonblocking(true).unwrap();
            let guest = tokio::net::UnixStream::from_std(guest).unwrap();
            tokio::spawn(iso_guest_agent::serve_connection(guest));
            Ok(std::os::fd::OwnedFd::from(host))
        }
    }

    pub(super) fn app() -> Router {
        let cfg = Config {
            db_path: ":memory:".into(),
            default_vcpus: 1,
            default_mem_mib: 512,
            pool_watermark_percent: 90.0,
            graceful_stop: Duration::from_secs(1),
            slot_capacity: 8,
            forward_ports: (20000, 30000),
            vsock_cid: Some(3),
            guest_agent_port: 5000,
        };
        let cp = Arc::new(
            ControlPlane::new(cfg, MNet, MStore, MRun(Mutex::new(Default::default()))).unwrap(),
        );
        cp.register_template(&TemplateDef {
            name: "base".into(),
            rootfs_template: "base".into(),
            snapshot: None,
            vcpus: 1,
            mem_mib: 512,
            kernel: "/k".into(),
            boot_args: String::new(),
        })
        .unwrap();
        router(cp)
    }

    pub(super) async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    pub(super) fn post(path: &str, json: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn create_list_stats_roundtrip() {
        let app = app();
        // create
        let resp = app
            .clone()
            .oneshot(post("/vms", serde_json::json!({"template":"base","egress":"allow"})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let id = body_json(resp).await["id"].as_str().unwrap().to_string();
        assert!(VmId::parse(&id).is_some());

        // list
        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/vms").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let list = body_json(resp).await;
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["egress"], "allow");
        assert_eq!(list[0]["state"], "running");

        // stats
        let resp = app
            .oneshot(Request::builder().uri("/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let s = body_json(resp).await;
        assert_eq!(s["vms"], 1);
        assert_eq!(s["slots_used"], 1);
        assert_eq!(s["data_percent"], 10.0);
    }

    #[tokio::test]
    async fn unknown_template_maps_to_404() {
        let resp = app()
            .oneshot(post("/vms", serde_json::json!({"template":"ghost"})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn bad_id_maps_to_400() {
        let resp = app()
            .oneshot(post("/vms/not-a-uuid/stop", serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod guest_tests {
    use super::tests::{app, body_json, post};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn create_vm(app: &axum::Router, lifecycle: &str) -> String {
        let resp = app
            .clone()
            .oneshot(post("/vms", serde_json::json!({ "template": "base", "lifecycle": lifecycle })))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        body_json(resp).await["id"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn exec_runs_a_program_in_the_guest() {
        let app = app();
        let id = create_vm(&app, "ephemeral").await;
        let resp = app
            .clone()
            .oneshot(post(
                &format!("/vms/{id}/exec"),
                serde_json::json!({ "cmd": "sh", "args": ["-c", "printf hello; echo oops >&2; exit 4"] }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["exit_code"], 4);
        assert_eq!(v["stdout"], "hello");
        assert_eq!(v["stderr"], "oops\n");
        assert_eq!(v["timed_out"], false);
    }

    #[tokio::test]
    async fn files_round_trip_through_the_guest() {
        let app = app();
        let id = create_vm(&app, "ephemeral").await;
        let dir = std::env::temp_dir().join(format!("iso-http-guest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join("notes/todo.md");
        let path = file.to_str().unwrap();

        let put = Request::builder()
            .method("PUT")
            .uri(format!("/vms/{id}/files?path={path}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({ "content": "# hi\n", "mkdir": true }).to_string()))
            .unwrap();
        let resp = app.clone().oneshot(put).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["bytes"], 5);

        let resp = app
            .clone()
            .oneshot(Request::get(format!("/vms/{id}/files?path={path}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["size"], 5);
        assert_eq!(v["content_b64"], "IyBoaQo=");

        let resp = app
            .clone()
            .oneshot(Request::get(format!("/vms/{id}/dir?path={}", dir.join("notes").display())).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["entries"][0]["name"], "todo.md");

        let resp = app
            .clone()
            .oneshot(Request::delete(format!("/vms/{id}/files?path={}&recursive=true", dir.display())).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(!dir.exists());

        // The agent's own refusal is the caller's error, not the host's.
        let resp = app
            .clone()
            .oneshot(Request::get(format!("/vms/{id}/files?path={}", dir.join("gone").display())).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn agent_endpoints_need_a_running_vm() {
        let app = app();
        let id = create_vm(&app, "durable").await;
        let resp = app
            .clone()
            .oneshot(Request::get(format!("/vms/{id}/agent")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["agent"], "iso-guest-agent");

        let resp = app.clone().oneshot(post(&format!("/vms/{id}/stop"), serde_json::json!({}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let resp = app
            .clone()
            .oneshot(post(&format!("/vms/{id}/exec"), serde_json::json!({ "cmd": "true" })))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "stopped vm has no guest channel");
    }
}
