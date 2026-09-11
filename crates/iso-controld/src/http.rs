//! axum admin API over the (transport-agnostic) control-plane core.
//!
//! Admin-only: host-global stats live here, never on a VM-facing surface.
//!
//! The OpenAPI document is generated from the handler and DTO annotations
//! below ([`ApiDoc`]) and served at `GET /openapi.json`; `iso-openapi` prints
//! it, and `crates/iso-client` is generated from it (`scripts/gen-client.sh`).

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
    EgressMode, NetworkManager, Protocol, SnapshotRef, StorageManager, VmId, VmRuntime,
};
use iso_control_plane::types::{egress_parse, egress_str, TemplateDef};
use iso_control_plane::{ControlPlane, CreateVm, Error as CpError, VmRecord};
use iso_guest_proto::{AgentInfo, ClientError, DirEntry, ExecRequest, ExecResult, FileContent, GuestClient};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

type Cp<N, S, R> = Arc<ControlPlane<N, S, R>>;

/// The shape of every error response.
#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    /// What went wrong.
    pub error: String,
}


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

/// An ingress port forward from a host port to a port inside the VM.
#[derive(Serialize, Deserialize, ToSchema)]
struct PortForward {
    /// Allocated by the control plane; ignored on create, reported on read.
    #[serde(default)]
    host_port: u16,
    vm_port: u16,
    /// `tcp` or `udp`.
    proto: String,
}

/// Create and boot a VM. Only `template` is required.
#[derive(Deserialize, ToSchema)]
struct CreateVmRequest {
    /// A registered template name.
    template: String,
    /// `allow`, `proxy` or `deny` (default). Unrecognized values mean `deny`.
    #[serde(default)]
    egress: String,
    /// Ports to forward into the VM; host ports are allocated.
    #[serde(default)]
    ingress: Vec<PortForward>,
    /// Free-form labels; `name` is surfaced to the guest's metadata.
    #[serde(default)]
    labels: HashMap<String, String>,
    /// `ephemeral` (default: deleted on stop) or `durable` (rootfs kept).
    #[serde(default)]
    lifecycle: String,
    /// `never` (default), `on_failure` or `always`.
    #[serde(default)]
    restart: String,
    /// Override the template's vCPU count (forces a cold boot).
    #[serde(default)]
    vcpus: Option<u32>,
    /// Override the template's memory (forces a cold boot).
    #[serde(default)]
    mem_mib: Option<u32>,
    /// Principal whose credentials the egress proxy injects.
    #[serde(default)]
    principal: Option<String>,
    /// Domains routed through the egress proxy.
    #[serde(default)]
    allow: Vec<String>,
}

/// The id of a newly created VM.
#[derive(Serialize, ToSchema)]
struct CreatedVm {
    id: String,
}

/// Open a new ingress forward. The host port is allocated by the control
/// plane and returned in the response.
#[derive(Deserialize, ToSchema)]
struct AddForwardRequest {
    vm_port: u16,
    /// `tcp` (default) or `udp`.
    #[serde(default)]
    proto: String,
}

/// Which protocol's forward to remove (defaults to tcp).
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ProtoQuery {
    /// `tcp` (default) or `udp`.
    #[serde(default)]
    proto: Option<String>,
}

/// A VM as the control plane sees it.
#[derive(Serialize, ToSchema)]
struct Vm {
    id: String,
    /// Placement slot; absent while a durable VM is stopped.
    slot: Option<u16>,
    template: String,
    /// `creating`, `running`, `suspended`, `stopped` or `failed`.
    state: String,
    /// `allow`, `proxy` or `deny`.
    egress: String,
    /// `ephemeral` or `durable`.
    lifecycle: String,
    /// `never`, `on_failure` or `always`.
    restart: String,
    labels: HashMap<String, String>,
    ingress: Vec<PortForward>,
    tap: Option<String>,
    rootfs_device: Option<String>,
    principal: Option<String>,
    allow: Vec<String>,
}

/// Change a running VM's egress policy. Omitted fields are left unchanged.
#[derive(Deserialize, ToSchema)]
struct PolicyRequest {
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    allow: Option<Vec<String>>,
    /// `allow`, `proxy` or `deny`; anything else leaves the mode unchanged.
    #[serde(default)]
    egress: Option<String>,
}

/// Which path inside the guest a file operation targets.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct PathQuery {
    /// Absolute path inside the guest.
    path: String,
    /// Read at most this many bytes (default 16 MiB).
    #[serde(default)]
    max_bytes: Option<u64>,
    /// Remove a directory and everything under it.
    #[serde(default)]
    recursive: bool,
}

/// Write a file inside the guest: one of `content` (UTF-8 text) or
/// `content_b64` (arbitrary bytes).
#[derive(Deserialize, ToSchema)]
struct WriteFileRequest {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    content_b64: Option<String>,
    /// Permission bits to set, e.g. 493 for `0755`.
    #[serde(default)]
    mode: Option<u32>,
    /// Create missing parent directories.
    #[serde(default)]
    mkdir: bool,
}

/// Bytes written.
#[derive(Serialize, ToSchema)]
struct Written {
    bytes: u64,
}

/// A directory listing (not recursive).
#[derive(Serialize, ToSchema)]
struct DirListing {
    entries: Vec<DirEntry>,
}

/// Host capacity.
#[derive(Serialize, ToSchema)]
struct Stats {
    /// Thin-pool data usage, percent.
    data_percent: f64,
    /// Thin-pool metadata usage, percent.
    metadata_percent: f64,
    slots_used: usize,
    slots_total: usize,
    /// VM records, in any state.
    vms: usize,
}

/// Register a template built by `isoctl bake`. Paths are host paths.
#[derive(Deserialize, ToSchema)]
struct TemplateRequest {
    name: String,
    /// The LVM template volume, without the `tpl_` prefix.
    rootfs_template: String,
    /// Memory snapshot; with `snapshot_vmstate`, VMs resume warm.
    #[serde(default)]
    snapshot_mem: Option<String>,
    #[serde(default)]
    snapshot_vmstate: Option<String>,
    vcpus: u32,
    mem_mib: u32,
    /// Uncompressed guest kernel.
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

fn to_req(r: CreateVmRequest) -> CreateVm {
    CreateVm {
        template: r.template,
        egress: egress_from(&r.egress),
        ingress: r
            .ingress
            .into_iter()
            .map(|f| iso_common::PortForward {
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

fn vm_resp(r: &VmRecord) -> Vm {
    Vm {
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
            .map(|f| PortForward {
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

#[utoipa::path(post, path = "/vms", tag = "vms", request_body = CreateVmRequest,
    responses(
        (status = 200, description = "Created and booted", body = CreatedVm),
        (status = 404, description = "Unknown template", body = ErrorBody),
        (status = 409, description = "No free slot or port, or the pool is over its watermark", body = ErrorBody),
    ))]
async fn create<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Json(req): Json<CreateVmRequest>,
) -> Result<Json<CreatedVm>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let id = cp.create_vm(to_req(req)).await?;
    Ok(Json(CreatedVm { id: id.to_string() }))
}

#[utoipa::path(get, path = "/vms", tag = "vms",
    responses((status = 200, description = "Every VM record", body = Vec<Vm>)))]
async fn list<N, S, R>(State(cp): State<Cp<N, S, R>>) -> Result<Json<Vec<Vm>>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    Ok(Json(cp.list_vms()?.iter().map(vm_resp).collect()))
}

#[utoipa::path(get, path = "/vms/{id}", tag = "vms", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits")),
    responses((status = 200, description = "The VM", body = Vm), (status = 404, description = "Unknown VM", body = ErrorBody)))]
async fn get_one<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
) -> Result<Json<Vm>, ApiError>
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
    ($name:ident, $method:ident, $verb:ident, $path:literal, $desc:literal) => {
        #[utoipa::path($verb, path = $path, tag = "vms", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits")),
            responses(
                (status = 204, description = $desc),
                (status = 404, description = "Unknown VM", body = ErrorBody),
                (status = 409, description = "Not valid in the VM's current state", body = ErrorBody),
            ))]
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
lifecycle_handler!(start, start_vm, post, "/vms/{id}/start", "Booted a stopped durable VM, or resumed a suspended one");
lifecycle_handler!(stop, stop_vm, post, "/vms/{id}/stop", "Shut down gracefully; an ephemeral VM is then deleted");
lifecycle_handler!(suspend, suspend_vm, post, "/vms/{id}/suspend", "Paused and snapshotted in place");
lifecycle_handler!(halt, halt_vm, post, "/vms/{id}/halt", "Killed; an ephemeral VM is then deleted");
lifecycle_handler!(destroy, destroy_vm, delete, "/vms/{id}", "Destroyed with its storage and placement, whatever its lifecycle");

#[utoipa::path(post, path = "/templates", tag = "templates", request_body = TemplateRequest,
    responses((status = 201, description = "Registered (upsert by name)")))]
async fn register_template<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Json(t): Json<TemplateRequest>,
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

#[utoipa::path(patch, path = "/vms/{id}/policy", tag = "vms", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits")),
    request_body = PolicyRequest,
    responses((status = 204, description = "Applied to new connections"), (status = 404, description = "Unknown VM", body = ErrorBody)))]
async fn set_policy<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Json(req): Json<PolicyRequest>,
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

#[utoipa::path(post, path = "/vms/{id}/forwards", tag = "vms", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits")),
    request_body = AddForwardRequest,
    responses(
        (status = 200, description = "The forward, with its allocated host port", body = PortForward),
        (status = 404, description = "Unknown VM", body = ErrorBody),
        (status = 409, description = "No free host port", body = ErrorBody),
    ))]
async fn add_forward<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Json(req): Json<AddForwardRequest>,
) -> Result<Json<PortForward>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let fwd = cp
        .add_forward(parse_id(&id)?, req.vm_port, proto_from(&req.proto))
        .await?;
    Ok(Json(PortForward {
        host_port: fwd.host_port,
        vm_port: fwd.vm_port,
        proto: proto_to(fwd.proto),
    }))
}

#[utoipa::path(delete, path = "/vms/{id}/forwards/{host_port}", tag = "vms",
    params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits"), ("host_port" = u16, Path, description = "The allocated host port"), ProtoQuery),
    responses((status = 204, description = "Closed"), (status = 404, description = "Unknown VM or forward", body = ErrorBody)))]
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

#[utoipa::path(get, path = "/stats", tag = "host", responses((status = 200, description = "Host capacity", body = Stats)))]
async fn stats<N, S, R>(State(cp): State<Cp<N, S, R>>) -> Result<Json<Stats>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let s = cp.stats().await?;
    Ok(Json(Stats {
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

#[utoipa::path(get, path = "/vms/{id}/agent", tag = "guest", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits")),
    responses(
        (status = 200, description = "The guest agent answered", body = AgentInfo),
        (status = 409, description = "The VM is not running", body = ErrorBody),
        (status = 502, description = "No agent reachable in the guest", body = ErrorBody),
    ))]
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

#[utoipa::path(post, path = "/vms/{id}/exec", tag = "guest", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits")),
    request_body = ExecRequest,
    responses(
        (status = 200, description = "The program ran (its exit status is in the body)", body = ExecResult),
        (status = 400, description = "The agent refused: bad program, cwd, or request", body = ErrorBody),
        (status = 409, description = "The VM is not running", body = ErrorBody),
        (status = 502, description = "No agent reachable in the guest", body = ErrorBody),
        (status = 504, description = "The agent did not answer in time", body = ErrorBody),
    ))]
async fn guest_exec<N, S, R>(
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

#[utoipa::path(get, path = "/vms/{id}/files", tag = "guest", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits"), PathQuery),
    responses(
        (status = 200, description = "The file, base64", body = FileContent),
        (status = 400, description = "No such file, or not a regular file", body = ErrorBody),
        (status = 409, description = "The VM is not running", body = ErrorBody),
        (status = 502, description = "No agent reachable in the guest", body = ErrorBody),
    ))]
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

#[utoipa::path(put, path = "/vms/{id}/files", tag = "guest", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits"), PathQuery),
    request_body = WriteFileRequest,
    responses(
        (status = 200, description = "Written", body = Written),
        (status = 400, description = "Bad content, or the agent could not write there", body = ErrorBody),
        (status = 409, description = "The VM is not running", body = ErrorBody),
        (status = 502, description = "No agent reachable in the guest", body = ErrorBody),
    ))]
async fn write_file<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
    Json(req): Json<WriteFileRequest>,
) -> Result<Json<Written>, ApiError>
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
    Ok(Json(Written { bytes }))
}

#[utoipa::path(delete, path = "/vms/{id}/files", tag = "guest", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits"), PathQuery),
    responses(
        (status = 204, description = "Removed"),
        (status = 400, description = "No such path, or a directory without recursive", body = ErrorBody),
        (status = 409, description = "The VM is not running", body = ErrorBody),
        (status = 502, description = "No agent reachable in the guest", body = ErrorBody),
    ))]
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

#[utoipa::path(get, path = "/vms/{id}/dir", tag = "guest", params(("id" = String, Path, description = "VM id, as a hyphenated UUID or 32 hex digits"), PathQuery),
    responses(
        (status = 200, description = "The entries, sorted by name", body = DirListing),
        (status = 400, description = "No such directory", body = ErrorBody),
        (status = 409, description = "The VM is not running", body = ErrorBody),
        (status = 502, description = "No agent reachable in the guest", body = ErrorBody),
    ))]
async fn list_dir<N, S, R>(
    State(cp): State<Cp<N, S, R>>,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<DirListing>, ApiError>
where
    N: NetworkManager + Send + Sync + 'static,
    S: StorageManager + Send + Sync + 'static,
    R: VmRuntime + Send + Sync + 'static,
{
    let mut g = guest(&cp, &id).await?;
    let entries = bounded(GUEST_IO_TIMEOUT, g.list_dir(&q.path)).await?;
    Ok(Json(DirListing { entries }))
}

/// The admin API's OpenAPI document, derived from the handlers above.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "iso admin API",
        description = "Create Firecracker microVMs, set their egress policy, and reach the agent inside them. \
            Served on the daemon's unix socket (root only) and on its TCP listener, where a client \
            certificate issued by the host's admin CA (`isoctl admin issue-client`) is required.",
        license(name = "MIT"),
    ),
    paths(create, list, get_one, start, stop, suspend, halt, destroy, set_policy, add_forward, remove_forward,
        register_template, stats, agent_info, guest_exec, read_file, write_file, remove_path, list_dir),
    components(schemas(ErrorBody, PortForward, CreateVmRequest, CreatedVm, AddForwardRequest, Vm, PolicyRequest,
        WriteFileRequest, Written, DirListing, Stats, TemplateRequest,
        ExecRequest, ExecResult, AgentInfo, FileContent, DirEntry, iso_guest_proto::FileKind)),
    tags(
        (name = "vms", description = "VM lifecycle, policy and port forwards"),
        (name = "guest", description = "Run programs and move files inside a VM through its agent"),
        (name = "templates", description = "Baked templates VMs are cloned from"),
        (name = "host", description = "Host capacity"),
    )
)]
pub struct ApiDoc;

async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
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
        .route("/vms/{id}/exec", post(guest_exec::<N, S, R>))
        .route(
            "/vms/{id}/files",
            get(read_file::<N, S, R>).put(write_file::<N, S, R>).delete(remove_path::<N, S, R>),
        )
        .route("/vms/{id}/dir", get(list_dir::<N, S, R>))
        .route("/templates", post(register_template::<N, S, R>))
        .route("/stats", get(stats::<N, S, R>))
        .route("/openapi.json", get(openapi_json))
        .with_state(cp)
}

#[cfg(test)]
pub(crate) mod tests {
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

    pub(crate) fn app() -> Router {
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

#[cfg(test)]
mod openapi_tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every `(method, path)` the router serves, read from this file's
    /// `.route(...)` calls so the test needs no hand-kept list.
    fn routes_in_source() -> BTreeSet<(String, String)> {
        let src = include_str!("http.rs");
        let mut out = BTreeSet::new();
        for chunk in src.split(".route(").skip(1) {
            let path = chunk.split('"').nth(1).unwrap_or_default().to_string();
            let call = chunk.split(".route(").next().unwrap_or_default();
            let call = call.split(".with_state").next().unwrap_or_default();
            for verb in ["get", "post", "put", "patch", "delete"] {
                if call.contains(&format!("{verb}(")) {
                    out.insert((verb.to_uppercase(), path.clone()));
                }
            }
        }
        out.remove(&("GET".into(), "/openapi.json".into()));
        out
    }

    #[test]
    fn document_covers_exactly_the_routes_the_router_serves() {
        let doc: serde_json::Value = serde_json::from_str(&ApiDoc::openapi().to_json().unwrap()).unwrap();
        let mut documented = BTreeSet::new();
        for (path, item) in doc["paths"].as_object().unwrap() {
            for verb in item.as_object().unwrap().keys() {
                documented.insert((verb.to_uppercase(), path.clone()));
            }
        }
        let served = routes_in_source();
        let missing: Vec<_> = served.difference(&documented).collect();
        let extra: Vec<_> = documented.difference(&served).collect();
        assert!(missing.is_empty(), "routes without an OpenAPI operation: {missing:?}");
        assert!(extra.is_empty(), "documented operations with no route: {extra:?}");
        assert_eq!(served.len(), 19, "operation count; update when routes change on purpose");
    }

    #[test]
    fn document_is_openapi_3_0_for_the_client_generator() {
        let json = ApiDoc::openapi().to_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["openapi"].as_str().unwrap().starts_with("3.0"), "progenitor reads OpenAPI 3.0.x");
        assert!(v["components"]["schemas"]["ExecRequest"].is_object());
    }

    /// The copy the client crate is generated from must match the code.
    #[test]
    fn checked_in_document_matches_the_code() {
        let current: serde_json::Value = serde_json::from_str(&ApiDoc::openapi().to_json().unwrap()).unwrap();
        let checked_in: serde_json::Value =
            serde_json::from_str(include_str!("../../iso-client/openapi.json")).unwrap();
        assert_eq!(checked_in, current, "crates/iso-client/openapi.json is stale: run scripts/gen-client.sh");
    }

    #[tokio::test]
    async fn openapi_json_is_served() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let resp = tests::app().oneshot(Request::get("/openapi.json").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = tests::body_json(resp).await;
        assert_eq!(v["info"]["title"], "iso admin API");
    }
}
