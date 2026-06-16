//! axum admin API over the (transport-agnostic) control-plane core.
//!
//! Admin-only: host-global stats live here, never on a VM-facing surface.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use iso_common::{
    EgressMode, NetworkManager, PortForward, Protocol, SnapshotRef, StorageManager, VmId,
    VmRuntime,
};
use iso_control_plane::types::{egress_parse, egress_str, TemplateDef};
use iso_control_plane::{ControlPlane, CreateVm, Error as CpError, VmRecord};
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
            CpError::UnknownVm(_) | CpError::UnknownTemplate(_) => StatusCode::NOT_FOUND,
            CpError::SlotsExhausted | CpError::PoolFull { .. } | CpError::InvalidState { .. } => {
                StatusCode::CONFLICT
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(code, e.to_string())
    }
}

fn parse_id(s: &str) -> Result<VmId, ApiError> {
    VmId::parse(s).ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "invalid vm id".into()))
}

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
    }

    fn app() -> Router {
        let cfg = Config {
            db_path: ":memory:".into(),
            default_vcpus: 1,
            default_mem_mib: 512,
            pool_watermark_percent: 90.0,
            graceful_stop: Duration::from_secs(1),
            slot_capacity: 8,
            forward_ports: (20000, 30000),
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

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn post(path: &str, json: serde_json::Value) -> Request<Body> {
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
