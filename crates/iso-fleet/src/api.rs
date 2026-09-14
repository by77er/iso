//! The fleet API. It is the host admin API with the host removed: the same
//! paths and bodies, so every existing client works by changing a URL.
//! `POST /vms` places; `GET /vms` reads the fleet's record; everything under
//! `/vms/{id}/…` is forwarded to the VM's host as it came.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, patch, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::hosts::CallError;
use crate::store::{VmRow, state};
use crate::{Fleet, placement};

type Shared = Arc<Fleet>;

pub fn router(fleet: Shared) -> Router {
    Router::new()
        .route("/vms", post(create).get(list))
        .route("/vms/{id}", get(get_one).delete(delete_one))
        .route("/vms/{id}/policy", patch(set_policy))
        .route("/vms/{id}/{*rest}", any(forward))
        .route("/hosts", get(hosts))
        .route("/stats", get(stats))
        .route("/openapi.json", get(openapi))
        .with_state(fleet)
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("store: {e}"))
    }
}

/// A VM as the fleet describes it: the host's record (live if given, else
/// the one from the last sync, else one synthesized from the create request
/// so the shape is always the host's), plus where it is and what the fleet
/// knows. Typed clients generated from the host API read it unchanged.
fn view(row: &VmRow, host_view: Option<Value>) -> Value {
    let mut v = host_view.or_else(|| row.view.clone()).unwrap_or_else(|| {
        let s = &row.spec;
        json!({
            "id": row.id,
            "slot": null,
            "template": row.template,
            "state": row.host_state.clone().unwrap_or_else(|| "creating".into()),
            "egress": s["egress"].as_str().unwrap_or("deny"),
            "lifecycle": s["lifecycle"].as_str().unwrap_or("ephemeral"),
            "restart": s["restart"].as_str().unwrap_or("never"),
            "labels": row.labels,
            "ingress": [],
            "tap": null,
            "rootfs_device": null,
            "principal": s["principal"],
            "allow": s["allow"].as_array().cloned().unwrap_or_default(),
            "rules": s["rules"].as_array().cloned().unwrap_or_default(),
            "policy_gen": 1,
        })
    });
    if let Some(o) = v.as_object_mut() {
        o.insert("host".into(), json!(row.host));
        o.insert("fleet_state".into(), json!(row.fleet_state));
        if let Some(e) = &row.last_error {
            o.insert("fleet_error".into(), json!(e));
        }
    }
    v
}

async fn create(
    State(fleet): State<Shared>,
    Json(mut body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let template = body["template"]
        .as_str()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "template is required".into()))?
        .to_string();
    let pin = body.get("host").and_then(Value::as_str).map(str::to_string);
    if let Some(o) = body.as_object_mut() {
        o.remove("host");
        o.remove("id");
    }
    let labels = body.get("labels").cloned().unwrap_or_else(|| json!({}));
    // The policy as the client gave it, checked here so a bad rule is a 400
    // before anything is recorded, and signed below for whichever host takes
    // the VM.
    let policy = PolicyFields::from_create(&body);
    policy.check().map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;

    let hosts = fleet.store.list_hosts()?;
    let candidates = placement::candidates(&hosts, &template, pin.as_deref());
    if candidates.is_empty() {
        return Err(if !placement::template_known(&hosts, &template) {
            ApiError(
                StatusCode::NOT_FOUND,
                format!("no host has template {template:?}"),
            )
        } else {
            ApiError(
                StatusCode::CONFLICT,
                format!("no healthy host with a free slot has template {template:?}"),
            )
        });
    }

    let id = fleet.new_id();
    body["id"] = json!(id);
    // Write-ahead: the record exists before any host is asked, so a lost
    // reply is reconciled by the sync loop rather than becoming a second VM.
    fleet
        .store
        .insert_vm(&id, &candidates[0].name, &template, &labels, &body)?;

    let mut last = String::from("no candidate");
    for host in candidates {
        fleet.store.set_vm_host(&id, &host.name)?;
        let client = fleet
            .host(&host.name)
            .ok_or_else(|| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "host vanished".into()))?;
        // Signed for this host by name: the tier accepts it only from the
        // edge whose certificate carries that name.
        body["signed"] = json!(policy.sign(&fleet, &host.name, &id, 1)?);
        match client.create(&body).await {
            Ok((status, resp)) if status.is_success() => {
                fleet
                    .store
                    .set_vm_state(&id, state::PLACED, Some("creating"), None)?;
                let _ = fleet.store.host_took_slot(&host.name);
                // The host's record right away, so a read that follows the
                // create does not have to wait for the next sync.
                if let Ok((StatusCode::OK, _, body)) = client
                    .forward("GET", &format!("/vms/{id}"), None, Bytes::new())
                    .await
                    && let Ok(v) = serde_json::from_slice::<Value>(&body)
                {
                    let _ = fleet.store.set_vm_view(&id, &v);
                }
                tracing::info!("placed vm {id} ({template}) on {}", host.name);
                return Ok(Json(
                    json!({ "id": resp["id"].as_str().unwrap_or(&id), "host": host.name }),
                ));
            }
            Ok((StatusCode::CONFLICT, resp)) => {
                let msg = resp["error"].as_str().unwrap_or("conflict").to_string();
                if msg.contains("already exists") {
                    // Our own earlier create got through after all.
                    fleet.store.set_vm_state(&id, state::PLACED, None, None)?;
                    return Ok(Json(json!({ "id": id, "host": host.name })));
                }
                // No slot, no port, pool full: the host is honest about
                // capacity, so try the next one.
                tracing::info!("host {} refused vm {id}: {msg}; trying the next", host.name);
                last = format!("{}: {msg}", host.name);
            }
            Ok((status, resp)) => {
                // The request itself is wrong (a bad rule, an unknown
                // template on this host): no host will take it.
                fleet.store.delete_vm(&id)?;
                let msg = resp["error"].as_str().unwrap_or("host error").to_string();
                return Err(ApiError(status, format!("{}: {msg}", host.name)));
            }
            Err(CallError::Unreachable(e)) => {
                tracing::warn!("host {} unreachable for create: {e}", host.name);
                let _ = fleet.store.host_unreachable(&host.name, &e);
                last = format!("{}: {e}", host.name);
            }
            Err(CallError::Ambiguous(e)) => {
                // The host may have created it. Leave the record in
                // `creating`; the sync loop settles it either way.
                fleet
                    .store
                    .set_vm_state(&id, state::CREATING, None, Some(&e))?;
                return Err(ApiError(
                    StatusCode::BAD_GATEWAY,
                    format!(
                        "{}: no reply ({e}); vm {id} will be reconciled, check GET /vms/{id}",
                        host.name
                    ),
                ));
            }
        }
    }
    fleet.store.delete_vm(&id)?;
    Err(ApiError(
        StatusCode::CONFLICT,
        format!("no host could take vm ({last})"),
    ))
}

async fn list(State(fleet): State<Shared>) -> Result<Json<Vec<Value>>, ApiError> {
    Ok(Json(
        fleet
            .store
            .list_vms()?
            .iter()
            .map(|r| view(r, None))
            .collect(),
    ))
}

async fn get_one(
    State(fleet): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let row = fleet
        .store
        .get_vm(&id)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such vm".into()))?;
    if (row.fleet_state == state::PLACED || row.fleet_state == state::CREATING)
        && let Some(client) = fleet.host(&row.host)
        && let Ok((StatusCode::OK, _, body)) = client
            .forward("GET", &format!("/vms/{id}"), None, Bytes::new())
            .await
        && let Ok(v) = serde_json::from_slice::<Value>(&body)
    {
        let _ = fleet.store.set_vm_view(&id, &v);
        return Ok(Json(view(&row, Some(v))));
    }
    Ok(Json(view(&row, None)))
}

async fn delete_one(
    State(fleet): State<Shared>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let row = fleet
        .store
        .get_vm(&id)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such vm".into()))?;
    if row.fleet_state == state::LOST || row.fleet_state == state::FAILED {
        fleet.store.delete_vm(&id)?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let Some(client) = fleet.host(&row.host) else {
        fleet.store.delete_vm(&id)?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    match client.delete_vm(&id).await {
        Ok(s) if s == StatusCode::NO_CONTENT || s == StatusCode::NOT_FOUND => {
            fleet.store.delete_vm(&id)?;
            let _ = fleet.store.host_freed_slot(&row.host);
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Ok(s) => Err(ApiError(s, format!("{}: refused the delete", row.host))),
        Err(e) => {
            fleet
                .store
                .set_vm_state(&id, state::DELETING, None, Some(&e.to_string()))?;
            Ok((
                StatusCode::ACCEPTED,
                Json(json!({ "id": id, "fleet_state": state::DELETING, "host": row.host })),
            )
                .into_response())
        }
    }
}

/// The policy fields of a create or a policy change, as the host takes them.
#[derive(Clone, Debug, Default)]
struct PolicyFields {
    egress: String,
    principal: Option<String>,
    allow: Vec<String>,
    rules: Vec<String>,
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

impl PolicyFields {
    /// From a create body: the host's defaults for what is absent.
    fn from_create(body: &Value) -> Self {
        let egress = match body["egress"].as_str() {
            Some(e) if e == "proxy" || e == "deny" => e.to_string(),
            _ => "deny".to_string(),
        };
        Self {
            egress,
            principal: body["principal"].as_str().map(str::to_string),
            allow: strings(&body["allow"]),
            rules: strings(&body["rules"]),
        }
    }

    /// From a host's record of a VM, as `GET /vms/{id}` returns it.
    fn from_view(view: &Value) -> Self {
        Self {
            egress: view["egress"].as_str().unwrap_or("deny").to_string(),
            principal: view["principal"].as_str().map(str::to_string),
            allow: strings(&view["allow"]),
            rules: strings(&view["rules"]),
        }
    }

    /// A policy change laid over the current policy, the way the host merges
    /// it: given fields replace, absent ones stay. An `egress` the host would
    /// not recognise leaves the mode unchanged, as on the host.
    fn patched(&self, change: &Value) -> Self {
        let mut out = self.clone();
        if let Some(p) = change["principal"].as_str() {
            out.principal = Some(p.to_string());
        }
        if change["allow"].is_array() {
            out.allow = strings(&change["allow"]);
        }
        if change["rules"].is_array() {
            out.rules = strings(&change["rules"]);
        }
        if let Some(e) = change["egress"].as_str()
            && (e == "proxy" || e == "deny")
        {
            out.egress = e.to_string();
        }
        out
    }

    fn check(&self) -> Result<(), String> {
        iso_policy::RuleSet::from_record(&self.allow, &self.rules)
            .map(|_| ())
            .map_err(|e| format!("invalid rule: {e}"))
    }

    fn sign(&self, fleet: &Fleet, host: &str, vm: &str, policy_gen: u64) -> Result<iso_policy::signed::SignedPolicy, ApiError> {
        fleet
            .sign_policy(host, vm, &self.egress, self.principal.as_deref(), &self.allow, &self.rules, policy_gen)
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("invalid rule: {e}")))
    }
}

/// `PATCH /vms/{id}/policy`, signed. The change is laid over the host's
/// current policy exactly as the host will lay it, signed at the next
/// generation for the VM's host, and sent on with the signature. A client's
/// own `signed` field is ignored: only the fleet signs.
async fn set_policy(
    State(fleet): State<Shared>,
    Path(id): Path<String>,
    Json(mut change): Json<Value>,
) -> Result<Response, ApiError> {
    let row = fleet
        .store
        .get_vm(&id)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such vm".into()))?;
    if row.fleet_state != state::PLACED && row.fleet_state != state::CREATING {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("vm is {} on {}", row.fleet_state, row.host),
        ));
    }
    let client = fleet.host(&row.host).ok_or_else(|| {
        ApiError(StatusCode::CONFLICT, format!("host {} is no longer configured", row.host))
    })?;
    let unreachable = |e: CallError| {
        let _ = fleet.store.host_unreachable(&row.host, &e.to_string());
        ApiError(StatusCode::BAD_GATEWAY, format!("{}: {e}", row.host))
    };
    // The host's current record, fresh: the generation and the fields the
    // change is laid over must be the host's, not a stale view.
    let (status, _, bytes) = client
        .forward("GET", &format!("/vms/{id}"), None, Bytes::new())
        .await
        .map_err(unreachable)?;
    if status != StatusCode::OK {
        return Err(ApiError(status, format!("{}: has no vm {id}", row.host)));
    }
    let view: Value = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("{}: bad record: {e}", row.host)))?;
    let current_gen = view["policy_gen"].as_u64().unwrap_or(1);
    let next = PolicyFields::from_view(&view).patched(&change);
    next.check().map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    if let Some(o) = change.as_object_mut() {
        o.insert("signed".into(), json!(next.sign(&fleet, &row.host, &id, current_gen + 1)?));
    }
    let ct = HeaderValue::from_static("application/json");
    let (status, ct, bytes) = client
        .forward("PATCH", &format!("/vms/{id}/policy"), Some(&ct), Bytes::from(change.to_string()))
        .await
        .map_err(unreachable)?;
    if status.is_success()
        && let Ok((StatusCode::OK, _, body)) = client
            .forward("GET", &format!("/vms/{id}"), None, Bytes::new())
            .await
        && let Ok(v) = serde_json::from_slice::<Value>(&body)
    {
        let _ = fleet.store.set_vm_view(&id, &v);
    }
    let mut resp = Response::builder().status(status);
    if let Some(ct) = ct {
        resp = resp.header(http::header::CONTENT_TYPE, ct);
    }
    Ok(resp.body(Body::from(bytes)).unwrap())
}

/// Renew this fleet's own signature on a VM's policy, for the sync loop
/// when it is about to expire. What is signed is what the fleet signed
/// before, with a new expiry: never what the host currently reports, so a
/// change made behind the fleet's back stays unsigned until it is made
/// through the fleet. A host whose policy no longer matches answers 400.
pub(crate) async fn refresh_signature(
    fleet: &Fleet,
    client: &crate::hosts::HostClient,
    claims: &iso_policy::signed::PolicyClaims,
) -> Result<(), String> {
    let id = &claims.vm;
    let body = json!({ "signed": fleet.resign(claims) });
    let ct = HeaderValue::from_static("application/json");
    let (status, _, bytes) = client
        .forward("PATCH", &format!("/vms/{id}/policy"), Some(&ct), Bytes::from(body.to_string()))
        .await
        .map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("host answered {status}: {}", String::from_utf8_lossy(&bytes)));
    }
    Ok(())
}

async fn forward(
    State(fleet): State<Shared>,
    Path((id, rest)): Path<(String, String)>,
    method: Method,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let row = fleet
        .store
        .get_vm(&id)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such vm".into()))?;
    if row.fleet_state != state::PLACED && row.fleet_state != state::CREATING {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("vm is {} on {}", row.fleet_state, row.host),
        ));
    }
    let client = fleet.host(&row.host).ok_or_else(|| {
        ApiError(
            StatusCode::CONFLICT,
            format!("host {} is no longer configured", row.host),
        )
    })?;
    let mut pq = format!("/vms/{id}/{rest}");
    if let Some(q) = query {
        pq.push('?');
        pq.push_str(&q);
    }
    let ct = headers.get(http::header::CONTENT_TYPE);
    match client.forward(method.as_str(), &pq, ct, body).await {
        Ok((status, ct, bytes)) => {
            let mut resp = Response::builder().status(status);
            if let Some(ct) = ct {
                resp = resp.header(http::header::CONTENT_TYPE, ct);
            }
            Ok(resp.body(Body::from(bytes)).unwrap())
        }
        Err(e) => {
            let _ = fleet.store.host_unreachable(&row.host, &e.to_string());
            Err(ApiError(
                StatusCode::BAD_GATEWAY,
                format!("{}: {e}", row.host),
            ))
        }
    }
}

async fn hosts(State(fleet): State<Shared>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!(fleet.store.list_hosts()?)))
}

/// Host-shaped, so a typed client reads it: capacity summed over healthy
/// hosts, pool usage as the worst host's, plus fleet-only fields a host
/// client ignores.
async fn stats(State(fleet): State<Shared>) -> Result<Json<Value>, ApiError> {
    let hosts = fleet.store.list_hosts()?;
    let vms = fleet.store.list_vms()?;
    let mut by_state = serde_json::Map::new();
    for v in &vms {
        let n = by_state
            .get(&v.fleet_state)
            .and_then(Value::as_u64)
            .unwrap_or(0);
        by_state.insert(v.fleet_state.clone(), json!(n + 1));
    }
    let healthy: Vec<_> = hosts.iter().filter(|h| h.healthy).collect();
    let slots_total: u32 = healthy.iter().map(|h| h.slots_total).sum();
    let slots_free: u32 = healthy.iter().map(|h| h.slots_free).sum();
    let data = healthy
        .iter()
        .map(|h| h.pool_data_percent)
        .fold(0.0_f64, f64::max);
    let meta = healthy
        .iter()
        .map(|h| h.pool_metadata_percent)
        .fold(0.0_f64, f64::max);
    Ok(Json(json!({
        "storage_backend": null,
        "pool_capacity_bytes": null,
        "pool_used_bytes": null,
        "snapshot_bytes": null,
        "filesystem_capacity_bytes": null,
        "filesystem_available_bytes": null,
        "data_percent": data,
        "metadata_percent": meta,
        "slots_used": slots_total.saturating_sub(slots_free),
        "slots_total": slots_total,
        "vms": vms.len(),
        "hosts": hosts.len(),
        "hosts_healthy": healthy.len(),
        "slots_free": slots_free,
        "vms_by_state": by_state,
        "orphans": hosts.iter().map(|h| h.orphans).sum::<u32>(),
    })))
}

/// The host API's document: the fleet serves the same operations. `POST /vms`
/// additionally accepts `host` to pin a placement, and VM records carry
/// `host` and `fleet_state`.
async fn openapi() -> Response {
    const DOC: &str = include_str!("../../iso-client/openapi.json");
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        DOC,
    )
        .into_response()
}
