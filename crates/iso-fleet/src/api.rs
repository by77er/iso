//! The fleet API. It is the host admin API with the host removed: the same
//! paths and bodies, so every existing client works by changing a URL.
//! `POST /vms` places; `GET /vms` reads the fleet's record; everything under
//! `/vms/{id}/…` is forwarded to the VM's host as it came.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
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

/// A VM as the fleet describes it: the host's record when the host answers,
/// plus where it is and what the fleet knows.
fn view(row: &VmRow, host_view: Option<Value>) -> Value {
    let mut v = host_view.unwrap_or_else(|| {
        json!({
            "id": row.id,
            "template": row.template,
            "labels": row.labels,
            "state": row.host_state,
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
        match client.create(&body).await {
            Ok((status, resp)) if status.is_success() => {
                fleet
                    .store
                    .set_vm_state(&id, state::PLACED, Some("creating"), None)?;
                let _ = fleet.store.host_took_slot(&host.name);
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
    Ok(Json(json!({
        "hosts": hosts.len(),
        "hosts_healthy": hosts.iter().filter(|h| h.healthy).count(),
        "slots_free": hosts.iter().filter(|h| h.healthy).map(|h| h.slots_free).sum::<u32>(),
        "slots_total": hosts.iter().map(|h| h.slots_total).sum::<u32>(),
        "vms": vms.len(),
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
