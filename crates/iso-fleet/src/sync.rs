//! The sync loop: every few seconds, ask each host what it has and reconcile
//! it with the fleet's record. This is the observation a fleet needs, done at
//! the fleet rather than by rebuilding every host as a reconciler. Three
//! disagreements are settled here: a VM the fleet has and the host does not
//! (lost), a VM the host has and the fleet did not place (an orphan, counted
//! and logged), and a delete the host has not confirmed (retried).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::Fleet;
use crate::store::{now, state};

pub async fn run(fleet: Arc<Fleet>, every: Duration) {
    loop {
        sync_once(&fleet).await;
        tokio::time::sleep(every).await;
    }
}

/// One pass over every host, concurrently.
pub async fn sync_once(fleet: &Arc<Fleet>) {
    let mut set = tokio::task::JoinSet::new();
    for client in fleet.hosts.values().cloned() {
        let fleet = fleet.clone();
        set.spawn(async move { sync_host(&fleet, client).await });
    }
    while let Some(r) = set.join_next().await {
        if let Err(e) = r {
            tracing::warn!("sync task failed: {e}");
        }
    }
}

async fn sync_host(fleet: &Fleet, client: crate::hosts::HostClient) {
    let name = client.name.clone();
    let observed = async {
        let stats = client.stats().await?;
        let templates = client.templates().await?;
        let vms = client.list_vms().await?;
        Ok::<_, crate::hosts::CallError>((stats, templates, vms))
    }
    .await;

    let (stats, templates, vms) = match observed {
        Ok(o) => o,
        Err(e) => {
            tracing::info!("host {name}: {e}");
            let _ = fleet.store.host_unreachable(&name, &e.to_string());
            // Keep what we know; say it cannot be reached.
            if let Ok(rows) = fleet.store.list_vms_on(&name) {
                for r in rows {
                    if r.fleet_state == state::PLACED || r.fleet_state == state::CREATING {
                        let _ = fleet.store.set_vm_state(
                            &r.id,
                            state::UNREACHABLE,
                            None,
                            Some(&e.to_string()),
                        );
                    }
                }
            }
            return;
        }
    };

    let slots_total = stats["slots_total"].as_u64().unwrap_or(0) as u32;
    let slots_used = stats["slots_used"].as_u64().unwrap_or(0) as u32;
    let pool = stats["data_percent"]
        .as_f64()
        .or_else(|| stats["pool"]["data_percent"].as_f64())
        .unwrap_or(0.0);
    let meta = stats["metadata_percent"]
        .as_f64()
        .or_else(|| stats["pool"]["metadata_percent"].as_f64())
        .unwrap_or(0.0);
    let _ = fleet.store.host_seen(
        &name,
        slots_total.saturating_sub(slots_used),
        slots_total,
        pool,
        meta,
        &templates,
    );

    let on_host: HashMap<String, Value> = vms
        .into_iter()
        .filter_map(|v| {
            let id = v["id"].as_str()?.to_string();
            Some((id, v))
        })
        .collect();
    let Ok(rows) = fleet.store.list_vms_on(&name) else {
        return;
    };
    let grace = fleet.cfg.create_grace_secs as i64;
    let mut known = 0usize;
    for r in rows {
        match on_host.get(&r.id) {
            Some(v) => {
                known += 1;
                if r.fleet_state == state::DELETING {
                    match client.delete_vm(&r.id).await {
                        Ok(s) if s.is_success() || s == http::StatusCode::NOT_FOUND => {
                            let _ = fleet.store.delete_vm(&r.id);
                            let _ = fleet.store.host_freed_slot(&name);
                            tracing::info!("vm {} deleted from {name} on retry", r.id);
                        }
                        Ok(s) => tracing::warn!("vm {}: {name} refused delete: {s}", r.id),
                        Err(e) => tracing::info!("vm {}: delete retry: {e}", r.id),
                    }
                    continue;
                }
                let _ = fleet.store.set_vm_view(&r.id, v);
                let _ = fleet.store.set_vm_state(&r.id, state::PLACED, None, None);
                match fleet.own_claims(v) {
                    Some(c) if c.expires.saturating_sub(now() as u64) <= fleet.cfg.policy_ttl_secs / 3 => {
                        match crate::api::refresh_signature(fleet, &client, &c).await {
                            Ok(()) => tracing::info!("vm {}: policy re-signed on {name}", r.id),
                            Err(e) => tracing::warn!("vm {}: could not re-sign policy on {name}: {e}", r.id),
                        }
                    }
                    Some(_) => {}
                    // Not this fleet's signature, or none: the policy was
                    // changed behind the fleet's back (or by an older
                    // host). It is not blessed here; a tier that verifies
                    // refuses the VM until the policy is set through the
                    // fleet again, which is the point.
                    None => tracing::warn!(
                        "vm {} on {name} carries no signature of this fleet's; its policy was not set through the fleet",
                        r.id
                    ),
                }
            }
            None => match r.fleet_state.as_str() {
                state::DELETING => {
                    let _ = fleet.store.delete_vm(&r.id);
                }
                state::CREATING if now() - r.created_at < grace => {}
                state::CREATING => {
                    tracing::warn!("vm {} never appeared on {name}; marking failed", r.id);
                    let _ = fleet.store.set_vm_state(
                        &r.id,
                        state::FAILED,
                        None,
                        Some("host never reported it"),
                    );
                }
                state::LOST | state::FAILED => {}
                _ => {
                    tracing::warn!("vm {} is gone from {name}; marking lost", r.id);
                    let _ = fleet.store.set_vm_state(
                        &r.id,
                        state::LOST,
                        None,
                        Some("host no longer has it"),
                    );
                }
            },
        }
    }
    let orphans = on_host.len().saturating_sub(known) as u32;
    let _ = fleet.store.host_orphans(&name, orphans);
    if orphans > 0 {
        tracing::info!("host {name} has {orphans} vm(s) the fleet did not place");
    }
}
