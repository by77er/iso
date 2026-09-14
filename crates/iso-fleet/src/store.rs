//! The fleet's record of hosts and where every VM is. SQLite; every handler
//! is stateless over it, which is what lets more than one `iso-fleetd` share
//! a database later without a redesign.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

pub type Result<T> = std::result::Result<T, rusqlite::Error>;

/// Where the fleet thinks a VM stands, beside what its host last reported.
pub mod state {
    /// Recorded, the host has not confirmed it yet.
    pub const CREATING: &str = "creating";
    /// On its host, which reports it.
    pub const PLACED: &str = "placed";
    /// Its host cannot be reached; the record is kept.
    pub const UNREACHABLE: &str = "unreachable";
    /// Its host is reachable and does not have it.
    pub const LOST: &str = "lost";
    /// A delete was asked for and the host has not confirmed it.
    pub const DELETING: &str = "deleting";
    /// Never came up.
    pub const FAILED: &str = "failed";
}

#[derive(Clone, Debug, Serialize)]
pub struct HostRow {
    pub name: String,
    pub url: String,
    pub healthy: bool,
    pub last_seen: Option<i64>,
    pub slots_free: u32,
    pub slots_total: u32,
    pub pool_data_percent: f64,
    pub templates: Vec<String>,
    /// VMs the host has that the fleet did not place.
    pub orphans: u32,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VmRow {
    pub id: String,
    pub host: String,
    pub template: String,
    pub fleet_state: String,
    pub host_state: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_error: Option<String>,
    pub labels: serde_json::Value,
    /// The create request as the client sent it, minus the fleet's own fields.
    pub spec: serde_json::Value,
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = if path.as_os_str() == ":memory:" {
            Connection::open_in_memory()?
        } else {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            Connection::open(path)?
        };
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS hosts (
                name TEXT PRIMARY KEY, url TEXT NOT NULL, healthy INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER, slots_free INTEGER NOT NULL DEFAULT 0, slots_total INTEGER NOT NULL DEFAULT 0,
                pool_data REAL NOT NULL DEFAULT 0, templates TEXT NOT NULL DEFAULT '[]',
                orphans INTEGER NOT NULL DEFAULT 0, last_error TEXT);
             CREATE TABLE IF NOT EXISTS vms (
                id TEXT PRIMARY KEY, host TEXT NOT NULL, template TEXT NOT NULL,
                fleet_state TEXT NOT NULL, host_state TEXT, created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL, last_error TEXT, labels TEXT NOT NULL DEFAULT '{}',
                spec TEXT NOT NULL DEFAULT '{}');
             CREATE INDEX IF NOT EXISTS vms_host ON vms(host);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---- hosts ----

    pub fn upsert_host(&self, name: &str, url: &str) -> Result<()> {
        self.lock().execute(
            "INSERT INTO hosts (name, url) VALUES (?1, ?2) ON CONFLICT(name) DO UPDATE SET url=?2",
            params![name, url],
        )?;
        Ok(())
    }

    /// Forget hosts no longer configured. Their VM records stay, as unreachable.
    pub fn retain_hosts(&self, names: &[String]) -> Result<()> {
        let conn = self.lock();
        let existing: Vec<String> = conn
            .prepare("SELECT name FROM hosts")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_>>()?;
        for n in existing {
            if !names.contains(&n) {
                conn.execute("DELETE FROM hosts WHERE name=?1", params![n])?;
                conn.execute(
                    "UPDATE vms SET fleet_state=?2, updated_at=?3 WHERE host=?1 AND fleet_state NOT IN ('lost','failed')",
                    params![n, state::UNREACHABLE, now()],
                )?;
            }
        }
        Ok(())
    }

    pub fn list_hosts(&self) -> Result<Vec<HostRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT name, url, healthy, last_seen, slots_free, slots_total, pool_data, templates, orphans, last_error
             FROM hosts ORDER BY name",
        )?;
        let rows = stmt.query_map([], host_from_row)?;
        rows.collect()
    }

    pub fn get_host(&self, name: &str) -> Result<Option<HostRow>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT name, url, healthy, last_seen, slots_free, slots_total, pool_data, templates, orphans, last_error
             FROM hosts WHERE name=?1",
            params![name],
            host_from_row,
        )
        .optional()
    }

    pub fn host_seen(
        &self,
        name: &str,
        slots_free: u32,
        slots_total: u32,
        pool_data: f64,
        templates: &[String],
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE hosts SET healthy=1, last_seen=?2, slots_free=?3, slots_total=?4, pool_data=?5, templates=?6, last_error=NULL
             WHERE name=?1",
            params![name, now(), slots_free, slots_total, pool_data, serde_json::to_string(templates).unwrap_or_default()],
        )?;
        Ok(())
    }

    pub fn host_unreachable(&self, name: &str, err: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE hosts SET healthy=0, last_error=?2 WHERE name=?1",
            params![name, err],
        )?;
        Ok(())
    }

    pub fn host_orphans(&self, name: &str, n: u32) -> Result<()> {
        self.lock().execute(
            "UPDATE hosts SET orphans=?2 WHERE name=?1",
            params![name, n],
        )?;
        Ok(())
    }

    /// Slots free after a placement, so the next placement in the same sync
    /// window does not pile onto the same host.
    pub fn host_took_slot(&self, name: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE hosts SET slots_free = MAX(slots_free - 1, 0) WHERE name=?1",
            params![name],
        )?;
        Ok(())
    }

    // ---- vms ----

    pub fn insert_vm(
        &self,
        id: &str,
        host: &str,
        template: &str,
        labels: &serde_json::Value,
        spec: &serde_json::Value,
    ) -> Result<()> {
        let t = now();
        self.lock().execute(
            "INSERT INTO vms (id, host, template, fleet_state, created_at, updated_at, labels, spec)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7)",
            params![id, host, template, state::CREATING, t, labels.to_string(), spec.to_string()],
        )?;
        Ok(())
    }

    pub fn set_vm_host(&self, id: &str, host: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE vms SET host=?2, updated_at=?3 WHERE id=?1",
            params![id, host, now()],
        )?;
        Ok(())
    }

    pub fn set_vm_state(
        &self,
        id: &str,
        fleet_state: &str,
        host_state: Option<&str>,
        err: Option<&str>,
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE vms SET fleet_state=?2, host_state=COALESCE(?3, host_state), last_error=?4, updated_at=?5 WHERE id=?1",
            params![id, fleet_state, host_state, err, now()],
        )?;
        Ok(())
    }

    pub fn get_vm(&self, id: &str) -> Result<Option<VmRow>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, host, template, fleet_state, host_state, created_at, updated_at, last_error, labels, spec FROM vms WHERE id=?1",
            params![id],
            vm_from_row,
        )
        .optional()
    }

    pub fn list_vms(&self) -> Result<Vec<VmRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, host, template, fleet_state, host_state, created_at, updated_at, last_error, labels, spec FROM vms ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], vm_from_row)?;
        rows.collect()
    }

    pub fn list_vms_on(&self, host: &str) -> Result<Vec<VmRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, host, template, fleet_state, host_state, created_at, updated_at, last_error, labels, spec FROM vms WHERE host=?1",
        )?;
        let rows = stmt.query_map(params![host], vm_from_row)?;
        rows.collect()
    }

    pub fn delete_vm(&self, id: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM vms WHERE id=?1", params![id])?;
        Ok(())
    }
}

fn host_from_row(r: &rusqlite::Row<'_>) -> Result<HostRow> {
    let templates: String = r.get(7)?;
    Ok(HostRow {
        name: r.get(0)?,
        url: r.get(1)?,
        healthy: r.get::<_, i64>(2)? != 0,
        last_seen: r.get(3)?,
        slots_free: r.get(4)?,
        slots_total: r.get(5)?,
        pool_data_percent: r.get(6)?,
        templates: serde_json::from_str(&templates).unwrap_or_default(),
        orphans: r.get(8)?,
        last_error: r.get(9)?,
    })
}

fn vm_from_row(r: &rusqlite::Row<'_>) -> Result<VmRow> {
    let labels: String = r.get(8)?;
    let spec: String = r.get(9)?;
    Ok(VmRow {
        id: r.get(0)?,
        host: r.get(1)?,
        template: r.get(2)?,
        fleet_state: r.get(3)?,
        host_state: r.get(4)?,
        created_at: r.get(5)?,
        updated_at: r.get(6)?,
        last_error: r.get(7)?,
        labels: serde_json::from_str(&labels)
            .unwrap_or(serde_json::Value::Object(Default::default())),
        spec: serde_json::from_str(&spec).unwrap_or(serde_json::Value::Object(Default::default())),
    })
}
