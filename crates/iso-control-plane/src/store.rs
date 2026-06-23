//! SQLite persistence: the durable source of truth for VMs and templates.
//!
//! Access is synchronous under a `Mutex<Connection>` — store ops are local and
//! fast, and we never hold the lock across an `.await`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use iso_common::{EgressMode, PortForward, Protocol, SlotId, SnapshotRef, VmId};
use rusqlite::Connection;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::types::{egress_parse, egress_str, Labels, Lifecycle, RestartPolicy, TemplateDef, VmRecord, VmState};

pub struct Store {
    conn: Mutex<Connection>,
}

fn proto_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn proto_parse(s: &str) -> Protocol {
    if s.eq_ignore_ascii_case("udp") {
        Protocol::Udp
    } else {
        Protocol::Tcp
    }
}

/// Read a VM's declared forwards (the normalized `port_forwards` rows). Runs on
/// an already-held connection so callers can populate `VmRecord::ingress`.
fn forwards_in(conn: &Connection, id: VmId) -> Result<Vec<PortForward>> {
    let mut stmt = conn.prepare(
        "SELECT host_port, vm_port, proto FROM port_forwards WHERE vm_id=?1 ORDER BY host_port",
    )?;
    let mut rows = stmt.query([id.to_string()])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(PortForward {
            host_port: r.get::<_, u16>(0)?,
            vm_port: r.get::<_, u16>(1)?,
            proto: proto_parse(&r.get::<_, String>(2)?),
        });
    }
    Ok(out)
}

// Used only to migrate the legacy `vms.ingress` JSON blob into `port_forwards`.
#[derive(Deserialize)]
struct PfRow {
    host_port: u16,
    vm_port: u16,
    proto: String,
}

fn ingress_from_json(s: &str) -> std::result::Result<Vec<PortForward>, serde_json::Error> {
    let rows: Vec<PfRow> = serde_json::from_str(s)?;
    Ok(rows
        .into_iter()
        .map(|r| PortForward {
            host_port: r.host_port,
            vm_port: r.vm_port,
            proto: if r.proto == "udp" {
                Protocol::Udp
            } else {
                Protocol::Tcp
            },
        })
        .collect())
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        // ensure the state directory exists (skip for the `:memory:` sentinel).
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Store(format!("create {parent:?}: {e}")))?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS templates (
                name             TEXT PRIMARY KEY,
                rootfs_template  TEXT NOT NULL,
                snapshot_mem     TEXT,
                snapshot_vmstate TEXT,
                vcpus            INTEGER NOT NULL,
                mem_mib          INTEGER NOT NULL,
                kernel           TEXT NOT NULL,
                boot_args        TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vms (
                id            TEXT PRIMARY KEY,
                slot          INTEGER,
                template      TEXT NOT NULL,
                egress        TEXT NOT NULL,
                labels        TEXT NOT NULL,
                lifecycle     TEXT NOT NULL,
                restart       TEXT NOT NULL,
                vcpus         INTEGER,
                mem_mib       INTEGER,
                state         TEXT NOT NULL,
                rootfs_device TEXT,
                tap           TEXT,
                principal     TEXT,
                allow         TEXT NOT NULL DEFAULT '[]',
                created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            -- Ingress forwards, normalized: one row per forward (the desired
            -- state). `(host_port, proto)` is globally unique (the allocator
            -- never double-issues a port); the FK cascade reaps a VM's forwards
            -- when it's deleted, so the control plane only frees the host ports.
            CREATE TABLE IF NOT EXISTS port_forwards (
                vm_id     TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
                host_port INTEGER NOT NULL,
                vm_port   INTEGER NOT NULL,
                proto     TEXT NOT NULL,
                PRIMARY KEY (host_port, proto)
            );
            CREATE INDEX IF NOT EXISTS port_forwards_vm ON port_forwards(vm_id);
            ",
        )?;
        // Enforce the FK + ON DELETE CASCADE (off by default, per connection).
        conn.pragma_update(None, "foreign_keys", true)?;
        // Migrate pre-policy databases (idempotent; errors = column exists).
        let _ = conn.execute("ALTER TABLE vms ADD COLUMN principal TEXT", []);
        let _ = conn.execute("ALTER TABLE vms ADD COLUMN allow TEXT NOT NULL DEFAULT '[]'", []);
        // Migrate the legacy `vms.ingress` JSON blob into `port_forwards`, then
        // drop the column. No-op once migrated and on fresh databases.
        Self::migrate_ingress_blob(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// One-shot migration of the old `vms.ingress` JSON-blob column into the
    /// normalized `port_forwards` table.
    fn migrate_ingress_blob(conn: &Connection) -> Result<()> {
        let has_ingress = conn
            .prepare("SELECT 1 FROM pragma_table_info('vms') WHERE name='ingress'")?
            .exists([])?;
        if !has_ingress {
            return Ok(());
        }
        let legacy: Vec<(String, String)> = {
            let mut stmt = conn.prepare("SELECT id, ingress FROM vms")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, blob) in legacy {
            for f in ingress_from_json(&blob).unwrap_or_default() {
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO port_forwards (vm_id, host_port, vm_port, proto)
                     VALUES (?1,?2,?3,?4)",
                    rusqlite::params![id, f.host_port, f.vm_port, proto_str(f.proto)],
                );
            }
        }
        let _ = conn.execute("ALTER TABLE vms DROP COLUMN ingress", []);
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("store mutex poisoned")
    }

    // ---- templates ----

    pub fn upsert_template(&self, t: &TemplateDef) -> Result<()> {
        let (mem, vmstate) = match &t.snapshot {
            Some(s) => (
                Some(s.mem_file.to_string_lossy().into_owned()),
                Some(s.vmstate.to_string_lossy().into_owned()),
            ),
            None => (None, None),
        };
        self.lock().execute(
            "INSERT INTO templates
                (name, rootfs_template, snapshot_mem, snapshot_vmstate, vcpus, mem_mib, kernel, boot_args)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(name) DO UPDATE SET
                rootfs_template=?2, snapshot_mem=?3, snapshot_vmstate=?4,
                vcpus=?5, mem_mib=?6, kernel=?7, boot_args=?8",
            rusqlite::params![
                t.name,
                t.rootfs_template,
                mem,
                vmstate,
                t.vcpus,
                t.mem_mib,
                t.kernel.to_string_lossy(),
                t.boot_args,
            ],
        )?;
        Ok(())
    }

    pub fn get_template(&self, name: &str) -> Result<Option<TemplateDef>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT name, rootfs_template, snapshot_mem, snapshot_vmstate, vcpus, mem_mib, kernel, boot_args
             FROM templates WHERE name=?1",
        )?;
        let mut rows = stmt.query([name])?;
        match rows.next()? {
            Some(r) => Ok(Some(template_from_row(r)?)),
            None => Ok(None),
        }
    }

    // ---- vms ----

    pub fn insert_vm(&self, v: &VmRecord) -> Result<()> {
        self.lock().execute(
            "INSERT INTO vms
                (id, slot, template, egress, labels, lifecycle, restart,
                 vcpus, mem_mib, state, rootfs_device, tap, principal, allow)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            rusqlite::params![
                v.id.to_string(),
                v.slot.map(|s| s.get()),
                v.template,
                egress_str(v.egress),
                serde_json::to_string(&v.labels)?,
                v.lifecycle.as_str(),
                v.restart.as_str(),
                v.vcpus,
                v.mem_mib,
                v.state.as_str(),
                v.rootfs_device.as_ref().map(|p| p.to_string_lossy().into_owned()),
                v.tap,
                v.principal,
                serde_json::to_string(&v.allow)?,
            ],
        )?;
        Ok(())
    }

    /// Update only the *placement* columns (slot, state, device, tap) — the
    /// fields the lifecycle owns. Deliberately disjoint from the policy columns
    /// and the `port_forwards` rows, so a lifecycle transition can never clobber
    /// a concurrent policy/forward edit (and vice-versa).
    pub fn update_placement(&self, v: &VmRecord) -> Result<()> {
        self.lock().execute(
            "UPDATE vms SET slot=?2, state=?3, rootfs_device=?4, tap=?5 WHERE id=?1",
            rusqlite::params![
                v.id.to_string(),
                v.slot.map(|s| s.get()),
                v.state.as_str(),
                v.rootfs_device.as_ref().map(|p| p.to_string_lossy().into_owned()),
                v.tap,
            ],
        )?;
        Ok(())
    }

    /// Update only the *policy* columns (egress + the proxy's principal/allow).
    /// Disjoint from placement and forwards (see [`Self::update_placement`]).
    pub fn update_policy(
        &self,
        id: VmId,
        principal: Option<&str>,
        allow: &[String],
        egress: EgressMode,
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE vms SET egress=?2, principal=?3, allow=?4 WHERE id=?1",
            rusqlite::params![
                id.to_string(),
                egress_str(egress),
                principal,
                serde_json::to_string(allow)?,
            ],
        )?;
        Ok(())
    }

    // ---- forwards (normalized desired state) ----

    /// Declare a forward. The FK makes this atomic w.r.t. VM existence: if the
    /// VM was deleted out from under us, the insert fails the constraint and we
    /// report it as a vanished VM rather than orphaning a row.
    pub fn add_forward(&self, id: VmId, f: &PortForward) -> Result<()> {
        let res = self.lock().execute(
            "INSERT INTO port_forwards (vm_id, host_port, vm_port, proto) VALUES (?1,?2,?3,?4)",
            rusqlite::params![id.to_string(), f.host_port, f.vm_port, proto_str(f.proto)],
        );
        match res {
            Ok(_) => Ok(()),
            // The only constraint that can fire is the FK (host ports are
            // allocator-unique, so the PK can't collide): the VM is gone.
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(Error::UnknownVm(id))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Undeclare a forward. Returns whether a row was actually removed.
    pub fn remove_forward(&self, id: VmId, host_port: u16, proto: Protocol) -> Result<bool> {
        let n = self.lock().execute(
            "DELETE FROM port_forwards WHERE vm_id=?1 AND host_port=?2 AND proto=?3",
            rusqlite::params![id.to_string(), host_port, proto_str(proto)],
        )?;
        Ok(n > 0)
    }

    pub fn delete_vm(&self, id: VmId) -> Result<()> {
        // `port_forwards` rows cascade away via the FK.
        self.lock()
            .execute("DELETE FROM vms WHERE id=?1", [id.to_string()])?;
        Ok(())
    }

    pub fn get_vm(&self, id: VmId) -> Result<Option<VmRecord>> {
        let conn = self.lock();
        let rec = {
            let mut stmt = conn.prepare(VM_SELECT)?;
            let mut rows = stmt.query([id.to_string()])?;
            match rows.next()? {
                Some(r) => Some(vm_from_row(r)?),
                None => None,
            }
        };
        match rec {
            Some(mut rec) => {
                rec.ingress = forwards_in(&conn, id)?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    pub fn list_vms(&self) -> Result<Vec<VmRecord>> {
        let conn = self.lock();
        // Drain the base rows first (releases the statement), then attach each
        // VM's forwards in a second pass on the same connection.
        let mut out = {
            let mut stmt = conn.prepare(VM_SELECT_ALL)?;
            let mut rows = stmt.query([])?;
            let mut v = Vec::new();
            while let Some(r) = rows.next()? {
                v.push(vm_from_row(r)?);
            }
            v
        };
        for rec in &mut out {
            rec.ingress = forwards_in(&conn, rec.id)?;
        }
        Ok(out)
    }
}

const VM_SELECT: &str = "SELECT id, slot, template, egress, labels, lifecycle, restart, vcpus, mem_mib, state, rootfs_device, tap, principal, allow FROM vms WHERE id=?1";
const VM_SELECT_ALL: &str = "SELECT id, slot, template, egress, labels, lifecycle, restart, vcpus, mem_mib, state, rootfs_device, tap, principal, allow FROM vms";

fn template_from_row(r: &rusqlite::Row<'_>) -> Result<TemplateDef> {
    let mem: Option<String> = r.get(2)?;
    let vmstate: Option<String> = r.get(3)?;
    let snapshot = match (mem, vmstate) {
        (Some(m), Some(v)) => Some(SnapshotRef {
            mem_file: PathBuf::from(m),
            vmstate: PathBuf::from(v),
        }),
        _ => None,
    };
    Ok(TemplateDef {
        name: r.get(0)?,
        rootfs_template: r.get(1)?,
        snapshot,
        vcpus: r.get(4)?,
        mem_mib: r.get(5)?,
        kernel: PathBuf::from(r.get::<_, String>(6)?),
        boot_args: r.get(7)?,
    })
}

fn vm_from_row(r: &rusqlite::Row<'_>) -> Result<VmRecord> {
    let id = VmId::parse(&r.get::<_, String>(0)?)
        .ok_or_else(|| Error::Store("bad vm id".into()))?;
    let slot: Option<u16> = r.get(1)?;
    let egress = egress_parse(&r.get::<_, String>(3)?)
        .ok_or_else(|| Error::Store("bad egress".into()))?;
    let labels: Labels = serde_json::from_str(&r.get::<_, String>(4)?)?;
    let lifecycle = Lifecycle::parse(&r.get::<_, String>(5)?)
        .ok_or_else(|| Error::Store("bad lifecycle".into()))?;
    let restart = RestartPolicy::parse(&r.get::<_, String>(6)?)
        .ok_or_else(|| Error::Store("bad restart".into()))?;
    let state = VmState::parse(&r.get::<_, String>(9)?)
        .ok_or_else(|| Error::Store("bad state".into()))?;
    let rootfs_device: Option<String> = r.get(10)?;
    let tap: Option<String> = r.get(11)?;
    let principal: Option<String> = r.get(12)?;
    let allow: Vec<String> = serde_json::from_str(&r.get::<_, String>(13)?)?;
    Ok(VmRecord {
        id,
        slot: slot.and_then(|s| SlotId::new(s).ok()),
        template: r.get(2)?,
        egress,
        // Populated by the caller (get_vm/list_vms) from `port_forwards`.
        ingress: Vec::new(),
        labels,
        lifecycle,
        restart,
        vcpus: r.get(7)?,
        mem_mib: r.get(8)?,
        state,
        rootfs_device: rootfs_device.map(PathBuf::from),
        tap,
        principal,
        allow,
    })
}
