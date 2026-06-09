//! SQLite persistence: the durable source of truth for VMs and templates.
//!
//! Access is synchronous under a `Mutex<Connection>` — store ops are local and
//! fast, and we never hold the lock across an `.await`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use iso_common::{PortForward, Protocol, SlotId, SnapshotRef, VmId};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{egress_parse, egress_str, Labels, Lifecycle, RestartPolicy, TemplateDef, VmRecord, VmState};

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Serialize, Deserialize)]
struct PfRow {
    host_port: u16,
    vm_port: u16,
    proto: String,
}

fn ingress_to_json(ingress: &[PortForward]) -> std::result::Result<String, serde_json::Error> {
    let rows: Vec<PfRow> = ingress
        .iter()
        .map(|f| PfRow {
            host_port: f.host_port,
            vm_port: f.vm_port,
            proto: match f.proto {
                Protocol::Tcp => "tcp".into(),
                Protocol::Udp => "udp".into(),
            },
        })
        .collect();
    serde_json::to_string(&rows)
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
                ingress       TEXT NOT NULL,
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
            ",
        )?;
        // Migrate pre-policy databases (idempotent; errors = column exists).
        let _ = conn.execute("ALTER TABLE vms ADD COLUMN principal TEXT", []);
        let _ = conn.execute("ALTER TABLE vms ADD COLUMN allow TEXT NOT NULL DEFAULT '[]'", []);
        Ok(Self {
            conn: Mutex::new(conn),
        })
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
                (id, slot, template, egress, ingress, labels, lifecycle, restart,
                 vcpus, mem_mib, state, rootfs_device, tap, principal, allow)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            rusqlite::params![
                v.id.to_string(),
                v.slot.map(|s| s.get()),
                v.template,
                egress_str(v.egress),
                ingress_to_json(&v.ingress)?,
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

    /// Replace a VM's mutable fields (slot, state, device, tap, egress, ingress).
    pub fn update_vm(&self, v: &VmRecord) -> Result<()> {
        self.lock().execute(
            "UPDATE vms SET slot=?2, egress=?3, ingress=?4, state=?5,
                rootfs_device=?6, tap=?7, principal=?8, allow=?9 WHERE id=?1",
            rusqlite::params![
                v.id.to_string(),
                v.slot.map(|s| s.get()),
                egress_str(v.egress),
                ingress_to_json(&v.ingress)?,
                v.state.as_str(),
                v.rootfs_device.as_ref().map(|p| p.to_string_lossy().into_owned()),
                v.tap,
                v.principal,
                serde_json::to_string(&v.allow)?,
            ],
        )?;
        Ok(())
    }

    pub fn delete_vm(&self, id: VmId) -> Result<()> {
        self.lock()
            .execute("DELETE FROM vms WHERE id=?1", [id.to_string()])?;
        Ok(())
    }

    pub fn get_vm(&self, id: VmId) -> Result<Option<VmRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(VM_SELECT)?;
        let mut rows = stmt.query([id.to_string()])?;
        match rows.next()? {
            Some(r) => Ok(Some(vm_from_row(r)?)),
            None => Ok(None),
        }
    }

    pub fn list_vms(&self) -> Result<Vec<VmRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(VM_SELECT_ALL)?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(vm_from_row(r)?);
        }
        Ok(out)
    }
}

const VM_SELECT: &str = "SELECT id, slot, template, egress, ingress, labels, lifecycle, restart, vcpus, mem_mib, state, rootfs_device, tap, principal, allow FROM vms WHERE id=?1";
const VM_SELECT_ALL: &str = "SELECT id, slot, template, egress, ingress, labels, lifecycle, restart, vcpus, mem_mib, state, rootfs_device, tap, principal, allow FROM vms";

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
    let ingress = ingress_from_json(&r.get::<_, String>(4)?)?;
    let labels: Labels = serde_json::from_str(&r.get::<_, String>(5)?)?;
    let lifecycle = Lifecycle::parse(&r.get::<_, String>(6)?)
        .ok_or_else(|| Error::Store("bad lifecycle".into()))?;
    let restart = RestartPolicy::parse(&r.get::<_, String>(7)?)
        .ok_or_else(|| Error::Store("bad restart".into()))?;
    let state = VmState::parse(&r.get::<_, String>(10)?)
        .ok_or_else(|| Error::Store("bad state".into()))?;
    let rootfs_device: Option<String> = r.get(11)?;
    let tap: Option<String> = r.get(12)?;
    let principal: Option<String> = r.get(13)?;
    let allow: Vec<String> = serde_json::from_str(&r.get::<_, String>(14)?)?;
    Ok(VmRecord {
        id,
        slot: slot.and_then(|s| SlotId::new(s).ok()),
        template: r.get(2)?,
        egress,
        ingress,
        labels,
        lifecycle,
        restart,
        vcpus: r.get(8)?,
        mem_mib: r.get(9)?,
        state,
        rootfs_device: rootfs_device.map(PathBuf::from),
        tap,
        principal,
        allow,
    })
}
