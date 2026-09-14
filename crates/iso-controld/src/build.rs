//! Template builds through the API: `POST /templates/build` asks this host
//! to turn an OCI image into a template, and `GET /templates/builds/{name}`
//! says how that is going.
//!
//! The work is `isoctl bake --image …` as a child process: the bake needs
//! LVM, a network namespace, KVM and the guest kernel, all of which the
//! host has and the daemon already runs as root beside. One build at a
//! time: the builder VM uses one fixed slot. When the bake succeeds its
//! registration is read back and the template registered here, so a fleet
//! sees it on the next sync. Configured by `ISO_BAKE_KERNEL` and
//! `ISO_BAKE_AGENT_BIN` (the guest kernel and the static agent the bake
//! copies into the image); without them the endpoint answers 501.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use iso_common::{NetworkManager, SnapshotRef, StorageManager, VmRuntime};
use iso_control_plane::{ControlPlane, TemplateDef};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Where the bake finds what it needs on this host.
#[derive(Clone, Debug)]
pub struct BakeSettings {
    pub isoctl: PathBuf,
    pub kernel: PathBuf,
    pub agent_bin: PathBuf,
    pub state: PathBuf,
    pub vg: String,
    pub uplink: String,
    /// The builder VM's slot; one no VM is ever placed on.
    pub slot: u16,
}

/// Ask for a template from an image.
#[derive(Clone, Debug, Deserialize, ToSchema)]
pub struct BuildRequest {
    /// Template name: `[a-z0-9][a-z0-9-]{0,31}`.
    pub name: String,
    /// The OCI image, as `isoctl bake --image` takes it: `python:3.12-slim`,
    /// `ghcr.io/acme/tool:v3`, `registry/repo@sha256:…`.
    pub image: String,
    #[serde(default)]
    pub vcpus: Option<u32>,
    #[serde(default)]
    pub mem_mib: Option<u32>,
    /// Rootfs volume size, e.g. `16G`.
    #[serde(default)]
    pub size: Option<String>,
    /// Rebuild even when a template of this name is already registered.
    /// Without it, an existing template answers `ready` at once.
    #[serde(default)]
    pub force: bool,
}

/// How a build is going.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct BuildStatus {
    pub name: String,
    pub image: String,
    /// `building`, `ready` or `failed`.
    pub state: String,
    pub started_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The last few KiB of the bake's output.
    pub log_tail: String,
}

pub struct Builds {
    cfg: Option<BakeSettings>,
    jobs: Mutex<HashMap<String, BuildStatus>>,
    /// One bake at a time on a host.
    lane: tokio::sync::Mutex<()>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 32
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl Builds {
    pub fn new(cfg: Option<BakeSettings>) -> Arc<Self> {
        Arc::new(Self { cfg, jobs: Mutex::new(HashMap::new()), lane: tokio::sync::Mutex::new(()) })
    }

    pub fn configured(&self) -> bool {
        self.cfg.is_some()
    }

    pub fn list(&self) -> Vec<BuildStatus> {
        let mut v: Vec<_> = self.jobs.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.started_at));
        v
    }

    pub fn get(&self, name: &str) -> Option<BuildStatus> {
        self.jobs.lock().unwrap().get(name).cloned()
    }

    /// Start a build. `Err` names why not (misconfigured host, bad name, one
    /// already building under that name).
    pub fn start<N, S, R>(self: &Arc<Self>, cp: Arc<ControlPlane<N, S, R>>, req: BuildRequest) -> Result<BuildStatus, (u16, String)>
    where
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
        R: VmRuntime + Send + Sync + 'static,
    {
        let cfg = self
            .cfg
            .clone()
            .ok_or((501, "template builds are not configured on this host (ISO_BAKE_KERNEL, ISO_BAKE_AGENT_BIN)".to_string()))?;
        if !valid_name(&req.name) {
            return Err((400, format!("template name {:?}: use [a-z0-9][a-z0-9-]{{0,31}}", req.name)));
        }
        if req.image.trim().is_empty() {
            return Err((400, "image is required".into()));
        }
        let mut status = BuildStatus {
            name: req.name.clone(),
            image: req.image.clone(),
            state: "building".into(),
            started_at: now(),
            finished_at: None,
            error: None,
            log_tail: String::new(),
        };
        {
            let mut jobs = self.jobs.lock().unwrap();
            if jobs.get(&req.name).is_some_and(|b| b.state == "building") {
                return Err((409, format!("template {:?} is already building", req.name)));
            }
            // Already here and not asked to redo it: ready, and say so.
            let exists = cp.list_templates().map(|ts| ts.iter().any(|t| t.name == req.name)).unwrap_or(false);
            if exists && !req.force {
                status.state = "ready".into();
                status.finished_at = Some(now());
                status.log_tail = "already registered on this host".into();
                jobs.insert(req.name.clone(), status.clone());
                return Ok(status);
            }
            jobs.insert(req.name.clone(), status.clone());
        }
        let me = self.clone();
        tokio::spawn(async move {
            let _lane = me.lane.lock().await;
            let outcome = me.run(&cfg, &cp, &req).await;
            let mut jobs = me.jobs.lock().unwrap();
            if let Some(b) = jobs.get_mut(&req.name) {
                b.finished_at = Some(now());
                b.log_tail = log_tail(&cfg.state.join("templates").join(&req.name).join("build.log"));
                match outcome {
                    Ok(()) => b.state = "ready".into(),
                    Err(e) => {
                        b.state = "failed".into();
                        b.error = Some(e);
                    }
                }
            }
        });
        Ok(status)
    }

    async fn run<N, S, R>(&self, cfg: &BakeSettings, cp: &ControlPlane<N, S, R>, req: &BuildRequest) -> Result<(), String>
    where
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
        R: VmRuntime + Send + Sync + 'static,
    {
        let dir = cfg.state.join("templates").join(&req.name);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let log = std::fs::File::create(dir.join("build.log")).map_err(|e| format!("build.log: {e}"))?;
        let err_log = log.try_clone().map_err(|e| e.to_string())?;
        eprintln!("iso-controld: building template {:?} from {}", req.name, req.image);
        let mut cmd = tokio::process::Command::new(&cfg.isoctl);
        cmd.arg("bake")
            .args(["--name", &req.name, "--distro", "oci", "--image", &req.image])
            .arg("--kernel")
            .arg(&cfg.kernel)
            .arg("--agent-bin")
            .arg(&cfg.agent_bin)
            .arg("--state")
            .arg(&cfg.state)
            .args(["--vg", &cfg.vg, "--uplink", &cfg.uplink, "--slot", &cfg.slot.to_string()])
            .args(["--vcpus", &req.vcpus.unwrap_or(2).to_string()])
            .args(["--mem-mib", &req.mem_mib.unwrap_or(2048).to_string()])
            .args(["--size", req.size.as_deref().unwrap_or("16G")])
            .stdin(std::process::Stdio::null())
            .stdout(log)
            .stderr(err_log)
            .kill_on_drop(true);
        let status = cmd.status().await.map_err(|e| format!("spawn {}: {e}", cfg.isoctl.display()))?;
        if !status.success() {
            return Err(format!("isoctl bake exited with {status}"));
        }
        let reg = std::fs::read_to_string(dir.join("template.json")).map_err(|e| format!("template.json: {e}"))?;
        let v: serde_json::Value = serde_json::from_str(&reg).map_err(|e| format!("template.json: {e}"))?;
        let s = |k: &str| v[k].as_str().map(str::to_string);
        let snapshot = match (s("snapshot_mem"), s("snapshot_vmstate")) {
            (Some(m), Some(vs)) => Some(SnapshotRef { mem_file: PathBuf::from(m), vmstate: PathBuf::from(vs) }),
            _ => None,
        };
        cp.register_template(&TemplateDef {
            name: s("name").unwrap_or_else(|| req.name.clone()),
            rootfs_template: s("rootfs_template").unwrap_or_else(|| req.name.clone()),
            snapshot,
            vcpus: v["vcpus"].as_u64().unwrap_or(2) as u32,
            mem_mib: v["mem_mib"].as_u64().unwrap_or(2048) as u32,
            kernel: PathBuf::from(s("kernel").unwrap_or_default()),
            boot_args: s("boot_args").unwrap_or_default(),
        })
        .map_err(|e| format!("register: {e}"))?;
        eprintln!("iso-controld: template {:?} ready", req.name);
        Ok(())
    }
}

fn log_tail(path: &std::path::Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_default();
    let start = bytes.len().saturating_sub(4096);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lvm_and_url_safe() {
        assert!(valid_name("py312"));
        assert!(valid_name("hb-a1b2c3"));
        assert!(!valid_name(""));
        assert!(!valid_name("-x"));
        assert!(!valid_name("Has.Dots"));
        assert!(!valid_name(&"a".repeat(33)));
    }
}
