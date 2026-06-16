//! The [`Manager`]: implements [`iso_common::StorageManager`] on top of an LVM
//! thin pool backed by a sparse loop-mounted file.
//!
//! - `init` ensures the backing chain exists (sparse file → loop → PV → VG →
//!   thin pool).
//! - `create_template` makes a thin volume to be populated as a base image.
//! - `provision` is a thin (copy-on-write) **snapshot** of a template.
//! - `teardown` removes the snapshot.

use std::path::PathBuf;
use std::sync::Arc;

use iso_common::{Error, PoolStats, Result, StorageHandle, StorageManager, VmId, VolumeSpec};

use crate::command::{Cmd, CommandRunner, SystemRunner};
use crate::config::Config;

/// Manages per-VM storage on a single host.
#[derive(Clone)]
pub struct Manager {
    cfg: Config,
    runner: Arc<dyn CommandRunner>,
}

impl Manager {
    pub fn new(cfg: Config, runner: Arc<dyn CommandRunner>) -> Self {
        Self { cfg, runner }
    }

    /// A manager with default config that shells out to the host.
    pub fn with_defaults() -> Self {
        Self::new(Config::default(), Arc::new(SystemRunner))
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    // ---- naming (pure) ----

    /// LV name for a VM volume: `<volume_prefix><uuid-hex>`.
    pub fn volume_lv(&self, vm: VmId) -> String {
        format!("{}{:032x}", self.cfg.volume_prefix, vm.as_u128())
    }

    /// LV name for a template: `<template_prefix><name>`.
    pub fn template_lv(&self, template: &str) -> String {
        format!("{}{}", self.cfg.template_prefix, template)
    }

    fn vg_lv(&self, lv: &str) -> String {
        format!("{}/{}", self.cfg.vg, lv)
    }

    /// Device path handed to Firecracker for `lv`.
    pub fn dev_path(&self, lv: &str) -> PathBuf {
        PathBuf::from(format!("/dev/{}/{}", self.cfg.vg, lv))
    }

    // ---- command builders (pure) ----

    fn lv_exists_cmd(&self, lv: &str) -> Cmd {
        Cmd::lenient(&["lvs", "--noheadings", &self.vg_lv(lv)])
    }

    fn snapshot_cmd(&self, template_lv: &str, volume_lv: &str) -> Cmd {
        // A snapshot of a thin LV is itself thin (copy-on-write). Clear the
        // activation-skip flag so it comes up usable.
        Cmd::new(&[
            "lvcreate",
            "--snapshot",
            "--name",
            volume_lv,
            "--setactivationskip",
            "n",
            &self.vg_lv(template_lv),
        ])
    }

    fn activate_cmd(&self, lv: &str) -> Cmd {
        Cmd::new(&[
            "lvchange",
            "--activate",
            "y",
            "--ignoreactivationskip",
            &self.vg_lv(lv),
        ])
    }

    fn remove_cmd(&self, lv: &str) -> Cmd {
        Cmd::lenient(&["lvremove", "--force", &self.vg_lv(lv)])
    }

    fn template_create_cmd(&self, template_lv: &str, virtual_size: &str) -> Cmd {
        Cmd::new(&[
            "lvcreate",
            "--type",
            "thin",
            "--virtualsize",
            virtual_size,
            "--thinpool",
            &self.cfg.thin_pool,
            "--name",
            template_lv,
            &self.cfg.vg,
        ])
    }

    // ---- probes ----

    fn lv_exists(&self, lv: &str) -> Result<bool> {
        Ok(self.runner.run(&self.lv_exists_cmd(lv))?.ok)
    }

    // ---- sync orchestration ----

    /// Provision storage for `vm` as a snapshot of `spec.template`. Idempotent.
    pub fn provision_sync(&self, vm: VmId, spec: &VolumeSpec) -> Result<StorageHandle> {
        let volume = self.volume_lv(vm);
        let device_path = self.dev_path(&volume);
        // The base device this volume is (or will be) a CoW snapshot of — the
        // path a warm snapshot of `spec.template` reopens on resume. Recorded
        // here, at the one operation that knows the template→volume pairing.
        let backing_device = Some(self.dev_path(&self.template_lv(&spec.template)));

        if self.lv_exists(&volume)? {
            // already provisioned: just (re)activate and return.
            self.runner.run(&self.activate_cmd(&volume))?;
            return Ok(StorageHandle { vm, device_path, backing_device });
        }

        let template = self.template_lv(&spec.template);
        if !self.lv_exists(&template)? {
            return Err(Error::Backend(format!(
                "template '{}' not found (expected LV {})",
                spec.template,
                self.vg_lv(&template)
            )));
        }

        self.runner.run(&self.snapshot_cmd(&template, &volume))?;
        self.runner.run(&self.activate_cmd(&volume))?;
        Ok(StorageHandle { vm, device_path, backing_device })
    }

    /// Tear down `vm`'s volume. Idempotent.
    pub fn teardown_sync(&self, vm: VmId) -> Result<()> {
        let volume = self.volume_lv(vm);
        self.runner.run(&self.remove_cmd(&volume))?;
        Ok(())
    }

    /// Ensure the backing chain exists: sparse file → loop → PV → VG → thin
    /// pool. Idempotent. Returns the loop device path.
    pub fn ensure_backing_sync(&self) -> Result<String> {
        // 1. sparse flat file
        if !self.cfg.image_path.exists() {
            if let Some(parent) = self.cfg.image_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::Backend(format!("create {parent:?}: {e}")))?;
            }
            let f = std::fs::File::create(&self.cfg.image_path)
                .map_err(|e| Error::Backend(format!("create image: {e}")))?;
            f.set_len(self.cfg.image_size)
                .map_err(|e| Error::Backend(format!("size image: {e}")))?;
        }
        let image = self.cfg.image_path.to_string_lossy().into_owned();

        // 2. loop device (reuse an existing attachment if present)
        let existing = self
            .runner
            .run(&Cmd::lenient(&[
                "losetup", "-j", &image, "-O", "NAME", "--noheadings",
            ]))?
            .stdout
            .trim()
            .to_string();
        let loopdev = if existing.is_empty() {
            self.runner
                .run(&Cmd::new(&["losetup", "--find", "--show", &image]))?
                .stdout
                .trim()
                .to_string()
        } else {
            existing
        };
        if loopdev.is_empty() {
            return Err(Error::Backend("could not determine loop device".into()));
        }

        // 3. PV
        if !self.runner.run(&Cmd::lenient(&["pvs", &loopdev]))?.ok {
            self.runner.run(&Cmd::new(&["pvcreate", &loopdev]))?;
        }
        // 4. VG
        if !self.runner.run(&Cmd::lenient(&["vgs", &self.cfg.vg]))?.ok {
            self.runner
                .run(&Cmd::new(&["vgcreate", &self.cfg.vg, &loopdev]))?;
        }
        // 5. thin pool
        if !self.lv_exists(&self.cfg.thin_pool)? {
            self.runner.run(&Cmd::new(&[
                "lvcreate",
                "--type",
                "thin-pool",
                "-l",
                "100%FREE",
                "--name",
                &self.cfg.thin_pool,
                &self.cfg.vg,
            ]))?;
        }
        Ok(loopdev)
    }

    /// Ensure a template thin volume exists (to be populated with a base image).
    /// Idempotent.
    pub fn ensure_template_sync(&self, name: &str, virtual_size: &str) -> Result<()> {
        let template = self.template_lv(name);
        if self.lv_exists(&template)? {
            return Ok(());
        }
        self.runner
            .run(&self.template_create_cmd(&template, virtual_size))?;
        Ok(())
    }

    /// Read thin-pool utilisation (data/metadata percent).
    pub fn pool_stats_sync(&self) -> Result<PoolStats> {
        let out = self.runner.run(&Cmd::new(&[
            "lvs",
            "--noheadings",
            "--nosuffix",
            "-o",
            "data_percent,metadata_percent",
            &self.vg_lv(&self.cfg.thin_pool),
        ]))?;
        let mut fields = out.stdout.split_whitespace();
        let parse = |s: Option<&str>| s.and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
        Ok(PoolStats {
            data_percent: parse(fields.next()),
            metadata_percent: parse(fields.next()),
        })
    }

    // ---- async wrappers ----

    /// Ensure a template volume exists (off the async executor).
    pub async fn create_template(&self, name: &str, virtual_size: &str) -> Result<()> {
        let this = self.clone();
        let name = name.to_string();
        let size = virtual_size.to_string();
        blocking(move || this.ensure_template_sync(&name, &size)).await
    }
}

/// Run blocking CLI work off the async executor, flattening the join error.
async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Backend(format!("blocking task panicked: {e}")))?
}

impl StorageManager for Manager {
    async fn init(&self) -> Result<()> {
        let this = self.clone();
        blocking(move || this.ensure_backing_sync().map(|_| ())).await
    }

    async fn provision(&self, vm: VmId, spec: &VolumeSpec) -> Result<StorageHandle> {
        let this = self.clone();
        let spec = spec.clone();
        blocking(move || this.provision_sync(vm, &spec)).await
    }

    async fn teardown(&self, vm: VmId) -> Result<()> {
        let this = self.clone();
        blocking(move || this.teardown_sync(vm)).await
    }

    async fn pool_stats(&self) -> Result<PoolStats> {
        let this = self.clone();
        blocking(move || this.pool_stats_sync()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CmdOut, RecordingRunner};

    fn vm() -> VmId {
        VmId::from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788)
    }

    fn manager_with(runner: Arc<dyn CommandRunner>) -> Manager {
        Manager::new(Config::default(), runner)
    }

    #[test]
    fn names_and_paths() {
        let m = Manager::with_defaults();
        // vm_<32 hex of the uuid>, no hyphens (avoids dm-name escaping).
        assert_eq!(
            m.volume_lv(vm()),
            "vm_123456789abcdef01122334455667788"
        );
        assert_eq!(m.template_lv("ubuntu"), "tpl_ubuntu");
        assert_eq!(m.dev_path("vm_x"), PathBuf::from("/dev/iso/vm_x"));
    }

    #[test]
    fn pool_stats_parses_lvs_output() {
        let runner = Arc::new(RecordingRunner::with_responder(|_| CmdOut {
            ok: true,
            stdout: "  12.50  3.20 \n".to_string(),
        }));
        let stats = manager_with(runner).pool_stats_sync().unwrap();
        assert_eq!(stats.data_percent, 12.5);
        assert_eq!(stats.metadata_percent, 3.2);
    }

    #[test]
    fn snapshot_command_is_thin_cow() {
        let m = Manager::with_defaults();
        let c = m.snapshot_cmd("tpl_ubuntu", "vm_abc");
        assert_eq!(
            c.argv,
            vec![
                "lvcreate",
                "--snapshot",
                "--name",
                "vm_abc",
                "--setactivationskip",
                "n",
                "iso/tpl_ubuntu",
            ]
        );
    }

    #[test]
    fn remove_command_is_lenient() {
        let m = Manager::with_defaults();
        let c = m.remove_cmd("vm_abc");
        assert!(c.ignore_err);
        assert_eq!(c.argv, vec!["lvremove", "--force", "iso/vm_abc"]);
    }

    #[test]
    fn provision_snapshots_when_absent() {
        let vol = Manager::with_defaults().volume_lv(vm());
        let tpl = "tpl_base".to_string();
        let runner = Arc::new(RecordingRunner::with_responder(move |c| {
            // template exists; volume does not.
            let exists = c.argv[0] == "lvs" && c.argv.iter().any(|a| a.ends_with(&tpl));
            CmdOut {
                ok: exists,
                stdout: String::new(),
            }
        }));
        let m = manager_with(runner.clone());

        let h = m
            .provision_sync(
                vm(),
                &VolumeSpec {
                    template: "base".into(),
                },
            )
            .unwrap();
        assert_eq!(h.device_path, PathBuf::from(format!("/dev/iso/{vol}")));

        let argv0s: Vec<String> = runner.calls().iter().map(|c| c.argv[0].clone()).collect();
        assert!(argv0s.contains(&"lvcreate".to_string()), "should snapshot");
        assert!(argv0s.contains(&"lvchange".to_string()), "should activate");
    }

    #[test]
    fn provision_is_idempotent_when_present() {
        // every lvs probe says "exists" -> no lvcreate.
        let runner = Arc::new(RecordingRunner::with_responder(|_| CmdOut {
            ok: true,
            stdout: String::new(),
        }));
        let m = manager_with(runner.clone());
        m.provision_sync(vm(), &VolumeSpec { template: "base".into() })
            .unwrap();
        let argv0s: Vec<String> = runner.calls().iter().map(|c| c.argv[0].clone()).collect();
        assert!(!argv0s.contains(&"lvcreate".to_string()), "must not re-create");
    }

    #[test]
    fn provision_errors_when_template_missing() {
        // nothing exists.
        let runner = Arc::new(RecordingRunner::with_responder(|_| CmdOut {
            ok: false,
            stdout: String::new(),
        }));
        let m = manager_with(runner);
        let err = m
            .provision_sync(vm(), &VolumeSpec { template: "ghost".into() })
            .unwrap_err();
        assert!(matches!(err, Error::Backend(msg) if msg.contains("template 'ghost'")));
    }

    #[test]
    fn teardown_removes_volume() {
        let runner = Arc::new(RecordingRunner::new());
        let m = manager_with(runner.clone());
        m.teardown_sync(vm()).unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].argv[0], "lvremove");
        assert!(calls[0].ignore_err);
    }

    // ---- live test against real LVM (root + lvm2 tools required) ----

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn test_config() -> Config {
        Config {
            image_path: PathBuf::from("/tmp/iso-storage-test.img"),
            image_size: 2 * 1024 * 1024 * 1024, // 2 GiB sparse
            vg: "isotest".to_string(),
            thin_pool: "pool".to_string(),
            template_prefix: "tpl_".to_string(),
            volume_prefix: "vm_".to_string(),
        }
    }

    /// Best-effort teardown of the whole throwaway backing chain.
    fn cleanup(cfg: &Config) {
        use std::process::Command;
        let img = cfg.image_path.to_string_lossy().into_owned();
        let _ = Command::new("vgremove").args(["-f", &cfg.vg]).output();
        if let Ok(out) = Command::new("losetup")
            .args(["-j", &img, "-O", "NAME", "--noheadings"])
            .output()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let dev = line.trim();
                if !dev.is_empty() {
                    let _ = Command::new("losetup").args(["-d", dev]).output();
                }
            }
        }
        let _ = std::fs::remove_file(&cfg.image_path);
    }

    /// Full backing chain + template + COW snapshot + teardown against real LVM.
    /// Self-skips unless root (the lvm2/losetup tools also need to be present).
    #[tokio::test]
    async fn live_thin_pool_snapshot() {
        if !is_root() {
            eprintln!("skipping live_thin_pool_snapshot: requires root + lvm2 tools");
            return;
        }
        let cfg = test_config();
        cleanup(&cfg); // start clean

        let m = Manager::new(cfg.clone(), Arc::new(SystemRunner));
        m.init().await.expect("ensure backing");
        m.create_template("base", "1G").await.expect("create template");

        let id = VmId::from_u128(0xa1b2_c3d4_e5f6_0708_0910_1112_1314_1516);
        let spec = VolumeSpec {
            template: "base".into(),
        };

        let h = m.provision(id, &spec).await.expect("provision");
        assert!(
            h.device_path.exists(),
            "snapshot device {:?} should exist",
            h.device_path
        );

        // idempotent re-provision returns the same device.
        let h2 = m.provision(id, &spec).await.expect("re-provision");
        assert_eq!(h.device_path, h2.device_path);

        m.teardown(id).await.expect("teardown");
        assert!(
            !h.device_path.exists(),
            "device {:?} should be gone",
            h.device_path
        );
        m.teardown(id).await.expect("idempotent teardown");

        cleanup(&cfg);
    }
}
