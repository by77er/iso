use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub bind: String,
    pub public_origin: String,
    pub secure_cookie: bool,
    pub data_dir: PathBuf,
    pub ui_dir: PathBuf,
    pub pi_bin: PathBuf,
    pub pi_extension: PathBuf,
    pub pi_model: Option<String>,
    pub pi_env_file: Option<PathBuf>,
    pub idle_seconds: u64,
    pub max_agents: usize,
    pub demo: bool,
    pub planes: Vec<PlaneConfig>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".into(),
            public_origin: "http://127.0.0.1:8080".into(),
            secure_cookie: true,
            data_dir: "state/master".into(),
            ui_dir: "contrib/master/dist".into(),
            pi_bin: "contrib/master/node_modules/.bin/pi".into(),
            pi_extension: "contrib/master/pi/remote-tools.ts".into(),
            pi_model: None,
            pi_env_file: None,
            idle_seconds: 900,
            max_agents: 16,
            demo: false,
            planes: vec![],
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaneConfig {
    pub id: String,
    pub server: String,
    pub creds: PathBuf,
    #[serde(default = "client_name")]
    pub client: String,
    pub template: String,
    #[serde(default = "egress")]
    pub egress: String,
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default = "capacity")]
    pub max_vms: usize,
}
fn client_name() -> String {
    "orchestrator".into()
}
fn egress() -> String {
    "deny".into()
}
fn capacity() -> usize {
    32
}
impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let mut cfg: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        cfg.validate()?;
        let cwd = std::env::current_dir()?;
        for p in [
            &mut cfg.data_dir,
            &mut cfg.ui_dir,
            &mut cfg.pi_bin,
            &mut cfg.pi_extension,
        ] {
            if p.is_relative() {
                *p = cwd.join(&*p);
            }
        }
        for p in &mut cfg.planes {
            if p.creds.is_relative() {
                p.creds = cwd.join(&p.creds);
            }
        }
        Ok(cfg)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.idle_seconds > 0 && self.max_agents > 0,
            "idle_seconds/max_agents must be positive"
        );
        ensure!(!self.planes.is_empty(), "Configure at least one plane");
        ensure!(
            self.public_origin.starts_with("https://") || self.public_origin.starts_with("http://"),
            "Set public_origin"
        );
        ensure!(
            !self.public_origin.ends_with('/'),
            "public_origin must not end in /"
        );
        let mut seen = std::collections::HashSet::new();
        for p in &self.planes {
            ensure!(
                !p.id.is_empty()
                    && p.id.len() <= 64
                    && p.id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "Invalid plane ID"
            );
            ensure!(seen.insert(&p.id), "Duplicate plane ID");
            ensure!(
                self.demo || p.server.starts_with("https://"),
                "Live planes require HTTPS"
            );
            ensure!(
                matches!(p.egress.as_str(), "deny" | "proxy" | "allow"),
                "Invalid egress mode"
            );
            ensure!(
                p.max_vms > 0 && !p.template.is_empty(),
                "Invalid plane capacity/template"
            );
        }
        Ok(())
    }
    pub fn pi_env(&self) -> Result<BTreeMap<String, String>> {
        match &self.pi_env_file {
            Some(path) => {
                serde_json::from_slice(&std::fs::read(path)?).context("Invalid pi_env_file")
            }
            None => Ok(BTreeMap::new()),
        }
    }
}
