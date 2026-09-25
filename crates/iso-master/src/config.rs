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
    pub pi_models: Vec<String>,
    pub swarm_max_depth: usize,
    pub swarm_max_agents: usize,
    pub pi_env_file: Option<PathBuf>,
    pub idle_seconds: u64,
    /// Retire suspended execution state after this many seconds; zero disables.
    pub suspended_seconds: u64,
    pub max_agents: usize,
    pub demo: bool,
    /// Prometheus text metrics listener; empty disables it.
    pub metrics_bind: String,
    /// Recover sessions the master's own restart interrupted, at startup.
    /// Failure interrupts (worker crash, uncertain operations) stay manual.
    pub auto_recover: bool,
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
            pi_models: vec![],
            swarm_max_depth: 5,
            swarm_max_agents: 0,
            pi_env_file: None,
            idle_seconds: 900,
            suspended_seconds: 600,
            max_agents: 0,
            demo: false,
            metrics_bind: "127.0.0.1:9464".into(),
            auto_recover: true,
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
    0
}

/// A zero (or omitted) cap means unlimited; explicit positive caps remain supported.
pub fn below_limit(count: usize, limit: usize) -> bool {
    limit == 0 || count < limit
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
        ensure!(self.swarm_max_depth <= 16, "Invalid swarm limits");
        for model in self.models() {
            ensure!(
                model
                    .split_once('/')
                    .is_some_and(|(p, m)| !p.is_empty() && !m.is_empty())
                    && !model.chars().any(char::is_whitespace),
                "Models must use provider/model format"
            );
        }
        ensure!(self.idle_seconds > 0, "idle_seconds must be positive");
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
                matches!(p.egress.as_str(), "deny" | "proxy"),
                "Invalid egress mode: use 'proxy' or 'deny'"
            );
            ensure!(!p.template.is_empty(), "Invalid plane capacity/template");
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
    pub fn models(&self) -> Vec<String> {
        let mut models = self.pi_models.clone();
        if let Some(model) = &self.pi_model {
            models.push(model.clone());
        }
        models.sort();
        models.dedup();
        models
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn omitted_caps_are_unlimited_and_positive_caps_remain_explicit() {
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "demo": true, "planes": [{"id":"test", "server":"demo", "creds":"unused", "template":"debian"}]
        }))
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.max_agents, 0);
        assert_eq!(cfg.swarm_max_depth, 5);
        assert_eq!(cfg.swarm_max_agents, 0);
        assert_eq!(cfg.planes[0].max_vms, 0);
        assert!(below_limit(usize::MAX, 0));
        assert!(below_limit(15, 16));
        assert!(!below_limit(16, 16));
    }

    #[test]
    fn egress_is_proxy_or_deny() {
        let plane = |egress: &str| -> Config {
            serde_json::from_value(serde_json::json!({
                "demo": true, "planes": [{"id":"test", "server":"demo", "creds":"unused",
                "template":"debian", "egress": egress}]
            }))
            .unwrap()
        };
        plane("proxy").validate().unwrap();
        plane("deny").validate().unwrap();
        // The host maps any other value to deny without saying so, so a plane
        // written for the removed `allow` mode must fail here instead.
        assert!(plane("allow").validate().is_err());
    }
}
