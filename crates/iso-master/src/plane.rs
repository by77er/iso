use crate::config::PlaneConfig;
use anyhow::{Context, Result, bail};
use iso_client::{Client, Credentials, types};
use serde_json::{Value, json};
use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};
use tokio::sync::Mutex;

async fn wait_ready<F, Fut>(budget: Duration, mut probe: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    tokio::time::timeout(budget, async {
        let mut delay = Duration::from_millis(250);
        loop {
            if probe().await { return; }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(2));
        }
    }).await.context("Guest readiness timed out: guest agent and DNS resolution of metadata.iso.internal are required")
}

fn dns_probe() -> types::ExecRequest {
    types::ExecRequest {
        cmd: "getent".into(),
        args: vec![
            "-s".into(),
            "dns".into(),
            "ahostsv4".into(),
            "metadata.iso.internal".into(),
        ],
        cwd: Some("/".into()),
        env: Default::default(),
        max_output_bytes: Some(4096),
        stdin: None,
        timeout_ms: Some(2000),
    }
}

fn dns_ready(result: &types::ExecResult) -> bool {
    result.exit_code == Some(0)
        && !result.timed_out
        && result.signal.is_none()
        && result.stdout.lines().any(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readiness_retries_transient_failures_and_bounds_hanging_probes() {
        let mut attempts = 0;
        wait_ready(Duration::from_secs(2), || {
            attempts += 1;
            std::future::ready(attempts == 3)
        })
        .await
        .unwrap();
        assert_eq!(attempts, 3);
        let error = wait_ready(Duration::from_millis(20), || std::future::pending::<bool>())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("metadata.iso.internal"));
    }

    #[test]
    fn probe_requires_successful_dns_output_and_is_read_only() {
        let request = dns_probe();
        assert_eq!(request.cmd, "getent");
        assert_eq!(
            request.args,
            ["-s", "dns", "ahostsv4", "metadata.iso.internal"]
        );
        assert_eq!(request.timeout_ms, Some(2000));
        let mut result: types::ExecResult = serde_json::from_value(json!({
            "duration_ms":1,"exit_code":0,"signal":null,"stderr":"",
            "stdout":"172.22.0.1 STREAM metadata.iso.internal\n", "timed_out":false,"truncated":false
        })).unwrap();
        assert!(dns_ready(&result));
        result.timed_out = true;
        assert!(!dns_ready(&result));
        result.timed_out = false;
        result.exit_code = Some(2);
        assert!(!dns_ready(&result));
        result.exit_code = Some(0);
        result.stdout.clear();
        assert!(!dns_ready(&result));
    }
}

#[derive(Clone)]
pub struct Plane {
    pub config: PlaneConfig,
    client: Option<Client>,
    demo_vms: Arc<Mutex<BTreeMap<String, Value>>>,
}
impl Plane {
    pub fn new(config: PlaneConfig, demo: bool) -> Result<Self> {
        let client = if demo {
            None
        } else {
            Some(Client::connect(
                &config.server,
                &Credentials::from_dir(&config.creds, &config.client)?,
            )?)
        };
        Ok(Self {
            config,
            client,
            demo_vms: Default::default(),
        })
    }
    pub async fn list(&self) -> Result<Vec<Value>> {
        if let Some(c) = &self.client {
            let r = tokio::time::timeout(Duration::from_secs(5), c.list().send()).await??;
            Ok(r.iter().map(|v| serde_json::to_value(v).unwrap()).collect())
        } else {
            Ok(self.demo_vms.lock().await.values().cloned().collect())
        }
    }
    pub async fn create(&self, session: &str, name: &str) -> Result<String> {
        let body = json!({"template":self.config.template,"egress":self.config.egress,
            "allow":self.config.allow,"principal":self.config.principal,"lifecycle":"durable","restart":"never",
            "labels":{"name":name,"managed-by":"iso-master","master-session":session}});
        if let Some(c) = &self.client {
            let body: types::CreateVmRequest = serde_json::from_value(body)?;
            let r = tokio::time::timeout(Duration::from_secs(90), c.create().body(body).send())
                .await??;
            Ok(r.id.clone())
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let mut vm = body;
            vm["id"] = json!(id);
            vm["state"] = json!("running");
            self.demo_vms.lock().await.insert(id.clone(), vm);
            Ok(id)
        }
    }
    pub async fn get(&self, id: &str) -> Result<Value> {
        if let Some(c) = &self.client {
            Ok(serde_json::to_value(
                tokio::time::timeout(Duration::from_secs(10), c.get_one().id(id).send())
                    .await??
                    .into_inner(),
            )?)
        } else {
            self.demo_vms
                .lock()
                .await
                .get(id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("VM not found"))
        }
    }
    pub async fn action(&self, id: &str, action: &str) -> Result<()> {
        if let Some(c) = &self.client {
            tokio::time::timeout(Duration::from_secs(90), async {
                match action {
                    "start" => {
                        c.start().id(id).send().await?;
                    }
                    "suspend" => {
                        c.suspend().id(id).send().await?;
                    }
                    "halt" => {
                        c.halt().id(id).send().await?;
                    }
                    "destroy" => {
                        c.destroy().id(id).send().await?;
                    }
                    _ => bail!("Invalid action"),
                }
                Ok::<_, anyhow::Error>(())
            })
            .await??;
        } else {
            let mut vms = self.demo_vms.lock().await;
            if action == "destroy" {
                vms.remove(id);
                return Ok(());
            }
            let vm = vms
                .get_mut(id)
                .ok_or_else(|| anyhow::anyhow!("VM not found"))?;
            vm["state"] = json!(match action {
                "start" => "running",
                "suspend" => "suspended",
                "halt" => "stopped",
                _ => bail!("Invalid action"),
            });
        }
        Ok(())
    }
    pub async fn ready(&self, id: &str) -> Result<()> {
        if let Some(c) = &self.client {
            wait_ready(Duration::from_secs(60), || async {
                if !tokio::time::timeout(Duration::from_secs(3), c.agent_info().id(id).send())
                    .await
                    .is_ok_and(|r| r.is_ok())
                {
                    return false;
                }
                // Only this bounded, read-only infrastructure probe is retried.
                // DNS is forced through NSS's DNS backend, not /etc/hosts.
                tokio::time::timeout(
                    Duration::from_secs(3),
                    c.guest_exec().id(id).body(dns_probe()).send(),
                )
                .await
                .is_ok_and(|r| r.is_ok_and(|result| dns_ready(&result)))
            })
            .await?;
        }
        Ok(())
    }
}
