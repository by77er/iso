use crate::config::PlaneConfig;
use anyhow::{Result, bail};
use iso_client::{Client, Credentials, types};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;

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
            tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    if tokio::time::timeout(Duration::from_secs(3), c.agent_info().id(id).send())
                        .await
                        .is_ok_and(|r| r.is_ok())
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            })
            .await?;
        }
        Ok(())
    }
}
