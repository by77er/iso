//! A client per host: the host's admin API, spoken with the fleet's identity.
//! Everything the fleet does to a VM is one of these calls; the fleet adds
//! nothing the host does not already offer.

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use serde_json::Value;

use crate::config::{HostConfig, TlsFiles};

#[derive(Clone)]
pub struct HostClient {
    pub name: String,
    base: String,
    http: reqwest::Client,
}

#[derive(Debug)]
pub enum CallError {
    /// The host could not be reached at all: nothing was sent, so a retry
    /// elsewhere is safe.
    Unreachable(String),
    /// Something was sent and the reply was lost or malformed: the host may
    /// have acted. Only the sync loop can say.
    Ambiguous(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Unreachable(m) => write!(f, "unreachable: {m}"),
            CallError::Ambiguous(m) => write!(f, "no reply: {m}"),
        }
    }
}

fn classify(e: reqwest::Error) -> CallError {
    if e.is_connect() {
        CallError::Unreachable(e.to_string())
    } else {
        CallError::Ambiguous(e.to_string())
    }
}

impl HostClient {
    pub fn new(cfg: &HostConfig, tls: Option<&TlsFiles>) -> Result<Self, String> {
        let mut b = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            // Long enough for a create with a cold boot; exec has its own
            // timeout inside the host.
            .timeout(Duration::from_secs(300));
        if let Some(t) = tls {
            let creds = iso_client::Credentials::from_files(&t.ca, &t.cert, &t.key)
                .map_err(|e| e.to_string())?;
            let ca = reqwest::Certificate::from_pem(creds.ca_pem.as_bytes())
                .map_err(|e| e.to_string())?;
            let pem = format!("{}{}", creds.cert_pem, creds.key_pem);
            let id = reqwest::Identity::from_pem(pem.as_bytes()).map_err(|e| e.to_string())?;
            b = b.tls_certs_only([ca]).identity(id);
        }
        Ok(Self {
            name: cfg.name.clone(),
            base: cfg.url.trim_end_matches('/').to_string(),
            http: b.build().map_err(|e| e.to_string())?,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    async fn json(&self, path: &str) -> Result<Value, CallError> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .map_err(classify)?;
        if !resp.status().is_success() {
            return Err(CallError::Ambiguous(format!(
                "{path}: http {}",
                resp.status()
            )));
        }
        resp.json()
            .await
            .map_err(|e| CallError::Ambiguous(e.to_string()))
    }

    pub async fn stats(&self) -> Result<Value, CallError> {
        self.json("/stats").await
    }

    pub async fn templates(&self) -> Result<Vec<String>, CallError> {
        let v = self.json("/templates").await?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|t| t["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub async fn list_vms(&self) -> Result<Vec<Value>, CallError> {
        let v = self.json("/vms").await?;
        Ok(v.as_array().cloned().unwrap_or_default())
    }

    /// `POST /vms`. The status and body come back as they are; the caller
    /// decides what a 409 means.
    pub async fn create(&self, body: &Value) -> Result<(StatusCode, Value), CallError> {
        let resp = self
            .http
            .post(format!("{}/vms", self.base))
            .json(body)
            .send()
            .await
            .map_err(classify)?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        Ok((status, body))
    }

    pub async fn delete_vm(&self, id: &str) -> Result<StatusCode, CallError> {
        let resp = self
            .http
            .delete(format!("{}/vms/{id}", self.base))
            .send()
            .await
            .map_err(classify)?;
        Ok(resp.status())
    }

    /// Any other call, forwarded as it came: method, path and query, content
    /// type and body. The answer's status, content type and body come back.
    pub async fn forward(
        &self,
        method: &str,
        path_and_query: &str,
        content_type: Option<&HeaderValue>,
        body: Bytes,
    ) -> Result<(StatusCode, Option<HeaderValue>, Bytes), CallError> {
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| CallError::Unreachable(e.to_string()))?;
        let mut req = self
            .http
            .request(m, format!("{}{path_and_query}", self.base));
        if let Some(ct) = content_type {
            req = req.header(http::header::CONTENT_TYPE, ct.as_bytes());
        }
        if !body.is_empty() {
            req = req.body(body);
        }
        let resp = req.send().await.map_err(classify)?;
        let status = resp.status();
        let ct = resp.headers().get(http::header::CONTENT_TYPE).cloned();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| CallError::Ambiguous(e.to_string()))?;
        Ok((status, ct, bytes))
    }
}
