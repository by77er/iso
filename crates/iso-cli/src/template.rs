//! `isoctl template …` — templates on a host or across a fleet: what there
//! is, and building one from an OCI image.
//!
//! The build endpoints answer differently on a host (one build) and on the
//! fleet (one per host, plus a state for the whole), so these commands read
//! JSON rather than the typed client and print what they get.

use clap::{Args, Subcommand};
use serde_json::{json, Value};

use crate::vm::{connect, Conn};
use iso_client::ClientInfo as _;

type R<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Args)]
pub struct Template {
    #[command(flatten)]
    conn: Conn,
    #[command(subcommand)]
    cmd: TemplateCmd,
}

#[derive(Subcommand)]
pub enum TemplateCmd {
    /// Templates on the host, or per host across the fleet.
    List,
    /// Build a template from an OCI image; on the fleet, on every host.
    Build {
        /// Template name: `[a-z0-9][a-z0-9-]{0,31}`.
        #[arg(long)]
        name: String,
        /// The image: `python:3.12-slim`, `ghcr.io/acme/tool:v3`, `repo@sha256:…`.
        #[arg(long)]
        image: String,
        #[arg(long)]
        vcpus: Option<u32>,
        #[arg(long)]
        mem_mib: Option<u32>,
        /// Rootfs volume size, e.g. `16G`.
        #[arg(long)]
        size: Option<String>,
        /// Fleet only: build on this host alone.
        #[arg(long)]
        host: Option<String>,
        /// Rebuild even where the template already exists.
        #[arg(long)]
        force: bool,
        /// Wait for the build to finish.
        #[arg(long)]
        wait: bool,
    },
    /// Every build, newest first (per host on the fleet).
    Builds,
    /// Wait for a build to be ready; exits non-zero when it fails.
    Wait {
        name: String,
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
    },
}

pub async fn run(t: Template) -> R<()> {
    let c = connect(&t.conn)?;
    let base = c.baseurl().trim_end_matches('/').to_string();
    let http = c.client().clone();
    let get = |path: String| {
        let http = http.clone();
        let url = format!("{base}{path}");
        async move {
            let r = http.get(&url).send().await?;
            let status = r.status();
            let v: Value = r.json().await.unwrap_or(Value::Null);
            Ok::<_, Box<dyn std::error::Error>>((status, v))
        }
    };
    match t.cmd {
        TemplateCmd::List => {
            let (status, v) = get("/templates".into()).await?;
            if status.is_success() {
                for tpl in v.as_array().cloned().unwrap_or_default() {
                    println!("{}\t{} vcpu\t{} MiB\t{}", tpl["name"].as_str().unwrap_or("?"), tpl["vcpus"], tpl["mem_mib"], if tpl["warm"].as_bool().unwrap_or(false) { "warm" } else { "cold" });
                }
            } else {
                // The fleet: templates are per host.
                let (status, hosts) = get("/hosts".into()).await?;
                if !status.is_success() {
                    return Err(format!("GET /hosts: http {status}").into());
                }
                for h in hosts.as_array().cloned().unwrap_or_default() {
                    let names: Vec<String> = h["templates"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                    println!("{}\t{}\t{}", h["name"].as_str().unwrap_or("?"), if h["healthy"].as_bool().unwrap_or(false) { "healthy" } else { "down" }, names.join(","));
                }
            }
        }
        TemplateCmd::Build { name, image, vcpus, mem_mib, size, host, force, wait } => {
            let mut body = json!({ "name": name, "image": image, "force": force });
            if let Some(v) = vcpus { body["vcpus"] = json!(v); }
            if let Some(m) = mem_mib { body["mem_mib"] = json!(m); }
            if let Some(s) = size { body["size"] = json!(s); }
            if let Some(h) = host { body["host"] = json!(h); }
            let r = http.post(format!("{base}/templates/build")).json(&body).send().await?;
            let status = r.status();
            let v: Value = r.json().await.unwrap_or(Value::Null);
            println!("{}", serde_json::to_string_pretty(&v)?);
            if !status.is_success() {
                return Err(format!("build not accepted: http {status}").into());
            }
            if wait {
                wait_for(&get, &name, 1800).await?;
            }
        }
        TemplateCmd::Builds => {
            let (status, v) = get("/templates/builds".into()).await?;
            if !status.is_success() {
                return Err(format!("GET /templates/builds: http {status}").into());
            }
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        TemplateCmd::Wait { name, timeout } => wait_for(&get, &name, timeout).await?,
    }
    Ok(())
}

/// Poll a build until it is ready or failed. Understands both shapes: a
/// host's `{state}` and the fleet's `{state, hosts}`.
async fn wait_for<F, Fut>(get: &F, name: &str, timeout: u64) -> R<()>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = R<(reqwest::StatusCode, Value)>>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        let (status, v) = get(format!("/templates/builds/{name}")).await?;
        let state = v["state"].as_str().unwrap_or("unknown").to_string();
        if status.is_success() {
            match state.as_str() {
                "ready" => {
                    eprintln!("template {name}: ready");
                    println!("{}", serde_json::to_string_pretty(&v)?);
                    return Ok(());
                }
                "failed" => {
                    println!("{}", serde_json::to_string_pretty(&v)?);
                    return Err(format!("template {name}: build failed").into());
                }
                _ => {}
            }
        } else if status.as_u16() != 404 {
            return Err(format!("GET /templates/builds/{name}: http {status}").into());
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("template {name}: still {state} after {timeout}s").into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
