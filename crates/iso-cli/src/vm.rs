//! `isoctl vm …` — drive VMs through the admin API with the generated client.
//!
//! Connection settings come from flags or the environment: `--server` /
//! `ISO_SERVER` (default `https://127.0.0.1:7070`), and either `--creds DIR`
//! with `--client NAME` (`ISO_CREDS`, `ISO_CLIENT`, as written by
//! `isoctl admin issue-client`) or `--insecure` for a daemon on plain HTTP.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use iso_client::types;
use iso_client::{Client, Credentials};

type R<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Args)]
pub struct Vm {
    /// Admin API base URL.
    #[arg(long, env = "ISO_SERVER", default_value = "https://127.0.0.1:7070", global = true)]
    server: String,
    /// Directory holding `ca.crt`, `<client>.crt` and `<client>.key`.
    #[arg(long, env = "ISO_CREDS", global = true)]
    creds: Option<PathBuf>,
    /// Name of the client certificate in `--creds`.
    #[arg(long, env = "ISO_CLIENT", default_value = "admin", global = true)]
    client: String,
    /// Plain HTTP, for a daemon started with ISO_ADMIN_INSECURE=1.
    #[arg(long, global = true)]
    insecure: bool,
    #[command(subcommand)]
    cmd: VmCmd,
}

#[derive(Subcommand)]
pub enum VmCmd {
    /// List VMs.
    List,
    /// Show one VM as JSON.
    Get { id: String },
    /// Create and boot a VM.
    Create(Create),
    /// Destroy a VM, whatever its lifecycle.
    Rm { id: String },
    /// Boot a stopped durable VM, or resume a suspended one.
    Start { id: String },
    /// Shut a VM down gracefully.
    Stop { id: String },
    /// Kill a VM.
    Halt { id: String },
    /// Pause and snapshot a VM in place.
    Suspend { id: String },
    /// Change egress policy on a running VM.
    Policy {
        id: String,
        #[arg(long)]
        egress: Option<String>,
        #[arg(long)]
        principal: Option<String>,
        /// Replace the proxied-domain list (repeatable).
        #[arg(long = "allow")]
        allow: Vec<String>,
    },
    /// Ask the guest agent who it is.
    Agent { id: String },
    /// Run a program inside the VM; its stdout, stderr and exit status become ours.
    Exec {
        id: String,
        #[arg(long)]
        cwd: Option<String>,
        /// Wall-clock limit in seconds (default 120).
        #[arg(long)]
        timeout: Option<u64>,
        /// Extra environment, `KEY=VALUE` (repeatable).
        #[arg(long = "env")]
        env: Vec<String>,
        /// Feed this to the program's stdin.
        #[arg(long)]
        stdin: Option<String>,
        /// The program and its arguments, after `--`.
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Print a file from inside the VM.
    Cat { id: String, path: String },
    /// Write a file inside the VM from a local file or literal content.
    Put {
        id: String,
        path: String,
        #[arg(long, conflicts_with = "content")]
        from: Option<PathBuf>,
        #[arg(long)]
        content: Option<String>,
        /// Permission bits, octal (e.g. 755).
        #[arg(long)]
        mode: Option<String>,
        /// Create missing parent directories.
        #[arg(long)]
        mkdir: bool,
    },
    /// List a directory inside the VM.
    Ls { id: String, path: String },
    /// Remove a path inside the VM.
    RmPath {
        id: String,
        path: String,
        #[arg(long)]
        recursive: bool,
    },
}

#[derive(Args)]
pub struct Create {
    #[arg(long)]
    template: String,
    /// Stored as the `name` label and shown to the guest's metadata.
    #[arg(long)]
    name: Option<String>,
    /// `allow`, `proxy` or `deny` (default).
    #[arg(long, default_value = "deny")]
    egress: String,
    #[arg(long)]
    principal: Option<String>,
    /// Domains routed through the egress proxy (repeatable).
    #[arg(long = "allow")]
    allow: Vec<String>,
    /// Forward a VM port: `PORT` or `PORT/udp` (repeatable). The host port is allocated.
    #[arg(long = "forward")]
    forwards: Vec<String>,
    /// Keep the rootfs across stops.
    #[arg(long)]
    durable: bool,
    /// `never` (default), `on_failure` or `always`.
    #[arg(long, default_value = "never")]
    restart: String,
    #[arg(long)]
    vcpus: Option<u32>,
    #[arg(long)]
    mem_mib: Option<u32>,
    /// Extra labels, `KEY=VALUE` (repeatable).
    #[arg(long = "label")]
    labels: Vec<String>,
    /// Print only the id.
    #[arg(long, short)]
    quiet: bool,
}

fn kv(pairs: &[String], what: &str) -> R<Vec<(String, String)>> {
    pairs
        .iter()
        .map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| format!("{what} must be KEY=VALUE, got {p:?}").into())
        })
        .collect()
}

fn connect(v: &Vm) -> R<Client> {
    if v.insecure {
        let base = if v.server.starts_with("http") { v.server.clone() } else { format!("http://{}", v.server) };
        return Ok(Client::insecure(&base));
    }
    let dir = v.creds.clone().ok_or("--creds DIR (or ISO_CREDS) is required unless --insecure")?;
    let creds = Credentials::from_dir(&dir, &v.client)?;
    Ok(Client::connect(&v.server, &creds)?)
}

pub async fn run(v: Vm) -> R<()> {
    let c = connect(&v)?;
    match v.cmd {
        VmCmd::List => {
            let vms = c.list().send().await?.into_inner();
            #[allow(clippy::print_literal)]
            println!("{:<36}  {:<9}  {:<12}  {:<6}  {}", "ID", "STATE", "TEMPLATE", "EGRESS", "NAME");
            for vm in vms {
                let name = vm.labels.get("name").cloned().unwrap_or_default();
                println!("{:<36}  {:<9}  {:<12}  {:<6}  {}", vm.id, vm.state, vm.template, vm.egress, name);
            }
        }
        VmCmd::Get { id } => {
            let vm = c.get_one().id(id).send().await?.into_inner();
            println!("{}", serde_json::to_string_pretty(&vm)?);
        }
        VmCmd::Create(a) => {
            let mut labels: Vec<(String, String)> = kv(&a.labels, "--label")?;
            if let Some(name) = &a.name {
                labels.push(("name".into(), name.clone()));
            }
            let mut ingress = Vec::new();
            for f in &a.forwards {
                let (port, proto) = f.split_once('/').unwrap_or((f, "tcp"));
                let vm_port: u16 = port.parse().map_err(|_| format!("bad --forward {f:?}"))?;
                // The generated field types follow the OpenAPI integers.
                let forward: types::PortForward = types::PortForward::builder()
                    .host_port(Some(0))
                    .vm_port(vm_port as i32)
                    .proto(proto.to_string())
                    .try_into()?;
                ingress.push(forward);
            }
            let lifecycle = if a.durable { "durable" } else { "ephemeral" };
            let created = c
                .create()
                .body_map(|b| {
                    b.template(a.template.clone())
                        .egress(a.egress.clone())
                        .lifecycle(lifecycle.to_string())
                        .restart(a.restart.clone())
                        .principal(a.principal.clone())
                        .allow(a.allow.clone())
                        .ingress(ingress.clone())
                        .labels(labels.iter().cloned().collect::<std::collections::HashMap<_, _>>())
                        .vcpus(a.vcpus.map(|v| v as i32))
                        .mem_mib(a.mem_mib.map(|v| v as i32))
                })
                .send()
                .await?
                .into_inner();
            if a.quiet {
                println!("{}", created.id);
            } else {
                println!("created {}", created.id);
            }
        }
        VmCmd::Rm { id } => {
            c.destroy().id(id).send().await?;
        }
        VmCmd::Start { id } => {
            c.start().id(id).send().await?;
        }
        VmCmd::Stop { id } => {
            c.stop().id(id).send().await?;
        }
        VmCmd::Halt { id } => {
            c.halt().id(id).send().await?;
        }
        VmCmd::Suspend { id } => {
            c.suspend().id(id).send().await?;
        }
        VmCmd::Policy { id, egress, principal, allow } => {
            let allow = if allow.is_empty() { None } else { Some(allow) };
            c.set_policy()
                .id(id)
                .body_map(|b| b.egress(egress.clone()).principal(principal.clone()).allow(allow.clone()))
                .send()
                .await?;
        }
        VmCmd::Agent { id } => {
            let info = c.agent_info().id(id).send().await?.into_inner();
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        VmCmd::Exec { id, cwd, timeout, env, stdin, command } => {
            let env: std::collections::HashMap<String, String> = kv(&env, "--env")?.into_iter().collect();
            let (cmd, args) = command.split_first().ok_or("a command is required")?;
            let r = c
                .guest_exec()
                .id(id)
                .body_map(|b| {
                    b.cmd(cmd.clone())
                        .args(args.to_vec())
                        .cwd(cwd.clone())
                        .env(env.clone())
                        .stdin(stdin.clone())
                        .timeout_ms(timeout.map(|s| (s * 1000) as i64))
                })
                .send()
                .await?
                .into_inner();
            use std::io::Write;
            let _ = std::io::stdout().write_all(r.stdout.as_bytes());
            let _ = std::io::stderr().write_all(r.stderr.as_bytes());
            if r.timed_out {
                eprintln!("isoctl: timed out after {} ms", r.duration_ms);
            }
            if r.truncated {
                eprintln!("isoctl: output was truncated");
            }
            std::process::exit(r.exit_code.unwrap_or(128 + r.signal.unwrap_or(9)));
        }
        VmCmd::Cat { id, path } => {
            let f = c.read_file().id(id).path(path).send().await?.into_inner();
            let bytes = base64_decode(&f.content_b64)?;
            use std::io::Write;
            std::io::stdout().write_all(&bytes)?;
            if f.truncated {
                eprintln!("isoctl: file truncated at {} of {} bytes", bytes.len(), f.size);
            }
        }
        VmCmd::Put { id, path, from, content, mode, mkdir } => {
            let bytes = match (from, content) {
                (Some(p), None) => std::fs::read(&p)?,
                (None, Some(s)) => s.into_bytes(),
                (None, None) => {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
                (Some(_), Some(_)) => unreachable!("clap enforces conflicts_with"),
            };
            let mode = match mode {
                Some(m) => Some(i32::from_str_radix(&m, 8).map_err(|_| format!("bad --mode {m:?}, expected octal"))?),
                None => None,
            };
            let b64 = base64_encode(&bytes);
            let w = c
                .write_file()
                .id(id)
                .path(path)
                .body_map(|b| b.content_b64(Some(b64.clone())).mode(mode).mkdir(mkdir))
                .send()
                .await?
                .into_inner();
            eprintln!("wrote {} bytes", w.bytes);
        }
        VmCmd::Ls { id, path } => {
            let d = c.list_dir().id(id).path(path).send().await?.into_inner();
            for e in d.entries {
                let kind = serde_json::to_value(e.kind)?.as_str().unwrap_or("?").to_string();
                println!("{:<8} {:>10}  {:o}  {}", kind, e.size, e.mode, e.name);
            }
        }
        VmCmd::RmPath { id, path, recursive } => {
            c.remove_path().id(id).path(path).recursive(recursive).send().await?;
        }
    }
    Ok(())
}

// A dependency-free base64, so isoctl does not pull one in just for this.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

fn base64_decode(input: &str) -> R<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return Err(format!("invalid base64 byte {c:#x}").into()),
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for s in ["", "a", "ab", "abc", "hello, world", "\u{1F600}"] {
            assert_eq!(base64_decode(&base64_encode(s.as_bytes())).unwrap(), s.as_bytes());
        }
        assert_eq!(base64_encode(b"hi"), "aGk=");
        assert_eq!(base64_decode("IyBoaQo=").unwrap(), b"# hi\n");
    }
}
