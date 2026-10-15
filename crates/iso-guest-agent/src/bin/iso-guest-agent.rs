//! `iso-guest-agent` — listen on a vsock port (default 5000) and serve the
//! host's exec and file requests. `--listen-tcp ADDR` serves TCP instead, for
//! debugging outside a VM.
//!
//! `--reseed [--ssh-host-keys]` is a one-shot instead: reseed the kernel RNG
//! with the base64 bytes on stdin (and regenerate the SSH host keys), print
//! what was done as JSON, and exit non-zero if any of it was not. The host
//! runs it as root after resuming a clone; see `iso_guest_agent::reseed`.

use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

/// The stderr macro panics when stderr is closed, and this process may be
/// PID 1 of a bare test image with no console. Log on a best-effort basis.
macro_rules! log {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

fn usage() -> ! {
    log!(
        "usage: iso-guest-agent [--port N] [--listen-tcp ADDR] | --reseed [--ssh-host-keys] < base64"
    );
    std::process::exit(2)
}

fn main() {
    // PID 1 means a template with no init of its own: be one, and run the
    // agent proper as a child with the image's environment.
    if std::process::id() == 1 {
        let args: Vec<String> = std::env::args().skip(1).filter(|a| a != "--init").collect();
        let args = if args.is_empty() {
            vec![
                "--port".to_string(),
                iso_guest_proto::DEFAULT_PORT.to_string(),
            ]
        } else {
            args
        };
        iso_guest_agent::init::run(&args);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--reseed") {
        reseed(args.iter().any(|a| a == "--ssh-host-keys"));
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(serve());
}

fn reseed(ssh_host_keys: bool) -> ! {
    use std::io::{Read as _, Write as _};
    let mut stdin = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut stdin) {
        log!("iso-guest-agent: read stdin: {e}");
        std::process::exit(2);
    }
    let (report, ok) = iso_guest_agent::reseed::reseed_command(&stdin, ssh_host_keys);
    let _ = writeln!(std::io::stdout(), "{report}");
    std::process::exit(if ok { 0 } else { 1 })
}

async fn serve() {
    let mut port = iso_guest_proto::DEFAULT_PORT;
    let mut tcp: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => {
                port = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--listen-tcp" => tcp = Some(args.next().unwrap_or_else(|| usage())),
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }

    if let Some(addr) = tcp {
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                log!("iso-guest-agent: bind {addr}: {e}");
                std::process::exit(1);
            }
        };
        log!("iso-guest-agent: serving on tcp {addr}");
        loop {
            match listener.accept().await {
                Ok((s, _)) => {
                    tokio::spawn(iso_guest_agent::serve_connection(s));
                }
                Err(e) => log!("iso-guest-agent: accept: {e}"),
            }
        }
    }

    let listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port)) {
        Ok(l) => l,
        Err(e) => {
            log!("iso-guest-agent: bind vsock port {port}: {e}");
            std::process::exit(1);
        }
    };
    log!("iso-guest-agent: serving on vsock port {port}");
    loop {
        match listener.accept().await {
            Ok((s, _)) => {
                tokio::spawn(iso_guest_agent::serve_connection(s));
            }
            Err(e) => log!("iso-guest-agent: accept: {e}"),
        }
    }
}
