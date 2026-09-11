//! `iso-guest-agent` — listen on a vsock port (default 5000) and serve the
//! host's exec and file requests. `--listen-tcp ADDR` serves TCP instead, for
//! debugging outside a VM.

use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

fn usage() -> ! {
    eprintln!("usage: iso-guest-agent [--port N] [--listen-tcp ADDR]");
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    let mut port = iso_guest_proto::DEFAULT_PORT;
    let mut tcp: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => port = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage()),
            "--listen-tcp" => tcp = Some(args.next().unwrap_or_else(|| usage())),
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }

    if let Some(addr) = tcp {
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("iso-guest-agent: bind {addr}: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("iso-guest-agent: serving on tcp {addr}");
        loop {
            match listener.accept().await {
                Ok((s, _)) => {
                    tokio::spawn(iso_guest_agent::serve_connection(s));
                }
                Err(e) => eprintln!("iso-guest-agent: accept: {e}"),
            }
        }
    }

    let listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("iso-guest-agent: bind vsock port {port}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("iso-guest-agent: serving on vsock port {port}");
    loop {
        match listener.accept().await {
            Ok((s, _)) => {
                tokio::spawn(iso_guest_agent::serve_connection(s));
            }
            Err(e) => eprintln!("iso-guest-agent: accept: {e}"),
        }
    }
}
