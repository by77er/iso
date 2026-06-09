//! End-to-end live test: drives the real stack — LVM thin pool, netns/veth/tap/
//! nftables, and a Firecracker microVM on KVM — through the axum admin API.
//!
//! Self-skips unless run as root with a guest kernel available. All state is
//! wired under a throwaway `ISO_STATE_DIR`, with a throwaway VG, so the host's
//! real `iso` VG / state are untouched.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::Request;
use iso_common::VmId;
use iso_control_plane::{ControlPlane, TemplateDef};
use iso_controld::{http, settings};
use iso_firecracker::FirecrackerRuntime;
use iso_network_manager::Manager as NetManager;
use iso_storage_manager::command::SystemRunner;
use iso_storage_manager::Manager as StoreManager;
use tower::ServiceExt;

const STATE: &str = "/tmp/iso-e2e";
const VG: &str = "isoe2e";

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn pid_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn sh(args: &[&str]) -> bool {
    Command::new(args[0])
        .args(&args[1..])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn sh_out(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn find_kernel() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ISO_TEST_KERNEL") {
        return Some(p.into());
    }
    for e in std::fs::read_dir("/nix/store").ok()?.flatten() {
        if e.file_name().to_string_lossy().contains("firecracker-vmlinux") {
            let k = e.path().join("vmlinux");
            if k.exists() {
                return Some(k);
            }
        }
    }
    None
}

fn cleanup() {
    for n in 0..4u16 {
        let _ = sh(&["ip", "netns", "del", &format!("vm{n:04x}")]);
    }
    let _ = sh(&["vgremove", "-f", VG]);
    let image = format!("{STATE}/storage.img");
    for dev in sh_out(&["losetup", "-j", &image, "-O", "NAME", "--noheadings"]).lines() {
        let d = dev.trim();
        if !d.is_empty() {
            let _ = sh(&["losetup", "-d", d]);
        }
    }
    let _ = sh(&["ip", "link", "del", "dummy0"]);
    let _ = std::fs::remove_dir_all(STATE);
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn end_to_end_create_boot_destroy() {
    if !is_root() {
        eprintln!("skipping end_to_end: requires root (LVM + netns + KVM)");
        return;
    }
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping end_to_end: no firecracker vmlinux");
        return;
    };

    // wire all state under a throwaway dir + throwaway VG.
    unsafe {
        std::env::set_var("ISO_STATE_DIR", STATE);
        std::env::set_var("ISO_VG", VG);
        std::env::set_var("ISO_IMAGE_SIZE_GIB", "4");
    }
    cleanup(); // pre-clean any prior run

    let s = settings::from_env();
    let fc_state = s.firecracker.state_dir.clone();
    // a second storage handle for out-of-band template setup (cp owns the other)
    let setup = StoreManager::new(s.storage.clone(), Arc::new(SystemRunner));

    let cp = Arc::new(
        ControlPlane::new(
            s.control,
            NetManager::new(s.network),
            StoreManager::new(s.storage, Arc::new(SystemRunner)),
            FirecrackerRuntime::new(s.firecracker),
        )
        .expect("control plane"),
    );

    // start the host (storage backing pool + services dummy + sysctls)
    cp.start().await.expect("start host");

    // bake-substitute: create a template rootfs LV and put a filesystem on it.
    setup.create_template("base", "256M").await.expect("template lv");
    assert!(
        sh(&["mkfs.ext4", "-F", "-q", &format!("/dev/{VG}/tpl_base")]),
        "mkfs template rootfs"
    );

    cp.register_template(&TemplateDef {
        name: "e2e".into(),
        rootfs_template: "base".into(),
        snapshot: None, // fresh boot
        vcpus: 1,
        mem_mib: 128,
        kernel,
        boot_args: "console=ttyS0 reboot=k pci=off root=/dev/vda rw".into(),
    })
    .expect("register template");

    let app = http::router(cp.clone());

    // --- create a VM through the HTTP API (provisions storage, network, boots FC) ---
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vms")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"template":"e2e","egress":"deny"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create_vm should boot the microVM");
    let id = body_json(resp).await["id"].as_str().unwrap().to_string();
    let vmid = VmId::parse(&id).unwrap();

    tokio::time::sleep(Duration::from_millis(700)).await;

    // --- verify observable real state ---
    let list = body_json(
        app.clone()
            .oneshot(Request::builder().uri("/vms").body(Body::empty()).unwrap())
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(list[0]["state"], "running");
    let slot = list[0]["slot"].as_u64().unwrap() as u16;
    let netns = format!("vm{slot:04x}");

    // firecracker process is alive
    let pid: i32 = std::fs::read_to_string(fc_state.join(format!("{id}.pid")))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(pid_alive(pid), "firecracker process should be running");

    // netns and the COW rootfs LV exist
    assert!(sh(&["ip", "netns", "exec", &netns, "true"]), "netns exists");
    let lv = setup.volume_lv(vmid);
    assert!(sh(&["lvs", &format!("{VG}/{lv}")]), "rootfs snapshot LV exists");

    // --- destroy through the HTTP API ---
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/vms/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- verify teardown ---
    assert!(!pid_alive(pid), "firecracker should be gone");
    assert!(!sh(&["ip", "netns", "exec", &netns, "true"]), "netns removed");
    assert!(!sh(&["lvs", &format!("{VG}/{lv}")]), "rootfs LV removed");
    assert!(
        body_json(
            app.oneshot(Request::builder().uri("/vms").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await
        .as_array()
        .unwrap()
        .is_empty(),
        "registry empty after destroy"
    );

    cleanup();
}
