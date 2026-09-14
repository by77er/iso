//! The fleet against real hosts: two `iso-controld` admin APIs over the mock
//! managers (no root, no KVM), each on its own loopback port behind a gate
//! the test can close to take the host "down". The fleet runs in-process on
//! plain HTTP with an in-memory database. The guest agent behind `exec` is
//! the real one, on a socketpair.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iso_fleet::{Config, Fleet, HostConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A host's admin API on a port, reachable only while the gate is open.
struct Host {
    addr: SocketAddr,
    open: Arc<AtomicBool>,
    /// Live forwarders, so "down" also severs kept-alive connections the
    /// fleet's client would otherwise keep using.
    conns: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl Host {
    async fn start(templates: &[&str]) -> Host {
        let app = iso_controld::testing::app_with_templates(templates);
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inner_addr = inner.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(inner, app).await });

        let gate = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = gate.local_addr().unwrap();
        let open = Arc::new(AtomicBool::new(true));
        let conns: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let flag = open.clone();
        let live = conns.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = gate.accept().await else {
                    break;
                };
                if !flag.load(Ordering::Relaxed) {
                    drop(client);
                    continue;
                }
                let task = tokio::spawn(async move {
                    let Ok(mut upstream) = TcpStream::connect(inner_addr).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
                live.lock().unwrap().push(task.abort_handle());
            }
        });
        Host { addr, open, conns }
    }
    fn down(&self) {
        self.open.store(false, Ordering::Relaxed);
        for h in self.conns.lock().unwrap().drain(..) {
            h.abort();
        }
    }
    fn up(&self) {
        self.open.store(true, Ordering::Relaxed);
    }
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
    /// Talk to the host directly, behind the fleet's back.
    async fn direct(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nhost: h\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
            payload.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).to_string();
        let status: u16 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        (status, serde_json::from_str(body).unwrap_or(Value::Null))
    }
}

struct Rig {
    fleet: Arc<Fleet>,
    url: String,
    http: reqwest::Client,
    a: Host,
    b: Host,
}

impl Rig {
    async fn start() -> Rig {
        Self::start_with_ttl(86_400).await
    }
    /// `ttl` is how long the fleet's policy signatures live.
    async fn start_with_ttl(ttl: u64) -> Rig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let _ = tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_test_writer()
            .try_init();
        let a = Host::start(&["base"]).await;
        let b = Host::start(&["base", "debian"]).await;
        let mut cfg = Config::dev(vec![
            HostConfig {
                name: "a".into(),
                url: a.url(),
            },
            HostConfig {
                name: "b".into(),
                url: b.url(),
            },
        ]);
        cfg.policy_ttl_secs = ttl;
        let fleet = Fleet::new(cfg).unwrap();
        iso_fleet::sync::sync_once(&fleet).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, iso_fleet::router(fleet.clone())).into_future());
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        Rig {
            fleet,
            url,
            http,
            a,
            b,
        }
    }
    async fn sync(&self) {
        iso_fleet::sync::sync_once(&self.fleet).await;
    }
    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let r = self
            .http
            .post(format!("{}{path}", self.url))
            .json(&body)
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
    }
    async fn get(&self, path: &str) -> (u16, Value) {
        let r = self
            .http
            .get(format!("{}{path}", self.url))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
    }
    async fn delete(&self, path: &str) -> (u16, Value) {
        let r = self
            .http
            .delete(format!("{}{path}", self.url))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
    }
    async fn patch(&self, path: &str, body: Value) -> (u16, Value) {
        let r = self
            .http
            .patch(format!("{}{path}", self.url))
            .json(&body)
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
    }
    async fn create(&self, template: &str) -> (String, String) {
        let (s, v) = self
            .post("/vms", json!({ "template": template, "egress": "deny" }))
            .await;
        assert_eq!(s, 200, "create: {v}");
        (
            v["id"].as_str().unwrap().to_string(),
            v["host"].as_str().unwrap().to_string(),
        )
    }
    async fn host_of(&self, id: &str) -> Value {
        self.get(&format!("/vms/{id}")).await.1
    }
}

#[tokio::test]
async fn places_where_the_template_is_and_routes_by_id() {
    let r = Rig::start().await;
    let (id, host) = r.create("debian").await;
    assert_eq!(host, "b", "only b has debian");
    let v = r.host_of(&id).await;
    assert_eq!(v["host"], "b");
    assert_eq!(v["fleet_state"], "placed");
    assert_eq!(v["template"], "debian");

    // exec goes to the right host and runs through the real guest agent.
    let (s, out) = r
        .post(
            &format!("/vms/{id}/exec"),
            json!({ "cmd": "echo", "args": ["through the fleet"] }),
        )
        .await;
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["stdout"], "through the fleet\n");
    assert_eq!(out["exit_code"], 0);

    // and a query string survives forwarding.
    let (s, out) = r.get(&format!("/vms/{id}/dir?path=/")).await;
    assert_eq!(s, 200, "{out}");
    assert!(
        out["entries"]
            .as_array()
            .map(|e| !e.is_empty())
            .unwrap_or(false),
        "{out}"
    );

    let (s, v) = r.get("/vms/00000000-0000-0000-0000-000000000000").await;
    assert_eq!(s, 404, "{v}");
    let (s, v) = r.post("/vms", json!({ "template": "nope" })).await;
    assert_eq!(s, 404, "{v}");
}

#[tokio::test]
async fn spreads_by_load_and_lets_the_host_enforce_capacity() {
    let r = Rig::start().await;
    let mut on_a = 0;
    let mut on_b = 0;
    // The mock hosts have 8 slots each: 16 fit, the 17th does not.
    for _ in 0..16 {
        let (_, host) = r.create("base").await;
        if host == "a" { on_a += 1 } else { on_b += 1 }
    }
    assert_eq!((on_a, on_b), (8, 8), "least loaded first keeps them level");
    let (s, v) = r.post("/vms", json!({ "template": "base" })).await;
    assert_eq!(s, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("free slot"), "{v}");
    let (_, stats) = r.get("/stats").await;
    assert_eq!(stats["vms"], 16);
    assert_eq!(stats["slots_free"], 0);
    // A pinned placement on a full host is refused by that host, not moved.
    r.sync().await;
    let (s, v) = r
        .post("/vms", json!({ "template": "base", "host": "a" }))
        .await;
    assert_eq!(s, 409, "{v}");
    let (_, list) = r.get("/vms").await;
    assert_eq!(
        list.as_array().unwrap().len(),
        16,
        "no record for a create that failed everywhere"
    );
}

#[tokio::test]
async fn pinning_and_policy_forwarding() {
    let r = Rig::start().await;
    let (s, v) = r.post("/vms", json!({ "template": "base", "host": "b", "principal": "alice", "rules": ["allow https://api.github.com/**"] })).await;
    assert_eq!(s, 200, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["host"], "b");

    let (s, v) = r
        .patch(
            &format!("/vms/{id}/policy"),
            json!({ "rules": ["nonsense"] }),
        )
        .await;
    assert_eq!(
        s, 400,
        "a bad rule is refused by the host and passed through: {v}"
    );
    let (s, _) = r
        .patch(
            &format!("/vms/{id}/policy"),
            json!({ "rules": ["deny https://api.github.com/user/keys"], "principal": "bob" }),
        )
        .await;
    assert_eq!(s, 204);
    let v = r.host_of(&id).await;
    assert_eq!(v["principal"], "bob");
    assert_eq!(v["policy_gen"], 2);
    assert_eq!(v["rules"], json!(["deny https://api.github.com/user/keys"]));

    // A create the host rejects outright leaves no record behind.
    let (s, v) = r
        .post("/vms", json!({ "template": "base", "rules": ["bogus"] }))
        .await;
    assert_eq!(s, 400, "{v}");
    let (_, list) = r.get("/vms").await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn delete_removes_from_host_and_fleet() {
    let r = Rig::start().await;
    let (id, host) = r.create("base").await;
    let (s, _) = r.delete(&format!("/vms/{id}")).await;
    assert_eq!(s, 204);
    let (s, _) = r.get(&format!("/vms/{id}")).await;
    assert_eq!(s, 404);
    let h = if host == "a" { &r.a } else { &r.b };
    let (s, _) = h.direct("GET", &format!("/vms/{id}"), None).await;
    assert_eq!(s, 404, "gone from the host too");
}

#[tokio::test]
async fn sync_notices_orphans_and_lost_vms() {
    let r = Rig::start().await;
    let (id, host) = r.create("base").await;
    let h = if host == "a" { &r.a } else { &r.b };

    // Something creates a VM behind the fleet's back.
    let (s, v) = h
        .direct("POST", "/vms", Some(json!({ "template": "base" })))
        .await;
    assert_eq!(s, 200, "{v}");
    r.sync().await;
    let (_, hosts) = r.get("/hosts").await;
    let row = hosts
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == host)
        .unwrap();
    assert_eq!(row["orphans"], 1);
    assert_eq!(row["healthy"], true);

    // And something deletes the fleet's VM behind its back.
    let (s, _) = h.direct("DELETE", &format!("/vms/{id}"), None).await;
    assert_eq!(s, 204);
    r.sync().await;
    let v = r.host_of(&id).await;
    assert_eq!(v["fleet_state"], "lost", "{v}");
    let (s, v) = r
        .post(&format!("/vms/{id}/exec"), json!({ "cmd": "true" }))
        .await;
    assert_eq!(s, 409, "a lost vm is not forwarded to: {v}");
    let (s, _) = r.delete(&format!("/vms/{id}")).await;
    assert_eq!(s, 204, "the record can be cleared");
}

#[tokio::test]
async fn a_host_going_down_is_skipped_and_its_vms_come_back_with_it() {
    let r = Rig::start().await;
    let (id, _) = r.post("/vms", json!({ "template": "debian" })).await.1["id"]
        .as_str()
        .map(|s| (s.to_string(), ()))
        .unwrap();
    r.b.down();
    r.sync().await;
    let (_, hosts) = r.get("/hosts").await;
    let b = hosts
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "b")
        .unwrap();
    assert_eq!(b["healthy"], false);
    let v = r.host_of(&id).await;
    assert_eq!(v["fleet_state"], "unreachable", "{v}");
    assert_eq!(v["host"], "b", "the record is kept");
    let (s, v) = r
        .post(&format!("/vms/{id}/exec"), json!({ "cmd": "true" }))
        .await;
    assert_eq!(s, 409, "{v}");

    // Placement avoids the dead host, and a template only it has is unplaceable.
    let (_, host) = r.create("base").await;
    assert_eq!(host, "a");
    let (s, v) = r.post("/vms", json!({ "template": "debian" })).await;
    assert_eq!(s, 409, "{v}");

    // A delete while it is down is accepted and finished when it returns.
    let (s, v) = r.delete(&format!("/vms/{id}")).await;
    assert_eq!(s, 202, "{v}");
    assert_eq!(v["fleet_state"], "deleting");

    r.b.up();
    r.sync().await;
    let (_, hosts) = r.get("/hosts").await;
    let b = hosts
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "b")
        .unwrap();
    assert_eq!(b["healthy"], true);
    let (s, _) = r.get(&format!("/vms/{id}")).await;
    assert_eq!(s, 404, "the deferred delete completed");
    let (s, _) = r.b.direct("GET", &format!("/vms/{id}"), None).await;
    assert_eq!(s, 404);

    // And a VM that stayed on the host comes back as placed.
    let (id2, _) = r.create("debian").await;
    r.b.down();
    r.sync().await;
    assert_eq!(r.host_of(&id2).await["fleet_state"], "unreachable");
    r.b.up();
    r.sync().await;
    assert_eq!(r.host_of(&id2).await["fleet_state"], "placed");
}

#[tokio::test]
async fn a_create_that_never_lands_is_written_off_after_the_grace_period() {
    let r = Rig::start().await;
    // Simulate a lost reply: record a VM the host was never told about.
    r.fleet
        .store
        .insert_vm(
            "deadbeef-dead-beef-dead-beefdeadbeef",
            "a",
            "base",
            &json!({}),
            &json!({}),
        )
        .unwrap();
    r.sync().await;
    let v = r.host_of("deadbeef-dead-beef-dead-beefdeadbeef").await;
    assert_eq!(
        v["fleet_state"], "creating",
        "inside the grace period it is left alone"
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    r.sync().await;
    let v = r.host_of("deadbeef-dead-beef-dead-beefdeadbeef").await;
    assert_eq!(v["fleet_state"], "failed", "{v}");
    let (_, stats) = r.get("/stats").await;
    assert_eq!(stats["vms_by_state"]["failed"], 1);
}

#[tokio::test]
async fn the_api_is_the_host_api() {
    let r = Rig::start().await;
    let (s, doc) = r.get("/openapi.json").await;
    assert_eq!(s, 200);
    assert!(doc["paths"]["/vms/{id}/exec"].is_object());
    assert!(doc["paths"]["/vms/{id}/policy"].is_object());
}

#[tokio::test]
async fn the_generated_host_client_works_against_the_fleet_unchanged() {
    let r = Rig::start().await;
    let c = iso_client::Client::insecure(&r.url);
    let created = c
        .create()
        .body_map(|b| b.template("debian").egress(Some("deny".to_string())))
        .send()
        .await
        .unwrap()
        .into_inner();
    let id = created.id.clone();

    // Every read is host-shaped: the typed client deserializes it.
    let one = c.get_one().id(&id).send().await.unwrap().into_inner();
    assert_eq!(one.template, "debian");
    assert_eq!(one.egress, "deny");
    let list = c.list().send().await.unwrap().into_inner();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, id);
    let stats = c.stats().send().await.unwrap().into_inner();
    assert_eq!(stats.slots_total, 16);
    assert_eq!(stats.vms, 1);

    // And the forwarded calls too.
    let out = c
        .guest_exec()
        .id(&id)
        .body_map(|b| b.cmd("echo").args(vec!["typed".to_string()]))
        .send()
        .await
        .unwrap()
        .into_inner();
    assert_eq!(out.stdout, "typed\n");
    c.destroy().id(&id).send().await.unwrap();
    assert!(c.list().send().await.unwrap().into_inner().is_empty());

    // A record without a host view (its host is down) still has the shape.
    let (id2, _) = r.create("base").await;
    r.a.down();
    r.b.down();
    r.sync().await;
    let list = c.list().send().await.unwrap().into_inner();
    assert_eq!(list.iter().filter(|v| v.id == id2).count(), 1);
    let one = c.get_one().id(&id2).send().await.unwrap().into_inner();
    assert_eq!(one.template, "base");
}

/// Every policy the fleet places or changes is signed for the VM's host at
/// the generation the host stores it under; a client cannot supply its own
/// signature; and the sync loop re-signs an unchanged policy before the
/// signature expires without bumping the generation.
#[tokio::test]
async fn policies_are_signed_for_the_host_and_re_signed_before_they_expire() {
    use iso_common::identify::SignedPolicy;
    use iso_policy::signed::Verifier;
    let r = Rig::start_with_ttl(6).await;
    let verifier = Verifier::from_b64(&r.fleet.signer.public_key_b64()).unwrap();
    let signed_of = |v: &Value| -> SignedPolicy {
        serde_json::from_value(v["signed"].clone()).unwrap_or_else(|e| panic!("no signature on {v}: {e}"))
    };

    // "debian" is only on host b, so the signature must name b.
    let (s, v) = r
        .post("/vms", json!({ "template": "debian", "egress": "proxy", "principal": "alice", "allow": ["api.github.com"] }))
        .await;
    assert_eq!(s, 200, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    let v = r.host_of(&id).await;
    let c = verifier.verify(&signed_of(&v)).unwrap();
    assert_eq!((c.host.as_str(), c.vm.as_str(), c.policy_gen, c.egress.as_str()), ("b", id.as_str(), 1, "proxy"));
    assert_eq!(c.principal.as_deref(), Some("alice"));
    assert_eq!(
        c.rules,
        iso_policy::RuleSet::from_record(&["api.github.com".to_string()], &[]).unwrap().to_strings(),
        "the effective rule set, expanded the way the host serves it"
    );
    let first_expiry = c.expires;

    // A change is signed at the next generation, laid over the current policy.
    let (s, body) = r
        .patch(&format!("/vms/{id}/policy"), json!({ "rules": ["deny https://api.github.com/user/keys"] }))
        .await;
    assert_eq!(s, 204, "{body}");
    let v = r.host_of(&id).await;
    assert_eq!(v["policy_gen"], 2);
    let c = verifier.verify(&signed_of(&v)).unwrap();
    assert_eq!(c.policy_gen, 2);
    assert_eq!(c.principal.as_deref(), Some("alice"), "kept from the current policy");
    assert!(c.rules.contains(&"deny https://api.github.com/user/keys".to_string()), "{:?}", c.rules);

    // A signature a client sends is not the fleet's and is replaced.
    let (s, body) = r
        .patch(&format!("/vms/{id}/policy"), json!({ "principal": "bob", "signed": { "claims": "AAAA", "sig": "AAAA" } }))
        .await;
    assert_eq!(s, 204, "{body}");
    let v = r.host_of(&id).await;
    let c = verifier.verify(&signed_of(&v)).unwrap();
    assert_eq!((c.policy_gen, c.principal.as_deref()), (3, Some("bob")));

    // A signature with a third of its life left is renewed by the sync loop,
    // at the same generation.
    tokio::time::sleep(Duration::from_secs(4)).await;
    r.sync().await;
    let v = r.host_of(&id).await;
    assert_eq!(v["policy_gen"], 3, "a re-signing changes no policy");
    let c = verifier.verify(&signed_of(&v)).unwrap();
    assert!(c.expires > first_expiry + 3, "renewed: {} vs {first_expiry}", c.expires);
    assert_eq!((c.policy_gen, c.principal.as_deref()), (3, Some("bob")));

    // A change made on the host behind the fleet's back drops the signature,
    // and the fleet does not bless it on the next pass: only a change made
    // through the fleet is signed again.
    let (s, _) = r.b.direct("PATCH", &format!("/vms/{id}/policy"), Some(json!({ "principal": "eve" }))).await;
    assert_eq!(s, 204);
    r.sync().await;
    let v = r.host_of(&id).await;
    assert_eq!((v["policy_gen"].as_u64(), v["principal"].as_str()), (Some(4), Some("eve")));
    assert!(v.get("signed").is_none(), "not signed behind the fleet's back: {v}");
    let (s, _) = r.patch(&format!("/vms/{id}/policy"), json!({ "principal": "alice" })).await;
    assert_eq!(s, 204);
    let c = verifier.verify(&signed_of(&r.host_of(&id).await)).unwrap();
    assert_eq!((c.policy_gen, c.principal.as_deref()), (5, Some("alice")));
}
