use crate::model::{Phase, Session, now};
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{path::Path, sync::Mutex};

/// The interrupt reasons the master's own lifecycle writes — an unclean
/// restart and a graceful stop. Auto-recovery keys on these to separate
/// master fallout from real failures, which stay manual.
pub const RESTART_INTERRUPT: &str = "Master restarted during a live session. Recover will reboot the workspace without replaying prompts.";
pub const SHUTDOWN_INTERRUPT: &str =
    "Master stopped. Recover to resume; no prompts will be replayed.";

pub struct Store(Mutex<Connection>);
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL REFERENCES sessions(id), data TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS events_cursor ON events(session,seq);
          CREATE TABLE IF NOT EXISTS mailbox(id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, recipient TEXT NOT NULL REFERENCES sessions(id), message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending');
          CREATE INDEX IF NOT EXISTS mailbox_pending ON mailbox(recipient,status,id);
          CREATE TABLE IF NOT EXISTS board(id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, path TEXT NOT NULL, author TEXT NOT NULL, updated_by TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(scope,path));
          CREATE TABLE IF NOT EXISTS swarm_policy(scope TEXT PRIMARY KEY, acl TEXT NOT NULL, updated_at INTEGER NOT NULL);")?;
        let has_delivery: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('mailbox') WHERE name='delivery')",
            [],
            |r| r.get(0),
        )?;
        if !has_delivery {
            db.execute("ALTER TABLE mailbox ADD COLUMN delivery TEXT", [])?;
        }
        // Recover provenance for old UI events only when the durable mailbox
        // and tree confirm it; never classify arbitrary text by its prefix alone.
        db.execute_batch("UPDATE events SET data=json_object(
          'type','swarm_message','text',m.message,
          'source',json_object('id',m.sender,'name',json_extract(src.data,'$.name'),
            'role',json_extract(src.data,'$.swarm.role'),
            'relationship',CASE WHEN json_extract(dst.data,'$.swarm.parent')=m.sender THEN 'parent' ELSE 'child' END))
          FROM mailbox m JOIN sessions src ON src.id=m.sender JOIN sessions dst ON dst.id=m.recipient
          WHERE events.session=m.recipient
            AND json_extract(events.data,'$.type')='message'
            AND json_extract(events.data,'$.role')='user'
            AND json_extract(events.data,'$.text')='Message from your swarm relative ' || m.sender || ':' || char(10) || m.message
            AND json_extract(src.data,'$.swarm.root')=json_extract(dst.data,'$.swarm.root')
            AND (json_extract(dst.data,'$.swarm.parent')=m.sender OR json_extract(src.data,'$.swarm.parent')=m.recipient);")?;
        Ok(Self(Mutex::new(db)))
    }
    pub fn insert(&self, session: &Session) -> Result<()> {
        let mut db = self.0.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "INSERT INTO sessions VALUES (?,?)",
            params![session.id, serde_json::to_string(session)?],
        )?;
        if let Some(swarm) = &session.swarm
            && let Some(parent) = &swarm.parent
        {
            tx.execute(
                "INSERT INTO mailbox(sender,recipient,message) VALUES (?,?,?)",
                params![parent, session.id, swarm.task],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn get(&self, id: &str) -> Result<Session> {
        let raw: String = self
            .0
            .lock()
            .unwrap()
            .query_row("SELECT data FROM sessions WHERE id=?", [id], |r| r.get(0))
            .context("Session not found")?;
        Ok(serde_json::from_str(&raw)?)
    }
    pub fn list(&self) -> Result<Vec<Session>> {
        let db = self.0.lock().unwrap();
        let mut q = db.prepare("SELECT data FROM sessions ORDER BY rowid DESC")?;
        let rows = q.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn update(&self, id: &str, f: impl FnOnce(&mut Session) -> Result<()>) -> Result<Session> {
        let db = self.0.lock().unwrap();
        let raw: String =
            db.query_row("SELECT data FROM sessions WHERE id=?", [id], |r| r.get(0))?;
        let mut session: Session = serde_json::from_str(&raw)?;
        let old = session.phase;
        f(&mut session)?;
        old.check(session.phase)?;
        db.execute(
            "UPDATE sessions SET data=? WHERE id=?",
            params![serde_json::to_string(&session)?, id],
        )?;
        if old != session.phase
            && let Some(phase) = serde_json::to_value(session.phase)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
        {
            crate::metrics::Metrics::global()
                .transitions
                .with_label_values(&[&session.name, &phase])
                .inc();
        }
        Ok(session)
    }
    pub fn phase(&self, id: &str, next: Phase) -> Result<Session> {
        self.update(id, |s| {
            s.phase = next;
            s.last_active = now();
            s.error = None;
            Ok(())
        })
    }
    pub fn interrupt(&self, id: &str, error: &str) {
        let _ = self.update(id, |s| {
            if !matches!(
                s.phase,
                Phase::Closed | Phase::Closing | Phase::AllocationUnknown
            ) {
                s.phase = Phase::Interrupted;
                s.error = Some(error.into());
            }
            Ok(())
        });
        let _ = self.event(id, json!({"type":"notice","text":error}));
    }
    pub fn recover(&self) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE mailbox SET status='uncertain' WHERE status='dispatching'",
            [],
        )?;
        for s in self.list()? {
            if s.phase == Phase::Allocating {
                self.phase(&s.id, Phase::AllocationUnknown)?;
            } else if !matches!(
                s.phase,
                Phase::Closed
                    | Phase::Asleep
                    | Phase::Stopped
                    | Phase::AllocationUnknown
                    | Phase::Interrupted
            ) {
                self.interrupt(&s.id, RESTART_INTERRUPT);
            }
        }
        Ok(())
    }
    pub fn event(&self, id: &str, mut data: Value) -> Result<()> {
        if serde_json::to_vec(&data)?.len() > 262144 {
            data = json!({"type":"notice","text":"Large event omitted; full history is retained in pi's session file."});
        }
        self.0.lock().unwrap().execute(
            "INSERT INTO events(session,data) VALUES (?,?)",
            params![id, serde_json::to_string(&data)?],
        )?;
        Ok(())
    }
    pub fn events(&self, id: &str, after: u64) -> Result<Vec<Value>> {
        let db = self.0.lock().unwrap();
        let mut q = db.prepare(
            "SELECT seq,data FROM events WHERE session=? AND seq>? ORDER BY seq LIMIT 500",
        )?;
        let rows = q.query_map(params![id, after], |r| {
            Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|r| {
            let (seq, raw) = r?;
            let mut v: Value = serde_json::from_str(&raw)?;
            v["seq"] = json!(seq);
            Ok(v)
        })
        .collect()
    }
    pub fn pi_event(&self, id: &str, event: Value) {
        let kind = event["type"].as_str().unwrap_or("");
        let display = match kind {
            "agent_settled" => {
                let _ = self.update(id, |s| {
                    if s.phase == Phase::Working {
                        s.phase = Phase::Idle;
                        s.last_active = now();
                    }
                    Ok(())
                });
                None
            }
            "message_start" if event["message"]["role"] == "assistant" => {
                Some(json!({"type":"assistant_start"}))
            }
            "message_update" if event["assistantMessageEvent"]["type"] == "text_delta" => {
                Some(json!({"type":"delta","text":event["assistantMessageEvent"]["delta"]}))
            }
            "message_end" => {
                let m = &event["message"];
                if !matches!(m["role"].as_str(), Some("user" | "assistant")) {
                    return;
                }
                let text = m["content"].as_str().map(str::to_owned).unwrap_or_else(|| {
                    m["content"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter(|c| c["type"] == "text")
                                .filter_map(|c| c["text"].as_str())
                                .collect::<Vec<_>>()
                                .join("\n")
                        })
                        .unwrap_or_default()
                });
                if m["role"] == "user" && self.record_swarm_event(id, &text).unwrap_or(false) {
                    return;
                }
                Some(
                    json!({"type":"message","role":m["role"],"text":text,"error":m["errorMessage"]}),
                )
            }
            "tool_execution_start" => {
                if let Some(call) = event["toolCallId"].as_str() {
                    crate::metrics::Metrics::global()
                        .tool_start(call, event["toolName"].as_str().unwrap_or("unknown"));
                }
                Some(
                    json!({"type":"tool_start","id":event["toolCallId"],"name":event["toolName"],"args":event["args"]}),
                )
            }
            "tool_execution_end" => {
                if let (Some(call), Ok(session)) = (event["toolCallId"].as_str(), self.get(id)) {
                    let swarm = self.swarm_name(&session);
                    crate::metrics::Metrics::global().tool_end(
                        call,
                        &session,
                        &swarm,
                        event["isError"].as_bool().unwrap_or(false),
                    );
                }
                Some(
                    json!({"type":"tool_end","id":event["toolCallId"],"name":event["toolName"],"result":event["result"],"isError":event["isError"]}),
                )
            }
            _ => None,
        };
        if let Some(data) = display {
            let _ = self.event(id, data);
        }
    }
    pub fn enqueue(&self, sender: &str, recipient: &str, message: &str) -> Result<i64> {
        let db = self.0.lock().unwrap();
        let pending: i64 = db.query_row(
            "SELECT count(*) FROM mailbox WHERE recipient=? AND status='pending'",
            [recipient],
            |r| r.get(0),
        )?;
        anyhow::ensure!(pending < 100, "Recipient mailbox is full");
        db.execute(
            "INSERT INTO mailbox(sender,recipient,message) VALUES (?,?,?)",
            params![sender, recipient, message],
        )?;
        Ok(db.last_insert_rowid())
    }
    pub fn stage_delivery(&self, id: i64, prompt: &str, event: &Value) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE mailbox SET delivery=? WHERE id=?",
            params![
                serde_json::to_string(&json!({"prompt":prompt,"event":event}))?,
                id
            ],
        )?;
        Ok(())
    }
    pub fn operator_queue(&self, recipient: &str) -> Result<Vec<Value>> {
        let db = self.0.lock().unwrap();
        let mut query = db.prepare("SELECT id,message,status FROM mailbox WHERE recipient=? AND sender='operator' AND status IN ('pending','dispatching','uncertain') ORDER BY id")?;
        let rows = query.query_map([recipient], |row| Ok(json!({"id":row.get::<_,i64>(0)?,"message":row.get::<_,String>(1)?,"status":row.get::<_,String>(2)?})))?;
        rows.map(|row| Ok(row?)).collect()
    }
    pub fn has_pending_message(&self, recipient: &str) -> Result<bool> {
        Ok(self.0.lock().unwrap().query_row(
            "SELECT EXISTS(SELECT 1 FROM mailbox WHERE recipient=? AND status='pending')",
            [recipient],
            |row| row.get(0),
        )?)
    }
    pub fn cancel_operator_message(&self, recipient: &str, id: i64) -> Result<()> {
        let changed = self.0.lock().unwrap().execute("UPDATE mailbox SET status='cancelled' WHERE id=? AND recipient=? AND sender='operator' AND status='pending'", params![id,recipient])?;
        anyhow::ensure!(
            changed == 1,
            "Message is no longer pending or does not belong to this agent"
        );
        Ok(())
    }
    fn record_swarm_event(&self, recipient: &str, prompt: &str) -> Result<bool> {
        use rusqlite::OptionalExtension;
        let mut db = self.0.lock().unwrap();
        let tx = db.transaction()?;
        let row: Option<(i64,String)> = tx.query_row("SELECT id,delivery FROM mailbox WHERE recipient=? AND delivery IS NOT NULL AND json_extract(delivery,'$.prompt')=? ORDER BY id LIMIT 1", params![recipient,prompt], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((id, data)) = row else {
            return Ok(false);
        };
        let data: Value = serde_json::from_str(&data)?;
        tx.execute(
            "INSERT INTO events(session,data) VALUES (?,?)",
            params![recipient, serde_json::to_string(&data["event"])?],
        )?;
        tx.execute("UPDATE mailbox SET delivery=NULL WHERE id=?", [id])?;
        tx.commit()?;
        Ok(true)
    }
    pub fn mailbox(&self, id: &str) -> Result<Vec<Value>> {
        let db = self.0.lock().unwrap();
        let mut q = db.prepare("SELECT id,sender,recipient,message,status FROM mailbox WHERE sender=? OR recipient=? ORDER BY id DESC LIMIT 100")?;
        let rows = q.query_map(params![id,id], |r| Ok(json!({"id":r.get::<_,i64>(0)?,"sender":r.get::<_,String>(1)?,"recipient":r.get::<_,String>(2)?,"message":r.get::<_,String>(3)?,"status":r.get::<_,String>(4)?})))?;
        rows.map(|r| Ok(r?)).collect()
    }
    pub fn claim_message(&self, id: &str) -> Result<Option<(i64, String, String)>> {
        use rusqlite::OptionalExtension;
        let db = self.0.lock().unwrap();
        let row = db.query_row("SELECT id,sender,message FROM mailbox WHERE recipient=? AND status='pending' ORDER BY id LIMIT 1", [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((mid, _, _)) = &row {
            db.execute("UPDATE mailbox SET status='dispatching' WHERE id=?", [mid])?;
        }
        Ok(row)
    }
    pub fn message_status(&self, id: i64, status: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE mailbox SET status=? WHERE id=?",
            params![status, id],
        )?;
        Ok(())
    }
    /// Persist a swarm's (or standalone workspace's) egress ACL, keyed by the
    /// swarm root id. An empty ACL clears the row, reverting to plane defaults.
    pub fn set_swarm_policy(&self, scope: &str, acl: &crate::model::Acl) -> Result<()> {
        let db = self.0.lock().unwrap();
        if acl.is_empty() {
            db.execute("DELETE FROM swarm_policy WHERE scope=?", [scope])?;
        } else {
            db.execute(
                "INSERT INTO swarm_policy(scope,acl,updated_at) VALUES (?,?,?)
                 ON CONFLICT(scope) DO UPDATE SET acl=excluded.acl,updated_at=excluded.updated_at",
                params![scope, serde_json::to_string(acl)?, now()],
            )?;
        }
        Ok(())
    }
    pub fn get_swarm_policy(&self, scope: &str) -> Result<crate::model::Acl> {
        use rusqlite::OptionalExtension;
        let raw: Option<String> = self
            .0
            .lock()
            .unwrap()
            .query_row("SELECT acl FROM swarm_policy WHERE scope=?", [scope], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(match raw {
            Some(raw) => serde_json::from_str(&raw)?,
            None => crate::model::Acl::default(),
        })
    }
    /// The swarm a session belongs to, by its root's display name; empty for
    /// standalone sessions. Used as a metrics label.
    pub fn swarm_name(&self, session: &Session) -> String {
        session
            .swarm
            .as_ref()
            .and_then(|w| self.get(&w.root).ok())
            .map(|root| root.name)
            .unwrap_or_default()
    }
    /// Post count per board scope, for scrape-time gauges.
    pub fn board_counts(&self) -> Result<Vec<(String, i64)>> {
        let db = self.0.lock().unwrap();
        let mut q = db.prepare("SELECT scope,count(*) FROM board GROUP BY scope")?;
        let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.map(|r| Ok(r?)).collect()
    }
    /// Pending mailbox depth per recipient, for scrape-time gauges.
    pub fn mailbox_pending(&self) -> Result<Vec<(String, i64)>> {
        let db = self.0.lock().unwrap();
        let mut q = db.prepare(
            "SELECT recipient,count(*) FROM mailbox WHERE status='pending' GROUP BY recipient",
        )?;
        let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.map(|r| Ok(r?)).collect()
    }
    /// One shared message board per scope (a swarm root). Posts live at
    /// forward-slash paths, unique per scope, like files in a tree.
    pub fn board_create(&self, scope: &str, path: &str, author: &str, body: &str) -> Result<()> {
        let db = self.0.lock().unwrap();
        let count: i64 =
            db.query_row("SELECT count(*) FROM board WHERE scope=?", [scope], |r| {
                r.get(0)
            })?;
        anyhow::ensure!(count < 1000, "Board is full (1000 posts)");
        let t = now();
        let n = db.execute(
            "INSERT OR IGNORE INTO board(scope,path,author,updated_by,body,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
            params![scope, path, author, author, body, t, t],
        )?;
        anyhow::ensure!(
            n == 1,
            "A post already exists at this path; board_update replaces it"
        );
        Ok(())
    }
    pub fn board_update(&self, scope: &str, path: &str, editor: &str, body: &str) -> Result<()> {
        let n = self.0.lock().unwrap().execute(
            "UPDATE board SET body=?,updated_by=?,updated_at=? WHERE scope=? AND path=?",
            params![body, editor, now(), scope, path],
        )?;
        anyhow::ensure!(n == 1, "No post at this path");
        Ok(())
    }
    pub fn board_delete(&self, scope: &str, path: &str) -> Result<()> {
        let n = self.0.lock().unwrap().execute(
            "DELETE FROM board WHERE scope=? AND path=?",
            params![scope, path],
        )?;
        anyhow::ensure!(n == 1, "No post at this path");
        Ok(())
    }
    pub fn board_read(&self, scope: &str, path: &str) -> Result<Value> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT path,author,updated_by,body,created_at,updated_at FROM board WHERE scope=? AND path=?",
                params![scope, path],
                |r| {
                    Ok(json!({"path":r.get::<_,String>(0)?,"author":r.get::<_,String>(1)?,
                        "updated_by":r.get::<_,String>(2)?,"body":r.get::<_,String>(3)?,
                        "created_at":r.get::<_,u64>(4)?,"updated_at":r.get::<_,u64>(5)?}))
                },
            )
            .context("No post at this path")
    }
    /// Post metadata under a prefix directory ("" for the whole board),
    /// ordered by path so the tree folds deterministically. Bodies stay out;
    /// they are read one post at a time.
    pub fn board_list(&self, scope: &str, prefix: &str) -> Result<Vec<Value>> {
        let db = self.0.lock().unwrap();
        let mut q = db.prepare(
            "SELECT path,author,updated_by,length(body),created_at,updated_at FROM board
             WHERE scope=?1 AND (?2='' OR path=?2 OR substr(path,1,length(?2)+1)=?2||'/')
             ORDER BY path",
        )?;
        let rows = q.query_map(params![scope, prefix], |r| {
            Ok(
                json!({"path":r.get::<_,String>(0)?,"author":r.get::<_,String>(1)?,
                "updated_by":r.get::<_,String>(2)?,"bytes":r.get::<_,u64>(3)?,
                "created_at":r.get::<_,u64>(4)?,"updated_at":r.get::<_,u64>(5)?}),
            )
        })?;
        rows.map(|r| Ok(r?)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_swarm_events_require_matching_mailbox_and_tree() {
        use crate::model::{Role, Swarm};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let store = Store::open(&path).unwrap();
        for (id, parent) in [("root", None), ("child", Some("root"))] {
            store
                .insert(&Session {
                    id: id.into(),
                    name: id.into(),
                    plane: "east".into(),
                    vm: None,
                    phase: Phase::Idle,
                    created_at: now(),
                    last_active: now(),
                    error: None,
                    model: None,
                    swarm: Some(Swarm {
                        root: "root".into(),
                        parent: parent.map(str::to_owned),
                        role: if parent.is_some() {
                            Role::Worker
                        } else {
                            Role::Planner
                        },
                        depth: usize::from(parent.is_some()),
                        planner_model: "test/planner".into(),
                        worker_model: "test/worker".into(),
                        task: "Inspect".into(),
                    }),
                })
                .unwrap();
        }
        store.event("child", json!({"type":"message","role":"user","text":"Message from your swarm relative root:\nInspect"})).unwrap();
        store.event("child", json!({"type":"message","role":"user","text":"Message from your swarm relative root:\nUnverified text"})).unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        let events = store.events("child", 0).unwrap();
        assert_eq!(events[0]["type"], "swarm_message");
        assert_eq!(events[0]["source"]["relationship"], "parent");
        assert_eq!(events[0]["source"]["name"], "root");
        assert_eq!(events[0]["text"], "Inspect");
        assert_eq!(events[1]["type"], "message");
    }
    #[test]
    fn board_crud_and_prefix_listing() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        store
            .board_create("root", "design/auth/jwt", "a", "use RS256")
            .unwrap();
        store
            .board_create("root", "design/api", "a", "REST")
            .unwrap();
        store
            .board_create("root", "status/aster", "b", "done")
            .unwrap();
        store
            .board_create("other", "design/auth", "c", "isolated")
            .unwrap();
        // Create is create-only; the same path again is refused.
        assert!(store.board_create("root", "design/api", "b", "x").is_err());
        // A prefix folds on whole segments: "design/a" matches nothing.
        assert_eq!(store.board_list("root", "design").unwrap().len(), 2);
        assert_eq!(store.board_list("root", "design/a").unwrap().len(), 0);
        assert_eq!(store.board_list("root", "").unwrap().len(), 3);
        // Scopes are separate boards.
        assert_eq!(store.board_list("other", "").unwrap().len(), 1);
        store
            .board_update("root", "design/api", "b", "GraphQL")
            .unwrap();
        let post = store.board_read("root", "design/api").unwrap();
        assert_eq!(post["body"], "GraphQL");
        assert_eq!(post["author"], "a");
        assert_eq!(post["updated_by"], "b");
        assert!(store.board_update("root", "missing", "b", "x").is_err());
        store.board_delete("root", "design/api").unwrap();
        assert!(store.board_read("root", "design/api").is_err());
        assert!(store.board_delete("root", "design/api").is_err());
    }
    #[test]
    fn recovery_preserves_sleep_and_never_replays() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        for (id, phase) in [
            ("a", Phase::Allocating),
            ("b", Phase::Working),
            ("c", Phase::Asleep),
        ] {
            store
                .insert(&Session {
                    id: id.into(),
                    name: id.into(),
                    plane: "east".into(),
                    vm: None,
                    phase,
                    created_at: now(),
                    last_active: now(),
                    error: None,
                    model: None,
                    swarm: None,
                })
                .unwrap();
        }
        store.recover().unwrap();
        assert_eq!(store.get("a").unwrap().phase, Phase::AllocationUnknown);
        assert_eq!(store.get("b").unwrap().phase, Phase::Interrupted);
        assert_eq!(store.get("c").unwrap().phase, Phase::Asleep);
        store
            .event("c", json!({"type":"notice","text":"hello\u{2028}world"}))
            .unwrap();
        let rows = store.events("c", 0).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            store
                .events("c", rows[0]["seq"].as_u64().unwrap())
                .unwrap()
                .is_empty()
        );
    }
}
