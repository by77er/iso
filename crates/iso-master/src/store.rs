use crate::model::{Phase, Session, now};
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{path::Path, sync::Mutex};

pub struct Store(Mutex<Connection>);
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL REFERENCES sessions(id), data TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS events_cursor ON events(session,seq);")?;
        Ok(Self(Mutex::new(db)))
    }
    pub fn insert(&self, session: &Session) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO sessions VALUES (?,?)",
            params![session.id, serde_json::to_string(session)?],
        )?;
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
            if s.phase != Phase::Closed && s.phase != Phase::AllocationUnknown {
                s.phase = Phase::Interrupted;
                s.error = Some(error.into());
            }
            Ok(())
        });
        let _ = self.event(id, json!({"type":"notice","text":error}));
    }
    pub fn recover(&self) -> Result<()> {
        for s in self.list()? {
            if s.phase == Phase::Allocating {
                self.phase(&s.id, Phase::AllocationUnknown)?;
            } else if !matches!(
                s.phase,
                Phase::Closed | Phase::Asleep | Phase::AllocationUnknown | Phase::Interrupted
            ) {
                self.interrupt(&s.id,"Master restarted during a live session. Recover will reboot the workspace without replaying prompts.");
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
                Some(
                    json!({"type":"message","role":m["role"],"text":text,"error":m["errorMessage"]}),
                )
            }
            "tool_execution_start" => Some(
                json!({"type":"tool_start","id":event["toolCallId"],"name":event["toolName"],"args":event["args"]}),
            ),
            "tool_execution_end" => Some(
                json!({"type":"tool_end","id":event["toolCallId"],"name":event["toolName"],"result":event["result"],"isError":event["isError"]}),
            ),
            _ => None,
        };
        if let Some(data) = display {
            let _ = self.event(id, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
