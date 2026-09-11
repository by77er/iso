use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Allocating,
    AllocationUnknown,
    Starting,
    Idle,
    Working,
    Sleeping,
    Asleep,
    Waking,
    Interrupted,
    Closing,
    Closed,
}

impl Phase {
    pub fn check(self, next: Self) -> Result<()> {
        use Phase::*;
        let valid = self == next
            || matches!(
                (self, next),
                (Allocating, Starting | AllocationUnknown | Interrupted)
                    | (AllocationUnknown, Interrupted | Closed)
                    | (Starting, Idle | Interrupted)
                    | (Idle, Working | Sleeping | Interrupted | Closing)
                    | (Working, Idle | Interrupted | Closing)
                    | (Sleeping, Asleep | Interrupted)
                    | (Asleep, Waking | Closing | Interrupted)
                    | (Waking, Idle | Interrupted)
                    | (Interrupted, Starting | Closing)
                    | (Closing, Closed | Interrupted)
            );
        if !valid {
            bail!("Invalid transition: {self:?} -> {next:?}");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub plane: String,
    pub vm: Option<String>,
    pub phase: Phase,
    pub created_at: u64,
    pub last_active: u64,
    pub error: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub swarm: Option<Swarm>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Planner,
    Worker,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Swarm {
    pub root: String,
    pub parent: Option<String>,
    pub role: Role,
    pub depth: usize,
    pub planner_model: String,
    pub worker_model: String,
    pub task: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CreateOptions {
    pub model: Option<String>,
    pub swarm: bool,
    pub planner_model: Option<String>,
    pub worker_model: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normal_cycle_and_recovery() {
        use Phase::*;
        for path in [
            vec![
                Allocating, Starting, Idle, Working, Idle, Sleeping, Asleep, Waking, Idle, Closing,
                Closed,
            ],
            vec![Working, Interrupted, Starting, Idle],
            vec![Allocating, AllocationUnknown, Interrupted],
        ] {
            for pair in path.windows(2) {
                pair[0].check(pair[1]).unwrap();
            }
        }
        assert!(Closed.check(Working).is_err());
        assert!(Working.check(Sleeping).is_err());
        assert!(AllocationUnknown.check(Starting).is_err());
        assert!(Asleep.check(Working).is_err());
    }
}
