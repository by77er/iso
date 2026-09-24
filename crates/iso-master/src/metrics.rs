//! Application metrics, served as Prometheus text on a separate loopback
//! listener (`metrics_bind`) so the authenticated web surface is untouched.
//!
//! Counters and histograms accumulate at the observation points (pi's event
//! stream sees every tool call; the worker endpoint sees every swarm and
//! board action). State — session phases, plane capacity, VM states, board
//! and mailbox depth — is computed fresh at scrape time, so a scrape is the
//! truth of that moment rather than a shadow of it. Label cardinality is
//! per-agent and per-tool by design: this is a single-operator master, and
//! splitting by swarm, agent, VM and tool is the point.

use crate::model::Session;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::Instant,
};

pub struct Metrics {
    registry: Registry,
    /// Every tool call an agent makes, by outcome.
    pub tool_calls: IntCounterVec, // tool, agent, swarm, role, error
    /// Wall-clock duration of tool calls, matched start→end by call id.
    pub tool_duration: HistogramVec, // tool, agent
    /// Swarm-socket actions: board_* CRUD, spawn, send, status.
    pub worker_actions: IntCounterVec, // action, agent, swarm, error
    /// Prompts entering a session, by origin.
    pub prompts: IntCounterVec, // agent, source
    /// pi worker lifecycle: starts, exits, readiness failures.
    pub workers: IntCounterVec, // event, agent
    /// Session phase transitions.
    pub transitions: IntCounterVec, // agent, phase
    inflight: Mutex<HashMap<String, (Instant, String)>>,
}

impl Metrics {
    pub fn global() -> &'static Metrics {
        static METRICS: OnceLock<Metrics> = OnceLock::new();
        METRICS.get_or_init(|| {
            let registry = Registry::new();
            let tool_calls = IntCounterVec::new(
                Opts::new("iso_master_tool_calls_total", "Tool calls by agent"),
                &["tool", "agent", "swarm", "role", "error"],
            )
            .unwrap();
            let tool_duration = HistogramVec::new(
                HistogramOpts::new(
                    "iso_master_tool_duration_seconds",
                    "Tool call wall-clock duration",
                )
                .buckets(vec![
                    0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0,
                ]),
                &["tool", "agent"],
            )
            .unwrap();
            let worker_actions = IntCounterVec::new(
                Opts::new(
                    "iso_master_worker_actions_total",
                    "Swarm-socket actions (board CRUD, spawn, send, status)",
                ),
                &["action", "agent", "swarm", "error"],
            )
            .unwrap();
            let prompts = IntCounterVec::new(
                Opts::new("iso_master_prompts_total", "Prompts by origin"),
                &["agent", "source"],
            )
            .unwrap();
            let workers = IntCounterVec::new(
                Opts::new("iso_master_pi_workers_total", "pi worker lifecycle events"),
                &["event", "agent"],
            )
            .unwrap();
            let transitions = IntCounterVec::new(
                Opts::new(
                    "iso_master_phase_transitions_total",
                    "Session phase transitions",
                ),
                &["agent", "phase"],
            )
            .unwrap();
            for collector in [
                &tool_calls,
                &worker_actions,
                &prompts,
                &workers,
                &transitions,
            ] {
                registry.register(Box::new(collector.clone())).unwrap();
            }
            registry.register(Box::new(tool_duration.clone())).unwrap();
            Metrics {
                registry,
                tool_calls,
                tool_duration,
                worker_actions,
                prompts,
                workers,
                transitions,
                inflight: Mutex::new(HashMap::new()),
            }
        })
    }
    /// Remember a tool call starting, so its end can carry a duration.
    pub fn tool_start(&self, call_id: &str, tool: &str) {
        let mut inflight = self.inflight.lock().unwrap();
        // A worker that dies mid-call leaves the entry behind; keep the map bounded.
        if inflight.len() > 4096 {
            inflight.clear();
        }
        inflight.insert(call_id.into(), (Instant::now(), tool.into()));
    }
    pub fn tool_end(&self, call_id: &str, session: &Session, swarm_name: &str, is_error: bool) {
        let Some((started, tool)) = self.inflight.lock().unwrap().remove(call_id) else {
            return;
        };
        let role = session
            .swarm
            .as_ref()
            .map_or("standalone", |s| match s.role {
                crate::model::Role::Planner => "planner",
                crate::model::Role::Worker => "worker",
            });
        self.tool_calls
            .with_label_values(&[
                tool.as_str(),
                session.name.as_str(),
                swarm_name,
                role,
                if is_error { "true" } else { "false" },
            ])
            .inc();
        self.tool_duration
            .with_label_values(&[tool.as_str(), session.name.as_str()])
            .observe(started.elapsed().as_secs_f64());
    }
    /// Accumulated counters in Prometheus text form; the caller appends the
    /// scrape-time state series.
    pub fn encode(&self) -> String {
        let mut out = Vec::new();
        let _ = TextEncoder::new().encode(&self.registry.gather(), &mut out);
        String::from_utf8(out).unwrap_or_default()
    }
}

/// Escape a label value per the Prometheus text exposition format.
pub fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
