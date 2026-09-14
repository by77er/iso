import React, { useState, useRef, useEffect } from "react";
import {
  LoaderCircle,
  Server,
  Trash2,
  Moon,
  RotateCcw,
  Square,
  ArrowUp,
} from "lucide-react";
import { api, type Session, type ModelCatalog } from "../api";
import ModelSelect from "./ModelSelect";
import SwarmPanel from "./SwarmPanel";
import { reduceEvents, type Item, type Event } from "../transcript";
import { Badge, ErrorBanner } from "./shared";
import Transcript from "./Transcript";

type QueuedMessage = {
  id: number;
  message: string;
  status: "pending" | "dispatching" | "uncertain";
};

export default function Chat({
  id,
  onUpdate,
  select,
  sessions,
}: {
  id: string;
  onUpdate: (s: Session) => void;
  select: (id: string) => void;
  sessions: Session[];
}) {
  const [session, setSession] = useState<Session | null>(null),
    [queued, setQueued] = useState<QueuedMessage[]>([]),
    [items, setItems] = useState<Item[]>([]),
    [error, setError] = useState(""),
    [text, setText] = useState(""),
    [busy, setBusy] = useState(false),
    [details, setDetails] = useState(false);
  const updateRef = useRef(onUpdate);
  const [models, setModels] = useState<string[]>([]);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  useEffect(() => {
    let stopped = false;
    api<ModelCatalog>("/models")
      .then((catalog) => {
        if (!stopped) setModels(catalog.models);
      })
      .catch(() => {});
    return () => {
      stopped = true;
    };
  }, []);
  updateRef.current = onUpdate;
  useEffect(() => {
    let stopped = false,
      cursor = 0;
    let timer: ReturnType<typeof setTimeout>;
    setSession(null);
    setHistoryLoaded(false);
    setItems([]);
    setQueued([]);
    setText("");
    setError("");
    setBusy(false);
    async function poll() {
      try {
        const r = await api<{
          session: Session;
          events: Event[];
          queued?: QueuedMessage[];
        }>(`/sessions/${id}/events?after=${cursor}`);
        if (stopped) return;
        setSession(r.session);
        setQueued(r.queued || []);
        updateRef.current(r.session);
        if (r.events.length) {
          cursor = r.events.at(-1)!.seq;
          setItems((old) => reduceEvents(old, r.events));
        }
        if (r.events.length < 500) setHistoryLoaded(true);
        timer = setTimeout(
          poll,
          r.events.length === 500
            ? 0
            : r.session.phase === "working"
              ? 150
              : 700,
        );
      } catch (e) {
        if (!stopped) {
          setError((e as Error).message);
          timer = setTimeout(poll, 3000);
        }
      }
    }
    void poll();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [id]);
  async function act(action: string) {
    setBusy(true);
    setError("");
    try {
      await api(`/sessions/${id}/actions/${action}`, "POST", {});
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function close() {
    const subtree = new Set([id]);
    for (let size = -1; size !== subtree.size;) {
      size = subtree.size;
      for (const node of sessions)
        if (node.swarm?.parent && subtree.has(node.swarm.parent))
          subtree.add(node.id);
    }
    const names = sessions
      .filter((node) => subtree.has(node.id) && node.phase !== "closed")
      .map((node) => node.name);
    if (
      !confirm(
        session?.swarm?.role === "planner"
          ? `Close this planner and EVERY descendant, and permanently delete all their VM disks and snapshots? This includes any descendants not yet shown in the sidebar. Conversations remain readable.\n\nCurrently listed: ${names.join(", ")}`
          : "Close this agent and permanently delete its workspace? The conversation will remain readable.",
      )
    )
      return;
    setBusy(true);
    try {
      await api(`/sessions/${id}`, "DELETE");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function send(e?: React.FormEvent) {
    e?.preventDefault();
    if (
      !text.trim() ||
      busy ||
      !session ||
      !["idle", "asleep", "stopped", "working"].includes(session.phase)
    )
      return;
    setBusy(true);
    setError("");
    try {
      await api(`/sessions/${id}/prompt`, "POST", { message: text });
      setText("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!session)
    return (
      <div className="loading">
        <LoaderCircle className="spin" />
        Loading conversation…
        <ErrorBanner error={error} clear={() => setError("")} />
      </div>
    );
  const canSend =
    ["idle", "asleep", "stopped", "working"].includes(session.phase) && !busy;
  return (
    <div className="chat">
      <header className="workspace-header">
        <div>
          <h1>{session.name}</h1>
        </div>
        <div className="header-actions">
          <Badge phase={session.phase} />
          <button
            className="icon"
            aria-label="Workspace details"
            title="Workspace details"
            aria-expanded={details}
            onClick={() => setDetails(!details)}
          >
            <Server size={18} />
          </button>
          <button
            className="icon danger"
            aria-label={
              session.swarm?.role === "planner"
                ? "Close entire hierarchy"
                : "Close agent"
            }
            title={
              session.swarm?.role === "planner"
                ? "Close entire hierarchy"
                : "Close agent"
            }
            disabled={
              busy ||
              ![
                "idle",
                "working",
                "asleep",
                "stopped",
                "stopping",
                "interrupted",
                "closing",
                "starting",
                "waking",
              ].includes(session.phase)
            }
            onClick={close}
          >
            <Trash2 size={17} />
          </button>
        </div>
      </header>
      <div className="conversation-options">
        {session.swarm ? (
          <span>
            {session.swarm.role === "planner" ? "Read-only planner" : "Worker"}{" "}
            · {session.model}
          </span>
        ) : (
          <ModelSelect
            label="Model"
            models={models}
            value={session.model || ""}
            disabled={
              busy || !["idle", "asleep", "stopped", "interrupted"].includes(session.phase)
            }
            onChange={async (model) => {
              setBusy(true);
              setError("");
              try {
                const updated = await api<Session>(
                  `/sessions/${id}/model`,
                  "POST",
                  { model },
                );
                setSession(updated);
                updateRef.current(updated);
              } catch (error) {
                setError((error as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          />
        )}
      </div>
      {session.swarm && <SwarmPanel session={session} />}
      {details && (
        <div className="workspace-details">
          <span>
            <strong>Plane</strong>
            {session.plane}
          </span>
          <span>
            <strong>VM</strong>
            {session.vm || "Allocating"}
          </span>
          <span>
            <strong>Session</strong>
            {id}
          </span>
          <button
            className="secondary"
            disabled={busy || session.phase !== "idle"}
            onClick={() => act("sleep")}
          >
            <Moon size={14} />
            Sleep now
          </button>
          <button
            className="secondary"
            disabled={
              busy ||
              !["idle", "working", "asleep", "stopped", "interrupted"].includes(
                session.phase,
              )
            }
            onClick={() => {
              if (
                confirm(
                  "Stop this agent's VM and discard its running/suspended execution state? Workspace files and conversation are retained. Recovery requires an explicit cold boot. Other swarm agents are unaffected.",
                )
              )
                void act("stop-vm");
            }}
          >
            <Square size={14} /> Stop VM
          </button>
        </div>
      )}
      <ErrorBanner error={error} clear={() => setError("")} />
      {session.phase === "interrupted" && (
        <div className="recovery">
          <span>
            <strong>This session needs recovery.</strong>
            {session.error || "The previous operation was interrupted."}{" "}
            Recovery reboots the workspace to stop old commands; files and pi
            history are retained.
          </span>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => act("recover")}
          >
            <RotateCcw size={15} />
            Recover
          </button>
        </div>
      )}
      {session.phase === "allocation_unknown" && (
        <div className="recovery">
          <span>
            VM allocation was not confirmed. Reconcile by the session label
            before retrying. No replacement VM will be allocated automatically.
          </span>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => act("reconcile")}
          >
            Reconcile
          </button>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => {
              if (
                confirm(
                  "Retry allocation only after inspecting the plane and confirming the previous request is no longer running. A fresh label check must find zero VMs. This creates a workspace for this session; prompts will not be replayed. Continue?",
                )
              )
                void act("retry-allocation");
            }}
          >
            Retry allocation
          </button>
        </div>
      )}
      <Transcript
        key={id}
        historyLoaded={historyLoaded}
        items={items}
        phase={session.phase}
        select={select}
        session={session}
        sessions={sessions}
      />
      <div className="composer-area">
        {queued.length > 0 && (
          <section className="queued-messages" aria-label="Queued messages">
            <strong>
              {queued.length} queued message{queued.length === 1 ? "" : "s"}
            </strong>
            {queued.map((message) => (
              <div key={message.id} className="queued-message">
                <details>
                  <summary>
                    {message.status === "uncertain"
                      ? "Delivery unconfirmed — inspect chat before resending"
                      : message.status === "dispatching"
                        ? "Sending"
                        : "Queued"}
                    : {message.message.slice(0, 100)}
                    {message.message.length > 100 ? "…" : ""}
                  </summary>
                  <p>{message.message}</p>
                </details>
                {message.status === "pending" && (
                  <button
                    type="button"
                    className="secondary"
                    aria-label="Cancel queued message"
                    onClick={async () => {
                      try {
                        await api(
                          `/sessions/${id}/queue/${message.id}`,
                          "DELETE",
                        );
                        setQueued((old) =>
                          old.filter((entry) => entry.id !== message.id),
                        );
                      } catch (error) {
                        setError((error as Error).message);
                      }
                    }}
                  >
                    Cancel
                  </button>
                )}
              </div>
            ))}
          </section>
        )}
        {["asleep", "stopped"].includes(session.phase) && (
          <div className="wake-hint">
            <Moon size={14} />
            Workspace {session.phase}. Send a new message to wake it.
          </div>
        )}
        <form className="composer" onSubmit={send}>
          <textarea
            aria-label="Message your agent"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={
              session.phase === "closed"
                ? "This conversation is closed."
                : "Describe a task, ask a question, or share an idea…"
            }
            disabled={busy || session.phase === "closed"}
            rows={3}
            maxLength={100000}
            onKeyDown={(e) => {
              if (
                e.key === "Enter" &&
                !e.shiftKey &&
                !e.nativeEvent.isComposing
              ) {
                e.preventDefault();
                void send();
              }
            }}
          />
          <div className="composer-bottom">
            {session.phase === "working" && (
              <button
                type="button"
                className="stop"
                disabled={busy}
                onClick={() => {
                  if (
                    confirm(
                      "Stop the agent and halt its VM? Files are retained. Recovery is required before continuing.",
                    )
                  )
                    void act("abort");
                }}
              >
                <Square size={13} />
                Stop
              </button>
            )}
            <button
              className="send"
              aria-label={
                session.phase === "working" ||
                queued.some((m) => m.status === "pending")
                  ? "Queue message"
                  : "Send message"
              }
              disabled={!canSend || !text.trim()}
            >
              {busy ? (
                <LoaderCircle size={17} className="spin" />
              ) : (
                <ArrowUp size={18} />
              )}
              {session.phase === "working" ||
              queued.some((m) => m.status === "pending")
                ? "Queue"
                : "Send"}
            </button>
          </div>
        </form>
        <div className="composer-footnote">
          <span>Enter to send · Shift + Enter for a new line</span>
        </div>
      </div>
    </div>
  );
}
