import React, { useState, useRef, useEffect } from "react";
import {
  LoaderCircle,
  Server,
  Trash2,
  Moon,
  RotateCcw,
  Box,
  Square,
  ArrowUp,
  ShieldCheck,
} from "lucide-react";
import { api, type Session } from "../api";
import { reduceEvents, type Item, type Event } from "../transcript";
import { Badge, ErrorBanner } from "./shared";
import Transcript from "./Transcript";

export default function Chat({
  id,
  onUpdate,
}: {
  id: string;
  onUpdate: (s: Session) => void;
}) {
  const [session, setSession] = useState<Session | null>(null),
    [items, setItems] = useState<Item[]>([]),
    [error, setError] = useState(""),
    [text, setText] = useState(""),
    [busy, setBusy] = useState(false),
    [details, setDetails] = useState(false);
  const updateRef = useRef(onUpdate);
  updateRef.current = onUpdate;
  useEffect(() => {
    let stopped = false,
      cursor = 0;
    let timer: ReturnType<typeof setTimeout>;
    setSession(null);
    setItems([]);
    setText("");
    setError("");
    setBusy(false);
    async function poll() {
      try {
        const r = await api<{ session: Session; events: Event[] }>(
          `/sessions/${id}/events?after=${cursor}`,
        );
        if (stopped) return;
        setSession(r.session);
        updateRef.current(r.session);
        if (r.events.length) {
          cursor = r.events.at(-1)!.seq;
          setItems((old) => reduceEvents(old, r.events));
        }
        timer = setTimeout(poll, r.events.length === 500 ? 0 : 700);
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
    if (
      !confirm(
        "Close this agent and permanently delete its workspace? The conversation will remain readable.",
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
      !["idle", "asleep"].includes(session.phase)
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
  const canSend = ["idle", "asleep"].includes(session.phase) && !busy;
  return (
    <div className="chat">
      <header className="workspace-header">
        <div>
          <span className="breadcrumb">Agents / Workspace</span>
          <h1>{session.name}</h1>
        </div>
        <div className="header-actions">
          <Badge phase={session.phase} />
          <button
            className="icon"
            aria-label="Workspace details"
            onClick={() => setDetails(!details)}
          >
            <Server size={18} />
          </button>
          <button
            className="icon danger"
            aria-label="Close agent"
            disabled={
              busy ||
              !["idle", "working", "asleep", "interrupted"].includes(
                session.phase,
              )
            }
            onClick={close}
          >
            <Trash2 size={17} />
          </button>
        </div>
      </header>
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
        </div>
      )}
      <Transcript items={items} phase={session.phase} />
      <div className="composer-area">
        {session.phase === "asleep" && (
          <div className="wake-hint">
            <Moon size={14} />
            Workspace asleep. Send a message to pick up where you left off.
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
            disabled={!canSend}
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
            <span>
              <Box size={14} />
              pi · isolated workspace
            </span>
            {session.phase === "working" ? (
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
            ) : (
              <button
                className="send"
                aria-label="Send message"
                disabled={!canSend || !text.trim()}
              >
                {busy ? (
                  <LoaderCircle size={17} className="spin" />
                ) : (
                  <ArrowUp size={18} />
                )}
              </button>
            )}
          </div>
        </form>
        <div className="composer-footnote">
          <span>Enter to send · Shift + Enter for a new line</span>
          <span>
            <ShieldCheck size={12} />
            Private microVM
          </span>
        </div>
      </div>
    </div>
  );
}
