import { useEffect, useState } from "react";
import { GitBranch, Send } from "lucide-react";
import { api, type Session } from "../api";
import { ErrorBanner } from "./shared";

interface Mail {
  id: number;
  sender: string;
  recipient: string;
  message: string;
  status: string;
}
export default function SwarmPanel({ session }: { session: Session }) {
  const [nodes, setNodes] = useState<Session[]>([]),
    [messages, setMessages] = useState<Mail[]>([]),
    [error, setError] = useState(""),
    [adding, setAdding] = useState(false),
    [busy, setBusy] = useState(false),
    [name, setName] = useState(""),
    [task, setTask] = useState(""),
    [role, setRole] = useState("worker");
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const data = await api<{ nodes: Session[]; messages: Mail[] }>(
          `/sessions/${session.id}/swarm`,
        );
        if (!stopped) {
          setNodes(data.nodes);
          setMessages(data.messages);
        }
      } catch (error) {
        if (!stopped) setError((error as Error).message);
      }
      if (!stopped) timer = setTimeout(poll, 1500);
    }
    void poll();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [session.id]);
  async function schedule(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const child = await api<Session>(
        `/sessions/${session.id}/children`,
        "POST",
        { name, role, task },
      );
      setNodes((old) => [...old.filter((node) => node.id !== child.id), child]);
      setAdding(false);
      setName("");
      setTask("");
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <details className="swarm-panel">
      <summary>
        <GitBranch size={17} /> Coordination{" "}
        <span>
          {messages.filter((message) => message.status === "pending").length}{" "}
          queued
        </span>
      </summary>
      <div className="swarm-content">
        <ErrorBanner error={error} clear={() => setError("")} />
        {session.swarm?.role === "planner" &&
          !["closed", "closing", "interrupted"].includes(session.phase) && (
            <button
              className="secondary"
              onClick={() => setAdding(!adding)}
              disabled={busy}
              aria-expanded={adding}
            >
              Schedule child
            </button>
          )}
        {adding && (
          <form className="child-form" onSubmit={schedule}>
            <label>
              Child name
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                required
                maxLength={120}
                disabled={busy}
              />
            </label>
            <label>
              Role
              <select
                aria-label="Role"
                value={role}
                onChange={(event) => setRole(event.target.value)}
                disabled={busy}
              >
                <option value="worker">Worker</option>
                <option value="planner">Read-only planner</option>
              </select>
            </label>
            <label>
              Task
              <textarea
                value={task}
                onChange={(event) => setTask(event.target.value)}
                required
                maxLength={32000}
                disabled={busy}
              />
            </label>
            <button className="primary" disabled={busy}>
              {busy ? "Scheduling…" : "Schedule"}
            </button>
          </form>
        )}
        {!!messages.length && (
          <details className="swarm-mail">
            <summary>
              <Send size={14} /> Parent–child messages ({messages.length})
            </summary>
            {messages.map((message) => (
              <div key={message.id}>
                <strong>
                  {nodes.find((n) => n.id === message.sender)?.name ||
                    message.sender}{" "}
                  →{" "}
                  {nodes.find((n) => n.id === message.recipient)?.name ||
                    message.recipient}
                </strong>
                <span>{message.status}</span>
                <p>{message.message}</p>
              </div>
            ))}
          </details>
        )}
      </div>
    </details>
  );
}
