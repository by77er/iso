import { useState } from "react";
import {
  Plus,
  MessageSquare,
  Server,
  ChevronRight,
  LogOut,
  Archive,
  GitBranch,
  Box,
} from "lucide-react";
import type { Session, User } from "../api";
import { Brand, phaseLabel } from "./shared";
import ThemePicker from "./ThemePicker";

export default function Sidebar({
  sessions,
  selected,
  select,
  newAgent,
  view,
  setView,
  user,
  logout,
}: {
  sessions: Session[];
  selected: string | null;
  select: (id: string) => void;
  newAgent: () => void;
  view: string;
  setView: (v: string) => void;
  user: User;
  logout: () => void;
}) {
  const [archived, setArchived] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  const visible = sessions.filter(
    (session) => archived || session.phase !== "closed",
  );
  function node(session: Session): React.ReactNode {
    const children = visible
      .filter((child) => child.swarm?.parent === session.id)
      .sort((a, b) => a.created_at - b.created_at || a.id.localeCompare(b.id));
    const expanded = !collapsed.has(session.id);
    return (
      <li key={session.id}>
        <div className="sidebar-tree-row">
          {children.length ? (
            <button
              className="tree-toggle"
              aria-label={`${expanded ? "Collapse" : "Expand"} ${session.name}`}
              aria-expanded={expanded}
              onClick={() =>
                setCollapsed((old) => {
                  const next = new Set(old);
                  if (next.has(session.id)) next.delete(session.id);
                  else next.add(session.id);
                  return next;
                })
              }
            >
              <ChevronRight size={14} />
            </button>
          ) : (
            <span className="tree-toggle-space" />
          )}
          <button
            className={`session-link ${selected === session.id && view === "chat" ? "selected" : ""}`}
            onClick={() => select(session.id)}
            title={session.name}
            aria-current={
              selected === session.id && view === "chat" ? "page" : undefined
            }
          >
            {session.swarm ? (
              session.swarm.role === "planner" ? (
                <GitBranch size={17} />
              ) : (
                <Box size={17} />
              )
            ) : (
              <MessageSquare size={17} />
            )}
            <span>
              <strong>{session.name}</strong>
              <small>
                {session.swarm ? `${session.swarm.role} · ` : ""}
                {phaseLabel[session.phase]}
              </small>
            </span>
            <i className={`status-dot ${session.phase}`} />
          </button>
        </div>
        {!!children.length && expanded && <ul>{children.map(node)}</ul>}
      </li>
    );
  }
  return (
    <aside className="sidebar">
      <Brand />
      <button className="new-agent" onClick={newAgent}>
        <Plus size={18} />
        New agent
      </button>
      <div className="sidebar-section">
        <button aria-pressed={archived} onClick={() => setArchived(!archived)}>
          <Archive size={16} />
          {archived ? "Hide closed" : "Show closed"}
        </button>
      </div>
      <nav className="session-nav" aria-label="Agent sessions">
        <ul className="sidebar-tree" aria-label="Agents and swarms">
          {visible
            .filter(
              (session) =>
                !session.swarm?.parent ||
                !visible.some((parent) => parent.id === session.swarm?.parent),
            )
            .map(node)}
        </ul>
        {!sessions.length && (
          <p className="sidebar-empty">
            Your agents will appear here.
            <br />
            Create one to get started.
          </p>
        )}
      </nav>
      <div className="sidebar-bottom">
        <ThemePicker />
        <button
          className={view === "fleet" ? "selected" : ""}
          onClick={() => setView(view === "fleet" ? "chat" : "fleet")}
        >
          <Server size={17} />
          Control planes
          <ChevronRight size={15} />
        </button>
        <div className="identity">
          <div className="avatar">{user.user.slice(0, 1).toUpperCase()}</div>
          <div>
            <strong>{user.user}</strong>
            <small>{user.demo ? "Demo environment" : "Operator"}</small>
          </div>
          <button className="icon" aria-label="Sign out" onClick={logout}>
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </aside>
  );
}
