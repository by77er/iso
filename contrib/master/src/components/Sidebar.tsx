import { useState } from "react";
import {
  Plus,
  MessageSquare,
  Server,
  ChevronRight,
  LogOut,
} from "lucide-react";
import type { Session, User } from "../api";
import { Brand, phaseLabel } from "./shared";

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
  return (
    <aside className="sidebar">
      <Brand />
      <button className="new-agent" onClick={newAgent}>
        <Plus size={18} />
        New agent<span>+</span>
      </button>
      <div className="sidebar-section">
        <span>YOUR AGENTS</span>
        <button onClick={() => setArchived(!archived)}>
          {archived ? "Hide closed" : "Show closed"}
        </button>
      </div>
      <nav className="session-nav" aria-label="Agent sessions">
        {sessions
          .filter((s) => archived || s.phase !== "closed")
          .map((s) => (
            <button
              key={s.id}
              className={`session-link ${selected === s.id && view === "chat" ? "selected" : ""}`}
              onClick={() => select(s.id)}
            >
              <MessageSquare size={17} />
              <span>
                <strong>{s.name}</strong>
                <small>{phaseLabel[s.phase]}</small>
              </span>
              <i className={`status-dot ${s.phase}`} />
            </button>
          ))}
        {!sessions.length && (
          <p className="sidebar-empty">
            Your agents will appear here.
            <br />
            Create one to get started.
          </p>
        )}
      </nav>
      <div className="sidebar-bottom">
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
