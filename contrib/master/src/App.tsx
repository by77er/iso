import { useState, useEffect, useCallback } from "react";
import { LoaderCircle } from "lucide-react";
import { api, type User, type Session } from "./api";
import { ErrorBanner } from "./components/shared";
import Login from "./components/Login";
import NewAgent from "./components/NewAgent";
import Sidebar from "./components/Sidebar";
import Welcome from "./components/Welcome";
import Chat from "./components/Chat";
import Fleet from "./components/Fleet";

export default function App() {
  const [user, setUser] = useState<User | null>(null),
    [loading, setLoading] = useState(true),
    [sessions, setSessions] = useState<Session[]>([]),
    [selected, setSelected] = useState<string | null>(null),
    [view, setView] = useState("chat"),
    [creating, setCreating] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    api<User>("/me")
      .then(setUser)
      .catch(() => {})
      .finally(() => setLoading(false));
    const expired = () => {
      setUser(null);
      setSessions([]);
      setSelected(null);
    };
    window.addEventListener("auth-expired", expired);
    return () => window.removeEventListener("auth-expired", expired);
  }, []);
  useEffect(() => {
    if (!user) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const rows = await api<Session[]>("/sessions");
        if (!stopped) setSessions(rows);
      } catch (e) {
        if (!stopped) setError((e as Error).message);
      }
      if (!stopped) timer = setTimeout(poll, 4000);
    }
    void poll();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [user]);
  const update = useCallback(
    (s: Session) =>
      setSessions((rows) => rows.map((r) => (r.id === s.id ? s : r))),
    [],
  );
  function select(id: string) {
    setSelected(id);
    setView("chat");
  }
  async function logout() {
    try {
      await api("/logout", "POST", {});
      setUser(null);
      setSessions([]);
      setSelected(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  if (loading)
    return (
      <div className="loading">
        <LoaderCircle className="spin" />
        Connecting…
      </div>
    );
  if (!user) return <Login onLogin={setUser} />;
  return (
    <div className="app-shell">
      <Sidebar
        sessions={sessions}
        selected={selected}
        select={select}
        newAgent={() => setCreating(true)}
        view={view}
        setView={setView}
        user={user}
        logout={logout}
      />
      <main className="main-panel">
        {user.demo && (
          <div className="demo-banner">
            DEMO MODE<span>No real VMs, model calls, or tool execution.</span>
          </div>
        )}
        <ErrorBanner error={error} clear={() => setError("")} />
        {view === "fleet" ? (
          <Fleet />
        ) : selected ? (
          <Chat key={selected} id={selected} onUpdate={update} />
        ) : (
          <Welcome create={() => setCreating(true)} />
        )}
      </main>
      {creating && (
        <NewAgent
          onClose={() => setCreating(false)}
          onCreated={(s) => {
            setSessions((rows) => [s, ...rows]);
            select(s.id);
            setCreating(false);
          }}
        />
      )}
    </div>
  );
}
