import React, { useState } from "react";
import { ShieldCheck, LoaderCircle } from "lucide-react";
import { api, type User } from "../api";
import { Brand, ErrorBanner } from "./shared";

export default function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const [username, setUsername] = useState("admin"),
    [password, setPassword] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api("/login", "POST", { username, password });
      setPassword("");
      onLogin(await api<User>("/me"));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="login-screen">
      <div className="login-card">
        <Brand />
        <div className="eyebrow">YOUR PRIVATE AGENT WORKSPACE</div>
        <h1>Good work starts here.</h1>
        <p>Give your agent a task. We’ll take care of the workspace.</p>
        <form onSubmit={submit}>
          <label>
            Username
            <input
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </label>
          <label>
            Password
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>
          <ErrorBanner error={error} clear={() => setError("")} />
          <button className="primary wide" disabled={busy}>
            {busy ? <LoaderCircle className="spin" size={16} /> : null}Sign in
          </button>
        </form>
        <small>
          <ShieldCheck size={15} /> Isolated execution. Persistent
          conversations.
        </small>
      </div>
    </main>
  );
}
