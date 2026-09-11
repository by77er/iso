import React, { useState, useRef, useEffect } from "react";
import { Box, X, Moon, Plus, LoaderCircle } from "lucide-react";
import { api, type Session } from "../api";
import { ErrorBanner } from "./shared";

export default function NewAgent({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (s: Session) => void;
}) {
  const ref = useRef<HTMLDialogElement>(null),
    [name, setName] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      onCreated(
        await api<Session>("/sessions", "POST", {
          name: name.trim() || "New agent",
        }),
      );
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  }
  return (
    <dialog
      ref={ref}
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
    >
      <div className="dialog-heading">
        <Box size={26} />
        <button
          className="icon"
          aria-label="Close dialog"
          disabled={busy}
          onClick={onClose}
        >
          <X size={20} />
        </button>
      </div>
      <h2>Create an agent</h2>
      <p>
        A dedicated workspace, automatically placed on an available control
        plane. No infrastructure setup needed.
      </p>
      <form onSubmit={create}>
        <label>
          Agent name
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={120}
            placeholder="e.g. Build my dashboard"
            disabled={busy}
          />
        </label>
        <ErrorBanner error={error} clear={() => setError("")} />
        <button className="primary wide" disabled={busy}>
          {busy ? (
            <>
              <LoaderCircle size={16} className="spin" />
              Preparing your workspace…
            </>
          ) : (
            <>
              <Plus size={17} />
              Create agent
            </>
          )}
        </button>
      </form>
      <div className="dialog-note">
        <Moon size={15} />
        Sleeps when idle. Resumes when you return.
      </div>
    </dialog>
  );
}
