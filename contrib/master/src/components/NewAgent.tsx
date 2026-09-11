import React, { useState, useRef, useEffect } from "react";
import { Box, X, Plus, LoaderCircle } from "lucide-react";
import { api, type Session, type ModelCatalog } from "../api";
import ModelSelect from "./ModelSelect";
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
  const [models, setModels] = useState<string[]>([]),
    [model, setModel] = useState(""),
    [swarm, setSwarm] = useState(false),
    [plannerModel, setPlannerModel] = useState(""),
    [workerModel, setWorkerModel] = useState("");
  useEffect(() => {
    ref.current?.showModal();
    let stopped = false;
    api<ModelCatalog>("/models")
      .then((catalog) => {
        if (stopped) return;
        setModels(catalog.models);
        const initial = catalog.default || catalog.models[0] || "";
        setModel(initial);
        setPlannerModel(initial);
        setWorkerModel(initial);
      })
      .catch((error) => {
        if (!stopped) setError(error.message);
      });
    return () => {
      stopped = true;
    };
  }, []);
  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      onCreated(
        await api<Session>("/sessions", "POST", {
          name: name.trim() || "New agent",
          model: model || null,
          swarm,
          planner_model: plannerModel || null,
          worker_model: workerModel || null,
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
      <h2>{swarm ? "Create a swarm" : "Create an agent"}</h2>
      <p>
        {swarm
          ? "A read-only planner coordinates a tree of sub-planners and workers, each with its own workspace."
          : "Choose a model and give your agent a dedicated workspace."}
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
        <label className="swarm-toggle">
          <input
            type="checkbox"
            checked={swarm}
            onChange={(event) => setSwarm(event.target.checked)}
            disabled={busy}
          />
          <span>Swarm mode</span>
        </label>
        {swarm ? (
          <>
            <ModelSelect
              label="Planner model"
              models={models}
              value={plannerModel}
              onChange={setPlannerModel}
              disabled={busy}
            />
            <ModelSelect
              label="Worker model"
              models={models}
              value={workerModel}
              onChange={setWorkerModel}
              disabled={busy}
            />
            <p className="muted">
              Planners can inspect and delegate. Workers can run commands and
              change files.
            </p>
          </>
        ) : (
          <ModelSelect
            label="Model"
            models={models}
            value={model}
            onChange={setModel}
            disabled={busy}
          />
        )}
        <ErrorBanner error={error} clear={() => setError("")} />
        <button
          className="primary wide"
          disabled={busy || (swarm && (!plannerModel || !workerModel))}
        >
          {busy ? (
            <>
              <LoaderCircle size={16} className="spin" />
              Preparing your workspace…
            </>
          ) : (
            <>
              <Plus size={17} />
              {swarm ? "Create swarm" : "Create agent"}
            </>
          )}
        </button>
      </form>
    </dialog>
  );
}
