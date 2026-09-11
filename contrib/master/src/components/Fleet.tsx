import { useEffect, useState } from "react";
import { Server, ShieldCheck } from "lucide-react";
import { api, type Plane } from "../api";
import { ErrorBanner } from "./shared";

export default function Fleet() {
  const [planes, setPlanes] = useState<Plane[]>([]),
    [error, setError] = useState("");
  useEffect(() => {
    let closed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const data = await api<{ planes: Plane[] }>("/fleet");
        if (!closed) {
          setPlanes(data.planes);
          setError("");
        }
      } catch (e) {
        if (!closed) setError((e as Error).message);
      }
      if (!closed) timer = setTimeout(poll, 5000);
    }
    void poll();
    return () => {
      closed = true;
      clearTimeout(timer);
    };
  }, []);
  return (
    <div className="fleet-page">
      <header className="workspace-header">
        <div>
          <span className="breadcrumb">Infrastructure / Operator view</span>
          <h1>Control planes</h1>
        </div>
        <Server size={24} />
      </header>
      <div className="fleet-content">
        <p className="muted">
          Agents are placed automatically on the least populated reachable plane
          with capacity. Sleeping workspaces retain their placement.
        </p>
        <ErrorBanner error={error} clear={() => setError("")} />
        <div className="plane-grid">
          {planes.map((p) => (
            <section className="plane-card" key={p.id}>
              <div className="plane-heading">
                <Server size={22} />
                <span
                  className={`badge ${p.available ? "idle" : "interrupted"}`}
                >
                  <i />
                  {p.available ? "Connected" : "Unavailable"}
                </span>
              </div>
              <h2>{p.id}</h2>
              <p>
                {p.available
                  ? `${p.count} / ${p.capacity} VM capacity`
                  : "Other control planes remain available."}
              </p>
              <div className="plane-vms">
                {p.vms?.map((vm) => (
                  <div key={vm.id}>
                    <span>
                      {vm.labels?.name || vm.id}
                      <small>{vm.template}</small>
                    </span>
                    <span>{vm.state}</span>
                  </div>
                ))}
              </div>
            </section>
          ))}
        </div>
        <div className="operator-note">
          <ShieldCheck size={19} />
          <p>
            Control-plane endpoints, mTLS identities, templates, and credential
            principals are configured on the master—not supplied by agents.
          </p>
        </div>
      </div>
    </div>
  );
}
