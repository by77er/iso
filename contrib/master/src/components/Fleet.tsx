import { useEffect, useState } from "react";
import { Server, ShieldCheck } from "lucide-react";
import { api, type Plane } from "../api";
import { ErrorBanner } from "./shared";

function bytes(value?: number | null) {
  if (value == null || !Number.isFinite(value) || value < 0) return "Unknown";
  return `${(value / 1024 ** 3).toLocaleString(undefined, { maximumFractionDigits: 1 })} GiB`;
}

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
                  ? p.capacity === 0
                    ? `${p.count} VMs · No configured limit`
                    : `${p.count} / ${p.capacity} VM capacity`
                  : "Other control planes remain available."}
              </p>
              <dl className="storage-metrics">
                <div>
                  <dt>Storage backend</dt>
                  <dd>{p.storage?.storage_backend ?? "Unknown"}</dd>
                </div>
                <div>
                  <dt>Pool used / capacity</dt>
                  <dd>
                    {bytes(p.storage?.pool_used_bytes)} /{" "}
                    {bytes(p.storage?.pool_capacity_bytes)}
                  </dd>
                </div>
                <div>
                  <dt>VM suspension files</dt>
                  <dd>{bytes(p.storage?.snapshot_bytes)}</dd>
                </div>
                <div>
                  <dt>Backing filesystem capacity</dt>
                  <dd>{bytes(p.storage?.filesystem_capacity_bytes)}</dd>
                </div>
                <div>
                  <dt>Filesystem available</dt>
                  <dd>{bytes(p.storage?.filesystem_available_bytes)}</dd>
                </div>
              </dl>
              {(p.storage?.data_percent ?? 0) >= 90 && (
                <p role="alert">
                  Storage pool nearly full. VM writes may fail.
                </p>
              )}
              <p className="muted">
                Snapshot files show allocated host space, not virtual disk
                sizes. Shared storage figures are not additive; unsupported
                metrics show Unknown.
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
