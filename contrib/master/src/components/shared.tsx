import { Box, X } from "lucide-react";
import type { Phase } from "../api";
export const phaseLabel: Record<Phase, string> = {
  allocating: "Preparing workspace",
  allocation_unknown: "Needs reconciliation",
  starting: "Starting agent",
  idle: "Ready",
  working: "Working",
  sleeping: "Going to sleep",
  asleep: "Asleep",
  waking: "Waking workspace",
  interrupted: "Needs recovery",
  closing: "Closing",
  closed: "Closed",
};
export function Badge({ phase }: { phase: Phase }) {
  return (
    <span className={`badge ${phase}`}>
      <i />
      {phaseLabel[phase]}
    </span>
  );
}
export function Brand() {
  return (
    <div className="brand">
      <Box size={27} />
      <span>
        iso<span className="brand-sub"> / agents</span>
      </span>
    </div>
  );
}
export function ErrorBanner({
  error,
  clear,
}: {
  error: string;
  clear: () => void;
}) {
  return error ? (
    <div className="error-banner" role="alert">
      <span>{error}</span>
      <button className="icon" aria-label="Dismiss error" onClick={clear}>
        <X size={16} />
      </button>
    </div>
  ) : null;
}
