export type Phase =
  | "allocating"
  | "allocation_unknown"
  | "starting"
  | "idle"
  | "working"
  | "sleeping"
  | "asleep"
  | "waking"
  | "interrupted"
  | "closing"
  | "closed";
export interface Session {
  id: string;
  name: string;
  plane: string;
  vm: string | null;
  phase: Phase;
  created_at: number;
  last_active: number;
  error: string | null;
}
export interface User {
  user: string;
  demo: boolean;
  idle_seconds: number;
}
export interface Plane {
  id: string;
  available: boolean;
  capacity: number;
  count?: number;
  vms?: {
    id: string;
    state: string;
    labels: Record<string, string>;
    template: string;
  }[];
}
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const r = await fetch("/api" + path, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Iso-Master": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data;
  try {
    data = await r.json();
  } catch {
    throw new ApiError(`Server returned HTTP ${r.status}`, r.status);
  }
  if (!r.ok) {
    if (r.status === 401) window.dispatchEvent(new Event("auth-expired"));
    throw new ApiError(data.error || `HTTP ${r.status}`, r.status);
  }
  return data;
}
