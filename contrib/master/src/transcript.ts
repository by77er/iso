import type { Session } from "./api";

export type SwarmSource = {
  id: string;
  name: string;
  role: "planner" | "worker";
  relationship: "parent" | "child";
};
export type Event = {
  seq: number;
  type: string;
  role?: string;
  text?: string;
  error?: string;
  id?: string;
  name?: string;
  args?: unknown;
  result?: unknown;
  isError?: boolean;
  source?: SwarmSource;
};
export type Item = {
  outgoing?: boolean;
  key: number;
  kind: "user" | "assistant" | "tool" | "notice" | "swarm";
  text: string;
  streaming?: boolean;
  toolId?: string;
  name?: string;
  args?: unknown;
  result?: unknown;
  isError?: boolean;
  source?: SwarmSource;
};
export function reduceEvents(items: Item[], events: Event[]): Item[] {
  const result = items.map((i) => ({ ...i }));
  for (const e of events) {
    switch (e.type) {
      case "swarm_message":
        result.push({
          key: e.seq,
          kind: "swarm",
          text: e.text || "",
          source: e.source,
        });
        break;
      case "assistant_start":
        result.push({
          key: e.seq,
          kind: "assistant",
          text: "",
          streaming: true,
        });
        break;
      case "delta": {
        let item = result.findLast(
          (i) => i.kind === "assistant" && i.streaming,
        );
        if (!item) {
          item = { key: e.seq, kind: "assistant", text: "", streaming: true };
          result.push(item);
        }
        item.text += e.text || "";
        break;
      }
      case "message": {
        const text = (e.text || "") + (e.error ? `\n\nError: ${e.error}` : "");
        const item =
          e.role === "assistant"
            ? result.findLast((i) => i.kind === "assistant" && i.streaming)
            : undefined;
        if (item) {
          item.text = text;
          item.streaming = false;
        } else
          result.push({
            key: e.seq,
            kind: e.role === "user" ? "user" : "assistant",
            text,
          });
        break;
      }
      case "tool_start":
        result.push({
          key: e.seq,
          kind: "tool",
          text: "",
          toolId: e.id,
          name: e.name,
          args: e.args,
          streaming: true,
        });
        break;
      case "tool_end": {
        const item = result.find((i) => i.kind === "tool" && i.toolId === e.id);
        if (item) {
          item.result = e.result;
          item.isError = e.isError;
          item.streaming = false;
        } else
          result.push({
            key: e.seq,
            kind: "tool",
            text: "",
            toolId: e.id,
            name: e.name,
            result: e.result,
            isError: e.isError,
          });
        break;
      }
      case "notice":
        result.forEach((i) => {
          i.streaming = false;
        });
        result.push({ key: e.seq, kind: "notice", text: e.text || "" });
        break;
    }
  }
  return result;
}

export type TranscriptEntry =
  Item | { kind: "tools"; key: number; items: Item[] };

export function presentSwarmSends(
  items: Item[],
  session: Session,
  sessions: Session[],
): Item[] {
  return items.map((item) => {
    if (item.kind !== "tool" || item.name !== "swarm_send" || !session.swarm)
      return item;
    const args = item.args as
      { recipient?: unknown; message?: unknown } | undefined;
    if (typeof args?.recipient !== "string" || typeof args.message !== "string")
      return item;
    const recipient = sessions.find((node) => node.id === args.recipient);
    const relationship =
      session.swarm.parent === args.recipient
        ? "parent"
        : recipient?.swarm?.parent === session.id &&
            recipient.swarm.root === session.swarm.root
          ? "child"
          : undefined;
    if (!relationship) return item;
    return {
      ...item,
      kind: "swarm",
      outgoing: true,
      text: args.message,
      source: {
        id: args.recipient,
        name: recipient?.name || args.recipient,
        role: recipient?.swarm?.role || "planner",
        relationship,
      },
    };
  });
}

export function groupTranscript(items: Item[]): TranscriptEntry[] {
  const entries: TranscriptEntry[] = [];
  items.forEach((item, index) => {
    // Tool-only assistant turns should not leave an empty avatar row.
    if (
      item.kind === "assistant" &&
      !item.text.trim() &&
      (!item.streaming ||
        items[index + 1]?.kind === "tool" ||
        items[index + 1]?.outgoing)
    )
      return;
    if (item.kind === "tool") {
      const last = entries.at(-1);
      if (last?.kind === "tools") last.items.push(item);
      else entries.push({ kind: "tools", key: item.key, items: [item] });
    } else entries.push(item);
  });
  return entries;
}
