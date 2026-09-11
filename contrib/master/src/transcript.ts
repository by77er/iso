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
};
export type Item = {
  key: number;
  kind: "user" | "assistant" | "tool" | "notice";
  text: string;
  streaming?: boolean;
  toolId?: string;
  name?: string;
  args?: unknown;
  result?: unknown;
  isError?: boolean;
};
export function reduceEvents(items: Item[], events: Event[]): Item[] {
  const result = items.map((i) => ({ ...i }));
  for (const e of events) {
    switch (e.type) {
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
