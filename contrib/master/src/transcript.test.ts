import { describe, it, expect } from "vitest";
import { reduceEvents } from "./transcript";
describe("transcript event reducer", () => {
  it("replaces streamed content with the authoritative final message", () => {
    let items = reduceEvents(
      [],
      [
        { seq: 1, type: "assistant_start" },
        { seq: 2, type: "delta", text: "partial\u2028text" },
      ],
    );
    expect(items[0].text).toBe("partial\u2028text");
    items = reduceEvents(items, [
      { seq: 3, type: "message", role: "assistant", text: "final" },
    ]);
    expect(items).toHaveLength(1);
    expect(items[0].streaming).toBe(false);
    expect(items[0].text).toBe("final");
  });
  it("correlates parallel tool results by ID rather than arrival order", () => {
    const items = reduceEvents(
      [],
      [
        { seq: 1, type: "tool_start", id: "a", name: "bash" },
        { seq: 2, type: "tool_start", id: "b", name: "read" },
        { seq: 3, type: "tool_end", id: "b", result: "B" },
        { seq: 4, type: "tool_end", id: "a", result: "A", isError: true },
      ],
    );
    expect(items[0].result).toBe("A");
    expect(items[1].result).toBe("B");
    expect(items[0].isError).toBe(true);
  });
  it("ends stale streaming indicators on interruption without mutating previous state", () => {
    const before = reduceEvents([], [{ seq: 1, type: "assistant_start" }]);
    const after = reduceEvents(before, [
      { seq: 2, type: "notice", text: "Interrupted" },
    ]);
    expect(before[0].streaming).toBe(true);
    expect(after[0].streaming).toBe(false);
    expect(after[1].kind).toBe("notice");
  });
});
