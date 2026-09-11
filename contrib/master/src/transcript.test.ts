import { describe, it, expect } from "vitest";
import { groupTranscript, presentSwarmSends, reduceEvents } from "./transcript";
import type { Session } from "./api";
describe("transcript event reducer", () => {
  it("renders sends to verified parents and children without losing tool status", () => {
    const root: Session = {
      id: "root",
      name: "Planner",
      plane: "local",
      vm: null,
      phase: "idle",
      created_at: 0,
      last_active: 0,
      error: null,
      model: null,
      swarm: {
        root: "root",
        parent: null,
        role: "planner",
        depth: 0,
        planner_model: "planner",
        worker_model: "worker",
        task: "",
      },
    };
    const child: Session = {
      ...root,
      id: "child",
      name: "Builder",
      swarm: { ...root.swarm!, parent: "root", role: "worker", depth: 1 },
    };
    const items = reduceEvents(
      [],
      [
        { seq: 1, type: "assistant_start" },
        {
          seq: 2,
          type: "tool_start",
          id: "send",
          name: "swarm_send",
          args: { recipient: "child", message: "Build it" },
        },
      ],
    );
    const pending = presentSwarmSends(items, root, [root, child]);
    expect(groupTranscript(pending)).toHaveLength(1);
    expect(pending[1]).toMatchObject({
      kind: "swarm",
      outgoing: true,
      streaming: true,
      text: "Build it",
      source: { name: "Builder", relationship: "child" },
    });
    const failed = reduceEvents(items, [
      {
        seq: 3,
        type: "tool_end",
        id: "send",
        isError: true,
        result: "Unavailable",
      },
    ]);
    expect(presentSwarmSends(failed, root, [root, child])[1]).toMatchObject({
      isError: true,
      result: "Unavailable",
      streaming: false,
    });
    const upward = [
      { ...items[1], args: { recipient: "root", message: "Done" } },
    ];
    expect(presentSwarmSends(upward, child, [root, child])[0]).toMatchObject({
      source: { relationship: "parent", name: "Planner" },
    });
    expect(presentSwarmSends(items, root, [root])[1].kind).toBe("tool");
    expect(items[1].kind).toBe("tool");
  });
  it("keeps swarm provenance separate from user messages and groups tool-only turns", () => {
    const source = {
      id: "parent",
      name: "Planner",
      role: "planner" as const,
      relationship: "parent" as const,
    };
    const items = reduceEvents(
      [],
      [
        { seq: 1, type: "swarm_message", text: "Inspect the repo", source },
        { seq: 2, type: "assistant_start" },
        { seq: 3, type: "tool_start", id: "read", name: "read" },
        { seq: 4, type: "tool_end", id: "read", result: "file" },
        { seq: 5, type: "message", role: "assistant", text: "" },
        { seq: 6, type: "tool_start", id: "list", name: "list" },
        { seq: 7, type: "message", role: "assistant", text: "Findings" },
        { seq: 8, type: "tool_start", id: "next", name: "read" },
      ],
    );
    expect(items[0]).toMatchObject({ kind: "swarm", source });
    const entries = groupTranscript(items);
    expect(entries.map((entry) => entry.kind)).toEqual([
      "swarm",
      "tools",
      "assistant",
      "tools",
    ]);
    expect(entries[1]).toMatchObject({
      key: 3,
      items: [{ toolId: "read" }, { toolId: "list" }],
    });
  });
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
