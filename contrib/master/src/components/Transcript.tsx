import { useRef, useEffect, useState, useId } from "react";
import Markdown from "react-markdown";
import {
  Terminal,
  LoaderCircle,
  ChevronRight,
  Box,
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
} from "lucide-react";
import { groupTranscript, presentSwarmSends, type Item } from "../transcript";
import type { Phase, Session } from "../api";

function SwarmMessageBody({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false);
  const [overflowing, setOverflowing] = useState(false);
  const ref = useRef<HTMLParagraphElement>(null);
  const id = useId();
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const measure = () => {
      const lineHeight = parseFloat(getComputedStyle(node).lineHeight);
      setOverflowing(node.scrollHeight > lineHeight * 2 + 1);
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, [text]);
  return (
    <div
      className={`swarm-message-body ${expanded ? "expanded" : "collapsed"} ${overflowing ? "overflows" : ""}`}
    >
      <p ref={ref} id={id}>
        {text}
      </p>
      {overflowing && (
        <button
          className="swarm-expand"
          aria-expanded={expanded}
          aria-controls={id}
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Show less" : "Expand message"}
          <ChevronRight size={13} aria-hidden="true" />
        </button>
      )}
    </div>
  );
}

function ToolCard({ item }: { item: Item }) {
  return (
    <details className={`tool-card ${item.isError ? "failed" : ""}`}>
      <summary>
        {item.streaming ? (
          <LoaderCircle size={14} className="spin" />
        ) : (
          <Terminal size={14} />
        )}
        <strong>{item.name}</strong>
        <span>
          {item.streaming ? "Running" : item.isError ? "Failed" : "Completed"}
        </span>
        <ChevronRight size={14} />
      </summary>
      <pre>{JSON.stringify(item.args, null, 2)}</pre>
      {item.result !== undefined && (
        <pre>{JSON.stringify(item.result, null, 2)}</pre>
      )}
    </details>
  );
}
export default function Transcript({
  items,
  phase,
  select,
  session,
  sessions,
}: {
  items: Item[];
  phase: Phase;
  select: (id: string) => void;
  session: Session;
  sessions: Session[];
}) {
  const ref = useRef<HTMLDivElement>(null),
    atBottom = useRef(true),
    following = useRef(false),
    initialized = useRef(false);
  useEffect(() => {
    const node = ref.current;
    if (!node || !atBottom.current) return;
    if (
      !initialized.current ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      node.scrollTop = node.scrollHeight;
      initialized.current = items.length > 0;
      return;
    }
    let frame = 0;
    following.current = true;
    let previous = performance.now();
    const follow = (now: number) => {
      if (!atBottom.current) return;
      const distance = node.scrollHeight - node.clientHeight - node.scrollTop;
      const fraction = 1 - Math.exp(-Math.min(now - previous, 64) / 55);
      previous = now;
      node.scrollTop += distance * fraction;
      if (distance > 1) frame = requestAnimationFrame(follow);
      else following.current = false;
    };
    frame = requestAnimationFrame(follow);
    return () => {
      cancelAnimationFrame(frame);
      following.current = false;
    };
  }, [items, phase]);
  return (
    <div
      className="transcript"
      ref={ref}
      onWheel={(event) => {
        if (event.deltaY < 0) {
          atBottom.current = false;
          following.current = false;
        }
      }}
      onTouchMove={() => {
        atBottom.current = false;
        following.current = false;
      }}
      onScroll={() => {
        if (following.current) return;
        const n = ref.current!;
        atBottom.current = n.scrollHeight - n.scrollTop - n.clientHeight < 100;
      }}
    >
      <div className="transcript-inner">
        {!items.length && (
          <div className="empty-chat">
            <Box size={29} />
            <h2>What would you like to work on?</h2>
            <p>
              Your agent has a private workspace. Describe a task to get
              started.
            </p>
          </div>
        )}
        {groupTranscript(presentSwarmSends(items, session, sessions)).map(
          (i) =>
            i.kind === "tools" ? (
              <div
                key={i.key}
                className="tool-group"
                role="group"
                aria-label="Agent tool calls"
              >
                <Box size={19} className="tool-group-icon" aria-hidden="true" />
                <div className="tool-pills">
                  {i.items.map((item) => (
                    <ToolCard key={item.key} item={item} />
                  ))}
                </div>
              </div>
            ) : i.kind === "swarm" ? (
              <article
                key={i.key}
                className={`swarm-message ${i.source?.relationship || ""} ${i.outgoing ? "outgoing" : ""}`}
                aria-label={`Message ${i.outgoing ? "to" : "from"} ${i.source?.relationship || "swarm"}`}
              >
                <header>
                  {(i.source?.relationship === "parent") !== !!i.outgoing ? (
                    <ArrowDownLeft size={17} aria-hidden="true" />
                  ) : (
                    <ArrowUpRight size={17} aria-hidden="true" />
                  )}
                  <span>
                    {i.outgoing ? "To" : "From"}{" "}
                    {i.source?.relationship || "swarm"}
                  </span>
                  {i.source && (
                    <button
                      onClick={() => select(i.source!.id)}
                      title={`Open ${i.source.name} (${i.source.id})`}
                    >
                      {i.source.name}
                    </button>
                  )}
                  <span className="swarm-sender-role">{i.source?.role}</span>
                </header>
                <SwarmMessageBody text={i.text} />
                {i.outgoing && (
                  <details className="swarm-send-result">
                    <summary>
                      {i.streaming
                        ? "Sending…"
                        : i.isError
                          ? "Send failed — inspect before retrying"
                          : i.result === undefined
                            ? "Send unconfirmed"
                            : "Queued"}
                    </summary>
                    <pre>
                      {JSON.stringify(
                        i.result ?? "No confirmation received",
                        null,
                        2,
                      )}
                    </pre>
                  </details>
                )}
              </article>
            ) : i.kind === "notice" ? (
              <div className="notice" key={i.key}>
                <Activity size={14} />
                <span>{i.text}</span>
              </div>
            ) : (
              <article
                key={i.key}
                className={`message ${i.kind}`}
                aria-label={i.kind === "user" ? "You" : "Agent"}
              >
                {i.kind === "assistant" && (
                  <div className="message-label" aria-hidden="true">
                    <Box
                      size={19}
                      className={
                        i.streaming && phase === "working" ? "stream-label" : ""
                      }
                    />
                  </div>
                )}
                <div className="message-body">
                  <Markdown
                    disallowedElements={["img"]}
                    components={{
                      a: ({ children, ...props }) => (
                        <a {...props} target="_blank" rel="noopener noreferrer">
                          {children}
                        </a>
                      ),
                    }}
                  >
                    {i.text}
                  </Markdown>
                  {i.streaming && !i.text && phase === "working" && (
                    <LoaderCircle size={16} className="spin" />
                  )}
                </div>
              </article>
            ),
        )}
        {phase === "working" && !items.some((i) => i.streaming) && (
          <div className="notice">
            <LoaderCircle size={14} className="spin" />
            Agent is working…
          </div>
        )}
      </div>
    </div>
  );
}
