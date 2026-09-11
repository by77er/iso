import { useRef, useEffect } from "react";
import Markdown from "react-markdown";
import {
  Terminal,
  LoaderCircle,
  ChevronRight,
  Box,
  Activity,
} from "lucide-react";
import type { Item } from "../transcript";
import type { Phase } from "../api";

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
}: {
  items: Item[];
  phase: Phase;
}) {
  const ref = useRef<HTMLDivElement>(null),
    atBottom = useRef(true);
  useEffect(() => {
    if (atBottom.current && ref.current)
      ref.current.scrollTop = ref.current.scrollHeight;
  }, [items, phase]);
  return (
    <div
      className="transcript"
      ref={ref}
      onScroll={() => {
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
        {items.map((i) =>
          i.kind === "tool" ? (
            <ToolCard key={i.key} item={i} />
          ) : i.kind === "notice" ? (
            <div className="notice" key={i.key}>
              <Activity size={14} />
              <span>{i.text}</span>
            </div>
          ) : (
            <article key={i.key} className={`message ${i.kind}`}>
              <div className="message-label">
                {i.kind === "user" ? (
                  <span className="avatar tiny">Y</span>
                ) : (
                  <Box size={17} />
                )}
                <strong>{i.kind === "user" ? "You" : "Agent"}</strong>
                {i.streaming && phase === "working" && (
                  <span className="stream-label">Responding</span>
                )}
              </div>
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
