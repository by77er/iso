import { useEffect, useMemo, useState } from "react";
import { CircleStop, FileText, GitBranch, Send, Users } from "lucide-react";
import { api, type Acl, type Phase, type Session } from "../api";
import { Badge, ErrorBanner, phaseLabel } from "./shared";
import { BoardDir, fold, type BoardPost } from "./Board";
import AclEditor, {
  draftFromAcl,
  draftToAcl,
  emptyDraft,
  type AclDraft,
} from "./AclEditor";

interface Mail {
  id: number;
  sender: string;
  recipient: string;
  message: string;
  status: string;
}
export default function SwarmExplorer({
  rootId,
  sessions,
  select,
}: {
  rootId: string;
  sessions: Session[];
  select: (id: string) => void;
}) {
  const [nodes, setNodes] = useState<Session[]>([]),
    [messages, setMessages] = useState<Mail[]>([]),
    [posts, setPosts] = useState<BoardPost[]>([]),
    [selectedPath, setSelectedPath] = useState<string | null>(null),
    [body, setBody] = useState<string | null>(null),
    [bodyError, setBodyError] = useState(""),
    [stopping, setStopping] = useState<string | null>(null),
    [acl, setAcl] = useState<AclDraft>(emptyDraft),
    [aclSaving, setAclSaving] = useState(false),
    [aclResult, setAclResult] = useState<string>(""),
    [error, setError] = useState("");
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const [data, board] = await Promise.all([
          api<{ nodes: Session[]; messages: Mail[] }>(
            `/sessions/${rootId}/swarm`,
          ),
          api<{ posts: BoardPost[] }>(`/sessions/${rootId}/board`),
        ]);
        if (!stopped) {
          setNodes(data.nodes);
          setMessages(data.messages);
          setPosts(board.posts);
          setError("");
        }
      } catch (pollError) {
        if (!stopped) setError((pollError as Error).message);
      }
      if (!stopped) timer = setTimeout(poll, 2000);
    }
    void poll();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [rootId]);
  const known = nodes.length ? nodes : sessions;
  const name = (id: string) => known.find((node) => node.id === id)?.name || id;
  const root =
    nodes.find((node) => node.id === rootId) ||
    sessions.find((node) => node.id === rootId);
  const selected = posts.find((post) => post.path === selectedPath) || null;
  const updatedAt = selected?.updated_at;
  useEffect(() => {
    if (!selectedPath) return;
    let stopped = false;
    api<BoardPost & { body: string }>(
      `/sessions/${rootId}/board?` +
        new URLSearchParams({ path: selectedPath }),
    )
      .then((full) => {
        if (!stopped) {
          setBody(full.body);
          setBodyError("");
        }
      })
      .catch((loadError) => {
        if (!stopped) setBodyError((loadError as Error).message);
      });
    return () => {
      stopped = true;
    };
  }, [rootId, selectedPath, updatedAt]);
  const phases = useMemo(() => {
    const counts = new Map<Phase, number>();
    for (const node of nodes)
      counts.set(node.phase, (counts.get(node.phase) || 0) + 1);
    return [...counts.entries()]
      .map(([phase, count]) => `${count} ${phaseLabel[phase].toLowerCase()}`)
      .join(" · ");
  }, [nodes]);
  async function stopVm(node: Session) {
    if (
      !window.confirm(
        `Stop ${node.name}'s VM? Its disk and conversation are kept and it can be recovered; only the running workspace is reclaimed.`,
      )
    )
      return;
    setStopping(node.id);
    setError("");
    try {
      await api(`/sessions/${node.id}/actions/stop-vm`, "POST");
    } catch (stopError) {
      setError((stopError as Error).message);
    } finally {
      setStopping(null);
    }
  }
  // Reclaimable: a non-root node holding a live or suspended workspace.
  const stoppable: Phase[] = ["idle", "working", "asleep"];
  function branch(node: Session): React.ReactNode {
    const children = nodes
      .filter((child) => child.swarm?.parent === node.id)
      .sort((a, b) => a.created_at - b.created_at || a.id.localeCompare(b.id));
    const canStop = !!node.swarm?.parent && stoppable.includes(node.phase);
    return (
      <li key={node.id}>
        <div className="swarm-node-row">
          <button
            className="swarm-node"
            onClick={() => select(node.id)}
            title={`Open ${node.name}`}
          >
            <span>
              <strong>{node.name}</strong>
              <small>
                {node.swarm?.role || "agent"}
                {node.model ? ` · ${node.model}` : ""}
              </small>
            </span>
            <Badge phase={node.phase} />
          </button>
          {canStop && (
            <button
              className="node-stop"
              onClick={() => stopVm(node)}
              disabled={stopping === node.id}
              title={`Stop ${node.name}'s VM (reclaim resources; keeps disk & history)`}
              aria-label={`Stop ${node.name}'s VM`}
            >
              <CircleStop size={15} />
            </button>
          )}
        </div>
        {!!children.length && <ul>{children.map(branch)}</ul>}
      </li>
    );
  }
  useEffect(() => {
    let stopped = false;
    api<Acl>(`/sessions/${rootId}/acl`)
      .then((current) => {
        if (!stopped) setAcl(draftFromAcl(current));
      })
      .catch(() => {});
    return () => {
      stopped = true;
    };
  }, [rootId]);
  async function saveAcl() {
    setAclSaving(true);
    setAclResult("");
    setError("");
    try {
      const res = await api<{
        applied_to: { agent: string; applied: boolean }[];
      }>(`/sessions/${rootId}/acl`, "PUT", draftToAcl(acl));
      const applied = res.applied_to.filter((r) => r.applied).length;
      setAclResult(
        `Saved. Applied to ${applied}/${res.applied_to.length} live agent${
          res.applied_to.length === 1 ? "" : "s"
        }; new agents inherit it.`,
      );
    } catch (saveError) {
      setError((saveError as Error).message);
    } finally {
      setAclSaving(false);
    }
  }
  const roots = nodes.filter(
    (node) =>
      !node.swarm?.parent ||
      !nodes.some((other) => other.id === node.swarm?.parent),
  );
  return (
    <div className="swarm-explorer">
      <header className="workspace-header">
        <div>
          <h1>{root?.name || "Swarm"}</h1>
          <p className="muted swarm-explorer-sub">
            {nodes.length} agent{nodes.length === 1 ? "" : "s"}
            {phases ? ` · ${phases}` : ""}
          </p>
        </div>
        <GitBranch size={24} />
      </header>
      <div className="swarm-explorer-body">
        <section className="explorer-card explorer-board">
          <h2>
            <FileText size={15} /> Message board
            <span>
              {posts.length} post{posts.length === 1 ? "" : "s"}
            </span>
          </h2>
          <ErrorBanner error={error} clear={() => setError("")} />
          {posts.length ? (
            <div className="board-split">
              <div className="board-nav">
                <BoardDir
                  node={fold(posts)}
                  name={null}
                  renderPost={(post) => (
                    <button
                      key={post.path}
                      className={`board-row ${post.path === selectedPath ? "selected" : ""}`}
                      onClick={() => {
                        if (post.path === selectedPath) return;
                        setBody(null);
                        setBodyError("");
                        setSelectedPath(post.path);
                      }}
                    >
                      <FileText size={13} />
                      <span>{post.path.split("/").at(-1)}</span>
                    </button>
                  )}
                />
              </div>
              <div className="board-reading">
                {selected ? (
                  <>
                    <h3>{selected.path}</h3>
                    <div className="board-meta">
                      <span>By {name(selected.author)}</span>
                      <span>Updated by {name(selected.updated_by)}</span>
                      <span>
                        Created{" "}
                        {new Date(selected.created_at * 1000).toLocaleString()}
                      </span>
                      <span>
                        Updated{" "}
                        {new Date(selected.updated_at * 1000).toLocaleString()}
                      </span>
                      <span>{selected.bytes} bytes</span>
                    </div>
                    {bodyError ? (
                      <p className="error">{bodyError}</p>
                    ) : (
                      <pre>{body ?? "Loading…"}</pre>
                    )}
                  </>
                ) : (
                  <p className="board-empty">Select a post to read it.</p>
                )}
              </div>
            </div>
          ) : (
            <p className="board-empty">
              No posts yet. Agents publish findings here as they work.
            </p>
          )}
        </section>
        <aside className="explorer-side">
          <section className="explorer-card">
            <h2>
              <Users size={15} /> Agents
            </h2>
            <ul className="swarm-tree">{roots.map(branch)}</ul>
          </section>
          <section className="explorer-card">
            <h2>Egress ACL</h2>
            <p className="muted">
              One policy for the whole swarm. Saving applies it to every live
              agent now, and new agents inherit it.
            </p>
            <AclEditor draft={acl} onChange={setAcl} disabled={aclSaving} />
            {aclResult && <p className="acl-result">{aclResult}</p>}
            <button className="primary" onClick={saveAcl} disabled={aclSaving}>
              {aclSaving ? "Applying…" : "Save & apply to swarm"}
            </button>
          </section>
          <section className="explorer-card">
            <h2>
              <Send size={15} /> Messages
              <span>
                {
                  messages.filter((message) => message.status === "pending")
                    .length
                }{" "}
                queued
              </span>
            </h2>
            {messages.length ? (
              <div className="mail-feed">
                {messages.map((message) => (
                  <div key={message.id}>
                    <strong>
                      {name(message.sender)} → {name(message.recipient)}
                    </strong>
                    <span>{message.status}</span>
                    <p>{message.message}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="board-empty">No parent–child messages yet.</p>
            )}
          </section>
        </aside>
      </div>
    </div>
  );
}
