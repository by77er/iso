import { Folder } from "lucide-react";

export interface BoardPost {
  path: string;
  author: string;
  updated_by: string;
  bytes: number;
  created_at: number;
  updated_at: number;
}
export interface BoardNode {
  dirs: Map<string, BoardNode>;
  posts: BoardPost[];
}
export function fold(posts: BoardPost[]): BoardNode {
  const root: BoardNode = { dirs: new Map(), posts: [] };
  for (const post of posts) {
    const segments = post.path.split("/");
    let node = root;
    for (const segment of segments.slice(0, -1)) {
      let next = node.dirs.get(segment);
      if (!next) {
        next = { dirs: new Map(), posts: [] };
        node.dirs.set(segment, next);
      }
      node = next;
    }
    node.posts.push(post);
  }
  return root;
}
export function BoardDir({
  node,
  name,
  renderPost,
}: {
  node: BoardNode;
  name: string | null;
  renderPost: (post: BoardPost) => React.ReactNode;
}) {
  const entries = (
    <>
      {[...node.dirs.entries()].map(([dir, child]) => (
        <BoardDir key={dir} node={child} name={dir} renderPost={renderPost} />
      ))}
      {node.posts.map(renderPost)}
    </>
  );
  if (name === null) return <div className="board-tree">{entries}</div>;
  return (
    <details className="board-dir" open>
      <summary>
        <Folder size={13} /> {name}/
      </summary>
      <div className="board-indent">{entries}</div>
    </details>
  );
}
