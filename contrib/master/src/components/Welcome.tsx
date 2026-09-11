import { Layers, Plus, Code2, Search, ShieldCheck, Moon } from "lucide-react";

export default function Welcome({ create }: { create: () => void }) {
  return (
    <div className="welcome">
      <div className="welcome-icon">
        <Layers size={30} />
      </div>
      <div className="eyebrow">LESS SETUP. MORE BUILDING.</div>
      <h1>A workspace for every idea.</h1>
      <p>
        Start a conversation with an agent. It gets its own isolated
        <br className="desktop-break" /> environment, remembers its work, and
        sleeps when you do.
      </p>
      <button className="primary" onClick={create}>
        <Plus size={18} />
        Create your first agent
      </button>
      <div className="feature-grid">
        <div>
          <Code2 />
          <h3>Build something</h3>
          <p>From a small script to a new application.</p>
        </div>
        <div>
          <Search />
          <h3>Explore a codebase</h3>
          <p>Understand, review, and improve existing code.</p>
        </div>
        <div>
          <ShieldCheck />
          <h3>Keep it isolated</h3>
          <p>Tools run in a dedicated microVM, not on the master.</p>
        </div>
      </div>
      <small>
        <Moon size={15} />
        Workspaces resume automatically when you send a message.
      </small>
    </div>
  );
}
