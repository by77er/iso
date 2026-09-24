import { ShieldCheck } from "lucide-react";
import type { Acl } from "../api";

// One egress ACL, edited as text: a mode, a newline/comma-separated host
// allow-list, and optional URI-level rules. Empty everywhere means "use the
// plane's configured defaults".
export interface AclDraft {
  egress: string;
  allow: string;
  rules: string;
}
export const emptyDraft: AclDraft = { egress: "", allow: "", rules: "" };

export function draftFromAcl(acl: Acl): AclDraft {
  return {
    egress: acl.egress ?? "",
    allow: acl.allow.join("\n"),
    rules: acl.rules.join("\n"),
  };
}
const lines = (text: string): string[] =>
  text
    .split(/[\n,]/)
    .map((line) => line.trim())
    .filter(Boolean);
export function draftToAcl(draft: AclDraft): Acl {
  return {
    egress: draft.egress || null,
    allow: lines(draft.allow),
    rules: lines(draft.rules),
  };
}

export default function AclEditor({
  draft,
  onChange,
  disabled,
  title,
}: {
  draft: AclDraft;
  onChange: (draft: AclDraft) => void;
  disabled?: boolean;
  title?: string;
}) {
  return (
    <fieldset className="acl-editor" disabled={disabled}>
      {title && (
        <div className="acl-title">
          <ShieldCheck size={15} /> {title}
        </div>
      )}
      <label>
        Mode
        <select
          value={draft.egress}
          onChange={(e) => onChange({ ...draft, egress: e.target.value })}
        >
          <option value="">Plane default</option>
          <option value="proxy">
            proxy — allow-listed HTTPS, credentials injected
          </option>
          <option value="deny">deny — no external egress</option>
        </select>
      </label>
      <label>
        Allowed hosts
        <textarea
          value={draft.allow}
          onChange={(e) => onChange({ ...draft, allow: e.target.value })}
          placeholder={"github.com\napi.anthropic.com\npypi.org"}
          rows={4}
        />
        <small>
          One host per line. Each becomes <code>allow https://host/**</code>{" "}
          (and wss). Use <code>*</code> to allow all HTTPS.
        </small>
      </label>
      <details className="acl-rules">
        <summary>Advanced: URI rules</summary>
        <textarea
          value={draft.rules}
          onChange={(e) => onChange({ ...draft, rules: e.target.value })}
          placeholder={
            "allow https://api.github.com/**\ndeny https://api.github.com/user/keys"
          }
          rows={3}
        />
        <small>
          Full rule grammar, one per line. Deny wins; replaces the host list
          above when set.
        </small>
      </details>
    </fieldset>
  );
}
