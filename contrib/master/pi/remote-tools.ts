// Dedicated headless extension: no local-tool fallback, no VM lifecycle commands.
import https from "node:https";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  createReadTool,
  createWriteTool,
  createEditTool,
  createBashTool,
  type ExtensionAPI,
  type BashOperations,
} from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI) {
  const cfg = JSON.parse(process.env.MASTER_REMOTE!) as {
    server: string;
    creds: string;
    client: string;
    vm: string;
  };
  if (!cfg.server?.startsWith("https://") || !/^[0-9a-f-]{36}$/.test(cfg.vm))
    throw new Error("Missing remote sandbox configuration");
  const tls = {
    ca: readFileSync(join(cfg.creds, "ca.crt")),
    cert: readFileSync(join(cfg.creds, `${cfg.client}.crt`)),
    key: readFileSync(join(cfg.creds, `${cfg.client}.key`)),
  };
  async function call<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<T> {
    const data = body === undefined ? undefined : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = https.request(
        new URL(`/vms/${cfg.vm}${path}`, cfg.server),
        {
          ...tls,
          method,
          signal,
          headers: data
            ? {
                "content-type": "application/json",
                "content-length": Buffer.byteLength(data),
              }
            : {},
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (c) => {
            size += c.length;
            if (size > 24 * 1024 * 1024)
              res.destroy(new Error("iso response too large"));
            else chunks.push(c);
          });
          res.on("error", reject);
          res.on("end", () => {
            if (
              !res.statusCode ||
              res.statusCode < 200 ||
              res.statusCode >= 300
            )
              return reject(new Error(`iso returned HTTP ${res.statusCode}`));
            try {
              resolve(JSON.parse(Buffer.concat(chunks).toString()));
            } catch (e) {
              reject(e);
            }
          });
        },
      );
      req.setTimeout(630000, () =>
        req.destroy(new Error("iso tool request timed out")),
      );
      req.on("error", reject);
      req.end(data);
    });
  }
  const cwd = "/home/coder";
  const file = (p: string) => "/files?" + new URLSearchParams({ path: p });
  const read = {
    readFile: async (p: string) => {
      const r = await call<{ truncated: boolean; content_b64: string }>(
        "GET",
        file(p),
      );
      if (r.truncated)
        throw new Error(
          "File exceeds remote read limit; use bash to read a range",
        );
      return Buffer.from(r.content_b64, "base64");
    },
    access: async (p: string) => {
      await call("GET", file(p) + "&max_bytes=0");
    },
    detectImageMimeType: async () => null,
  };
  const write = {
    writeFile: async (p: string, content: string) => {
      await call("PUT", file(p), { content, mkdir: true });
    },
    mkdir: async () => {}, // PUT mkdir=true creates parents in the guest.
  };
  const bash: BashOperations = {
    exec: async (command, workdir, { onData, signal, timeout }) => {
      const r = await call<{
        stdout: string;
        stderr: string;
        truncated: boolean;
        timed_out: boolean;
        exit_code: number | null;
        signal: number | null;
      }>(
        "POST",
        "/exec",
        {
          cmd: "bash",
          args: ["-lc", command],
          cwd: workdir,
          timeout_ms: Math.min(timeout ?? 600, 600) * 1000,
          max_output_bytes: 262144,
        },
        signal,
      );
      onData(
        Buffer.from(
          r.stdout +
            r.stderr +
            (r.truncated ? "\n[Guest output truncated]\n" : ""),
        ),
      );
      if (r.timed_out) throw new Error("Guest command timed out");
      return { exitCode: r.exit_code ?? (r.signal ? 128 + r.signal : null) };
    },
  };
  const promptGuidelines = [
    "read, write, edit and bash operate only inside the assigned iso microVM. Use bash for file search.",
  ];
  pi.registerTool({
    ...createReadTool(cwd, { operations: read }),
    promptGuidelines,
  });
  pi.registerTool({
    ...createWriteTool(cwd, { operations: write }),
    promptGuidelines,
  });
  pi.registerTool({
    ...createEditTool(cwd, { operations: { ...read, ...write } }),
    promptGuidelines,
  });
  pi.registerTool({
    ...createBashTool(cwd, { operations: bash }),
    promptGuidelines,
  });
  pi.on("before_agent_start", (event) => ({
    systemPrompt: event.systemPrompt.replace(
      `Current working directory: ${process.cwd()}`,
      `Current working directory: ${cwd} (inside an iso microVM; master files are not accessible)`,
    ),
  }));
  pi.on("user_bash", () => ({ operations: bash }));
  pi.on("session_start", (_event, ctx) => {
    pi.setActiveTools(["read", "write", "edit", "bash"]);
    ctx.ui.notify("iso-master-remote-ready", "info");
  });
}
