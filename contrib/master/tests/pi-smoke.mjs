// Real pi process + mock mTLS iso endpoint. No model calls or real VM commands.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, copyFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawn } from "node:child_process";
import https from "node:https";
import http from "node:http";
import { once } from "node:events";

const dir = mkdtempSync(join(tmpdir(), "iso-pi-smoke-"));
let child, server, swarmServer;
try {
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=IP:127.0.0.1,DNS:localhost",
      "-keyout",
      join(dir, "test.key"),
      "-out",
      join(dir, "test.crt"),
      "-days",
      "1",
    ],
    { stdio: "ignore" },
  );
  copyFileSync(join(dir, "test.crt"), join(dir, "ca.crt"));
  const calls = [];
  server = https.createServer(
    {
      key: readFileSync(join(dir, "test.key")),
      cert: readFileSync(join(dir, "test.crt")),
      ca: readFileSync(join(dir, "ca.crt")),
      requestCert: true,
      rejectUnauthorized: true,
    },
    (req, res) => {
      let body = "";
      req.on("data", (b) => {
        body += b;
      });
      req.on("end", () => {
        calls.push({ url: req.url, body: body ? JSON.parse(body) : undefined });
        res.setHeader("content-type", "application/json");
        if (req.url.endsWith("/exec"))
          res.end(
            JSON.stringify({
              stdout: "remote-only\u2028result",
              stderr: "",
              exit_code: 0,
              signal: null,
              truncated: false,
              timed_out: false,
              duration_ms: 1,
            }),
          );
        else if (req.method === "PUT") res.end('{"bytes":4}');
        else
          res.end(
            JSON.stringify({
              size: 5,
              content_b64: Buffer.from("remote file").toString("base64"),
              truncated: false,
            }),
          );
      });
    },
  );
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const config = {
    server: `https://127.0.0.1:${server.address().port}`,
    creds: dir,
    client: "test",
    vm: "11111111-1111-4111-8111-111111111111",
  };
  process.env.MASTER_REMOTE = JSON.stringify(config);
  const { default: extension } = await import("../pi/remote-tools.ts");
  const tools = [];
  extension({ registerTool: (t) => tools.push(t), on: () => {} });
  assert.deepEqual(
    tools.map((t) => t.name),
    ["read", "write", "edit", "bash"],
  );
  const read = await tools[0].execute("read-1", {
    path: "/master-secret-sentinel",
  });
  assert.match(read.content[0].text, /remote file/);
  assert.match(calls.at(-1).url, /master-secret-sentinel/);
  await tools[1].execute("write-1", {
    path: "/home/coder/test.txt",
    content: "test",
  });
  assert.equal(calls.at(-1).body.content, "test");
  // Real pi supplies a host cwd as the fifth argument to extension tools.
  const hostContext = { cwd: "/master/session-not-in-guest" };
  await tools[3].execute(
    "bash-cwd",
    { command: "pwd", timeout: 10 },
    undefined,
    undefined,
    hostContext,
  );
  assert.equal(calls.at(-1).body.cwd, "/home/coder");
  assert.equal(calls.at(-1).body.timeout_ms, 10000);
  await tools[0].execute(
    "read-cwd",
    { path: "test.txt" },
    undefined,
    undefined,
    hostContext,
  );
  assert.equal(
    new URL(calls.at(-1).url, "https://localhost").searchParams.get("path"),
    "/home/coder/test.txt",
  );
  await tools[1].execute(
    "write-cwd",
    { path: "test.txt", content: "test" },
    undefined,
    undefined,
    hostContext,
  );
  assert.equal(
    new URL(calls.at(-1).url, "https://localhost").searchParams.get("path"),
    "/home/coder/test.txt",
  );
  await tools[2].execute(
    "edit-cwd",
    {
      path: "test.txt",
      edits: [{ oldText: "remote file", newText: "updated file" }],
    },
    undefined,
    undefined,
    hostContext,
  );
  assert.equal(
    new URL(calls.at(-1).url, "https://localhost").searchParams.get("path"),
    "/home/coder/test.txt",
  );
  delete process.env.MASTER_REMOTE;
  assert.throws(() =>
    extension({
      registerTool: () => assert.fail("must fail closed"),
      on: () => {},
    }),
  );

  const swarmCalls = [];
  swarmServer = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      assert.equal(req.headers.authorization, "Bearer test");
      assert.equal(req.url, "/worker");
      swarmCalls.push(JSON.parse(body));
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ ok: true }));
    });
  });
  swarmServer.listen(join(dir, "swarm.sock"));
  await once(swarmServer, "listening");
  process.env.MASTER_REMOTE = JSON.stringify(config);
  process.env.MASTER_SWARM = JSON.stringify({
    session: "planner",
    role: "planner",
    parent: null,
    task: "Plan",
    socket: join(dir, "swarm.sock"),
    token: "test",
  });
  const plannerTools = [],
    handlers = new Map();
  extension({
    registerTool: (tool) => plannerTools.push(tool),
    on: (event, handler) => handlers.set(event, handler),
  });
  assert.deepEqual(
    plannerTools.map((tool) => tool.name),
    ["read", "list", "swarm_status", "swarm_send", "swarm_spawn"],
  );
  await plannerTools
    .find((tool) => tool.name === "swarm_spawn")
    .execute("spawn", { name: "Child", role: "worker", task: "Implement" });
  assert.deepEqual(swarmCalls.at(-1), {
    action: "spawn",
    name: "Child",
    role: "worker",
    task: "Implement",
  });
  await plannerTools
    .find((tool) => tool.name === "swarm_send")
    .execute("send", { recipient: "child", message: "Update" });
  assert.deepEqual(swarmCalls.at(-1), {
    action: "send",
    recipient: "child",
    message: "Update",
  });
  await plannerTools
    .find((tool) => tool.name === "swarm_status")
    .execute("status", {});
  assert.deepEqual(swarmCalls.at(-1), { action: "status" });
  assert.throws(
    () =>
      handlers.get("user_bash")().operations.exec("touch forbidden", "/", {}),
    /Planners cannot execute/,
  );
  await plannerTools[0].execute(
    "planner-read",
    { path: "test.txt" },
    undefined,
    undefined,
    hostContext,
  );
  assert.equal(
    new URL(calls.at(-1).url, "https://localhost").searchParams.get("path"),
    "/home/coder/test.txt",
  );
  process.env.MASTER_SWARM = JSON.stringify({
    session: "worker",
    role: "worker",
    parent: "planner",
    task: "Work",
    socket: "/unused",
    token: "test",
  });
  const workerTools = [];
  extension({ registerTool: (tool) => workerTools.push(tool), on: () => {} });
  assert.deepEqual(
    workerTools.map((tool) => tool.name),
    ["read", "write", "edit", "bash", "swarm_status", "swarm_send"],
  );
  delete process.env.MASTER_SWARM;
  delete process.env.MASTER_REMOTE;

  const events = [];
  child = spawn(
    process.execPath,
    [
      resolve("node_modules/.bin/pi"),
      "--mode",
      "rpc",
      "--no-builtin-tools",
      "--no-extensions",
      "--no-skills",
      "--no-prompt-templates",
      "--no-themes",
      "--no-context-files",
      "--no-approve",
      "-e",
      resolve("pi/remote-tools.ts"),
      "--session",
      join(dir, "session.jsonl"),
    ],
    {
      cwd: dir,
      env: {
        PATH: process.env.PATH,
        HOME: dir,
        PI_CODING_AGENT_DIR: join(dir, "config"),
        PI_OFFLINE: "1",
        PI_TELEMETRY: "0",
        MASTER_REMOTE: JSON.stringify(config),
        ...(process.env.ISO_TEST_PLANNER
          ? {
              MASTER_SWARM: JSON.stringify({
                session: "planner",
                role: "planner",
                parent: null,
                task: "Plan",
                socket: "/unused",
                token: "test",
              }),
            }
          : {}),
      },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  let buffer = "";
  let stderr = "";
  child.stderr.on("data", (b) => {
    stderr = (stderr + b).slice(-2000);
  });
  child.stdout.on("data", (b) => {
    buffer += b.toString();
    let index;
    while ((index = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      try {
        events.push(JSON.parse(line));
      } catch {
        /* non-protocol output fails readiness below */
      }
    }
  });
  async function wait(predicate) {
    const until = Date.now() + 20000;
    while (Date.now() < until) {
      const e = events.find(predicate);
      if (e) return e;
      if (child.exitCode !== null) throw new Error(`pi exited: ${stderr}`);
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error(`Timed out: ${stderr}`);
  }
  await wait((e) => e.message === "iso-master-remote-ready");
  child.stdin.write(JSON.stringify({ type: "get_state", id: "state" }) + "\n");
  assert.equal((await wait((e) => e.id === "state")).success, true);
  child.stdin.write(
    JSON.stringify({
      type: "bash",
      id: "shell",
      command: "echo isolation-check",
    }) + "\n",
  );
  const result = await wait((e) => e.id === "shell" && e.type === "response");
  if (process.env.ISO_TEST_PLANNER) {
    assert.ok(result.success === false || result.data?.exitCode !== 0);
    assert.match(JSON.stringify(result), /Planners cannot execute/);
    assert.ok(
      !calls.some((call) => call.body?.args?.[1] === "echo isolation-check"),
    );
  } else {
    assert.equal(result.success, true);
    assert.match(result.data.output, /remote-only\u2028result/);
    assert.equal(calls.at(-1).body.args[1], "echo isolation-check");
  }
  console.log(
    "PASS: real pi RPC readiness, mTLS guest routing, read/write, Unicode framing, fail-closed configuration",
  );
} finally {
  if (child && child.exitCode === null) {
    child.kill("SIGKILL");
    await once(child, "exit");
  }
  if (server) {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
  if (swarmServer) {
    swarmServer.closeAllConnections();
    await new Promise((resolve) => swarmServer.close(resolve));
  }
  rmSync(dir, { recursive: true, force: true });
}
