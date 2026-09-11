import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
const directory = mkdtempSync(join(tmpdir(), "iso-master-browser-"));
const config = {
  demo: true,
  pi_model: "demo/planner",
  pi_models: ["demo/planner", "demo/worker"],
  bind: "127.0.0.1:8791",
  public_origin: "http://127.0.0.1:8791",
  secure_cookie: false,
  data_dir: directory,
  ui_dir: resolve("dist"),
  idle_seconds: 60,
  planes: ["east", "west"].map((id) => ({
    id,
    server: "demo",
    creds: "unused",
    template: "debian",
  })),
};
const path = join(directory, "config.json");
writeFileSync(path, JSON.stringify(config));
const child = spawn(resolve("../../target/debug/iso-master"), [path], {
  env: {
    ...process.env,
    MASTER_USER: "admin",
    MASTER_PASSWORD: "browser-test-password",
  },
  stdio: "inherit",
});
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => child.kill("SIGTERM"));
child.on("exit", (code) => {
  rmSync(directory, { recursive: true, force: true });
  process.exitCode = code || 0;
});
