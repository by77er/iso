// Drive the iso extension's operations against the mock admin API using
// pi's own tool implementations, without a model or a VM.
//
//   node contrib/pi/test/run.mjs
//
// Needs pi installed (npm i -g @mariozechner/pi-coding-agent) and rg/fd on
// PATH (pi keeps copies in ~/.pi/agent/bin).

import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const npmRoot = (await run("npm", ["root", "-g"])).trim();
const piDir = path.join(npmRoot, "@mariozechner/pi-coding-agent");
const piRequire = createRequire(path.join(piDir, "package.json"));

function run(cmd, args) {
	return new Promise((resolve, reject) => {
		const c = spawn(cmd, args, { stdio: ["ignore", "pipe", "inherit"] });
		let out = "";
		c.stdout.on("data", (d) => (out += d));
		c.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(`${cmd} exited ${code}`))));
	});
}

// --- load the extension through jiti with pi's aliases ---
const { createJiti } = await import(pathToFileURL(path.join(piDir, "node_modules/jiti/lib/jiti.mjs")).href);
// Only what iso.ts imports itself; pi's own modules resolve from their tree.
const alias = {
	"@mariozechner/pi-coding-agent": path.join(piDir, "dist/index.js"),
	typebox: piRequire.resolve("typebox"),
};
const jiti = createJiti(import.meta.url, { alias, interopDefault: true });
const ext = await jiti.import(path.join(here, "..", "iso.ts"));
const pi = await import(pathToFileURL(alias["@mariozechner/pi-coding-agent"]).href);

// --- mock server ---
process.env.PATH = `${path.join(os.homedir(), ".pi/agent/bin")}:${process.env.PATH}`;
const mock = spawn(process.execPath, [path.join(here, "mock-admin.mjs"), "0"], { stdio: ["ignore", "pipe", "inherit"] });
const port = await new Promise((resolve) => {
	mock.stdout.on("data", (d) => {
		const m = /listening (\d+)/.exec(String(d));
		if (m) resolve(Number(m[1]));
	});
});
const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "iso-pi-test-"));
process.env.ISO_SERVER = `http://127.0.0.1:${port}`;
process.env.ISO_INSECURE = "1";
process.env.ISO_WORKDIR = tmp;

let failures = 0;
const check = (name, ok, extra = "") => {
	console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : ` ${extra}`}`);
	if (!ok) failures++;
};
const text = (r) => r.content.map((c) => (c.type === "text" ? c.text : "")).join("");

try {
	const cfg = ext.configFromEnv();
	check("config: insecure http", cfg.insecure && cfg.server.startsWith("http://") && cfg.workdir === tmp);
	const client = new ext.IsoClient(cfg);
	const { id } = await client.createVm("test");
	check("create vm", typeof id === "string" && id.length > 10, id);
	const info = await client.agent(id);
	check("agent ping", info.agent === "iso-guest-agent");
	const ops = new ext.GuestOps(client, id);

	const write = pi.createWriteTool(tmp, { operations: ops.write });
	await write.execute("1", { path: "notes/a.txt", content: "hello\nworld\n" });
	check("write (with mkdir)", (await fs.readFile(path.join(tmp, "notes/a.txt"), "utf8")) === "hello\nworld\n");

	const read = pi.createReadTool(tmp, { operations: ops.read });
	const r1 = await read.execute("2", { path: "notes/a.txt" });
	check("read", text(r1).includes("hello") && text(r1).includes("world"), text(r1));

	const edit = pi.createEditTool(tmp, { operations: ops.edit });
	await edit.execute("3", { path: "notes/a.txt", edits: [{ oldText: "world", newText: "there" }] });
	check("edit", (await fs.readFile(path.join(tmp, "notes/a.txt"), "utf8")) === "hello\nthere\n");

	const bash = pi.createBashTool(tmp, { operations: ops.bash });
	const r2 = await bash.execute("4", { command: "echo out; echo err >&2; pwd" });
	check("bash output + cwd", text(r2).includes("out") && text(r2).includes("err") && text(r2).includes(tmp), text(r2));
	let r3;
	try {
		r3 = await bash.execute("5", { command: "exit 3" });
		check("bash exit code surfaces", /exit code 3|exited with code 3/i.test(text(r3)), text(r3));
	} catch (e) {
		check("bash exit code surfaces", /3/.test(e.message), e.message);
	}
	try {
		const r4 = await bash.execute("6", { command: "sleep 5", timeout: 1 });
		check("bash timeout", /timeout|timed out/i.test(text(r4)), text(r4));
	} catch (e) {
		check("bash timeout", /timeout|timed out/i.test(e.message), e.message);
	}

	const ls = pi.createLsTool(tmp, { operations: ops.ls });
	const r5 = await ls.execute("7", { path: "." });
	check("ls", text(r5).includes("notes/"), text(r5));

	const find = pi.createFindTool(tmp, { operations: ops.find });
	const r6 = await find.execute("8", { pattern: "*.txt" });
	check("find (fd in guest)", text(r6).includes("notes/a.txt"), text(r6));

	const r7 = await ext.grepInGuest(ops, tmp, { pattern: "hello" });
	check("grep (rg in guest)", text(r7).trim() === "notes/a.txt:1: hello", JSON.stringify(text(r7)));
	const r8 = await ext.grepInGuest(ops, tmp, { pattern: "nothing-here" });
	check("grep no matches", text(r8) === "No matches found", text(r8));
	const r9 = await ext.grepInGuest(ops, tmp, { pattern: "hello", context: 1 });
	check("grep with context", text(r9).includes("notes/a.txt:1: hello") && text(r9).includes("notes/a.txt-2- there"), JSON.stringify(text(r9)));

	await client.destroyVm(id);
	let gone = false;
	try {
		await client.getVm(id);
	} catch (e) {
		gone = e.status === 404;
	}
	check("destroy vm", gone);
} catch (e) {
	console.log(`FAIL unexpected: ${e.stack ?? e}`);
	failures++;
} finally {
	mock.kill();
	await fs.rm(tmp, { recursive: true, force: true });
}
console.log(failures === 0 ? "all passed" : `${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
