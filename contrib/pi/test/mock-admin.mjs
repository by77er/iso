// A stand-in for iso-controld's admin API that runs everything on this
// machine, so the pi extension can be exercised without a VM. It implements
// the subset the extension uses: create/get/destroy a VM, ping its agent,
// exec, files and dir. Paths are used as given, so the harness points the
// extension's working directory at a temp directory here.
//
// Start: node mock-admin.mjs <port>   (prints "listening" when ready)

import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import * as http from "node:http";
import * as path from "node:path";

const port = Number(process.argv[2] ?? 0);
const vms = new Map();
let nextId = 1;

const json = (res, status, body) => {
	res.writeHead(status, { "content-type": "application/json" });
	res.end(body === undefined ? "" : JSON.stringify(body));
};
const fail = (res, status, error) => json(res, status, { error });

async function readBody(req) {
	const chunks = [];
	for await (const c of req) chunks.push(c);
	const text = Buffer.concat(chunks).toString("utf8");
	return text ? JSON.parse(text) : {};
}

function exec(req) {
	return new Promise((resolve) => {
		const started = Date.now();
		const cap = req.max_output_bytes ?? 1024 * 1024;
		const child = spawn(req.cmd, req.args ?? [], {
			cwd: req.cwd || undefined,
			env: { ...process.env, ...(req.env ?? {}) },
			stdio: [req.stdin !== undefined ? "pipe" : "ignore", "pipe", "pipe"],
			detached: true,
		});
		let out = Buffer.alloc(0);
		let err = Buffer.alloc(0);
		let truncated = false;
		const take = (buf, data) => {
			if (buf.length >= cap) {
				truncated = true;
				return buf;
			}
			const room = cap - buf.length;
			if (data.length > room) truncated = true;
			return Buffer.concat([buf, data.subarray(0, room)]);
		};
		child.stdout.on("data", (d) => (out = take(out, d)));
		child.stderr.on("data", (d) => (err = take(err, d)));
		if (req.stdin !== undefined) {
			child.stdin.end(req.stdin);
		}
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			try {
				process.kill(-child.pid, "SIGKILL");
			} catch {}
		}, req.timeout_ms ?? 120_000);
		child.on("error", (e) => {
			clearTimeout(timer);
			resolve({ error: `spawn ${req.cmd}: ${e.message}` });
		});
		child.on("close", (code, signal) => {
			clearTimeout(timer);
			resolve({
				exit_code: timedOut ? null : code,
				signal: signal ? 9 : null,
				stdout: out.toString("utf8"),
				stderr: err.toString("utf8"),
				timed_out: timedOut,
				truncated,
				duration_ms: Date.now() - started,
			});
		});
	});
}

const server = http.createServer(async (req, res) => {
	try {
		const url = new URL(req.url, "http://x");
		const parts = url.pathname.split("/").filter(Boolean);
		if (req.method === "POST" && url.pathname === "/vms") {
			const body = await readBody(req);
			const id = `00000000-0000-4000-8000-${String(nextId++).padStart(12, "0")}`;
			vms.set(id, { id, state: "running", template: body.template, egress: body.egress ?? "deny", labels: body.labels ?? {}, principal: body.principal ?? null, allow: body.allow ?? [] });
			return json(res, 200, { id });
		}
		if (req.method === "GET" && url.pathname === "/vms") return json(res, 200, [...vms.values()]);
		if (parts[0] !== "vms" || !parts[1]) return fail(res, 404, "no such route");
		const vm = vms.get(parts[1]);
		if (!vm) return fail(res, 404, `unknown vm ${parts[1]}`);
		const sub = parts[2];
		if (!sub) {
			if (req.method === "GET") return json(res, 200, vm);
			if (req.method === "DELETE") {
				vms.delete(vm.id);
				return json(res, 204);
			}
		}
		if (sub === "agent") return json(res, 200, { agent: "iso-guest-agent", version: "mock", hostname: "mock", uid: process.getuid(), cwd: process.cwd() });
		if (sub === "exec" && req.method === "POST") {
			const body = await readBody(req);
			if (!body.cmd) return fail(res, 400, "cmd is required");
			const r = await exec(body);
			return r.error ? fail(res, 400, r.error) : json(res, 200, r);
		}
		const p = url.searchParams.get("path");
		if (sub === "files") {
			if (!p) return fail(res, 400, "path is required");
			if (req.method === "GET") {
				let st;
				try {
					st = await fs.stat(p);
				} catch (e) {
					return fail(res, 400, `stat ${p}: ${e.message}`);
				}
				if (!st.isFile()) return fail(res, 400, `read ${p}: not a regular file`);
				const max = url.searchParams.has("max_bytes") ? Number(url.searchParams.get("max_bytes")) : 16 * 1024 * 1024;
				const data = (await fs.readFile(p)).subarray(0, max);
				return json(res, 200, { path: p, size: st.size, content_b64: data.toString("base64"), truncated: st.size > max });
			}
			if (req.method === "PUT") {
				const body = await readBody(req);
				const data = body.content_b64 !== undefined ? Buffer.from(body.content_b64, "base64") : Buffer.from(body.content ?? "", "utf8");
				if (body.mkdir) await fs.mkdir(path.dirname(p), { recursive: true });
				try {
					await fs.writeFile(p, data);
				} catch (e) {
					return fail(res, 400, `write ${p}: ${e.message}`);
				}
				if (body.mode !== undefined) await fs.chmod(p, body.mode);
				return json(res, 200, { bytes: data.length });
			}
			if (req.method === "DELETE") {
				try {
					await fs.rm(p, { recursive: url.searchParams.get("recursive") === "true" });
				} catch (e) {
					return fail(res, 400, `remove ${p}: ${e.message}`);
				}
				return json(res, 204);
			}
		}
		if (sub === "dir" && req.method === "GET") {
			if (!p) return fail(res, 400, "path is required");
			let names;
			try {
				names = await fs.readdir(p);
			} catch (e) {
				return fail(res, 400, `list ${p}: ${e.message}`);
			}
			const entries = [];
			for (const name of names.sort()) {
				const st = await fs.lstat(path.join(p, name));
				entries.push({ name, kind: st.isSymbolicLink() ? "symlink" : st.isDirectory() ? "dir" : st.isFile() ? "file" : "other", size: st.size, mode: st.mode & 0o7777 });
			}
			return json(res, 200, { entries });
		}
		return fail(res, 405, "method not allowed");
	} catch (e) {
		return fail(res, 500, e.message);
	}
});

server.listen(port, "127.0.0.1", () => {
	console.log(`listening ${server.address().port}`);
});
