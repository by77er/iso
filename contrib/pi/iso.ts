/**
 * iso — run pi's default tools inside an iso microVM.
 *
 * With this extension installed, `read`, `write`, `edit`, `bash`, `ls`,
 * `find` and `grep` (and `!` shell commands) act on a fresh VM created
 * through the iso admin API instead of on this machine. The harness stays
 * here; only the tool calls cross into the guest, over the daemon's vsock
 * channel to the guest agent. The VM is created on the first tool call and
 * destroyed when the session ends, unless told to keep it.
 *
 * Configuration (environment, or flags where noted):
 *   ISO_SERVER        admin API base URL      (default https://127.0.0.1:7070)
 *   ISO_CREDS         directory with ca.crt, <ISO_CLIENT>.crt, <ISO_CLIENT>.key
 *                     from `isoctl admin issue-client`; or ISO_CA, ISO_CLIENT_CERT,
 *                     ISO_CLIENT_KEY as individual files
 *   ISO_CLIENT        client certificate name  (default admin)
 *   ISO_INSECURE=1    plain HTTP, for a daemon started with ISO_ADMIN_INSECURE=1
 *   ISO_TEMPLATE      template to clone       (default base)      [--iso-template]
 *   ISO_EGRESS        allow | proxy | deny    (default proxy)     [--iso-egress]
 *   ISO_PRINCIPAL     principal for injected credentials          [--iso-principal]
 *   ISO_ALLOW         comma-separated domains the proxy passes    [--iso-allow]
 *   ISO_WORKDIR       working directory in the guest (default /home/coder)
 *   ISO_VM            attach to an existing VM instead of creating one [--iso-vm]
 *   ISO_KEEP=1        do not destroy the VM at session end        [--iso-keep]
 *   ISO_DISABLE=1     leave pi's tools local                      [--no-iso]
 *
 * Install: symlink or copy this file into ~/.pi/agent/extensions/.
 */

import * as http from "node:http";
import * as https from "node:https";
import { readFileSync } from "node:fs";
import { join, posix } from "node:path";
import {
	type BashOperations,
	createBashTool,
	createEditTool,
	createFindTool,
	createGrepTool,
	createLsTool,
	createReadTool,
	createWriteTool,
	DEFAULT_MAX_BYTES,
	type EditOperations,
	type ExtensionAPI,
	type FindOperations,
	formatSize,
	type LsOperations,
	type ReadOperations,
	truncateHead,
	truncateLine,
	type WriteOperations,
} from "@mariozechner/pi-coding-agent";
import { Type } from "typebox";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface IsoCredentials {
	ca: string;
	cert: string;
	key: string;
}

export interface IsoConfig {
	server: string;
	insecure: boolean;
	creds?: IsoCredentials;
	template: string;
	egress: string;
	principal?: string;
	allow: string[];
	workdir: string;
	attachTo?: string;
	keep: boolean;
}

const env = (k: string): string | undefined => {
	const v = process.env[k];
	return v && v.trim() !== "" ? v.trim() : undefined;
};

const truthy = (v: string | undefined) => v !== undefined && ["1", "true", "yes"].includes(v.toLowerCase());

/** Read the configuration from the environment; flags override it later. */
export function configFromEnv(): IsoConfig {
	const insecure = truthy(env("ISO_INSECURE"));
	let creds: IsoCredentials | undefined;
	if (!insecure) {
		const dir = env("ISO_CREDS");
		const name = env("ISO_CLIENT") ?? "admin";
		const ca = env("ISO_CA") ?? (dir ? join(dir, "ca.crt") : undefined);
		const cert = env("ISO_CLIENT_CERT") ?? (dir ? join(dir, `${name}.crt`) : undefined);
		const key = env("ISO_CLIENT_KEY") ?? (dir ? join(dir, `${name}.key`) : undefined);
		if (ca && cert && key) {
			creds = { ca: readFileSync(ca, "utf8"), cert: readFileSync(cert, "utf8"), key: readFileSync(key, "utf8") };
		}
	}
	return {
		server: (env("ISO_SERVER") ?? "https://127.0.0.1:7070").replace(/\/+$/, ""),
		insecure,
		creds,
		template: env("ISO_TEMPLATE") ?? "base",
		egress: env("ISO_EGRESS") ?? "proxy",
		principal: env("ISO_PRINCIPAL"),
		allow: (env("ISO_ALLOW") ?? "")
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean),
		workdir: env("ISO_WORKDIR") ?? "/home/coder",
		attachTo: env("ISO_VM"),
		keep: truthy(env("ISO_KEEP")),
	};
}

// ---------------------------------------------------------------------------
// Admin API client (the generated Rust client's shapes, in a few lines of TS)
// ---------------------------------------------------------------------------

export interface ExecResult {
	exit_code: number | null;
	signal: number | null;
	stdout: string;
	stderr: string;
	timed_out: boolean;
	truncated: boolean;
	duration_ms: number;
}

export interface DirEntry {
	name: string;
	kind: "file" | "dir" | "symlink" | "other";
	size: number;
	mode: number;
}

export class IsoError extends Error {
	constructor(
		public status: number,
		message: string,
	) {
		super(message);
	}
}

export class IsoClient {
	constructor(private cfg: IsoConfig) {}

	request(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<{ status: number; body: any }> {
		const url = new URL(this.cfg.server + path);
		const tls = url.protocol === "https:";
		const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
		const options: https.RequestOptions = {
			method,
			hostname: url.hostname,
			port: url.port || (tls ? 443 : 80),
			path: url.pathname + url.search,
			headers: {
				accept: "application/json",
				...(payload ? { "content-type": "application/json", "content-length": String(payload.length) } : {}),
			},
			signal,
		};
		if (tls) {
			if (!this.cfg.creds) {
				throw new IsoError(0, "iso: https needs client credentials (ISO_CREDS + ISO_CLIENT, or ISO_CA/ISO_CLIENT_CERT/ISO_CLIENT_KEY)");
			}
			Object.assign(options, { ca: this.cfg.creds.ca, cert: this.cfg.creds.cert, key: this.cfg.creds.key });
		}
		return new Promise((resolve, reject) => {
			const req = (tls ? https : http).request(options, (res) => {
				const chunks: Buffer[] = [];
				res.on("data", (c) => chunks.push(c));
				res.on("end", () => {
					const text = Buffer.concat(chunks).toString("utf8");
					let parsed: any = undefined;
					if (text) {
						try {
							parsed = JSON.parse(text);
						} catch {
							parsed = { error: text };
						}
					}
					resolve({ status: res.statusCode ?? 0, body: parsed });
				});
			});
			req.on("error", (e) => reject(new IsoError(0, `iso: ${method} ${path}: ${e.message}`)));
			if (payload) req.write(payload);
			req.end();
		});
	}

	/** A request that must succeed; the daemon's `{"error": ...}` becomes the message. */
	async call(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<any> {
		const { status, body: resp } = await this.request(method, path, body, signal);
		if (status < 200 || status >= 300) {
			throw new IsoError(status, `iso: ${method} ${path} -> ${status}: ${resp?.error ?? JSON.stringify(resp)}`);
		}
		return resp;
	}

	createVm(name: string): Promise<{ id: string }> {
		return this.call("POST", "/vms", {
			template: this.cfg.template,
			egress: this.cfg.egress,
			principal: this.cfg.principal,
			allow: this.cfg.allow,
			labels: { name, "created-by": "pi" },
		});
	}

	getVm(id: string): Promise<any> {
		return this.call("GET", `/vms/${id}`);
	}

	destroyVm(id: string): Promise<void> {
		return this.call("DELETE", `/vms/${id}`);
	}

	agent(id: string): Promise<any> {
		return this.call("GET", `/vms/${id}/agent`);
	}

	exec(
		id: string,
		req: { cmd: string; args?: string[]; cwd?: string; env?: Record<string, string>; stdin?: string; timeout_ms?: number; max_output_bytes?: number },
		signal?: AbortSignal,
	): Promise<ExecResult> {
		return this.call("POST", `/vms/${id}/exec`, req, signal);
	}

	async readFile(id: string, path: string, maxBytes?: number): Promise<{ size: number; content: Buffer; truncated: boolean }> {
		const q = new URLSearchParams({ path });
		if (maxBytes !== undefined) q.set("max_bytes", String(maxBytes));
		const r = await this.call("GET", `/vms/${id}/files?${q}`);
		return { size: r.size, content: Buffer.from(r.content_b64, "base64"), truncated: r.truncated };
	}

	async writeFile(id: string, path: string, content: string | Buffer, mkdir = true): Promise<number> {
		const q = new URLSearchParams({ path });
		const body = typeof content === "string" ? { content, mkdir } : { content_b64: content.toString("base64"), mkdir };
		const r = await this.call("PUT", `/vms/${id}/files?${q}`, body);
		return r.bytes;
	}

	async listDir(id: string, path: string): Promise<DirEntry[]> {
		const r = await this.call("GET", `/vms/${id}/dir?${new URLSearchParams({ path })}`);
		return r.entries;
	}
}

// ---------------------------------------------------------------------------
// Tool operations over a VM
// ---------------------------------------------------------------------------

const sh = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** Everything the tools need from one VM. */
export class GuestOps {
	/** Directory listings fetched by ls, so its per-entry stat() calls do not each cross into the guest. */
	private dirCache = new Map<string, Map<string, DirEntry>>();

	constructor(
		readonly client: IsoClient,
		readonly vm: string,
	) {}

	/** Run a program in the guest, throwing when it could not be started. */
	async run(cmd: string, args: string[], opts: { cwd?: string; timeoutMs?: number; signal?: AbortSignal; maxOutput?: number } = {}): Promise<ExecResult> {
		return this.client.exec(
			this.vm,
			{ cmd, args, cwd: opts.cwd, timeout_ms: opts.timeoutMs, max_output_bytes: opts.maxOutput },
			opts.signal,
		);
	}

	/** `stat -c` of one path; null when it does not exist. */
	async kind(path: string): Promise<"file" | "dir" | "symlink" | "other" | null> {
		const dir = posix.dirname(path);
		const cached = this.dirCache.get(dir)?.get(posix.basename(path));
		if (cached) return cached.kind;
		const r = await this.run("stat", ["-c", "%F", "--", path]);
		if (r.exit_code !== 0) return null;
		const t = r.stdout.trim();
		if (t === "directory") return "dir";
		if (t === "regular file" || t === "regular empty file") return "file";
		if (t === "symbolic link") return "symlink";
		return "other";
	}

	read: ReadOperations = {
		readFile: async (p) => (await this.client.readFile(this.vm, p)).content,
		access: async (p) => {
			await this.client.readFile(this.vm, p, 0);
		},
		detectImageMimeType: async (p) => {
			const byExt: Record<string, string> = { ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp" };
			try {
				const r = await this.run("file", ["--mime-type", "-b", "--", p]);
				const m = r.stdout.trim();
				if (r.exit_code === 0) return ["image/jpeg", "image/png", "image/gif", "image/webp"].includes(m) ? m : null;
			} catch {
				// `file` is not installed in every guest; fall back to the extension.
			}
			return byExt[posix.extname(p).toLowerCase()] ?? null;
		},
	};

	write: WriteOperations = {
		writeFile: async (p, content) => {
			await this.client.writeFile(this.vm, p, content, true);
			this.dirCache.delete(posix.dirname(p));
		},
		mkdir: async (dir) => {
			const r = await this.run("mkdir", ["-p", "--", dir]);
			if (r.exit_code !== 0) throw new Error(r.stderr.trim() || `mkdir ${dir} failed`);
		},
	};

	edit: EditOperations = {
		readFile: this.read.readFile,
		access: this.read.access,
		writeFile: this.write.writeFile,
	};

	bash: BashOperations = {
		exec: async (command, cwd, { onData, signal, timeout }) => {
			const r = await this.run("bash", ["-lc", command], {
				cwd,
				timeoutMs: timeout ? timeout * 1000 : 600_000,
				signal,
				maxOutput: 4 * 1024 * 1024,
			});
			if (r.stdout) onData(Buffer.from(r.stdout));
			if (r.stderr) onData(Buffer.from(r.stderr));
			if (r.truncated) onData(Buffer.from("\n[iso: output truncated at 4 MB inside the guest]\n"));
			if (r.timed_out) throw new Error(`timeout:${timeout ?? 600}`);
			this.dirCache.clear();
			return { exitCode: r.exit_code ?? (r.signal !== null ? 128 + r.signal : null) };
		},
	};

	ls: LsOperations = {
		exists: async (p) => (await this.kind(p)) !== null,
		stat: async (p) => {
			const k = await this.kind(p);
			if (k === null) throw new Error(`ENOENT: ${p}`);
			return { isDirectory: () => k === "dir" };
		},
		readdir: async (p) => {
			const entries = await this.client.listDir(this.vm, p);
			this.dirCache.set(p, new Map(entries.map((e) => [e.name, e])));
			return entries.map((e) => e.name);
		},
	};

	find: FindOperations = {
		exists: async (p) => (await this.kind(p)) !== null,
		glob: async (pattern, cwd, { limit }) => {
			// pi's own fd invocation, run in the guest.
			const args = ["--glob", "--color=never", "--hidden", "--no-require-git", "--max-results", String(limit)];
			let effective = pattern;
			if (pattern.includes("/")) {
				args.push("--full-path");
				if (!pattern.startsWith("/") && !pattern.startsWith("**/") && pattern !== "**") effective = `**/${pattern}`;
			}
			args.push("--", effective, cwd);
			const r = await this.run("fd", args, { maxOutput: DEFAULT_MAX_BYTES * 4 });
			if (r.exit_code !== 0) throw new Error(r.stderr.trim() || `fd exited with code ${r.exit_code}`);
			return r.stdout.split("\n").filter(Boolean);
		},
	};
}

// ---------------------------------------------------------------------------
// grep: pi's built-in always spawns a local rg, so this one runs rg in the
// guest and formats matches the way the built-in does.
// ---------------------------------------------------------------------------

const GREP_DEFAULT_LIMIT = 100;
const GREP_MAX_LINE_LENGTH = 500;

const grepSchema = Type.Object({
	pattern: Type.String({ description: "Search pattern (regex or literal string)" }),
	path: Type.Optional(Type.String({ description: "Directory or file to search (default: current directory)" })),
	glob: Type.Optional(Type.String({ description: "Filter files by glob pattern, e.g. '*.ts' or '**/*.spec.ts'" })),
	ignoreCase: Type.Optional(Type.Boolean({ description: "Case-insensitive search (default: false)" })),
	literal: Type.Optional(Type.Boolean({ description: "Treat pattern as literal string instead of regex (default: false)" })),
	context: Type.Optional(Type.Number({ description: "Number of lines to show before and after each match (default: 0)" })),
	limit: Type.Optional(Type.Number({ description: `Maximum number of matches to return (default: ${GREP_DEFAULT_LIMIT})` })),
});

export async function grepInGuest(
	ops: GuestOps,
	workdir: string,
	params: { pattern: string; path?: string; glob?: string; ignoreCase?: boolean; literal?: boolean; context?: number; limit?: number },
	signal?: AbortSignal,
) {
	const searchPath = posix.resolve(workdir, (params.path ?? ".").replace(/^@/, ""));
	const kind = await ops.kind(searchPath);
	if (kind === null) throw new Error(`Path not found: ${searchPath}`);
	const isDirectory = kind === "dir";
	const limit = Math.max(1, params.limit ?? GREP_DEFAULT_LIMIT);
	const context = params.context && params.context > 0 ? params.context : 0;
	const args = ["--line-number", "--color=never", "--hidden", "--no-heading", "--with-filename", "--max-count", String(limit)];
	if (params.ignoreCase) args.push("--ignore-case");
	if (params.literal) args.push("--fixed-strings");
	if (params.glob) args.push("--glob", params.glob);
	if (context > 0) args.push("--context", String(context));
	args.push("--", params.pattern, searchPath);
	const r = await ops.run("rg", args, { signal, maxOutput: DEFAULT_MAX_BYTES * 4 });
	if (r.exit_code !== 0 && r.exit_code !== 1) throw new Error(r.stderr.trim() || `ripgrep exited with code ${r.exit_code}`);
	if (r.exit_code === 1 || !r.stdout.trim()) return { content: [{ type: "text" as const, text: "No matches found" }], details: undefined };

	const formatPath = (filePath: string) => {
		if (isDirectory) {
			const rel = posix.relative(searchPath, filePath);
			if (rel && !rel.startsWith("..")) return rel;
		}
		return posix.basename(filePath);
	};
	// rg prints `path:line:text` for matches and `path-line-text` for context.
	let matches = 0;
	let linesTruncated = false;
	let matchLimitReached = false;
	const out: string[] = [];
	for (const line of r.stdout.split("\n")) {
		if (!line) continue;
		if (line === "--") {
			out.push("--");
			continue;
		}
		const m = /^(.*?)([:-])(\d+)\2(.*)$/.exec(line);
		if (!m) continue;
		const [, file, sep, num, text] = m;
		if (sep === ":") {
			matches++;
			if (matches > limit) {
				matchLimitReached = true;
				break;
			}
		}
		const { text: shown, wasTruncated } = truncateLine(text, GREP_MAX_LINE_LENGTH);
		if (wasTruncated) linesTruncated = true;
		out.push(context > 0 ? `${formatPath(file)}${sep}${num}${sep} ${shown}` : `${formatPath(file)}:${num}: ${shown}`);
	}
	if (matches === 0) return { content: [{ type: "text" as const, text: "No matches found" }], details: undefined };
	const truncation = truncateHead(out.join("\n"), { maxLines: Number.MAX_SAFE_INTEGER });
	let output = truncation.content;
	const details: Record<string, unknown> = {};
	const notices: string[] = [];
	if (matchLimitReached || matches >= limit) {
		notices.push(`${limit} matches limit reached. Use limit=${limit * 2} for more, or refine pattern`);
		details.matchLimitReached = limit;
	}
	if (truncation.truncated) {
		notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
		details.truncation = truncation;
	}
	if (linesTruncated) {
		notices.push(`Some lines truncated to ${GREP_MAX_LINE_LENGTH} chars. Use read tool to see full lines`);
		details.linesTruncated = true;
	}
	if (notices.length > 0) output += `\n\n[${notices.join(". ")}]`;
	return { content: [{ type: "text" as const, text: output }], details: Object.keys(details).length > 0 ? details : undefined };
}

// ---------------------------------------------------------------------------
// The extension
// ---------------------------------------------------------------------------

export default function (pi: ExtensionAPI) {
	pi.registerFlag("no-iso", { description: "Run pi's tools locally instead of in an iso VM", type: "boolean" });
	pi.registerFlag("iso-vm", { description: "Attach to this iso VM id instead of creating one", type: "string" });
	pi.registerFlag("iso-template", { description: "iso template to clone (default: base)", type: "string" });
	pi.registerFlag("iso-egress", { description: "iso egress mode: allow, proxy, deny (default: proxy)", type: "string" });
	pi.registerFlag("iso-principal", { description: "iso principal whose credentials the proxy injects", type: "string" });
	pi.registerFlag("iso-allow", { description: "Comma-separated domains the iso proxy passes", type: "string" });
	pi.registerFlag("iso-keep", { description: "Keep the iso VM when the session ends", type: "boolean" });

	let cfg: IsoConfig | null = null;
	let client: IsoClient | null = null;
	let ops: GuestOps | null = null;
	let created = false;
	let disabled = truthy(env("ISO_DISABLE"));

	const localCwd = process.cwd();
	const localGrep = createGrepTool(localCwd);
	const local = {
		read: createReadTool(localCwd),
		write: createWriteTool(localCwd),
		edit: createEditTool(localCwd),
		bash: createBashTool(localCwd),
		ls: createLsTool(localCwd),
		find: createFindTool(localCwd),
	};

	/** The VM, created on first use. */
	async function guest(ctx: { ui: any }): Promise<GuestOps> {
		if (ops) return ops;
		if (!cfg) cfg = configFromEnv();
		client ??= new IsoClient(cfg);
		let id: string;
		if (cfg.attachTo) {
			id = (await client.getVm(cfg.attachTo)).id;
		} else {
			const name = `pi-${pi.getSessionName?.() ?? process.pid}`.replace(/[^a-zA-Z0-9_.-]+/g, "-").slice(0, 60);
			id = (await client.createVm(name)).id;
			created = true;
		}
		// Wait for the agent: a warm clone answers within a second, a cold boot
		// takes a few.
		const deadline = Date.now() + 60_000;
		let last = "";
		while (Date.now() < deadline) {
			try {
				await client.agent(id);
				last = "";
				break;
			} catch (e) {
				last = (e as Error).message;
				await new Promise((r) => setTimeout(r, 500));
			}
		}
		if (last) throw new Error(`iso: VM ${id} came up but its agent never answered: ${last}`);
		ops = new GuestOps(client, id);
		ctx.ui?.setStatus?.("iso", ctx.ui?.theme?.fg?.("accent", `iso: ${id.slice(0, 8)}`) ?? `iso: ${id.slice(0, 8)}`);
		return ops;
	}

	async function release() {
		if (ops && created && cfg && !cfg.keep && client) {
			try {
				await client.destroyVm(ops.vm);
			} catch {
				// Best effort: the daemon's supervisor reaps ephemeral VMs anyway.
			}
		}
		ops = null;
		created = false;
	}

	const workdir = () => (cfg ?? configFromEnv()).workdir;

	// Each built-in, rebuilt over the guest's operations at call time so the
	// VM is only created when a tool actually runs.
	pi.registerTool({
		...local.read,
		async execute(id, params, signal, onUpdate, ctx) {
			if (disabled) return local.read.execute(id, params, signal, onUpdate);
			const g = await guest(ctx);
			return createReadTool(workdir(), { operations: g.read }).execute(id, params, signal, onUpdate);
		},
	});
	pi.registerTool({
		...local.write,
		async execute(id, params, signal, onUpdate, ctx) {
			if (disabled) return local.write.execute(id, params, signal, onUpdate);
			const g = await guest(ctx);
			return createWriteTool(workdir(), { operations: g.write }).execute(id, params, signal, onUpdate);
		},
	});
	pi.registerTool({
		...local.edit,
		async execute(id, params, signal, onUpdate, ctx) {
			if (disabled) return local.edit.execute(id, params, signal, onUpdate);
			const g = await guest(ctx);
			return createEditTool(workdir(), { operations: g.edit }).execute(id, params, signal, onUpdate);
		},
	});
	pi.registerTool({
		...local.bash,
		promptGuidelines: [
			"bash, read, write, edit, ls, find and grep run inside a Debian microVM (iso), not on the user's machine; its working directory is the one in the system prompt, and files on the user's machine are not visible.",
			"Inside the iso VM, install packages with `sudo apt install`; outbound HTTPS goes through a proxy that injects credentials, so never ask for or paste API tokens.",
		],
		async execute(id, params, signal, onUpdate, ctx) {
			if (disabled) return local.bash.execute(id, params, signal, onUpdate);
			const g = await guest(ctx);
			return createBashTool(workdir(), { operations: g.bash }).execute(id, params, signal, onUpdate);
		},
	});
	pi.registerTool({
		...local.ls,
		async execute(id, params, signal, onUpdate, ctx) {
			if (disabled) return local.ls.execute(id, params, signal, onUpdate);
			const g = await guest(ctx);
			return createLsTool(workdir(), { operations: g.ls }).execute(id, params, signal, onUpdate);
		},
	});
	pi.registerTool({
		...local.find,
		async execute(id, params, signal, onUpdate, ctx) {
			if (disabled) return local.find.execute(id, params, signal, onUpdate);
			const g = await guest(ctx);
			return createFindTool(workdir(), { operations: g.find }).execute(id, params, signal, onUpdate);
		},
	});
	pi.registerTool({
		name: "grep",
		label: "grep",
		description: `Search file contents for a pattern in the working directory (inside the iso VM). Returns up to ${GREP_DEFAULT_LIMIT} matches as path:line: text, with optional context lines.`,
		promptSnippet: "Search file contents for a pattern (ripgrep)",
		parameters: grepSchema,
		async execute(_id, params, signal, _onUpdate, ctx) {
			if (disabled) return localGrep.execute(_id, params, signal, _onUpdate);
			const g = await guest(ctx);
			return grepInGuest(g, workdir(), params, signal);
		},
	});

	// `!` shell commands go to the guest too.
	pi.on("user_bash", () => {
		if (disabled || !ops) return;
		return { operations: ops.bash };
	});

	pi.on("session_start", async (_event, ctx) => {
		if (pi.getFlag("no-iso")) disabled = true;
		if (disabled) return;
		cfg = configFromEnv();
		// Nothing configured on this machine: stay local rather than fail the
		// first tool call. ISO_SERVER or ISO_CREDS (or ISO_INSECURE) turns it on.
		if (!env("ISO_SERVER") && !cfg.creds && !cfg.insecure) {
			disabled = true;
			ctx.ui?.notify?.("iso: not configured (set ISO_SERVER and ISO_CREDS); tools stay local", "info");
			return;
		}
		const flag = (k: string) => pi.getFlag(k) as string | undefined;
		if (flag("iso-vm")) cfg.attachTo = flag("iso-vm");
		if (flag("iso-template")) cfg.template = flag("iso-template")!;
		if (flag("iso-egress")) cfg.egress = flag("iso-egress")!;
		if (flag("iso-principal")) cfg.principal = flag("iso-principal");
		if (flag("iso-allow")) cfg.allow = flag("iso-allow")!.split(",").map((s) => s.trim()).filter(Boolean);
		if (pi.getFlag("iso-keep")) cfg.keep = true;
		client = new IsoClient(cfg);
		ctx.ui?.setStatus?.("iso", `iso: ${cfg.attachTo ? `attach ${cfg.attachTo.slice(0, 8)}` : `new ${cfg.template}`}`);
	});

	pi.on("session_shutdown", async () => {
		await release();
	});

	// The model sees the guest's working directory, not this machine's.
	pi.on("before_agent_start", async (event) => {
		if (disabled) return;
		const c = cfg ?? configFromEnv();
		const where = ops ? `iso VM ${ops.vm}` : `an iso VM (created on first tool use, template ${c.template})`;
		return {
			systemPrompt: event.systemPrompt.replace(
				`Current working directory: ${localCwd}`,
				`Current working directory: ${c.workdir} (inside ${where}; the user's own machine is not visible to tools)`,
			),
		};
	});

	pi.registerCommand("iso", {
		description: "iso VM: /iso [status|new|rm|keep]",
		handler: async (args, ctx) => {
			const sub = (args ?? "").trim() || "status";
			switch (sub) {
				case "status":
					ctx.ui.notify(ops ? `iso VM ${ops.vm} (${created ? "created by this session" : "attached"})` : "no iso VM yet; one is created on the first tool call", "info");
					break;
				case "new":
					await release();
					await guest(ctx);
					ctx.ui.notify(`iso VM ${ops!.vm} ready`, "info");
					break;
				case "rm":
					if (ops && client) {
						const id = ops.vm;
						created = true;
						if (cfg) cfg.keep = false;
						await release();
						ctx.ui.notify(`destroyed iso VM ${id}`, "info");
					}
					break;
				case "keep":
					if (cfg) cfg.keep = true;
					ctx.ui.notify(ops ? `iso VM ${ops.vm} will be kept` : "the next VM will be kept", "info");
					break;
				default:
					ctx.ui.notify("usage: /iso [status|new|rm|keep]", "warning");
			}
		},
	});
}
