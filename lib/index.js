import z from "@deepseek-ai/schemastery";
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path, { dirname } from "node:path";
import { createHash } from "node:crypto";
import ssh2 from "ssh2";
import { FsError, FsTargetKey, FsVersion } from "@deepseek-ai/dsh-fs";
import { SandboxedFileSystem } from "@deepseek-ai/dsh-fs-sandbox";
import { LocalSubprocessRuntime } from "@deepseek-ai/dsh-subprocess-local";
import { SandboxBashExecutor } from "@deepseek-ai/dsh-bash-sandbox";
//#region src/config.ts
/**
* Plugin configuration schema. Schemastery is mandatory: the Loader applies
* row `config` through it, and a zod schema rejects the undefined row config
* (the dsh-remote postmortem lesson).
* @module dsh-remote-development/config
*/
const Config = z.object({
	/** Default SSH host for CLI/headless use (empty → start with no machine). */
	host: z.string().default(""),
	/** Default SSH port. */
	port: z.number().step(1).min(1).max(65535).default(22),
	/** Default SSH login user. */
	username: z.string().default(""),
	/** Default password (only when the remote has no key). */
	password: z.string().default(""),
	/** Explicit private-key path (never auto-reads ~/.ssh). */
	privateKeyPath: z.string().default(""),
	/** Key passphrase when the key is encrypted. */
	passphrase: z.string().default(""),
	/** Default remote workspace root for CLI/headless use (empty → none). */
	workspace: z.string().default(""),
	/** Per-command timeout in milliseconds. */
	commandTimeoutMs: z.number().step(1).min(1e3).default(2e4),
	/** SSH connection establishment timeout in milliseconds. */
	connectTimeoutMs: z.number().step(1).min(1e3).default(15e3),
	/** Hard ceiling on collected remote command output, in characters. */
	maxOutputChars: z.number().step(1).min(1024).default(2e5),
	/** Skip remote file reads larger than this many bytes (0 = no cap). */
	maxFileBytes: z.number().step(1).min(0).default(52428800),
	/** Host-key policy: `accept-new` (default) | `verify` | `off`. */
	hostKeyMode: z.string().default("accept-new"),
	/** Use the OpenSSH agent (SSH_AUTH_SOCK) when no password/key is configured. */
	useAgent: z.boolean().default(false),
	/** Allow keyboard-interactive auth (OTP/MFA) using the configured password. */
	keyboardInteractive: z.boolean().default(false),
	/** Jump host / bastion; an empty `host` means none. */
	proxy: z.object({
		host: z.string().default(""),
		port: z.number().step(1).min(1).max(65535).default(22),
		username: z.string().default(""),
		password: z.string().default(""),
		privateKeyPath: z.string().default(""),
		passphrase: z.string().default("")
	}),
	/** Append executed remote commands to the audit log under the harness home. */
	auditLog: z.boolean().default(true),
	/** Root holding anchor workspace directories; empty → `$DSH_HOME/remote-workspaces`. */
	anchorRoot: z.string().default(""),
	/** ripgrep command name on the remote host for the grep/glob tools. */
	remoteRipgrep: z.string().default("rg")
});
//#endregion
//#region src/hostkey.ts
/**
* Host-key fingerprint helpers (TOFU). ssh2 ≥1.17 hands `hostVerifier` the RAW
* wire-format host-key blob (`string(algo) string(keydata)`), not the older
* `{ algo, hash }` object — both shapes are accepted defensively.
* @module dsh-remote-development/hostkey
*/
/**
* Extract the SSH host-key algorithm name from a raw host-key blob.
* @param blob - the ssh2 hostVerifier key argument.
* @returns the algorithm name, or '' when unreadable.
*/
function blobAlgorithm(blob) {
	if (!Buffer.isBuffer(blob) || blob.length < 4) return "";
	try {
		const len = blob.readUInt32BE(0);
		return blob.toString("utf8", 4, 4 + len);
	} catch {
		return "";
	}
}
/**
* SHA-256 fingerprint (unpadded base64, the known_hosts `SHA256:…` body) of a
* host-key blob.
* @param key - raw Buffer blob or the legacy `{ hash }` object.
* @returns the fingerprint string.
* @throws when no key material is present.
*/
function keyFingerprint(key) {
	const blob = Buffer.isBuffer(key) ? key : key?.hash;
	if (!blob) throw new Error("host key missing (hostVerifier received no key blob)");
	return createHash("sha256").update(blob).digest("base64");
}
/**
* Stateful TOFU guard for one host:port. `verify` additionally rejects hosts
* never seen before; `off` accepts everything.
*/
var HostKeyGuard = class {
	mode;
	store;
	known;
	/**
	* @param mode - the machine's host-key policy.
	* @param store - read/write access to the durable known-hosts map.
	*/
	constructor(mode, store) {
		this.mode = mode;
		this.store = store;
		this.known = new Map(Object.entries(store.read()));
	}
	/**
	* Verify one presented host key per the TOFU policy.
	* @param hostId - `host:port` registry key.
	* @param key - the presented key blob.
	* @returns the decision; `recorded` means a first-seen key was just trusted.
	*/
	verify(hostId, key) {
		if (this.mode === "off") return { kind: "trusted" };
		let fingerprint;
		try {
			fingerprint = keyFingerprint(key);
		} catch {
			return {
				kind: "rejected",
				reason: "host key missing from the SSH handshake"
			};
		}
		const stored = this.known.get(hostId);
		if (stored) {
			if (stored.fingerprint === fingerprint) return { kind: "trusted" };
			return {
				kind: "rejected",
				reason: `host key for ${hostId} CHANGED (stored ${stored.fingerprint}, received ${fingerprint}) — possible man-in-the-middle; re-trust it from the settings page if this is expected`
			};
		}
		if (this.mode === "verify") return {
			kind: "rejected",
			reason: `unknown host key for ${hostId} (hostKeyMode=verify)`
		};
		const entry = {
			algo: blobAlgorithm(key) || "unknown",
			fingerprint,
			firstSeen: (/* @__PURE__ */ new Date()).toISOString()
		};
		this.known.set(hostId, entry);
		this.store.write(Object.fromEntries(this.known));
		return { kind: "recorded" };
	}
	/**
	* Drop one host's trusted key so the next connect re-records it.
	* @param hostId - `host:port` registry key.
	*/
	forget(hostId) {
		this.known.delete(hostId);
		this.store.write(Object.fromEntries(this.known));
	}
};
//#endregion
//#region src/paths.ts
/**
* Collapse `//`, strip a trailing slash (except the root), and resolve `.`/`..`
* lexically. No I/O: remote realpath is a separate round trip callers opt into.
* @param p - remote path to normalize.
* @returns the normalized absolute-or-relative remote path.
*/
function normalizeRemotePath(p) {
	let s = String(p ?? "").replace(/\\/g, "/");
	if (!s) return "";
	const absolute = s.startsWith("/");
	const out = [];
	for (const seg of s.split("/")) {
		if (seg === "" || seg === ".") continue;
		if (seg === "..") {
			if (out.length > 0 && out[out.length - 1] !== "..") out.pop();
			else if (!absolute) out.push("..");
			continue;
		}
		out.push(seg);
	}
	const joined = out.join("/");
	if (absolute) return "/" + joined;
	return joined || ".";
}
/**
* The parent directory of a remote path.
* @param p - remote path.
* @returns the parent path ('/' for root children, '.' for a bare name).
*/
function remoteDirname(p) {
	const norm = normalizeRemotePath(p);
	const i = norm.lastIndexOf("/");
	if (i < 0) return ".";
	if (i === 0) return "/";
	return norm.slice(0, i);
}
/**
* The final segment of a remote path.
* @param p - remote path.
* @returns the basename ('' for the root).
*/
function remoteBasename(p) {
	const norm = normalizeRemotePath(p);
	if (norm === "/") return "";
	const i = norm.lastIndexOf("/");
	return i < 0 ? norm : norm.slice(i + 1);
}
/**
* The path relative to `root`, or `null` when `p` is not under it. Both inputs
* are normalized first, so either spelling works.
* @param root - candidate ancestor directory.
* @param p - candidate descendant path.
* @returns the relative path ('' when equal), or null when not under the root.
*/
function relUnder(root, p) {
	const r = normalizeRemotePath(root);
	const norm = normalizeRemotePath(p);
	if (r === norm) return "";
	const prefix = r === "/" ? "/" : r + "/";
	if (!norm.startsWith(prefix)) return null;
	return norm.slice(prefix.length);
}
/**
* Quote one string as a single POSIX shell word (single-quote escaping).
* @param s - raw string to quote.
* @returns the safely quoted word.
*/
function shq(s) {
	return `'${String(s ?? "").replaceAll("'", `'\\''`)}'`;
}
/**
* Compose one remote command line from an argv vector. Every element is
* quoted, so the join is safe under the login shell that runs SSH exec.
* @param argv - exact program and arguments.
* @returns the quoted command line.
*/
function argvToRemoteCommand(argv) {
	return argv.map(shq).join(" ");
}
/** Deterministic 8-hex suffix for disambiguating same-named anchors. */
function shortHash(s) {
	let h = 5381;
	for (let i = 0; i < s.length; i++) h = (h << 5) + h + s.charCodeAt(i) | 0;
	return (h >>> 0).toString(16).padStart(8, "0");
}
/**
* Truncate collected text to a character ceiling, keeping the HEAD (command
* output reads best from the top) and marking nothing — the caller decides
* how to surface truncation.
* @param s - collected text.
* @param maxChars - inclusive ceiling.
* @returns the possibly shortened text.
*/
function truncateHead(s, maxChars) {
	if (s.length <= maxChars) return s;
	return s.slice(0, Math.max(0, maxChars));
}
//#endregion
//#region src/pool.ts
/**
* Per-machine SSH connection pool (one persistent client per remote identity)
* with TOFU host-key verification, password/key/agent/keyboard-interactive
* auth, optional proxy jump, exec with bounded output + timeout + one stale-
* connection retry, and a timeout-guarded SFTP surface.
*
* The pool is testable without a network: the `clientFactory` option injects
* fake ssh2 clients. Windows remote machines are detected and refused with a
* clear error — the Git Bash adapter is a reserved follow-up.
* @module dsh-remote-development/pool
*/
const { Client } = ssh2;
/** Raised when the remote machine is a Windows host (unsupported in v1). */
var UnsupportedRemoteError = class extends Error {
	constructor() {
		super("the remote machine runs Windows, which dsh-remote-development does not support yet (POSIX remotes only in v1)");
		this.name = "UnsupportedRemoteError";
	}
};
const CHANNEL_DEAD_PATTERN = /channel open failure|open failed|unexpected .*session termination|session termination|disconnect/i;
/**
* One persistent SSH connection to a single remote identity. Concurrent calls
* share the connection; a dead pooled connection is invalidated and retried
* once on a fresh one. An epoch token orphans in-flight connects after a
* target change or close.
*/
var SshPool = class SshPool {
	target;
	tunablesSnapshot;
	hostKeys;
	newClient;
	client = null;
	connecting = null;
	sftpSession = null;
	proxyPool = null;
	epoch = 0;
	platform = "unknown";
	detecting = null;
	/**
	* @param target - connection identity and credentials.
	* @param tunables - timeouts and output caps (live plugin config).
	* @param hostKeys - durable TOFU storage.
	* @param newClient - client factory (tests inject fakes).
	*/
	constructor(target, tunables, hostKeys, newClient = () => new Client()) {
		this.target = { ...target };
		this.tunablesSnapshot = { ...tunables };
		this.hostKeys = hostKeys;
		this.newClient = newClient;
	}
	/** The identity this pool is pinned to. */
	get targetInfo() {
		return this.target;
	}
	/** The live tunables (output caps, timeouts) this pool applies. */
	get tunables() {
		return this.tunablesSnapshot;
	}
	/** Detected remote platform ('unknown' before the first command). */
	get platformInfo() {
		return this.platform;
	}
	/** Replace connection tunables (a settings change reaches live pools). */
	retune(tunables) {
		this.tunablesSnapshot = { ...tunables };
	}
	/**
	* Drop the cached connection so the next call opens a fresh one. Called when
	* a channel error shows the pooled connection died server-side.
	*/
	invalidate() {
		this.epoch++;
		const client = this.client;
		this.client = null;
		const sftp = this.sftpSession;
		this.sftpSession = null;
		if (sftp) try {
			sftp.end();
		} catch {}
		const pending = this.connecting;
		this.connecting = null;
		pending?.catch(() => {});
		if (this.proxyPool) {
			try {
				this.proxyPool.close();
			} catch {}
			this.proxyPool = null;
		}
		if (client) try {
			client.end();
		} catch {}
	}
	/** Close the connection and orphan every in-flight connect. */
	close() {
		this.invalidate();
	}
	/** Connect (or return the live client). */
	connect() {
		if (this.client) return Promise.resolve(this.client);
		if (this.connecting) return this.connecting;
		const epoch = this.epoch;
		const pending = this.doConnect(epoch);
		this.connecting = pending;
		const clear = () => {
			if (this.epoch === epoch && this.connecting === pending) this.connecting = null;
		};
		pending.then(clear, clear);
		return pending;
	}
	async doConnect(epoch) {
		const isCurrent = () => this.epoch === epoch;
		const client = this.newClient();
		let settled = false;
		const fail = (err) => {
			if (settled) throw err;
			settled = true;
			if (isCurrent() && this.client === client) this.client = null;
			throw err;
		};
		let sock;
		const proxy = this.target.proxy;
		if (proxy && proxy.host) try {
			this.proxyPool = new SshPool({
				host: proxy.host,
				port: proxy.port || 22,
				username: proxy.username || this.target.username || "root",
				password: proxy.password,
				privateKeyPath: proxy.privateKeyPath,
				passphrase: proxy.passphrase,
				useAgent: false,
				keyboardInteractive: false,
				hostKeyMode: this.target.hostKeyMode
			}, this.tunablesSnapshot, this.hostKeys, this.newClient);
			const bastion = await this.proxyPool.connect();
			if (!isCurrent()) throw new Error("ssh target changed during proxy connect");
			sock = await new Promise((resolve, reject) => {
				bastion.forwardOut("127.0.0.1", 0, this.target.host, this.target.port, (err, channel) => {
					if (err) reject(/* @__PURE__ */ new Error(`proxy forward to target failed: ${err.message}`));
					else resolve(channel);
				});
			});
		} catch (err) {
			return fail(err);
		}
		return new Promise((resolve, reject) => {
			const rejectOnce = (err) => {
				if (settled) return;
				settled = true;
				if (isCurrent() && this.client === client) this.client = null;
				reject(err);
			};
			client.on("ready", () => {
				if (settled) return;
				settled = true;
				if (!isCurrent()) {
					try {
						client.end();
					} catch {}
					reject(/* @__PURE__ */ new Error("ssh target changed during connect"));
					return;
				}
				this.client = client;
				resolve(client);
			});
			client.on("error", (err) => rejectOnce(err));
			client.on("close", () => rejectOnce(/* @__PURE__ */ new Error("ssh connection closed")));
			const buildOpts = () => {
				const opts = {
					host: this.target.host,
					port: this.target.port,
					username: this.target.username,
					readyTimeout: this.tunablesSnapshot.connectTimeoutMs,
					keepaliveInterval: 15e3,
					keepaliveCountMax: 3,
					hostVerifier: (key) => {
						if (this.target.hostKeyMode === "off") return true;
						let fingerprint;
						try {
							fingerprint = keyFingerprint(key);
						} catch {
							return false;
						}
						const hostId = `${this.target.host}:${this.target.port}`;
						const stored = this.hostKeys.read()[hostId];
						if (stored) return stored.fingerprint === fingerprint;
						if (this.target.hostKeyMode === "verify") return false;
						this.hostKeys.write({
							...this.hostKeys.read(),
							[hostId]: {
								algo: "unknown",
								fingerprint,
								firstSeen: (/* @__PURE__ */ new Date()).toISOString()
							}
						});
						return true;
					}
				};
				if (sock) opts.sock = sock;
				if (this.target.useAgent && process.env.SSH_AUTH_SOCK) opts.agent = process.env.SSH_AUTH_SOCK;
				if (this.target.password) {
					opts.password = this.target.password;
					opts.tryKeyboard = true;
				} else if (this.target.keyboardInteractive && !this.target.privateKeyPath) opts.tryKeyboard = true;
				if (this.target.privateKeyPath) {
					const keyPath = this.target.privateKeyPath.startsWith("~/") ? path.join(homedir(), this.target.privateKeyPath.slice(1)) : this.target.privateKeyPath;
					let key;
					try {
						key = readFileSync(keyPath);
					} catch (err) {
						throw new Error(`cannot read private key "${keyPath}": ${err.message}`);
					}
					opts.privateKey = key;
					if (this.target.passphrase) opts.passphrase = this.target.passphrase;
				} else if (!this.target.password && !opts.agent) throw new Error("no credentials: set a password or a private key path to connect");
				return opts;
			};
			let opts;
			try {
				opts = buildOpts();
			} catch (err) {
				rejectOnce(err);
				return;
			}
			if (opts.tryKeyboard === true) client.on("keyboard-interactive", (_name, _instructions, _lang, prompts, finish) => {
				finish(prompts.map(() => this.target.password));
			});
			client.connect(opts);
		});
	}
	/**
	* Detect the remote platform once per target. Windows remotes are refused in
	* v1; detection failures land on 'posix' (the overwhelmingly common case).
	*/
	async detectPlatform() {
		if (this.platform !== "unknown") return this.platform;
		if (this.detecting) return this.detecting.then(() => this.platform);
		this.detecting = (async () => {
			try {
				const res = await this.execOnce("uname -s", Math.min(this.tunablesSnapshot.commandTimeoutMs, 8e3), {});
				if (/mingw|msys|cygwin|windows/i.test(res.stdout) || /mingw|msys|cygwin|windows/i.test(res.stderr)) {
					this.platform = "windows";
					return;
				}
				this.platform = "posix";
			} catch {
				this.platform = "posix";
			}
		})();
		try {
			await this.detecting;
		} finally {
			this.detecting = null;
		}
		return this.platform;
	}
	/**
	* Run one remote command with bounded output, timeout kill, and one
	* stale-connection retry. Windows remotes fail loud before anything runs.
	* @param command - remote command line (run under the login shell).
	* @param opts - timeout override, stdin payload, and abort signal.
	* @returns exit facts and collected output.
	*/
	async exec(command, opts = {}) {
		if (await this.detectPlatform() === "windows") throw new UnsupportedRemoteError();
		const timeoutMs = opts.timeoutMs ?? this.tunablesSnapshot.commandTimeoutMs;
		let retried = false;
		const attempt = () => this.execOnce(command, timeoutMs, opts);
		try {
			return await attempt();
		} catch (err) {
			if (retried || !CHANNEL_DEAD_PATTERN.test(String(err.message))) throw err;
			retried = true;
			this.invalidate();
			return attempt();
		}
	}
	execOnce(command, timeoutMs, opts) {
		return this.connect().then((client) => new Promise((resolve, reject) => {
			client.exec(command, {}, (err, stream) => {
				if (err) {
					reject(/* @__PURE__ */ new Error(`ssh exec failed: ${err.message}`));
					return;
				}
				let stdout = "";
				let stderr = "";
				let settled = false;
				let code = null;
				let sig = null;
				let timedOut = false;
				const hardCap = Math.max(this.tunablesSnapshot.maxOutputChars * 4, 1048576);
				const settle = () => {
					if (settled) return;
					settled = true;
					clearTimeout(timer);
					offAbort();
					resolve({
						code,
						signal: sig,
						stdout: truncateHead(stdout, this.tunablesSnapshot.maxOutputChars),
						stderr: truncateHead(stderr, this.tunablesSnapshot.maxOutputChars),
						timedOut
					});
				};
				const timer = setTimeout(() => {
					if (settled) return;
					timedOut = true;
					sig = "SIGTERM";
					code = null;
					try {
						stream.signal("SIGTERM");
					} catch {}
					setTimeout(() => {
						try {
							stream.close();
						} catch {}
					}, 800).unref();
					settle();
				}, timeoutMs);
				const onAbort = () => {
					if (settled) return;
					timedOut = false;
					sig = "SIGTERM";
					code = null;
					try {
						stream.signal("SIGTERM");
					} catch {}
					settle();
				};
				const offAbort = attachAbort$1(opts.signal, onAbort);
				stream.on("close", (c, s) => {
					if (settled) return;
					code = typeof c === "number" ? c : null;
					sig = s === "SIGTERM" ? "SIGTERM" : sig;
					settle();
				});
				stream.on("data", (d) => {
					if (stdout.length < hardCap) stdout += d.toString("utf8");
				});
				stream.stderr?.on("data", (d) => {
					if (stderr.length < hardCap) stderr += d.toString("utf8");
				});
				stream.on("error", (e) => {
					if (settled) return;
					settled = true;
					clearTimeout(timer);
					offAbort();
					reject(/* @__PURE__ */ new Error(`ssh stream error: ${e.message}`));
				});
				if (opts.stdin !== void 0) stream.end(opts.stdin);
			});
		}));
	}
	/**
	* Resolve the pool's one shared SFTP session. The SFTP protocol multiplexes
	* every request over its single subsystem channel, so one session serves all
	* concurrent file operations; opening a channel per call would leak sessions
	* until the server's MaxSessions cap answers every open with a channel
	* failure. The cache drops on session death, so the next call reopens.
	*/
	async sftp() {
		if (this.sftpSession) return this.sftpSession;
		const client = await this.connectWithRetry();
		return new Promise((resolve, reject) => {
			client.sftp((err, sftp) => {
				if (err) {
					reject(/* @__PURE__ */ new Error(`ssh sftp failed: ${err.message}`));
					return;
				}
				const drop = () => {
					if (this.sftpSession === sftp) this.sftpSession = null;
				};
				sftp.on("close", drop);
				sftp.on("error", drop);
				this.sftpSession = sftp;
				resolve(sftp);
			});
		});
	}
	async connectWithRetry() {
		try {
			return await this.connect();
		} catch (err) {
			if (!CHANNEL_DEAD_PATTERN.test(String(err.message))) throw err;
			this.invalidate();
			return this.connect();
		}
	}
};
/**
* Attach an abort listener that runs `fn` once; returns the detach function.
* @param signal - optional abort signal.
* @param fn - listener to run on abort.
* @returns a detacher safe to call unconditionally.
*/
function attachAbort$1(signal, fn) {
	if (!signal) return () => {};
	if (signal.aborted) {
		fn();
		return () => {};
	}
	const listener = () => fn();
	signal.addEventListener("abort", listener, { once: true });
	return () => signal.removeEventListener("abort", listener);
}
//#endregion
//#region src/anchors.ts
/**
* Anchor directories: the real local workspace directories that stand in for
* remote roots. An anchor is created under the anchor root when the user picks
* a remote directory; the harness adopts it as an ordinary workspace, and the
* session cwd becomes the routing key that maps every tool call onto the
* remote host.
*
* Anchor layout: `<anchorRoot>/<host>-<user>-<port>/<basename>`, with a
* same-named remote origin reusing its existing directory (idempotent) and a
* colliding basename disambiguated by a short hash of the remote path.
* @module dsh-remote-development/anchors
*/
/** Metadata file stored inside every anchor directory. */
const ANCHOR_META_FILE = ".dsh-remote-development.json";
/**
* The anchor directory for one remote origin under a machine tag directory.
* Pure so tests can assert naming without touching the filesystem.
* @param root - anchor root directory.
* @param machine - target machine.
* @param remotePath - remote workspace path.
* @returns the anchor directory path (not created).
*/
function anchorDirFor(root, machine, remotePath) {
	const tag = [
		machine.host,
		machine.username,
		machine.port
	].filter((part) => part !== void 0 && part !== null && String(part).length > 0).join("-").replace(/[^a-zA-Z0-9._-]/g, "_");
	const base = remoteBasename(remotePath) || "workspace";
	return path.join(root, tag, base);
}
/**
* Read one anchor's metadata; null when absent or unreadable.
* @param dir - candidate anchor directory.
* @returns the parsed metadata, or null.
*/
function readAnchorMeta(dir) {
	try {
		const raw = JSON.parse(readFileSync(path.join(dir, ANCHOR_META_FILE), "utf8"));
		if (typeof raw.host !== "string" || typeof raw.remotePath !== "string") return null;
		return {
			host: raw.host,
			port: Number(raw.port) || 22,
			username: String(raw.username ?? ""),
			remotePath: normalizeRemotePath(raw.remotePath),
			createdAt: String(raw.createdAt ?? "")
		};
	} catch {
		return null;
	}
}
/** List immediate child directories of `dir`, ignoring unreadable entries. */
function childDirs(dir) {
	try {
		return readdirSync(dir, { withFileTypes: true }).filter((e) => {
			try {
				return statSync(path.join(dir, e.name)).isDirectory();
			} catch {
				return false;
			}
		}).map((e) => e.name);
	} catch {
		return [];
	}
}
/**
* Scan an anchor root and collect every anchor directory.
* @param root - anchor root directory.
* @returns all anchors found.
*/
function scanAnchors(root) {
	const out = [];
	if (!existsSync(root)) return out;
	for (const tag of childDirs(root)) for (const name of childDirs(path.join(root, tag))) {
		const dir = path.join(root, tag, name);
		const meta = readAnchorMeta(dir);
		if (!meta) continue;
		out.push({
			dir,
			meta,
			remoteRoot: meta.remotePath
		});
	}
	return out;
}
/**
* Create (or reuse) the anchor directory for one remote origin.
* @param root - anchor root directory.
* @param machine - target machine.
* @param remotePath - remote workspace path.
* @returns the anchor directory path.
*/
function createAnchorDir(root, machine, remotePath) {
	const norm = normalizeRemotePath(remotePath);
	const plain = anchorDirFor(root, machine, norm);
	const existing = readAnchorMeta(plain);
	if (existing && existing.remotePath === norm && existing.host === machine.host && Number(existing.port) === Number(machine.port) && existing.username === machine.username) return plain;
	const dir = existsSync(plain) ? plain + "-" + shortHash(norm) : plain;
	mkdirSync(dir, { recursive: true });
	writeFileSync(path.join(dir, ANCHOR_META_FILE), JSON.stringify({
		host: machine.host,
		port: machine.port,
		username: machine.username,
		remotePath: norm,
		createdAt: (/* @__PURE__ */ new Date()).toISOString()
	}, null, 2) + "\n", { mode: 384 });
	return dir;
}
/**
* Match a remote-coordinate path against the known anchors (longest root wins).
* @param remotePath - candidate remote path.
* @param anchors - known anchors.
* @returns the matched route, or null when no anchor claims the path.
*/
function matchRemotePath(remotePath, anchors) {
	const norm = normalizeRemotePath(remotePath);
	let best = null;
	for (const anchor of anchors) {
		const rel = relUnder(anchor.remoteRoot, norm);
		if (rel === null) continue;
		const mapped = rel === "" ? anchor.remoteRoot : normalizeRemotePath(`${anchor.remoteRoot}/${rel}`);
		if (best === null || anchor.remoteRoot.length > best.anchor.remoteRoot.length) best = {
			anchor,
			remotePath: mapped
		};
	}
	return best;
}
//#endregion
//#region src/registry.ts
/**
* Machine registry: the durable list of saved SSH machines and which one is
* current. Pure functions over a file path so tests drive real files. Saved
* machines are STANDBY connections; only an explicit "set current" (or the
* config default on a fresh registry) activates one.
* @module dsh-remote-development/registry
*/
/** Registry file layout; `null` currentId is a deliberate "no active machine". */
const REGISTRY_VERSION = 1;
/**
* Derive the stable machine id from its identity triple.
* @param host - SSH host.
* @param port - SSH port.
* @param username - login user.
* @returns the opaque machine id.
*/
function machineId(host, port, username) {
	return [
		host || "?",
		port || 22,
		username || "?"
	].join("|");
}
/**
* Fill defaults and drop whitespace on one machine record from untrusted input.
* @param raw - partial machine fields (e.g. a UI payload or config row).
* @returns the sanitized record with an id.
*/
function sanitizeMachine(raw) {
	const host = String(raw.host ?? "").trim();
	const port = Number(raw.port) > 0 ? Math.floor(Number(raw.port)) : 22;
	const username = String(raw.username ?? "").trim();
	const machine = {
		id: String(raw.id ?? "") || machineId(host, port, username),
		name: String(raw.name ?? "").trim() || host,
		host,
		port,
		username,
		password: String(raw.password ?? ""),
		privateKeyPath: String(raw.privateKeyPath ?? "").trim(),
		passphrase: String(raw.passphrase ?? ""),
		useAgent: raw.useAgent === true,
		keyboardInteractive: raw.keyboardInteractive === true,
		hostKeyMode: [
			"accept-new",
			"verify",
			"off"
		].includes(String(raw.hostKeyMode)) ? String(raw.hostKeyMode) : "accept-new",
		workspace: String(raw.workspace ?? "").trim()
	};
	if (raw.proxy && String(raw.proxy.host ?? "").trim()) machine.proxy = {
		host: String(raw.proxy.host).trim(),
		port: Number(raw.proxy.port) > 0 ? Math.floor(Number(raw.proxy.port)) : 22,
		username: String(raw.proxy.username ?? "").trim(),
		password: String(raw.proxy.password ?? ""),
		privateKeyPath: String(raw.proxy.privateKeyPath ?? "").trim(),
		passphrase: String(raw.proxy.passphrase ?? "")
	};
	if (Array.isArray(raw.recentWorkspaces)) machine.recentWorkspaces = raw.recentWorkspaces.map((w) => String(w)).filter(Boolean).slice(0, 8);
	return machine;
}
/**
* Load the registry from disk; a missing or corrupt file is a fresh registry.
* @param file - registry file path.
* @returns the parsed (or fresh) registry data.
*/
function loadRegistry(file) {
	try {
		const raw = JSON.parse(readFileSync(file, "utf8"));
		if (!raw || !Array.isArray(raw.machines)) return {
			version: REGISTRY_VERSION,
			currentId: null,
			machines: []
		};
		const machines = raw.machines.map((m) => sanitizeMachine(m));
		const currentId = typeof raw.currentId === "string" && machines.some((m) => m.id === raw.currentId) ? raw.currentId : null;
		return {
			version: REGISTRY_VERSION,
			currentId,
			machines
		};
	} catch {
		return {
			version: REGISTRY_VERSION,
			currentId: null,
			machines: []
		};
	}
}
/**
* Persist the registry atomically (temp file + rename).
* @param file - registry file path.
* @param data - the registry to write.
*/
function saveRegistry(file, data) {
	mkdirSync(dirname(file), { recursive: true });
	const tmp = file + ".tmp";
	writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", { mode: 384 });
	renameSync(tmp, file);
}
/**
* Whether the registry file exists at all (a present file with `currentId:
* null` means "explicitly no active machine" and must not fall back to the
* config default).
* @param file - registry file path.
* @returns true when the file exists.
*/
function registryExists(file) {
	return existsSync(file);
}
//#endregion
//#region src/world.ts
/**
* The remote world: one coordinator owning the machine registry, the anchor
* index, per-machine SSH pools, and the audit log. Both the routing providers
* and the web routes go through it, so a settings change, an added machine,
* or a new anchor is visible to every consumer the same way.
* @module dsh-remote-development/world
*/
/** Harness home: `DSH_HOME` when set, else `~/.dsh`. */
function dshHome() {
	const env = process.env.DSH_HOME;
	if (env && env.trim()) return path.resolve(env.trim());
	return path.join(homedir(), ".dsh");
}
/**
* Coordinator for the remote execution world. Constructed once by the plugin's
* `apply`; its `dispose()` closes every pool (registered as a ctx effect).
*/
var RemoteWorld = class {
	config;
	registryFile;
	knownHostsFile;
	anchorRoot;
	registry;
	anchorCache = null;
	pools = /* @__PURE__ */ new Map();
	/**
	* @param config - validated plugin config.
	*/
	constructor(config) {
		this.config = config;
		const base = config.anchorRoot.trim() || path.join(dshHome(), "remote-workspaces");
		this.anchorRoot = base;
		this.registryFile = path.join(base, "machines.json");
		this.knownHostsFile = path.join(base, "known_hosts.json");
		this.registry = loadRegistry(this.registryFile);
		if (!registryExists(this.registryFile) && config.host) {
			const machine = sanitizeMachine({
				host: config.host,
				port: config.port,
				username: config.username,
				password: config.password,
				privateKeyPath: config.privateKeyPath,
				passphrase: config.passphrase,
				hostKeyMode: config.hostKeyMode,
				workspace: config.workspace
			});
			this.registry.machines.push(machine);
			this.registry.currentId = machine.id;
			saveRegistry(this.registryFile, this.registry);
		}
	}
	/** Close every pool (composition teardown). */
	dispose() {
		for (const pool of this.pools.values()) try {
			pool.close();
		} catch {}
		this.pools.clear();
	}
	/** All saved machines, plus the config default when no registry exists. */
	listMachines() {
		return [...this.registry.machines];
	}
	/** The currently active machine, or null. */
	currentMachine() {
		if (!this.registry.currentId) return null;
		return this.registry.machines.find((m) => m.id === this.registry.currentId) ?? null;
	}
	/**
	* Add or update a machine by identity; returns the stored record.
	* @param raw - machine fields from the UI or config.
	* @returns the sanitized stored machine.
	*/
	upsertMachine(raw) {
		const machine = sanitizeMachine(raw);
		const index = this.registry.machines.findIndex((m) => m.id === machine.id);
		if (index >= 0) this.registry.machines[index] = machine;
		else this.registry.machines.push(machine);
		saveRegistry(this.registryFile, this.registry);
		return machine;
	}
	/**
	* Remove one machine; anchors stay (their metadata is durable) but lose
	* their credential source until the machine is re-added.
	* @param id - machine id.
	* @returns true when a machine was removed.
	*/
	removeMachine(id) {
		const index = this.registry.machines.findIndex((m) => m.id === id);
		if (index < 0) return false;
		this.registry.machines.splice(index, 1);
		if (this.registry.currentId === id) this.registry.currentId = null;
		saveRegistry(this.registryFile, this.registry);
		const key = [...this.pools.keys()].find((k) => k.startsWith(id + "\0"));
		if (key) {
			this.pools.get(key)?.close();
			this.pools.delete(key);
		}
		return true;
	}
	/**
	* Set (or clear) the active machine.
	* @param id - machine id, or null to deactivate.
	* @returns true when the registry changed.
	*/
	setCurrent(id) {
		if (id === null) {
			this.registry.currentId = null;
			saveRegistry(this.registryFile, this.registry);
			return true;
		}
		if (!this.registry.machines.some((m) => m.id === id)) return false;
		this.registry.currentId = id;
		saveRegistry(this.registryFile, this.registry);
		return true;
	}
	/**
	* Resolve the machine record for an anchor origin. Anchors record only
	* host/port/user; the registry supplies credentials. The config default
	* covers an anchor created before its machine was saved under a matching
	* identity.
	* @param meta - anchor metadata.
	* @returns the machine reference, or null when unresolvable.
	*/
	machineForMeta(meta) {
		const id = machineId(meta.host, meta.port, meta.username);
		const stored = this.registry.machines.find((m) => m.id === id);
		if (stored) return {
			source: "registry",
			machine: stored
		};
		if (this.config.host && this.config.host === meta.host && Number(this.config.port) === Number(meta.port) && this.config.username === meta.username) return {
			source: "config",
			machine: sanitizeMachine({
				host: this.config.host,
				port: this.config.port,
				username: this.config.username,
				password: this.config.password,
				privateKeyPath: this.config.privateKeyPath,
				passphrase: this.config.passphrase,
				hostKeyMode: this.config.hostKeyMode
			})
		};
		return null;
	}
	/**
	* Resolve the machine for one anchor (by its metadata).
	* @param anchor - the anchor.
	* @returns the machine reference, or null when unresolvable.
	*/
	machineForAnchor(anchor) {
		return this.machineForMeta(anchor.meta);
	}
	/**
	* Look a machine up by id. The config default is registered into the
	* registry at construction, so the registry list is exhaustive here.
	* @param id - machine id.
	* @returns the machine reference, or null.
	*/
	machineById(id) {
		const stored = this.registry.machines.find((m) => m.id === id);
		return stored ? {
			source: "registry",
			machine: stored
		} : null;
	}
	/**
	* A non-persisted machine reference for one-shot flows (test-connection
	* with unsaved fields).
	* @param raw - partial machine fields.
	* @returns the ephemeral machine reference.
	*/
	ephemeralRef(raw) {
		return {
			source: "config",
			machine: sanitizeMachine(raw)
		};
	}
	/** All anchors, rescanned when the cache is dirty. */
	anchors() {
		if (this.anchorCache === null) this.anchorCache = scanAnchors(this.anchorRoot);
		return this.anchorCache;
	}
	/**
	* Create (or reuse) the anchor for one remote origin and refresh the cache.
	* @param machine - target machine.
	* @param remotePath - remote workspace path.
	* @returns the anchor directory.
	*/
	createAnchor(machine, remotePath) {
		const dir = createAnchorDir(this.anchorRoot, machine, remotePath);
		this.anchorCache = null;
		return dir;
	}
	/**
	* Classify a host-absolute path: under an anchor → remote (with its remote
	* path); an anchor's own metadata file → stays local.
	* @param absPath - absolute local path.
	* @returns the routing decision.
	*/
	classifyHostPath(absPath) {
		const norm = path.normalize(absPath);
		for (const anchor of this.anchors()) if (norm === path.join(anchor.dir, ".dsh-remote-development.json")) return {
			kind: "meta",
			dir: anchor.dir
		};
		for (const anchor of this.anchors()) {
			const rel = relUnderLocal(anchor.dir, norm);
			if (rel !== null) return {
				kind: "remote",
				route: {
					anchor,
					remotePath: rel === "" ? anchor.remoteRoot : normalizeRemotePath(`${anchor.remoteRoot}/${rel}`)
				}
			};
		}
		return { kind: "local" };
	}
	/**
	* Classify a remote-coordinate path (the model may name remote paths
	* directly after seeing them in command output).
	* @param remotePath - candidate remote path.
	* @returns the matched route, or null.
	*/
	classifyRemotePath(remotePath) {
		return matchRemotePath(remotePath, this.anchors());
	}
	/**
	* The pool for one machine identity (created lazily, shared across calls).
	* @param ref - the machine reference.
	* @returns the pool.
	*/
	poolFor(ref) {
		const m = ref.machine;
		const key = m.id + "\0" + m.host + "\0" + m.port + "\0" + m.username;
		const existing = this.pools.get(key);
		if (existing) {
			existing.retune(this.tunables());
			return existing;
		}
		const pool = new SshPool(this.poolTarget(m), this.tunables(), {
			read: () => this.readKnownHosts(),
			write: (entries) => this.writeKnownHosts(entries)
		});
		this.pools.set(key, pool);
		return pool;
	}
	tunables() {
		return {
			connectTimeoutMs: this.config.connectTimeoutMs,
			commandTimeoutMs: this.config.commandTimeoutMs,
			maxOutputChars: this.config.maxOutputChars,
			maxFileBytes: this.config.maxFileBytes
		};
	}
	poolTarget(m) {
		return {
			host: m.host,
			port: m.port,
			username: m.username || "root",
			password: m.password,
			privateKeyPath: m.privateKeyPath,
			passphrase: m.passphrase,
			useAgent: m.useAgent,
			keyboardInteractive: m.keyboardInteractive,
			...m.proxy ? { proxy: m.proxy } : {},
			hostKeyMode: m.hostKeyMode || this.config.hostKeyMode
		};
	}
	/**
	* Run one command on a machine with the audit hook and the Windows-remote
	* refusal surfaced as a typed error.
	* @param ref - machine reference.
	* @param command - remote command line.
	* @param opts - timeout/stdin/abort.
	* @returns the exec result.
	*/
	async execOn(ref, command, opts = {}) {
		const pool = this.poolFor(ref);
		try {
			const result = await pool.exec(command, opts);
			this.audit(ref, command, result.code);
			return result;
		} catch (err) {
			if (err instanceof UnsupportedRemoteError) {
				this.audit(ref, command, null);
				throw err;
			}
			this.audit(ref, command, null);
			throw err;
		}
	}
	auditFile() {
		return path.join(this.anchorRoot, "audit.log");
	}
	/**
	* Append one audit line; failures are swallowed (the audit log must never
	* break a tool call).
	* @param ref - machine acted on.
	* @param command - command text or operation detail.
	* @param code - exit code, or null when not applicable.
	*/
	audit(ref, command, code) {
		if (!this.config.auditLog) return;
		try {
			mkdirSync(this.anchorRoot, { recursive: true });
			const line = [
				(/* @__PURE__ */ new Date()).toISOString(),
				`${ref.machine.username || "?"}@${ref.machine.host}:${ref.machine.port}`,
				String(command).replace(/\s+/g, " ").slice(0, 400),
				code == null ? "-" : String(code)
			].join(" | ") + "\n";
			appendFileSync(this.auditFile(), line, "utf8");
		} catch {}
	}
	readKnownHosts() {
		try {
			const raw = JSON.parse(readFileSync(this.knownHostsFile, "utf8"));
			if (raw && typeof raw === "object" && !Array.isArray(raw)) return raw;
		} catch {}
		return {};
	}
	writeKnownHosts(entries) {
		try {
			mkdirSync(path.dirname(this.knownHostsFile), { recursive: true });
			const tmp = this.knownHostsFile + ".tmp";
			writeFileSync(tmp, JSON.stringify(entries, null, 2) + "\n", { mode: 384 });
			renameSync(tmp, this.knownHostsFile);
		} catch (err) {
			throw new Error(`cannot persist known hosts: ${err.message}`);
		}
	}
	/** Drop one host's trusted key (re-trust flow). */
	forgetHostKey(host, port) {
		new HostKeyGuard("accept-new", {
			read: () => this.readKnownHosts(),
			write: (entries) => this.writeKnownHosts(entries)
		}).forget(`${host}:${port}`);
	}
	/** Build a plain guard for ad-hoc verification (test-connection flow). */
	hostKeyGuard() {
		return new HostKeyGuard(this.config.hostKeyMode, {
			read: () => this.readKnownHosts(),
			write: (entries) => this.writeKnownHosts(entries)
		});
	}
};
/** Local prefix containment for anchor dirs (lexical, no I/O). */
function relUnderLocal(dir, p) {
	const d = dir.endsWith(path.sep) ? dir : dir + path.sep;
	if (p === dir) return "";
	if (!p.startsWith(d)) return null;
	return p.slice(d.length);
}
//#endregion
//#region src/remote-io.ts
/** Thrown by sftp calls that exceed their deadline. */
var SftpTimeoutError = class extends Error {
	constructor(op) {
		super(`sftp ${op} timed out`);
		this.name = "SftpTimeoutError";
	}
};
/**
* Run one callback-style sftp operation with a deadline and an abort hook.
* @param sftp - the SFTP channel.
* @param op - operation name (diagnostics only).
* @param signal - optional abort signal.
* @param timeoutMs - deadline for the operation.
* @param run - invokes the operation, receiving its node-style callback.
* @returns the operation's value.
* @throws {FsError} FS_ABORTED when the signal fires first.
*/
function sftpCall(op, signal, timeoutMs, run) {
	return new Promise((resolve, reject) => {
		let settled = false;
		let timer;
		const finish = (err, value) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			offAbort();
			if (err) reject(mapSftpError(err, op));
			else resolve(value);
		};
		const onAbort = () => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			reject(new FsError("remote file operation aborted", "FS_ABORTED"));
		};
		const offAbort = attachAbort(signal, onAbort);
		timer = setTimeout(() => finish(new SftpTimeoutError(op), void 0), timeoutMs);
		try {
			run((err, value) => finish(err, value));
		} catch (err) {
			finish(err, void 0);
		}
	});
}
function attachAbort(signal, fn) {
	if (!signal) return () => {};
	if (signal.aborted) {
		fn();
		return () => {};
	}
	const listener = () => fn();
	signal.addEventListener("abort", listener, { once: true });
	return () => signal.removeEventListener("abort", listener);
}
/** SFTP wire status codes (SSH_FX_*) the mapping recognizes. */
const SFTP_NO_SUCH = /* @__PURE__ */ new Set([2, 10]);
const SFTP_PERMISSION = /* @__PURE__ */ new Set([3]);
/** Map a raw SFTP error onto the fs error taxonomy where the code is known.
* ssh2 surfaces numeric SSH_FX_* codes; errno-style string codes appear on
* fakes and some servers. */
function mapSftpError(err, op) {
	const code = err.code;
	const numeric = typeof code === "number" ? code : void 0;
	if (typeof code === "string" && (code === "ENOENT" || code === "ENOTDIR")) return new FsError(err.message, code === "ENOTDIR" ? "FS_NOT_DIRECTORY" : "FS_NOT_FOUND");
	if (numeric !== void 0 && SFTP_NO_SUCH.has(numeric)) return new FsError(err.message, "FS_NOT_FOUND");
	if (typeof code === "string" && (code === "EACCES" || code === "EPERM") || numeric !== void 0 && SFTP_PERMISSION.has(numeric)) return new FsError(err.message, "FS_PERMISSION_DENIED");
	return new FsError(`${op} failed: ${err.message}`, "FS_IO_ERROR", { cause: err });
}
/**
* The freshness token for a remote file: stat identity, stable across aliases.
* @param stats - the SFTP stat result.
* @returns the branded version string.
*/
function versionOf(stats) {
	return FsVersion(`${Math.floor(Number(stats.mtime) * 1e3)}-${stats.size}`);
}
/** The fs metadata type for one stat result. */
function typeOf(stats, symlink) {
	if (symlink) return "symlink";
	if (stats.isDirectory()) return "directory";
	if (stats.isFile()) return "file";
	return "other";
}
/**
* Stat a remote path (follows symlinks).
* @param sftp - the SFTP channel.
* @param p - remote path.
* @param signal - abort hook.
* @param timeoutMs - operation deadline.
* @returns metadata, or undefined when absent.
*/
async function statPath(sftp, p, signal, timeoutMs) {
	try {
		const stats = await sftpCall("stat", signal, timeoutMs, (cb) => sftp.stat(p, cb));
		return {
			version: versionOf(stats),
			type: typeOf(stats, false),
			size: stats.size
		};
	} catch (err) {
		if (err.code === "FS_NOT_FOUND") return void 0;
		throw err;
	}
}
/**
* Lstat a remote path (does not follow the final component).
* @param sftp - the SFTP channel.
* @param p - remote path.
* @param signal - abort hook.
* @param timeoutMs - operation deadline.
* @returns metadata, or undefined when absent.
*/
async function lstatPath(sftp, p, signal, timeoutMs) {
	try {
		const stats = await sftpCall("lstat", signal, timeoutMs, (cb) => sftp.lstat(p, cb));
		return {
			version: versionOf(stats),
			type: typeOf(stats, stats.isSymbolicLink()),
			size: stats.size
		};
	} catch (err) {
		if (err.code === "FS_NOT_FOUND") return void 0;
		throw err;
	}
}
/**
* List one remote directory level.
* @param sftp - the SFTP channel.
* @param dir - remote directory.
* @param signal - abort hook.
* @param timeoutMs - operation deadline.
* @returns name/type/size rows in wire order (caller sorts).
*/
async function listRemoteDir(sftp, dir, signal, timeoutMs) {
	return (await sftpCall("readdir", signal, timeoutMs, (cb) => sftp.readdir(dir, cb))).map((e) => ({
		name: e.name,
		type: typeOf(e.attrs, e.attrs.isSymbolicLink()),
		...e.attrs.isFile() ? { size: e.attrs.size } : {},
		version: versionOf(e.attrs)
	}));
}
/**
* Read a whole remote file as bytes, bounded by `maxBytes`.
* @param sftp - the SFTP channel.
* @param p - remote path.
* @param signal - abort hook.
* @param timeoutMs - operation deadline.
* @param maxBytes - inclusive cap; a larger file fails FS_TOO_LARGE.
* @returns the raw bytes.
*/
async function readRemoteBytes(sftp, p, signal, timeoutMs, maxBytes) {
	const stats = await sftpCall("stat", signal, timeoutMs, (cb) => sftp.stat(p, cb));
	if (!stats.isFile()) throw new FsError(`"${p}" is not a regular file`, "FS_NOT_REGULAR_FILE");
	if (maxBytes > 0 && stats.size > maxBytes) throw new FsError(`"${p}" is ${stats.size} bytes, above the ${maxBytes}-byte read cap`, "FS_TOO_LARGE");
	return sftpCall("readFile", signal, timeoutMs, (cb) => sftp.readFile(p, cb));
}
/**
* Read a whole remote file as decoded UTF-8 text with binary rejection.
* @param sftp - the SFTP channel.
* @param p - remote path.
* @param signal - abort hook.
* @param timeoutMs - operation deadline.
* @param maxBytes - inclusive byte cap (0 = unbounded).
* @returns the decoded text.
*/
async function readRemoteText(sftp, p, signal, timeoutMs, maxBytes) {
	return decodeStrict(await readRemoteBytes(sftp, p, signal, timeoutMs, maxBytes), p);
}
/** Decode UTF-8 strictly; a NUL byte or invalid sequence is a text refusal. */
function decodeStrict(bytes, p) {
	if (bytes.includes(0)) throw new FsError(`cannot read "${p}": binary file`, "FS_NOT_TEXT");
	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
	} catch {
		throw new FsError(`cannot read "${p}": not valid UTF-8 text`, "FS_NOT_TEXT");
	}
}
/**
* Stream a remote text file as decoded chunks with cross-chunk UTF-8 handling.
* @param sftp - the SFTP channel.
* @param p - remote path.
* @param signal - abort hook.
* @param timeoutMs - inactivity deadline per awaited chunk.
* @param maxBytes - inclusive byte cap (0 = unbounded).
* @returns the decoded chunk iterable.
*/
function streamRemoteText(sftp, p, signal, timeoutMs, maxBytes) {
	async function* generate() {
		const stats = await sftpCall("stat", signal, timeoutMs, (cb) => sftp.stat(p, cb));
		if (!stats.isFile()) throw new FsError(`"${p}" is not a regular file`, "FS_NOT_REGULAR_FILE");
		if (maxBytes > 0 && stats.size > maxBytes) throw new FsError(`"${p}" is ${stats.size} bytes, above the ${maxBytes}-byte read cap`, "FS_TOO_LARGE");
		const stream = sftp.createReadStream(p);
		const decoder = new TextDecoder("utf-8", { fatal: false });
		let pending = /* @__PURE__ */ new Uint8Array(0);
		let sawBinary = false;
		try {
			for await (const chunk of stream) {
				if (signal?.aborted) throw new FsError("remote file read aborted", "FS_ABORTED");
				const bytes = new Uint8Array(chunk);
				if (bytes.includes(0)) {
					sawBinary = true;
					break;
				}
				const merged = mergeBytes(pending, bytes);
				const safe = merged.length >= 4 ? merged.length - 3 : 0;
				pending = merged.slice(safe);
				const text = decoder.decode(merged.slice(0, safe));
				if (text) yield text;
			}
		} finally {
			stream.destroy();
		}
		if (sawBinary) throw new FsError(`cannot read "${p}": binary file`, "FS_NOT_TEXT");
		try {
			const tail = decoder.decode();
			if (tail) yield tail;
		} catch {
			throw new FsError(`cannot read "${p}": not valid UTF-8 text`, "FS_NOT_TEXT");
		}
	}
	return generate();
}
function mergeBytes(a, b) {
	const out = new Uint8Array(a.length + b.length);
	out.set(a, 0);
	out.set(b, a.length);
	return out;
}
/**
* Create parent directories for a remote path (mkdir -p semantics).
* @param sftp - the SFTP channel.
* @param dir - deepest directory to ensure.
* @param signal - abort hook.
* @param timeoutMs - per-mkdir deadline.
*/
async function ensureRemoteDirs(sftp, dir, signal, timeoutMs) {
	const parts = dir.split("/").filter(Boolean);
	let cur = dir.startsWith("/") ? "" : ".";
	for (const part of parts) {
		cur = cur === "" ? "/" + part : cur === "." ? part : cur + "/" + part;
		try {
			await sftpCall("mkdir", signal, timeoutMs, (cb) => sftp.mkdir(cur, cb));
		} catch (err) {
			const code = err.code;
			if (code === "FS_IO_ERROR" || code === "FS_NOT_DIRECTORY") {
				if ((await statPath(sftp, cur, signal, timeoutMs))?.type === "directory") continue;
			}
			throw err;
		}
	}
}
/**
* Publish file content atomically: write a sibling temp file, then rename over
* the target (POSIX rename replaces; servers without that semantic fall back
* to unlink-then-rename, documented as a non-atomic fallback).
* @param sftp - the SFTP channel.
* @param p - remote target path.
* @param bytes - complete file content.
* @param signal - abort hook.
* @param timeoutMs - per-operation deadline.
*/
async function publishRemoteFile(sftp, p, bytes, signal, timeoutMs) {
	const dir = remoteDirname(p);
	if (dir && dir !== ".") await ensureRemoteDirs(sftp, dir, signal, timeoutMs);
	const tmp = `${p}.dsh-rdv-tmp-${Math.random().toString(36).slice(2, 10)}`;
	await sftpCall("writeFile", signal, timeoutMs, (cb) => sftp.writeFile(tmp, Buffer.from(bytes), cb));
	try {
		await sftpCall("rename", signal, timeoutMs, (cb) => sftp.rename(tmp, p, cb));
	} catch (err) {
		try {
			await sftpCall("unlink", signal, timeoutMs, (cb) => sftp.unlink(p, cb));
			await sftpCall("rename", signal, timeoutMs, (cb) => sftp.rename(tmp, p, cb));
		} catch (retryErr) {
			try {
				await sftpCall("unlink", signal, timeoutMs, (cb) => sftp.unlink(tmp, cb));
			} catch {}
			throw retryErr;
		}
	}
}
/**
* Create or replace a remote text file with intent guards, mirroring the
* write contract: `createIfAbsent` rejects an existing target; a version
* guard rejects a file changed since observation.
* @param sftp - the SFTP channel.
* @param p - remote path.
* @param content - full new text.
* @param intent - optional guard.
* @param signal - abort hook.
* @param timeoutMs - per-operation deadline.
* @returns operation, before/after basis, and the produced version.
*/
async function writeRemoteText(sftp, p, content, intent, signal, timeoutMs) {
	const existing = await statPath(sftp, p, signal, timeoutMs);
	if (intent?.kind === "createIfAbsent" && existing) throw new FsError(`"${p}" already exists (createIfAbsent)`, "FS_NOT_OBSERVED");
	if (intent?.kind === "replaceIfVersion" && existing?.version !== intent.version) throw new FsError(`"${p}" changed since it was observed (stale version)`, "FS_STALE_VERSION");
	let before = null;
	if (existing?.type === "file") try {
		before = await readRemoteText(sftp, p, signal, timeoutMs, 0);
	} catch {
		before = null;
	}
	else if (existing) throw new FsError(`cannot write "${p}": not a regular file`, "FS_NOT_REGULAR_FILE");
	await publishRemoteFile(sftp, p, Buffer.from(content, "utf8"), signal, timeoutMs);
	const stats = await sftpCall("stat", signal, timeoutMs, (cb) => sftp.stat(p, cb));
	return {
		operation: existing ? "update" : "create",
		version: versionOf(stats),
		before,
		after: content
	};
}
/**
* Apply one literal edit to a remote text file with a version guard, sharing
* one read-guard-write critical section per call (the seam owns ordering by
* serializing per target at the router level).
* @param sftp - the SFTP channel.
* @param p - remote path.
* @param edit - literal search/replace request.
* @param expected - optional version guard.
* @param signal - abort hook.
* @param timeoutMs - per-operation deadline.
* @returns before/after basis and the produced version.
*/
async function editRemoteText(sftp, p, edit, expected, signal, timeoutMs) {
	const stats = await statPath(sftp, p, signal, timeoutMs);
	if (!stats) throw new FsError(`"${p}" was not found`, "FS_NOT_FOUND");
	if (stats.type !== "file") throw new FsError(`cannot edit "${p}": not a regular file`, "FS_NOT_REGULAR_FILE");
	if (expected && stats.version !== expected.version) throw new FsError(`"${p}" changed since it was observed (stale version)`, "FS_STALE_VERSION");
	const raw = await readRemoteText(sftp, p, signal, timeoutMs, 0);
	const crlf = detectCrlf(raw);
	const content = crlf ? raw.replaceAll("\r\n", "\n") : raw;
	const oldNorm = edit.oldString.replaceAll("\r\n", "\n");
	const newNorm = edit.newString.replaceAll("\r\n", "\n");
	if (oldNorm.length === 0) throw new FsError("old_string must be a non-empty string", "FS_EDIT_NOT_FOUND");
	const occurrences = countOccurrences(content, oldNorm);
	if (occurrences === 0) throw new FsError(`old_string was not found in "${p}"`, "FS_EDIT_NOT_FOUND");
	if (!edit.replaceAll && occurrences > 1) throw new FsError(`old_string matched ${occurrences} times in "${p}"; provide a more specific old_string or set replace_all to true`, "FS_AMBIGUOUS_EDIT");
	const edited = content.split(oldNorm).join(newNorm);
	const restored = crlf ? edited.split("\n").join("\r\n") : edited;
	await publishRemoteFile(sftp, p, Buffer.from(restored, "utf8"), signal, timeoutMs);
	return {
		version: (await statPath(sftp, p, signal, timeoutMs))?.version ?? FsVersion("unknown"),
		before: content,
		after: edited
	};
}
function detectCrlf(raw) {
	const sample = raw.slice(0, 4096);
	const crlf = sample.split("\r\n").length - 1;
	return crlf > sample.split("\n").length - 1 - crlf;
}
function countOccurrences(content, needle) {
	let count = 0;
	let index = 0;
	for (;;) {
		const found = content.indexOf(needle, index);
		if (found === -1) return count;
		count += 1;
		index = found + needle.length;
	}
}
//#endregion
//#region src/fs-router.ts
/**
* The routing `ctx.fs` provider: extends the sandboxed local backend with a
* remote branch for paths under an anchor directory (or under a registered
* remote root, the model-facing coordinate). Local calls delegate to the
* inherited backend untouched, so local sessions behave exactly as before the
* plugin was mounted.
*
* Remote target keys encode the machine identity and the remote path —
* `rdv:<json [machineId, remotePath]>` — because identical remote paths can
* exist on different machines. Keys stay opaque to consumers.
* @module dsh-remote-development/fs-router
*/
/** targetKey namespace marker for remote targets (opaque to consumers). */
const KEY_PREFIX = "rdv:";
/** The remote branch of the routing filesystem. */
var RoutingFileSystem = class RoutingFileSystem extends SandboxedFileSystem {
	world;
	opTimeoutMs;
	maxFileBytes;
	remoteLocks = /* @__PURE__ */ new Map();
	/**
	* @param ctx - plugin context (constructing registers this instance as `ctx.fs`).
	* @param world - the remote world coordinator.
	* @param opTimeoutMs - per-SFTP-operation deadline.
	* @param maxFileBytes - remote read byte cap (0 = unbounded).
	* @param baseConfig - the inherited local backend's config (defaults).
	*/
	constructor(ctx, world, opTimeoutMs, maxFileBytes, baseConfig = { cwd: process.cwd() }) {
		super(ctx, baseConfig);
		this.world = world;
		this.opTimeoutMs = opTimeoutMs;
		this.maxFileBytes = maxFileBytes;
	}
	/**
	* Decide the execution world for a path. Anchor-local coordinates win, then
	* registered remote roots (the model may name remote paths it saw in
	* command output), then the local backend.
	* @param p - the model/plugin-supplied path.
	* @param cwd - resolution base override.
	* @returns the remote route with its machine, or null for the local backend.
	*/
	routeOf(p, cwd) {
		const absolute = path.isAbsolute(p) ? path.normalize(p) : path.normalize(path.resolve(cwd ?? this.config.cwd, p));
		const local = this.world.classifyHostPath(absolute);
		if (local.kind === "remote") {
			const machine = this.world.machineForAnchor(local.route.anchor);
			if (machine) return {
				machine,
				remotePath: local.route.remotePath
			};
			return null;
		}
		if (local.kind === "meta") return null;
		if (path.isAbsolute(p)) {
			const remote = this.world.classifyRemotePath(p);
			if (remote) {
				const machine = this.world.machineForAnchor(remote.anchor);
				if (machine) return {
					machine,
					remotePath: remote.remotePath
				};
			}
		}
		return null;
	}
	/** Encode a remote identity into the opaque target key. */
	static keyOf(machineId, remotePath) {
		return FsTargetKey(KEY_PREFIX + JSON.stringify([machineId, remotePath]));
	}
	/** Decode a remote target key; null for local (inherited) keys. */
	static parseKey(target) {
		const key = target.targetKey;
		if (!key.startsWith(KEY_PREFIX)) return null;
		try {
			const [machineId, remotePath] = JSON.parse(key.slice(4));
			if (typeof machineId !== "string" || typeof remotePath !== "string") return null;
			return {
				machineId,
				remotePath
			};
		} catch {
			return null;
		}
	}
	async sftpFor(machine) {
		return this.world.poolFor(machine).sftp();
	}
	async resolve(p, opts) {
		const route = this.routeOf(p, opts?.cwd);
		if (!route) return super.resolve(p, opts);
		return {
			targetKey: RoutingFileSystem.keyOf(route.machine.machine.id, route.remotePath),
			displayPath: route.remotePath
		};
	}
	processPath(target) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.processPath(target);
		return remote.remotePath;
	}
	fileUrl(target) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.fileUrl(target);
		return "file://" + (remote.remotePath.startsWith("/") ? remote.remotePath : "/" + remote.remotePath);
	}
	contains(parent, child) {
		const parentRemote = RoutingFileSystem.parseKey(parent);
		const childRemote = RoutingFileSystem.parseKey(child);
		if (parentRemote === null && childRemote === null) return super.contains(parent, child);
		if (parentRemote === null || childRemote === null) return false;
		if (parentRemote.machineId !== childRemote.machineId) return false;
		return relUnder(parentRemote.remotePath, childRemote.remotePath) !== null;
	}
	async stat(target, signal) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.stat(target, signal);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw new FsError(`the machine for "${target.displayPath}" is no longer configured`, "FS_IO_ERROR");
		return statPath(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs);
	}
	async lstat(p, opts, signal) {
		const route = this.routeOf(p, opts?.cwd);
		if (!route) return super.lstat(p, opts, signal);
		return lstatPath(await this.sftpFor(route.machine), route.remotePath, signal, this.opTimeoutMs);
	}
	async readText(target, signal) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.readText(target, signal);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw new FsError(`the machine for "${target.displayPath}" is no longer configured`, "FS_IO_ERROR");
		return readRemoteText(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs, this.maxFileBytes);
	}
	async streamText(target, signal) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.streamText(target, signal);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw new FsError(`the machine for "${target.displayPath}" is no longer configured`, "FS_IO_ERROR");
		return streamRemoteText(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs, this.maxFileBytes);
	}
	async readBytes(target, signal, maxBytes) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.readBytes(target, signal, maxBytes);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw new FsError(`the machine for "${target.displayPath}" is no longer configured`, "FS_IO_ERROR");
		return readRemoteBytes(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs, maxBytes);
	}
	async listDir(target, signal) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.listDir(target, signal);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw new FsError(`the machine for "${target.displayPath}" is no longer configured`, "FS_IO_ERROR");
		return (await listRemoteDir(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs)).map((e) => {
			const child = remote.remotePath.endsWith("/") ? remote.remotePath + e.name : remote.remotePath + "/" + e.name;
			return {
				name: e.name,
				type: e.type,
				target: {
					targetKey: RoutingFileSystem.keyOf(remote.machineId, child),
					displayPath: child
				},
				...e.version !== void 0 ? { version: e.version } : {},
				...e.size !== void 0 ? { size: e.size } : {}
			};
		});
	}
	async writeText(target, content, expected, signal, sandboxPolicy) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.writeText(target, content, expected, signal, sandboxPolicy);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw new FsError(`the machine for "${target.displayPath}" is no longer configured`, "FS_IO_ERROR");
		this.checkRemoteMutation(remote.remotePath, target.displayPath, sandboxPolicy);
		return this.lockRemote(target.targetKey, async () => writeRemoteText(await this.sftpFor(machine), remote.remotePath, content, expected, signal, this.opTimeoutMs));
	}
	async editText(target, edit, expected, signal, sandboxPolicy) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.editText(target, edit, expected, signal, sandboxPolicy);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw new FsError(`the machine for "${target.displayPath}" is no longer configured`, "FS_IO_ERROR");
		this.checkRemoteMutation(remote.remotePath, target.displayPath, sandboxPolicy);
		return this.lockRemote(target.targetKey, async () => editRemoteText(await this.sftpFor(machine), remote.remotePath, edit, expected, signal, this.opTimeoutMs));
	}
	/**
	* Fence a remote mutation by the per-call policy: `read-only` denies;
	* `workspace-write` allows only under the remote root mapped from the
	* policy's workspace root (an anchor) or the remote `/tmp`.
	* @param remotePath - the remote target path.
	* @param displayPath - the model-facing path for the denial message.
	* @param sandboxPolicy - the per-call policy; omit to use deployment policy.
	*/
	checkRemoteMutation(remotePath, displayPath, sandboxPolicy) {
		const policy = sandboxPolicy ?? this.ctx.sandboxPolicy.resolve();
		if (policy.mode === "danger-full-access") return;
		if (policy.mode === "read-only") throw new FsError(`cannot write "${displayPath}": file access denied under read-only mode`, "FS_SANDBOX_DENIED");
		const roots = ["/tmp"];
		const mapped = this.world.classifyHostPath(path.normalize(policy.workspaceRoot));
		if (mapped.kind === "remote") roots.push(mapped.route.remotePath);
		for (const root of roots) if (relUnder(root, remotePath) !== null) return;
		throw new FsError(`cannot write "${displayPath}": file access denied under workspace-write mode`, "FS_SANDBOX_DENIED");
	}
	/** Serialize remote mutations per target (mirrors the local backend's lock). */
	lockRemote(key, op) {
		const run = (this.remoteLocks.get(key) ?? Promise.resolve()).then(op, op);
		const tail = run.then(() => void 0, () => void 0);
		this.remoteLocks.set(key, tail);
		return run;
	}
};
//#endregion
//#region src/subprocess-router.ts
/** Tail-keeping byte buffer with whole-stream offset reads. */
var CollectBuffer = class {
	maxBytes;
	bytes = /* @__PURE__ */ new Uint8Array(0);
	dropped = 0;
	received = 0;
	/**
	* @param maxBytes - in-memory cap; overflow keeps the tail.
	*/
	constructor(maxBytes) {
		this.maxBytes = maxBytes;
	}
	/** Append bytes, discarding the head beyond the cap. */
	push(chunk) {
		this.received += chunk.length;
		const merged = new Uint8Array(this.bytes.length + chunk.length);
		merged.set(this.bytes, 0);
		merged.set(chunk, this.bytes.length);
		if (this.maxBytes > 0 && merged.length > this.maxBytes) {
			const cut = merged.length - this.maxBytes;
			this.dropped += cut;
			this.bytes = merged.slice(cut);
			return;
		}
		this.bytes = merged;
	}
	/** Total bytes ever received. */
	get total() {
		return this.received;
	}
	/**
	* Offset-based, non-consuming read.
	* @param fromByte - whole-stream offset to resume from.
	* @returns the delta read.
	*/
	readFrom(fromByte) {
		if (fromByte < this.dropped) return {
			text: new TextDecoder().decode(this.bytes),
			nextOffset: this.received,
			lossy: true
		};
		const start = Math.min(Math.max(fromByte, 0), this.received) - this.dropped;
		return {
			text: new TextDecoder().decode(this.bytes.slice(Math.max(start, 0))),
			nextOffset: Math.max(fromByte, this.received),
			lossy: false
		};
	}
};
/** Build an offset-based reader view over one buffer. */
function readerOf(buffer) {
	return { readFrom: (fromByte) => buffer.readFrom(fromByte) };
}
/**
* One remote managed process over an SSH exec channel. The channel IS the
* process lifetime: `done` settles at channel close with the remote exit
* facts and rejects only when the channel cannot be opened (a spawn-level
* failure). Remote PIDs are not observable over SSH, so `pid` is -1.
*/
var RemoteSpawnHandle = class {
	pid = -1;
	done;
	state = null;
	terminated = false;
	spec;
	/**
	* Start the remote process for one spec. The SSH round trip begins
	* immediately; `spawn()` returns this handle synchronously.
	* @param world - remote world (pool access).
	* @param machine - target machine.
	* @param spec - fully-specified spawn request.
	*/
	constructor(world, machine, spec) {
		this.spec = spec;
		let resolveDone;
		let rejectDone;
		this.done = new Promise((resolve, reject) => {
			resolveDone = resolve;
			rejectDone = reject;
		});
		if (spec.signal) {
			if (spec.signal.aborted) this.terminate();
			else spec.signal.addEventListener("abort", () => this.terminate(), { once: true });
		}
		this.open(world, machine, resolveDone, rejectDone);
	}
	async open(world, machine, resolveDone, rejectDone) {
		try {
			const client = await world.poolFor(machine).connect();
			const command = buildRemoteCommand(rewriteRipgrep(this.spec.argv, world.config.remoteRipgrep), this.spec.env);
			await new Promise((resolve, reject) => {
				client.exec(command, {}, (err, channel) => {
					if (err) {
						reject(/* @__PURE__ */ new Error(`remote spawn failed: ${err.message}`));
						return;
					}
					this.attach(channel, resolveDone);
					resolve();
				});
			});
		} catch (err) {
			rejectDone(err);
		}
	}
	attach(channel, resolveDone) {
		const spec = this.spec;
		const state = {
			channel,
			stdoutBuffer: spec.stdio.stdout !== "pipe" && spec.stdio.stdout !== "inherit" ? new CollectBuffer(spec.stdio.stdout.maxBytes) : void 0,
			stderrBuffer: spec.stdio.stderr !== "pipe" && spec.stdio.stderr !== "inherit" ? new CollectBuffer(spec.stdio.stderr.maxBytes) : void 0,
			stdinPipe: spec.stdio.stdin === "pipe",
			stdoutPipe: spec.stdio.stdout === "pipe"
		};
		this.state = state;
		if (state.stdoutBuffer) channel.on("data", (d) => state.stdoutBuffer?.push(new Uint8Array(d)));
		if (state.stderrBuffer) channel.stderr?.on("data", (d) => state.stderrBuffer?.push(new Uint8Array(d)));
		if (spec.stdio.stderr === "inherit") channel.stderr?.on("data", (d) => process.stderr.write(d));
		if (spec.stdio.stdin === "ignore") try {
			channel.end();
		} catch {}
		else if (spec.stdio.stdin !== "pipe") {
			channel.write(spec.stdio.stdin.data, "utf8");
			try {
				channel.end();
			} catch {}
		}
		channel.on("close", (code, sig) => {
			resolveDone({
				exitCode: typeof code === "number" ? code : null,
				signal: sig ?? null
			});
		});
		channel.on("error", () => {
			resolveDone({
				exitCode: null,
				signal: null
			});
		});
		if (this.terminated) this.terminate();
	}
	get stdin() {
		return this.state?.stdinPipe ? this.state.channel : void 0;
	}
	get stdout() {
		return this.state?.stdoutPipe ? this.state.channel : void 0;
	}
	get stderr() {}
	get collected() {
		const state = this.state;
		if (!state) return {};
		return {
			...state.stdoutBuffer ? { stdout: readerOf(state.stdoutBuffer) } : {},
			...state.stderrBuffer ? { stderr: readerOf(state.stderrBuffer) } : {}
		};
	}
	terminate() {
		this.terminated = true;
		const state = this.state;
		if (!state) return;
		try {
			state.channel.signal("SIGTERM");
		} catch {}
		setTimeout(() => {
			try {
				state.channel.close();
			} catch {}
		}, 500).unref();
	}
	async waitForExit(signal) {
		if (signal?.aborted) return false;
		return Promise.race([this.done.then(() => true), ...signal ? [new Promise((resolve) => {
			const onAbort = () => resolve(false);
			signal.addEventListener("abort", onAbort, { once: true });
		})] : []]);
	}
};
/**
* Re-point the packaged ripgrep binary at the remote `rg` command.
* @param argv - the local argv vector.
* @param remoteRipgrep - the remote ripgrep command name.
* @returns the argv with argv[0] rewritten when it is the packaged rg.
*/
function rewriteRipgrep(argv, remoteRipgrep) {
	const first = argv[0] ?? "";
	const rest = argv.slice(1);
	const base = first.replace(/\\/g, "/").split("/").pop() ?? "";
	if (base === "rg" || base === "rg.exe") return [remoteRipgrep, ...rest];
	return [first, ...rest];
}
/** Compose the remote command line: optional env prefix, then the quoted argv. */
function buildRemoteCommand(argv, env) {
	if (env) {
		const parts = [];
		for (const [key, value] of Object.entries(env)) {
			if (value === void 0) continue;
			parts.push(`${key}=${shq(value)}`);
		}
		if (parts.length > 0) return `env ${parts.join(" ")} ${argvToRemoteCommand(argv)}`;
	}
	return argvToRemoteCommand(argv);
}
/**
* The routing subprocess runtime. Construction registers `ctx.subprocess`; on
* win32 hosts every call delegates (remote command routing is a POSIX-host
* capability in v1), so the disabled base row never leaves the seam empty.
*/
var RoutingSubprocessRuntime = class extends LocalSubprocessRuntime {
	world;
	/**
	* @param ctx - plugin context.
	* @param world - the remote world coordinator.
	*/
	constructor(ctx, world) {
		super(ctx);
		this.world = world;
	}
	spawn(spec) {
		if (process.platform === "win32") return super.spawn(spec);
		const route = this.world.classifyHostPath(spec.cwd);
		if (route.kind !== "remote") return super.spawn(spec);
		const machine = this.world.machineForAnchor(route.route.anchor);
		if (!machine) return super.spawn(spec);
		return new RemoteSpawnHandle(this.world, machine, spec);
	}
	async spawnTerminal(spec) {
		if (process.platform !== "win32") {
			if (this.world.classifyHostPath(spec.cwd).kind === "remote") throw new Error("remote terminal sessions are not supported by dsh-remote-development yet. Use the bash tool to run commands on the remote host instead.");
		}
		return super.spawnTerminal(spec);
	}
};
//#endregion
//#region src/shell-router.ts
/** Marker written by the cd guard so a failed cd is an infrastructure error. */
const CD_FAIL_MARKER = "@@RDV_CD_FAIL@@";
/** Marker line that reports the background script's root PID. */
const PID_MARKER = "@@RDV_PID:";
/**
* Replace anchor-directory spellings (absolute, `~`-relative, and `$HOME`/
* `${HOME}` forms) with the anchors' remote paths. Longest dirs replace
* first, so a directory that prefixes another anchor's name is replaced as
* its own anchor, not as a prefix.
* @param text - command text or an env value.
* @param anchors - the anchors eligible for rewriting.
* @param home - the local home directory the `~`/`$HOME` forms resolve against.
* @returns the text with anchor paths mapped to remote paths.
*/
function rewriteAnchorSpellings(text, anchors, home) {
	let out = text;
	const ordered = [...anchors].sort((left, right) => right.dir.length - left.dir.length);
	for (const anchor of ordered) {
		out = out.split(anchor.dir).join(anchor.remoteRoot);
		if (anchor.dir.startsWith(`${home}/`)) {
			const rel = anchor.dir.slice(home.length);
			out = out.split(`~${rel}`).join(anchor.remoteRoot);
			out = out.split(`$HOME${rel}`).join(anchor.remoteRoot);
			out = out.split(`\${HOME}${rel}`).join(anchor.remoteRoot);
		}
	}
	return out;
}
/** The remote branch of the bash executor. */
var RoutingBashExecutor = class extends SandboxBashExecutor {
	world;
	/**
	* @param ctx - plugin context.
	* @param config - the inherited executor config (defaults).
	* @param world - the remote world coordinator.
	*/
	constructor(ctx, config, world) {
		super(ctx, config);
		this.world = world;
	}
	/**
	* Resolve the remote path for a workdir, accepting both coordinates: the
	* anchor-local spelling (session cwd) and a remote path the model saw in
	* command output.
	* @param workdir - the resolved local workdir.
	* @returns the machine and remote cwd, or null for the local backend.
	*/
	remoteCwdOf(workdir) {
		const local = this.world.classifyHostPath(workdir);
		if (local.kind === "remote") {
			const machine = this.world.machineForAnchor(local.route.anchor);
			if (machine) return {
				machine,
				remotePath: local.route.remotePath
			};
			return null;
		}
		const remote = this.world.classifyRemotePath(workdir);
		if (remote) {
			const machine = this.world.machineForAnchor(remote.anchor);
			if (machine) return {
				machine,
				remotePath: remote.remotePath
			};
		}
		return null;
	}
	async run(spec) {
		const route = this.remoteCwdOf(spec.workdir);
		if (!route) return super.run(spec);
		return this.runRemote(spec, route);
	}
	start(spec) {
		const route = this.remoteCwdOf(spec.workdir);
		if (!route) return super.start(spec);
		return this.startRemote(spec, route);
	}
	/** Compose the remote script: cd guard, env exports, then the command. */
	script(route, spec, prefixLines) {
		const lines = [`cd ${shq(route.remotePath)} || { echo ${shq(CD_FAIL_MARKER)} >&2; exit 125; }`, ...prefixLines];
		if (spec.env) for (const [key, value] of Object.entries(spec.env)) {
			if (value === void 0) continue;
			lines.push(`export ${key}=${shq(this.rewriteAnchorPaths(value, route.machine))}`);
		}
		lines.push(this.rewriteAnchorPaths(spec.command, route.machine));
		return lines.join("\n") + "\n";
	}
	/**
	* Replace anchor-directory spellings in command text with their remote
	* paths. Only anchors of the machine the command runs on are rewritten —
	* another machine's handle must not be silently redirected.
	* @param text - command text or an env value.
	* @param machine - the machine the command will run on.
	* @returns the text with same-machine anchor paths mapped to remote paths.
	*/
	rewriteAnchorPaths(text, machine) {
		return rewriteAnchorSpellings(text, this.world.anchors().filter((anchor) => {
			const ref = this.world.machineForAnchor(anchor);
			return ref !== null && ref.machine.id === machine.machine.id;
		}).map((anchor) => ({
			dir: anchor.dir,
			remoteRoot: anchor.remoteRoot
		})), homedir());
	}
	async runRemote(spec, route) {
		const pool = this.world.poolFor(route.machine);
		const command = `bash -c ${shq(this.script(route, spec, []))}`;
		const result = await pool.exec(command, {
			timeoutMs: spec.timeoutMs,
			...spec.stdin !== void 0 ? { stdin: spec.stdin } : {},
			...spec.signal !== void 0 ? { signal: spec.signal } : {}
		});
		if (result.stderr.includes(CD_FAIL_MARKER) && result.code === 125) throw new Error(`cannot use remote working directory ${route.remotePath}: ${result.stderr.replace(CD_FAIL_MARKER, "").trim()}`);
		const stdout = {
			text: result.stdout,
			truncated: false
		};
		const stderr = {
			text: result.stderr,
			truncated: false
		};
		return {
			exitCode: result.code,
			signal: result.signal,
			timedOut: result.timedOut,
			aborted: !result.timedOut && spec.signal?.aborted === true,
			timeoutMs: spec.timeoutMs,
			stdout,
			stderr,
			sandbox: {
				mode: spec.sandboxPolicy?.mode ?? this.sandboxMode ?? "danger-full-access",
				denied: false
			}
		};
	}
	startRemote(spec, route) {
		const pool = this.world.poolFor(route.machine);
		const command = `bash -c ${shq(this.script(route, spec, [`printf '${PID_MARKER}%s\\n' "$$"`]))}`;
		return new RemoteBackgroundProcess(this.world, route.machine, command, spec, pool.tunables.maxOutputChars);
	}
};
/**
* One remote background process. The first stdout line carries the root PID
* marker (filtered out of job output); kill() signals the remote process
* group best-effort, then closes the channel.
*/
var RemoteBackgroundProcess = class {
	world;
	machine;
	command;
	spec;
	status = "running";
	exitCode = null;
	signal = null;
	done;
	chunks = [];
	readCursor = 0;
	retained = 0;
	dropped = 0;
	maxBytes;
	pending = "";
	markerDone = false;
	remotePid = null;
	killed = false;
	/**
	* @param world - remote world (pool + audit).
	* @param machine - target machine.
	* @param command - the composed remote command line.
	* @param spec - the resolved shell spec.
	* @param maxBytes - output cap.
	*/
	constructor(world, machine, command, spec, maxBytes) {
		this.world = world;
		this.machine = machine;
		this.command = command;
		this.spec = spec;
		this.maxBytes = maxBytes;
		let resolveDone;
		this.done = new Promise((resolve) => {
			resolveDone = resolve;
		});
		this.run(resolveDone);
	}
	async run(resolveDone) {
		try {
			const client = await this.world.poolFor(this.machine).connect();
			await new Promise((resolve, reject) => {
				client.exec(this.command, {}, (err, channel) => {
					if (err) {
						reject(/* @__PURE__ */ new Error(`remote background command failed to start: ${err.message}`));
						return;
					}
					channel.on("data", (d) => this.ingest(d.toString("utf8")));
					channel.stderr?.on("data", (d) => this.ingest(d.toString("utf8")));
					channel.on("close", (code, sig) => {
						this.status = this.killed ? "killed" : "completed";
						this.exitCode = typeof code === "number" ? code : null;
						this.signal = sig ?? null;
						this.world.audit(this.machine, this.spec.command, this.exitCode);
						resolveDone();
					});
					if (this.spec.stdin !== void 0) channel.write(this.spec.stdin, "utf8");
					try {
						channel.end();
					} catch {}
					if (this.spec.signal) {
						if (this.spec.signal.aborted) this.kill();
						else this.spec.signal.addEventListener("abort", () => this.kill(), { once: true });
					}
					resolve();
				});
			});
		} catch (err) {
			this.status = "killed";
			this.exitCode = null;
			this.ingest(`\n[remote background spawn failed] ${err.message}\n`);
			this.world.audit(this.machine, this.spec.command, null);
			resolveDone();
		}
	}
	ingest(text) {
		this.pending += text;
		if (!this.markerDone) {
			const nl = this.pending.indexOf("\n");
			if (nl >= 0) {
				const first = this.pending.slice(0, nl);
				this.pending = this.pending.slice(nl + 1);
				const at = first.indexOf(PID_MARKER);
				if (at >= 0) {
					const pid = Number.parseInt(first.slice(at + 10), 10);
					if (Number.isFinite(pid)) this.remotePid = pid;
				}
				this.markerDone = true;
			}
		}
		if (!this.pending) return;
		this.chunks.push(this.pending);
		this.retained += this.pending.length;
		this.pending = "";
		if (this.maxBytes > 0 && this.retained > this.maxBytes) {
			const cut = this.retained - this.maxBytes;
			this.dropped = cut;
			let remaining = cut;
			while (remaining > 0 && this.chunks.length > 0) {
				const head = this.chunks[0];
				if (head === void 0) break;
				if (head.length <= remaining) {
					remaining -= head.length;
					this.chunks.shift();
				} else {
					this.chunks[0] = head.slice(remaining);
					remaining = 0;
				}
			}
			this.retained = this.maxBytes;
		}
	}
	readOutput() {
		const lossy = this.dropped > 0;
		this.dropped = 0;
		let delta = "";
		while (this.readCursor < this.chunks.length) {
			const chunk = this.chunks[this.readCursor];
			if (chunk !== void 0) delta += chunk;
			this.readCursor += 1;
		}
		return {
			delta,
			lossy
		};
	}
	kill() {
		if (this.status !== "running") return false;
		this.killed = true;
		this.signalRemote("TERM");
		setTimeout(() => {
			if (this.status === "running") this.signalRemote("KILL");
		}, 3e3).unref();
		return true;
	}
	async signalRemote(scope) {
		if (this.remotePid === null) return;
		const flag = scope === "TERM" ? "-TERM" : "-KILL";
		const command = `kill ${flag} -- -${this.remotePid} 2>/dev/null || kill ${flag} ${this.remotePid} 2>/dev/null || true`;
		try {
			await this.world.execOn(this.machine, command, { timeoutMs: 5e3 });
		} catch {}
	}
};
//#endregion
//#region src/prompt.ts
/**
* Register the prompt section and the per-agent cwd override.
* @param ctx - plugin context.
* @param world - the remote world coordinator.
*/
function registerPrompt(ctx, world) {
	ctx.systemPrompt.section({
		name: "dsh-remote-development",
		order: 88,
		text: (promptContext) => {
			const cwd = (promptContext?.agent)?.session?.header?.cwd;
			if (!cwd) return "";
			const local = world.classifyHostPath(cwd);
			if (local.kind !== "remote") return "";
			const anchor = local.route.anchor;
			const machine = world.machineForAnchor(anchor);
			if (!machine) return "";
			const who = `${machine.machine.username || "user"}@${machine.machine.host}`;
			const name = remoteBasename(local.route.remotePath) || local.route.remotePath;
			return [
				"## Remote workspace",
				`This session's workspace is a remote directory: ${who}:${local.route.remotePath} ("${name}").`,
				"All file tools (read/write/edit/ls/grep/glob) and shell commands operate on that remote host directly.",
				`File paths in tool calls are remote paths under ${local.route.remotePath}; the local workspace directory on this machine is only a handle and does not mirror the remote files.`
			].join("\n");
		}
	});
	const fibers = /* @__PURE__ */ new Map();
	const install = (agent) => {
		if (fibers.has(agent)) return;
		fibers.set(agent, agent.ctx.inject(["systemPrompt"], (scope) => {
			scope.systemPrompt.variable("cwd", (context) => {
				const cwd = context.agent?.session?.header?.cwd;
				if (!cwd) return void 0;
				const local = world.classifyHostPath(cwd);
				return local.kind === "remote" ? local.route.remotePath : cwd;
			});
		}));
	};
	const dispose = (agent) => {
		const fiber = fibers.get(agent);
		if (fiber === void 0) return;
		fibers.delete(agent);
		fiber.dispose().catch((error) => {
			ctx.logger.warn(`dsh-remote-development: cwd override cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
		});
	};
	for (const agent of ctx.agents.list()) install(agent);
	ctx.on("agent/created", ({ agent }) => {
		install(agent);
	});
	ctx.on("agent/disposed", ({ agent }) => {
		dispose(agent);
	});
}
//#endregion
//#region src/routes.ts
const ROUTE_PREFIX = "/dsh-remote-development";
const BODY_LIMIT_BYTES = 262144;
/** One machine as the client may see it: credentials never leave the host. */
function publicMachine(m) {
	return {
		id: m.id,
		name: m.name,
		host: m.host,
		port: m.port,
		username: m.username,
		privateKeyPath: m.privateKeyPath,
		useAgent: m.useAgent,
		keyboardInteractive: m.keyboardInteractive,
		hasPassword: m.password.length > 0,
		hasPassphrase: m.passphrase.length > 0,
		hostKeyMode: m.hostKeyMode,
		proxyHost: m.proxy?.host ?? "",
		workspace: m.workspace
	};
}
/**
* Read one JSON body with a size cap.
* @param req - the request.
* @returns the parsed body, or null when absent/over the cap/invalid.
*/
function readJsonBody(req) {
	return new Promise((resolve) => {
		const chunks = [];
		let size = 0;
		let done = false;
		const finish = (value) => {
			if (done) return;
			done = true;
			resolve(value);
		};
		req.on("data", (chunk) => {
			size += chunk.length;
			if (size > BODY_LIMIT_BYTES) {
				finish(null);
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on("end", () => {
			if (done) return;
			const raw = Buffer.concat(chunks).toString("utf8").trim();
			if (!raw) return finish({});
			try {
				const parsed = JSON.parse(raw);
				finish(parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null);
			} catch {
				finish(null);
			}
		});
		req.on("error", () => finish(null));
	});
}
function sendJson(res, status, body) {
	const text = JSON.stringify(body);
	res.writeHead(status, {
		"Content-Type": "application/json; charset=utf-8",
		"Content-Length": Buffer.byteLength(text)
	});
	res.end(text);
}
/**
* Register the JSON routes on the live web server.
* @param ctx - plugin context (effects scope the disposers).
* @param webServer - the running web server.
* @param world - the remote world coordinator.
*/
function registerRoutes(ctx, webServer, world) {
	const machineFromBody = (body) => ({
		name: String(body.name ?? ""),
		host: String(body.host ?? ""),
		port: Number(body.port ?? 22),
		username: String(body.username ?? ""),
		password: String(body.password ?? ""),
		privateKeyPath: String(body.privateKeyPath ?? ""),
		passphrase: String(body.passphrase ?? ""),
		useAgent: body.useAgent === true,
		keyboardInteractive: body.keyboardInteractive === true,
		hostKeyMode: String(body.hostKeyMode ?? "accept-new"),
		...typeof body.proxyHost === "string" && body.proxyHost.trim() ? { proxy: {
			host: String(body.proxyHost),
			port: Number(body.proxyPort ?? 22),
			username: String(body.proxyUsername ?? ""),
			password: String(body.proxyPassword ?? ""),
			privateKeyPath: "",
			passphrase: ""
		} } : {}
	});
	const resolveRef = (body) => {
		const id = String(body.machineId ?? body.id ?? "");
		const ref = id ? world.machineById(id) : null;
		if (!ref) {
			const current = world.currentMachine();
			return current ? {
				source: "registry",
				machine: current
			} : null;
		}
		return ref;
	};
	const disposers = [
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/machines`,
			handler: async (req, res) => {
				if (req.method === "GET") return sendJson(res, 200, {
					machines: world.listMachines().map(publicMachine),
					currentId: world.currentMachine()?.id ?? null
				});
				if (req.method === "POST") {
					const body = await readJsonBody(req);
					if (!body) return sendJson(res, 400, {
						ok: false,
						error: "invalid JSON body"
					});
					if (!String(body.host ?? "").trim()) return sendJson(res, 400, {
						ok: false,
						error: "host is required"
					});
					return sendJson(res, 200, {
						ok: true,
						machine: publicMachine(world.upsertMachine(machineFromBody(body)))
					});
				}
				return sendJson(res, 405, {
					ok: false,
					error: "method not allowed"
				});
			}
		},
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/machines/delete`,
			handler: async (req, res) => {
				if (req.method !== "POST") return sendJson(res, 405, {
					ok: false,
					error: "method not allowed"
				});
				const body = await readJsonBody(req);
				const id = String(body?.id ?? "");
				if (!id) return sendJson(res, 400, {
					ok: false,
					error: "id is required"
				});
				return sendJson(res, 200, { ok: world.removeMachine(id) });
			}
		},
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/machines/current`,
			handler: async (req, res) => {
				if (req.method !== "POST") return sendJson(res, 405, {
					ok: false,
					error: "method not allowed"
				});
				const body = await readJsonBody(req);
				if (!body) return sendJson(res, 400, {
					ok: false,
					error: "invalid JSON body"
				});
				const id = body.id === null ? null : String(body.id ?? "");
				return sendJson(res, 200, { ok: world.setCurrent(id) });
			}
		},
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/test`,
			handler: async (req, res) => {
				if (req.method !== "POST") return sendJson(res, 405, {
					ok: false,
					error: "method not allowed"
				});
				const body = await readJsonBody(req);
				if (!body) return sendJson(res, 400, {
					ok: false,
					error: "invalid JSON body"
				});
				const ref = resolveRef(body) ?? world.ephemeralRef(machineFromBody(body));
				try {
					const pool = world.poolFor(ref);
					await pool.exec("echo dsh-remote-development-ok", { timeoutMs: Math.min(world.config.connectTimeoutMs + world.config.commandTimeoutMs, 3e4) });
					return sendJson(res, 200, {
						ok: true,
						platform: pool.platformInfo
					});
				} catch (err) {
					return sendJson(res, 200, {
						ok: false,
						error: err.message
					});
				}
			}
		},
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/ls`,
			handler: async (req, res) => {
				if (req.method !== "POST") return sendJson(res, 405, {
					ok: false,
					error: "method not allowed"
				});
				const body = await readJsonBody(req);
				if (!body) return sendJson(res, 400, {
					ok: false,
					error: "invalid JSON body"
				});
				const ref = resolveRef(body);
				if (!ref) return sendJson(res, 400, {
					ok: false,
					error: "no machine available"
				});
				try {
					const path = normalizeRemotePath(String(body.path ?? "~"));
					const expanded = path === "~" || path.startsWith("~/") ? (await world.execOn(ref, "echo $HOME", { timeoutMs: 8e3 })).stdout.trim() : "";
					const dir = expanded ? normalizeRemotePath(path.replace(/^~/, expanded)) : path;
					const result = await world.execOn(ref, `ls -1Ap ${JSON.stringify(dir)} 2>/dev/null | head -500`, { timeoutMs: world.config.commandTimeoutMs });
					if (result.code !== 0) return sendJson(res, 200, {
						ok: false,
						error: `cannot list ${dir}: ${result.stderr.trim() || `exit ${result.code}`}`
					});
					return sendJson(res, 200, {
						ok: true,
						path: dir,
						entries: result.stdout.split("\n").filter(Boolean).map((line) => {
							const isDir = line.endsWith("/");
							const name = isDir ? line.slice(0, -1) : line;
							return {
								name,
								dir: isDir,
								path: dir === "/" ? `/${name}` : `${dir}/${name}`
							};
						})
					});
				} catch (err) {
					return sendJson(res, 200, {
						ok: false,
						error: err.message
					});
				}
			}
		},
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/mkdir`,
			handler: async (req, res) => {
				if (req.method !== "POST") return sendJson(res, 405, {
					ok: false,
					error: "method not allowed"
				});
				const body = await readJsonBody(req);
				if (!body) return sendJson(res, 400, {
					ok: false,
					error: "invalid JSON body"
				});
				const ref = resolveRef(body);
				if (!ref) return sendJson(res, 400, {
					ok: false,
					error: "no machine available"
				});
				const parent = normalizeRemotePath(String(body.path ?? ""));
				const name = String(body.name ?? "").trim();
				if (!name || name.includes("/")) return sendJson(res, 400, {
					ok: false,
					error: "a single folder name is required"
				});
				const target = parent === "/" ? `/${name}` : `${parent}/${name}`;
				try {
					const result = await world.execOn(ref, `mkdir ${JSON.stringify(target)}`, { timeoutMs: world.config.commandTimeoutMs });
					if (result.code !== 0) return sendJson(res, 200, {
						ok: false,
						error: result.stderr.trim() || `exit ${result.code}`
					});
					return sendJson(res, 200, {
						ok: true,
						path: target
					});
				} catch (err) {
					return sendJson(res, 200, {
						ok: false,
						error: err.message
					});
				}
			}
		},
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/anchor`,
			handler: async (req, res) => {
				if (req.method !== "POST") return sendJson(res, 405, {
					ok: false,
					error: "method not allowed"
				});
				const body = await readJsonBody(req);
				if (!body) return sendJson(res, 400, {
					ok: false,
					error: "invalid JSON body"
				});
				const ref = resolveRef(body);
				if (!ref) return sendJson(res, 400, {
					ok: false,
					error: "no machine available"
				});
				const remotePath = normalizeRemotePath(String(body.path ?? ""));
				if (!remotePath.startsWith("/")) return sendJson(res, 400, {
					ok: false,
					error: "an absolute remote directory path is required"
				});
				try {
					return sendJson(res, 200, {
						ok: true,
						anchorPath: world.createAnchor(ref.machine, remotePath),
						remotePath
					});
				} catch (err) {
					return sendJson(res, 200, {
						ok: false,
						error: err.message
					});
				}
			}
		},
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/session-remote`,
			handler: async (req, res) => {
				if (req.method !== "GET") return sendJson(res, 405, {
					ok: false,
					error: "method not allowed"
				});
				const sessionId = new URL(req.url ?? "/", "http://localhost").searchParams.get("sessionId") ?? "";
				if (!sessionId) return sendJson(res, 400, {
					ok: false,
					error: "sessionId is required"
				});
				const sessions = ctx.get("sessions");
				if (sessions === void 0) return sendJson(res, 200, { remote: false });
				try {
					const cwd = sessions.get(sessionId)?.header?.cwd;
					if (!cwd) return sendJson(res, 200, { remote: false });
					const local = world.classifyHostPath(cwd);
					if (local.kind !== "remote") return sendJson(res, 200, { remote: false });
					return sendJson(res, 200, {
						remote: true,
						remotePath: local.route.remotePath
					});
				} catch (err) {
					return sendJson(res, 200, {
						remote: false,
						error: err.message
					});
				}
			}
		},
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/status`,
			handler: async (_req, res) => {
				const current = world.currentMachine();
				return sendJson(res, 200, {
					current: current ? publicMachine(current) : null,
					anchors: world.anchors().map((a) => ({
						dir: a.dir,
						remotePath: a.remoteRoot
					}))
				});
			}
		}
	].map((route) => webServer.register(route));
	ctx.effect(() => () => disposers.forEach((dispose) => dispose()), "dsh-remote-development.routes");
}
//#endregion
//#region src/index.ts
const name = "dsh-remote-development";
/** systemPrompt must exist before the section registers; sandboxPolicy before the sandboxed providers read it; agents before the per-agent cwd override enumerates live agents. */
const inject = [
	"systemPrompt",
	"sandboxPolicy",
	"agents"
];
/** Local-backend defaults used when constructing the routing providers by hand. */
const LOCAL_FS_DIFF_BASIS_MAX_BYTES = 10485760;
const BASH_TIMEOUT_MS = 12e4;
const BASH_MAX_TIMEOUT_MS = 6e5;
const BASH_MAX_OUTPUT_BYTES = 64e3;
const BASH_MAX_SPILL_BYTES = 67108864;
const BASH_GRACE_MS = 3e3;
/**
* Plugin body: construct the world and mount every routing provider.
* @param ctx - the plugin context; registrations are effects scoped to it.
* @param config - schemastery-validated plugin config.
*/
function apply(ctx, config) {
	const world = new RemoteWorld(config);
	ctx.effect(() => () => world.dispose(), "dsh-remote-development.world");
	new RoutingFileSystem(ctx, world, config.commandTimeoutMs, config.maxFileBytes, {
		cwd: process.cwd(),
		diffBasisMaxBytes: LOCAL_FS_DIFF_BASIS_MAX_BYTES
	});
	new RoutingSubprocessRuntime(ctx, world);
	if (process.platform !== "win32") new RoutingBashExecutor(ctx, {
		cwd: process.cwd(),
		timeoutMs: BASH_TIMEOUT_MS,
		maxTimeoutMs: BASH_MAX_TIMEOUT_MS,
		maxOutputBytes: BASH_MAX_OUTPUT_BYTES,
		maxSpillBytes: BASH_MAX_SPILL_BYTES,
		graceMs: BASH_GRACE_MS
	}, world);
	registerPrompt(ctx, world);
	ctx.inject(["webServer"], (serviceCtx) => {
		registerRoutes(serviceCtx, serviceCtx.webServer, world);
	});
}
//#endregion
export { Config, apply, inject, name };

//# sourceMappingURL=index.js.map