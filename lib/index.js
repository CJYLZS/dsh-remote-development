import { createRequire as __rdvCreateRequire } from "node:module";
import { fileURLToPath as __rdvFileURLToPath } from "node:url";
import { dirname as __rdvDirname } from "node:path";
__rdvCreateRequire(import.meta.url);
const __filename = __rdvFileURLToPath(import.meta.url);
const __dirname = __rdvDirname(__filename);
import { createRequire } from "node:module";
import z from "@deepseek-ai/schemastery";
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path, { dirname } from "node:path";
import { createHash } from "node:crypto";
import { FsError, FsTargetKey, FsVersion } from "@deepseek-ai/dsh-fs";
import { SandboxedFileSystem } from "@deepseek-ai/dsh-fs-sandbox";
import { LocalSubprocessRuntime } from "@deepseek-ai/dsh-subprocess-local";
import { SandboxBashExecutor } from "@deepseek-ai/dsh-bash-sandbox";
import { SandboxPwshExecutor } from "@deepseek-ai/dsh-pwsh-sandbox";
//#region \0rolldown/runtime.js
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJSMin = (cb, mod) => () => (mod || (cb((mod = { exports: {} }).exports, mod), cb = null), mod.exports);
var __copyProps = (to, from, except, desc) => {
	if (from && typeof from === "object" || typeof from === "function") for (var keys = __getOwnPropNames(from), i = 0, n = keys.length, key; i < n; i++) {
		key = keys[i];
		if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, {
			get: ((k) => from[k]).bind(null, key),
			enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
		});
	}
	return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule || !__hasOwnProp.call(mod, "default") ? __defProp(target, "default", {
	value: mod,
	enumerable: true
}) : target, mod));
var __require = /* #__PURE__ */ (() => createRequire(import.meta.url))();
//#endregion
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
//#region node_modules/.pnpm/asn1@0.2.6/node_modules/asn1/lib/ber/errors.js
var require_errors = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	module.exports = { newInvalidAsn1Error: function(msg) {
		var e = /* @__PURE__ */ new Error();
		e.name = "InvalidAsn1Error";
		e.message = msg || "";
		return e;
	} };
}));
//#endregion
//#region node_modules/.pnpm/asn1@0.2.6/node_modules/asn1/lib/ber/types.js
var require_types = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	module.exports = {
		EOC: 0,
		Boolean: 1,
		Integer: 2,
		BitString: 3,
		OctetString: 4,
		Null: 5,
		OID: 6,
		ObjectDescriptor: 7,
		External: 8,
		Real: 9,
		Enumeration: 10,
		PDV: 11,
		Utf8String: 12,
		RelativeOID: 13,
		Sequence: 16,
		Set: 17,
		NumericString: 18,
		PrintableString: 19,
		T61String: 20,
		VideotexString: 21,
		IA5String: 22,
		UTCTime: 23,
		GeneralizedTime: 24,
		GraphicString: 25,
		VisibleString: 26,
		GeneralString: 28,
		UniversalString: 29,
		CharacterString: 30,
		BMPString: 31,
		Constructor: 32,
		Context: 128
	};
}));
//#endregion
//#region node_modules/.pnpm/safer-buffer@2.1.2/node_modules/safer-buffer/safer.js
var require_safer = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var buffer = __require("buffer");
	var Buffer = buffer.Buffer;
	var safer = {};
	var key;
	for (key in buffer) {
		if (!buffer.hasOwnProperty(key)) continue;
		if (key === "SlowBuffer" || key === "Buffer") continue;
		safer[key] = buffer[key];
	}
	var Safer = safer.Buffer = {};
	for (key in Buffer) {
		if (!Buffer.hasOwnProperty(key)) continue;
		if (key === "allocUnsafe" || key === "allocUnsafeSlow") continue;
		Safer[key] = Buffer[key];
	}
	safer.Buffer.prototype = Buffer.prototype;
	if (!Safer.from || Safer.from === Uint8Array.from) Safer.from = function(value, encodingOrOffset, length) {
		if (typeof value === "number") throw new TypeError("The \"value\" argument must not be of type number. Received type " + typeof value);
		if (value && typeof value.length === "undefined") throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof value);
		return Buffer(value, encodingOrOffset, length);
	};
	if (!Safer.alloc) Safer.alloc = function(size, fill, encoding) {
		if (typeof size !== "number") throw new TypeError("The \"size\" argument must be of type number. Received type " + typeof size);
		if (size < 0 || size >= 2 * (1 << 30)) throw new RangeError("The value \"" + size + "\" is invalid for option \"size\"");
		var buf = Buffer(size);
		if (!fill || fill.length === 0) buf.fill(0);
		else if (typeof encoding === "string") buf.fill(fill, encoding);
		else buf.fill(fill);
		return buf;
	};
	if (!safer.kStringMaxLength) try {
		safer.kStringMaxLength = process.binding("buffer").kStringMaxLength;
	} catch (e) {}
	if (!safer.constants) {
		safer.constants = { MAX_LENGTH: safer.kMaxLength };
		if (safer.kStringMaxLength) safer.constants.MAX_STRING_LENGTH = safer.kStringMaxLength;
	}
	module.exports = safer;
}));
//#endregion
//#region node_modules/.pnpm/asn1@0.2.6/node_modules/asn1/lib/ber/reader.js
var require_reader = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var assert$2 = __require("assert");
	var Buffer = require_safer().Buffer;
	var ASN1 = require_types();
	var newInvalidAsn1Error = require_errors().newInvalidAsn1Error;
	function Reader(data) {
		if (!data || !Buffer.isBuffer(data)) throw new TypeError("data must be a node Buffer");
		this._buf = data;
		this._size = data.length;
		this._len = 0;
		this._offset = 0;
	}
	Object.defineProperty(Reader.prototype, "length", {
		enumerable: true,
		get: function() {
			return this._len;
		}
	});
	Object.defineProperty(Reader.prototype, "offset", {
		enumerable: true,
		get: function() {
			return this._offset;
		}
	});
	Object.defineProperty(Reader.prototype, "remain", { get: function() {
		return this._size - this._offset;
	} });
	Object.defineProperty(Reader.prototype, "buffer", { get: function() {
		return this._buf.slice(this._offset);
	} });
	/**
	* Reads a single byte and advances offset; you can pass in `true` to make this
	* a "peek" operation (i.e., get the byte, but don't advance the offset).
	*
	* @param {Boolean} peek true means don't move offset.
	* @return {Number} the next byte, null if not enough data.
	*/
	Reader.prototype.readByte = function(peek) {
		if (this._size - this._offset < 1) return null;
		var b = this._buf[this._offset] & 255;
		if (!peek) this._offset += 1;
		return b;
	};
	Reader.prototype.peek = function() {
		return this.readByte(true);
	};
	/**
	* Reads a (potentially) variable length off the BER buffer.  This call is
	* not really meant to be called directly, as callers have to manipulate
	* the internal buffer afterwards.
	*
	* As a result of this call, you can call `Reader.length`, until the
	* next thing called that does a readLength.
	*
	* @return {Number} the amount of offset to advance the buffer.
	* @throws {InvalidAsn1Error} on bad ASN.1
	*/
	Reader.prototype.readLength = function(offset) {
		if (offset === void 0) offset = this._offset;
		if (offset >= this._size) return null;
		var lenB = this._buf[offset++] & 255;
		if (lenB === null) return null;
		if ((lenB & 128) === 128) {
			lenB &= 127;
			if (lenB === 0) throw newInvalidAsn1Error("Indefinite length not supported");
			if (lenB > 4) throw newInvalidAsn1Error("encoding too long");
			if (this._size - offset < lenB) return null;
			this._len = 0;
			for (var i = 0; i < lenB; i++) this._len = (this._len << 8) + (this._buf[offset++] & 255);
		} else this._len = lenB;
		return offset;
	};
	/**
	* Parses the next sequence in this BER buffer.
	*
	* To get the length of the sequence, call `Reader.length`.
	*
	* @return {Number} the sequence's tag.
	*/
	Reader.prototype.readSequence = function(tag) {
		var seq = this.peek();
		if (seq === null) return null;
		if (tag !== void 0 && tag !== seq) throw newInvalidAsn1Error("Expected 0x" + tag.toString(16) + ": got 0x" + seq.toString(16));
		var o = this.readLength(this._offset + 1);
		if (o === null) return null;
		this._offset = o;
		return seq;
	};
	Reader.prototype.readInt = function() {
		return this._readTag(ASN1.Integer);
	};
	Reader.prototype.readBoolean = function() {
		return this._readTag(ASN1.Boolean) === 0 ? false : true;
	};
	Reader.prototype.readEnumeration = function() {
		return this._readTag(ASN1.Enumeration);
	};
	Reader.prototype.readString = function(tag, retbuf) {
		if (!tag) tag = ASN1.OctetString;
		var b = this.peek();
		if (b === null) return null;
		if (b !== tag) throw newInvalidAsn1Error("Expected 0x" + tag.toString(16) + ": got 0x" + b.toString(16));
		var o = this.readLength(this._offset + 1);
		if (o === null) return null;
		if (this.length > this._size - o) return null;
		this._offset = o;
		if (this.length === 0) return retbuf ? Buffer.alloc(0) : "";
		var str = this._buf.slice(this._offset, this._offset + this.length);
		this._offset += this.length;
		return retbuf ? str : str.toString("utf8");
	};
	Reader.prototype.readOID = function(tag) {
		if (!tag) tag = ASN1.OID;
		var b = this.readString(tag, true);
		if (b === null) return null;
		var values = [];
		var value = 0;
		for (var i = 0; i < b.length; i++) {
			var byte = b[i] & 255;
			value <<= 7;
			value += byte & 127;
			if ((byte & 128) === 0) {
				values.push(value);
				value = 0;
			}
		}
		value = values.shift();
		values.unshift(value % 40);
		values.unshift(value / 40 >> 0);
		return values.join(".");
	};
	Reader.prototype._readTag = function(tag) {
		assert$2.ok(tag !== void 0);
		var b = this.peek();
		if (b === null) return null;
		if (b !== tag) throw newInvalidAsn1Error("Expected 0x" + tag.toString(16) + ": got 0x" + b.toString(16));
		var o = this.readLength(this._offset + 1);
		if (o === null) return null;
		if (this.length > 4) throw newInvalidAsn1Error("Integer too long: " + this.length);
		if (this.length > this._size - o) return null;
		this._offset = o;
		var fb = this._buf[this._offset];
		var value = 0;
		for (var i = 0; i < this.length; i++) {
			value <<= 8;
			value |= this._buf[this._offset++] & 255;
		}
		if ((fb & 128) === 128 && i !== 4) value -= 1 << i * 8;
		return value >> 0;
	};
	module.exports = Reader;
}));
//#endregion
//#region node_modules/.pnpm/asn1@0.2.6/node_modules/asn1/lib/ber/writer.js
var require_writer = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var assert$1 = __require("assert");
	var Buffer = require_safer().Buffer;
	var ASN1 = require_types();
	var newInvalidAsn1Error = require_errors().newInvalidAsn1Error;
	var DEFAULT_OPTS = {
		size: 1024,
		growthFactor: 8
	};
	function merge(from, to) {
		assert$1.ok(from);
		assert$1.equal(typeof from, "object");
		assert$1.ok(to);
		assert$1.equal(typeof to, "object");
		Object.getOwnPropertyNames(from).forEach(function(key) {
			if (to[key]) return;
			var value = Object.getOwnPropertyDescriptor(from, key);
			Object.defineProperty(to, key, value);
		});
		return to;
	}
	function Writer(options) {
		options = merge(DEFAULT_OPTS, options || {});
		this._buf = Buffer.alloc(options.size || 1024);
		this._size = this._buf.length;
		this._offset = 0;
		this._options = options;
		this._seq = [];
	}
	Object.defineProperty(Writer.prototype, "buffer", { get: function() {
		if (this._seq.length) throw newInvalidAsn1Error(this._seq.length + " unended sequence(s)");
		return this._buf.slice(0, this._offset);
	} });
	Writer.prototype.writeByte = function(b) {
		if (typeof b !== "number") throw new TypeError("argument must be a Number");
		this._ensure(1);
		this._buf[this._offset++] = b;
	};
	Writer.prototype.writeInt = function(i, tag) {
		if (typeof i !== "number") throw new TypeError("argument must be a Number");
		if (typeof tag !== "number") tag = ASN1.Integer;
		var sz = 4;
		while (((i & 4286578688) === 0 || (i & 4286578688) === -8388608) && sz > 1) {
			sz--;
			i <<= 8;
		}
		if (sz > 4) throw newInvalidAsn1Error("BER ints cannot be > 0xffffffff");
		this._ensure(2 + sz);
		this._buf[this._offset++] = tag;
		this._buf[this._offset++] = sz;
		while (sz-- > 0) {
			this._buf[this._offset++] = (i & 4278190080) >>> 24;
			i <<= 8;
		}
	};
	Writer.prototype.writeNull = function() {
		this.writeByte(ASN1.Null);
		this.writeByte(0);
	};
	Writer.prototype.writeEnumeration = function(i, tag) {
		if (typeof i !== "number") throw new TypeError("argument must be a Number");
		if (typeof tag !== "number") tag = ASN1.Enumeration;
		return this.writeInt(i, tag);
	};
	Writer.prototype.writeBoolean = function(b, tag) {
		if (typeof b !== "boolean") throw new TypeError("argument must be a Boolean");
		if (typeof tag !== "number") tag = ASN1.Boolean;
		this._ensure(3);
		this._buf[this._offset++] = tag;
		this._buf[this._offset++] = 1;
		this._buf[this._offset++] = b ? 255 : 0;
	};
	Writer.prototype.writeString = function(s, tag) {
		if (typeof s !== "string") throw new TypeError("argument must be a string (was: " + typeof s + ")");
		if (typeof tag !== "number") tag = ASN1.OctetString;
		var len = Buffer.byteLength(s);
		this.writeByte(tag);
		this.writeLength(len);
		if (len) {
			this._ensure(len);
			this._buf.write(s, this._offset);
			this._offset += len;
		}
	};
	Writer.prototype.writeBuffer = function(buf, tag) {
		if (typeof tag !== "number") throw new TypeError("tag must be a number");
		if (!Buffer.isBuffer(buf)) throw new TypeError("argument must be a buffer");
		this.writeByte(tag);
		this.writeLength(buf.length);
		this._ensure(buf.length);
		buf.copy(this._buf, this._offset, 0, buf.length);
		this._offset += buf.length;
	};
	Writer.prototype.writeStringArray = function(strings) {
		if (!strings instanceof Array) throw new TypeError("argument must be an Array[String]");
		var self = this;
		strings.forEach(function(s) {
			self.writeString(s);
		});
	};
	Writer.prototype.writeOID = function(s, tag) {
		if (typeof s !== "string") throw new TypeError("argument must be a string");
		if (typeof tag !== "number") tag = ASN1.OID;
		if (!/^([0-9]+\.){3,}[0-9]+$/.test(s)) throw new Error("argument is not a valid OID string");
		function encodeOctet(bytes, octet) {
			if (octet < 128) bytes.push(octet);
			else if (octet < 16384) {
				bytes.push(octet >>> 7 | 128);
				bytes.push(octet & 127);
			} else if (octet < 2097152) {
				bytes.push(octet >>> 14 | 128);
				bytes.push((octet >>> 7 | 128) & 255);
				bytes.push(octet & 127);
			} else if (octet < 268435456) {
				bytes.push(octet >>> 21 | 128);
				bytes.push((octet >>> 14 | 128) & 255);
				bytes.push((octet >>> 7 | 128) & 255);
				bytes.push(octet & 127);
			} else {
				bytes.push((octet >>> 28 | 128) & 255);
				bytes.push((octet >>> 21 | 128) & 255);
				bytes.push((octet >>> 14 | 128) & 255);
				bytes.push((octet >>> 7 | 128) & 255);
				bytes.push(octet & 127);
			}
		}
		var tmp = s.split(".");
		var bytes = [];
		bytes.push(parseInt(tmp[0], 10) * 40 + parseInt(tmp[1], 10));
		tmp.slice(2).forEach(function(b) {
			encodeOctet(bytes, parseInt(b, 10));
		});
		var self = this;
		this._ensure(2 + bytes.length);
		this.writeByte(tag);
		this.writeLength(bytes.length);
		bytes.forEach(function(b) {
			self.writeByte(b);
		});
	};
	Writer.prototype.writeLength = function(len) {
		if (typeof len !== "number") throw new TypeError("argument must be a Number");
		this._ensure(4);
		if (len <= 127) this._buf[this._offset++] = len;
		else if (len <= 255) {
			this._buf[this._offset++] = 129;
			this._buf[this._offset++] = len;
		} else if (len <= 65535) {
			this._buf[this._offset++] = 130;
			this._buf[this._offset++] = len >> 8;
			this._buf[this._offset++] = len;
		} else if (len <= 16777215) {
			this._buf[this._offset++] = 131;
			this._buf[this._offset++] = len >> 16;
			this._buf[this._offset++] = len >> 8;
			this._buf[this._offset++] = len;
		} else throw newInvalidAsn1Error("Length too long (> 4 bytes)");
	};
	Writer.prototype.startSequence = function(tag) {
		if (typeof tag !== "number") tag = ASN1.Sequence | ASN1.Constructor;
		this.writeByte(tag);
		this._seq.push(this._offset);
		this._ensure(3);
		this._offset += 3;
	};
	Writer.prototype.endSequence = function() {
		var seq = this._seq.pop();
		var start = seq + 3;
		var len = this._offset - start;
		if (len <= 127) {
			this._shift(start, len, -2);
			this._buf[seq] = len;
		} else if (len <= 255) {
			this._shift(start, len, -1);
			this._buf[seq] = 129;
			this._buf[seq + 1] = len;
		} else if (len <= 65535) {
			this._buf[seq] = 130;
			this._buf[seq + 1] = len >> 8;
			this._buf[seq + 2] = len;
		} else if (len <= 16777215) {
			this._shift(start, len, 1);
			this._buf[seq] = 131;
			this._buf[seq + 1] = len >> 16;
			this._buf[seq + 2] = len >> 8;
			this._buf[seq + 3] = len;
		} else throw newInvalidAsn1Error("Sequence too long");
	};
	Writer.prototype._shift = function(start, len, shift) {
		assert$1.ok(start !== void 0);
		assert$1.ok(len !== void 0);
		assert$1.ok(shift);
		this._buf.copy(this._buf, start + shift, start, start + len);
		this._offset += shift;
	};
	Writer.prototype._ensure = function(len) {
		assert$1.ok(len);
		if (this._size - this._offset < len) {
			var sz = this._size * this._options.growthFactor;
			if (sz - this._offset < len) sz += len;
			var buf = Buffer.alloc(sz);
			this._buf.copy(buf, 0, 0, this._offset);
			this._buf = buf;
			this._size = sz;
		}
	};
	module.exports = Writer;
}));
//#endregion
//#region node_modules/.pnpm/asn1@0.2.6/node_modules/asn1/lib/ber/index.js
var require_ber = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var errors = require_errors();
	var types = require_types();
	module.exports = {
		Reader: require_reader(),
		Writer: require_writer()
	};
	for (var t in types) if (types.hasOwnProperty(t)) module.exports[t] = types[t];
	for (var e in errors) if (errors.hasOwnProperty(e)) module.exports[e] = errors[e];
}));
//#endregion
//#region node_modules/.pnpm/asn1@0.2.6/node_modules/asn1/lib/index.js
var require_lib$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var Ber = require_ber();
	module.exports = {
		Ber,
		BerReader: Ber.Reader,
		BerWriter: Ber.Writer
	};
}));
//#endregion
//#region node_modules/.pnpm/tweetnacl@0.14.5/node_modules/tweetnacl/nacl-fast.js
var require_nacl_fast = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	(function(nacl) {
		"use strict";
		var gf = function(init) {
			var i, r = /* @__PURE__ */ new Float64Array(16);
			if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
			return r;
		};
		var randombytes = function() {
			throw new Error("no PRNG");
		};
		var _0 = /* @__PURE__ */ new Uint8Array(16);
		var _9 = /* @__PURE__ */ new Uint8Array(32);
		_9[0] = 9;
		var gf0 = gf(), gf1 = gf([1]), _121665 = gf([56129, 1]), D = gf([
			30883,
			4953,
			19914,
			30187,
			55467,
			16705,
			2637,
			112,
			59544,
			30585,
			16505,
			36039,
			65139,
			11119,
			27886,
			20995
		]), D2 = gf([
			61785,
			9906,
			39828,
			60374,
			45398,
			33411,
			5274,
			224,
			53552,
			61171,
			33010,
			6542,
			64743,
			22239,
			55772,
			9222
		]), X = gf([
			54554,
			36645,
			11616,
			51542,
			42930,
			38181,
			51040,
			26924,
			56412,
			64982,
			57905,
			49316,
			21502,
			52590,
			14035,
			8553
		]), Y = gf([
			26200,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214,
			26214
		]), I = gf([
			41136,
			18958,
			6951,
			50414,
			58488,
			44335,
			6150,
			12099,
			55207,
			15867,
			153,
			11085,
			57099,
			20417,
			9344,
			11139
		]);
		function ts64(x, i, h, l) {
			x[i] = h >> 24 & 255;
			x[i + 1] = h >> 16 & 255;
			x[i + 2] = h >> 8 & 255;
			x[i + 3] = h & 255;
			x[i + 4] = l >> 24 & 255;
			x[i + 5] = l >> 16 & 255;
			x[i + 6] = l >> 8 & 255;
			x[i + 7] = l & 255;
		}
		function vn(x, xi, y, yi, n) {
			var i, d = 0;
			for (i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];
			return (1 & d - 1 >>> 8) - 1;
		}
		function crypto_verify_16(x, xi, y, yi) {
			return vn(x, xi, y, yi, 16);
		}
		function crypto_verify_32(x, xi, y, yi) {
			return vn(x, xi, y, yi, 32);
		}
		function core_salsa20(o, p, k, c) {
			var j0 = c[0] & 255 | (c[1] & 255) << 8 | (c[2] & 255) << 16 | (c[3] & 255) << 24, j1 = k[0] & 255 | (k[1] & 255) << 8 | (k[2] & 255) << 16 | (k[3] & 255) << 24, j2 = k[4] & 255 | (k[5] & 255) << 8 | (k[6] & 255) << 16 | (k[7] & 255) << 24, j3 = k[8] & 255 | (k[9] & 255) << 8 | (k[10] & 255) << 16 | (k[11] & 255) << 24, j4 = k[12] & 255 | (k[13] & 255) << 8 | (k[14] & 255) << 16 | (k[15] & 255) << 24, j5 = c[4] & 255 | (c[5] & 255) << 8 | (c[6] & 255) << 16 | (c[7] & 255) << 24, j6 = p[0] & 255 | (p[1] & 255) << 8 | (p[2] & 255) << 16 | (p[3] & 255) << 24, j7 = p[4] & 255 | (p[5] & 255) << 8 | (p[6] & 255) << 16 | (p[7] & 255) << 24, j8 = p[8] & 255 | (p[9] & 255) << 8 | (p[10] & 255) << 16 | (p[11] & 255) << 24, j9 = p[12] & 255 | (p[13] & 255) << 8 | (p[14] & 255) << 16 | (p[15] & 255) << 24, j10 = c[8] & 255 | (c[9] & 255) << 8 | (c[10] & 255) << 16 | (c[11] & 255) << 24, j11 = k[16] & 255 | (k[17] & 255) << 8 | (k[18] & 255) << 16 | (k[19] & 255) << 24, j12 = k[20] & 255 | (k[21] & 255) << 8 | (k[22] & 255) << 16 | (k[23] & 255) << 24, j13 = k[24] & 255 | (k[25] & 255) << 8 | (k[26] & 255) << 16 | (k[27] & 255) << 24, j14 = k[28] & 255 | (k[29] & 255) << 8 | (k[30] & 255) << 16 | (k[31] & 255) << 24, j15 = c[12] & 255 | (c[13] & 255) << 8 | (c[14] & 255) << 16 | (c[15] & 255) << 24;
			var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;
			for (var i = 0; i < 20; i += 2) {
				u = x0 + x12 | 0;
				x4 ^= u << 7 | u >>> 25;
				u = x4 + x0 | 0;
				x8 ^= u << 9 | u >>> 23;
				u = x8 + x4 | 0;
				x12 ^= u << 13 | u >>> 19;
				u = x12 + x8 | 0;
				x0 ^= u << 18 | u >>> 14;
				u = x5 + x1 | 0;
				x9 ^= u << 7 | u >>> 25;
				u = x9 + x5 | 0;
				x13 ^= u << 9 | u >>> 23;
				u = x13 + x9 | 0;
				x1 ^= u << 13 | u >>> 19;
				u = x1 + x13 | 0;
				x5 ^= u << 18 | u >>> 14;
				u = x10 + x6 | 0;
				x14 ^= u << 7 | u >>> 25;
				u = x14 + x10 | 0;
				x2 ^= u << 9 | u >>> 23;
				u = x2 + x14 | 0;
				x6 ^= u << 13 | u >>> 19;
				u = x6 + x2 | 0;
				x10 ^= u << 18 | u >>> 14;
				u = x15 + x11 | 0;
				x3 ^= u << 7 | u >>> 25;
				u = x3 + x15 | 0;
				x7 ^= u << 9 | u >>> 23;
				u = x7 + x3 | 0;
				x11 ^= u << 13 | u >>> 19;
				u = x11 + x7 | 0;
				x15 ^= u << 18 | u >>> 14;
				u = x0 + x3 | 0;
				x1 ^= u << 7 | u >>> 25;
				u = x1 + x0 | 0;
				x2 ^= u << 9 | u >>> 23;
				u = x2 + x1 | 0;
				x3 ^= u << 13 | u >>> 19;
				u = x3 + x2 | 0;
				x0 ^= u << 18 | u >>> 14;
				u = x5 + x4 | 0;
				x6 ^= u << 7 | u >>> 25;
				u = x6 + x5 | 0;
				x7 ^= u << 9 | u >>> 23;
				u = x7 + x6 | 0;
				x4 ^= u << 13 | u >>> 19;
				u = x4 + x7 | 0;
				x5 ^= u << 18 | u >>> 14;
				u = x10 + x9 | 0;
				x11 ^= u << 7 | u >>> 25;
				u = x11 + x10 | 0;
				x8 ^= u << 9 | u >>> 23;
				u = x8 + x11 | 0;
				x9 ^= u << 13 | u >>> 19;
				u = x9 + x8 | 0;
				x10 ^= u << 18 | u >>> 14;
				u = x15 + x14 | 0;
				x12 ^= u << 7 | u >>> 25;
				u = x12 + x15 | 0;
				x13 ^= u << 9 | u >>> 23;
				u = x13 + x12 | 0;
				x14 ^= u << 13 | u >>> 19;
				u = x14 + x13 | 0;
				x15 ^= u << 18 | u >>> 14;
			}
			x0 = x0 + j0 | 0;
			x1 = x1 + j1 | 0;
			x2 = x2 + j2 | 0;
			x3 = x3 + j3 | 0;
			x4 = x4 + j4 | 0;
			x5 = x5 + j5 | 0;
			x6 = x6 + j6 | 0;
			x7 = x7 + j7 | 0;
			x8 = x8 + j8 | 0;
			x9 = x9 + j9 | 0;
			x10 = x10 + j10 | 0;
			x11 = x11 + j11 | 0;
			x12 = x12 + j12 | 0;
			x13 = x13 + j13 | 0;
			x14 = x14 + j14 | 0;
			x15 = x15 + j15 | 0;
			o[0] = x0 >>> 0 & 255;
			o[1] = x0 >>> 8 & 255;
			o[2] = x0 >>> 16 & 255;
			o[3] = x0 >>> 24 & 255;
			o[4] = x1 >>> 0 & 255;
			o[5] = x1 >>> 8 & 255;
			o[6] = x1 >>> 16 & 255;
			o[7] = x1 >>> 24 & 255;
			o[8] = x2 >>> 0 & 255;
			o[9] = x2 >>> 8 & 255;
			o[10] = x2 >>> 16 & 255;
			o[11] = x2 >>> 24 & 255;
			o[12] = x3 >>> 0 & 255;
			o[13] = x3 >>> 8 & 255;
			o[14] = x3 >>> 16 & 255;
			o[15] = x3 >>> 24 & 255;
			o[16] = x4 >>> 0 & 255;
			o[17] = x4 >>> 8 & 255;
			o[18] = x4 >>> 16 & 255;
			o[19] = x4 >>> 24 & 255;
			o[20] = x5 >>> 0 & 255;
			o[21] = x5 >>> 8 & 255;
			o[22] = x5 >>> 16 & 255;
			o[23] = x5 >>> 24 & 255;
			o[24] = x6 >>> 0 & 255;
			o[25] = x6 >>> 8 & 255;
			o[26] = x6 >>> 16 & 255;
			o[27] = x6 >>> 24 & 255;
			o[28] = x7 >>> 0 & 255;
			o[29] = x7 >>> 8 & 255;
			o[30] = x7 >>> 16 & 255;
			o[31] = x7 >>> 24 & 255;
			o[32] = x8 >>> 0 & 255;
			o[33] = x8 >>> 8 & 255;
			o[34] = x8 >>> 16 & 255;
			o[35] = x8 >>> 24 & 255;
			o[36] = x9 >>> 0 & 255;
			o[37] = x9 >>> 8 & 255;
			o[38] = x9 >>> 16 & 255;
			o[39] = x9 >>> 24 & 255;
			o[40] = x10 >>> 0 & 255;
			o[41] = x10 >>> 8 & 255;
			o[42] = x10 >>> 16 & 255;
			o[43] = x10 >>> 24 & 255;
			o[44] = x11 >>> 0 & 255;
			o[45] = x11 >>> 8 & 255;
			o[46] = x11 >>> 16 & 255;
			o[47] = x11 >>> 24 & 255;
			o[48] = x12 >>> 0 & 255;
			o[49] = x12 >>> 8 & 255;
			o[50] = x12 >>> 16 & 255;
			o[51] = x12 >>> 24 & 255;
			o[52] = x13 >>> 0 & 255;
			o[53] = x13 >>> 8 & 255;
			o[54] = x13 >>> 16 & 255;
			o[55] = x13 >>> 24 & 255;
			o[56] = x14 >>> 0 & 255;
			o[57] = x14 >>> 8 & 255;
			o[58] = x14 >>> 16 & 255;
			o[59] = x14 >>> 24 & 255;
			o[60] = x15 >>> 0 & 255;
			o[61] = x15 >>> 8 & 255;
			o[62] = x15 >>> 16 & 255;
			o[63] = x15 >>> 24 & 255;
		}
		function core_hsalsa20(o, p, k, c) {
			var j0 = c[0] & 255 | (c[1] & 255) << 8 | (c[2] & 255) << 16 | (c[3] & 255) << 24, j1 = k[0] & 255 | (k[1] & 255) << 8 | (k[2] & 255) << 16 | (k[3] & 255) << 24, j2 = k[4] & 255 | (k[5] & 255) << 8 | (k[6] & 255) << 16 | (k[7] & 255) << 24, j3 = k[8] & 255 | (k[9] & 255) << 8 | (k[10] & 255) << 16 | (k[11] & 255) << 24, j4 = k[12] & 255 | (k[13] & 255) << 8 | (k[14] & 255) << 16 | (k[15] & 255) << 24, j5 = c[4] & 255 | (c[5] & 255) << 8 | (c[6] & 255) << 16 | (c[7] & 255) << 24, j6 = p[0] & 255 | (p[1] & 255) << 8 | (p[2] & 255) << 16 | (p[3] & 255) << 24, j7 = p[4] & 255 | (p[5] & 255) << 8 | (p[6] & 255) << 16 | (p[7] & 255) << 24, j8 = p[8] & 255 | (p[9] & 255) << 8 | (p[10] & 255) << 16 | (p[11] & 255) << 24, j9 = p[12] & 255 | (p[13] & 255) << 8 | (p[14] & 255) << 16 | (p[15] & 255) << 24, j10 = c[8] & 255 | (c[9] & 255) << 8 | (c[10] & 255) << 16 | (c[11] & 255) << 24, j11 = k[16] & 255 | (k[17] & 255) << 8 | (k[18] & 255) << 16 | (k[19] & 255) << 24, j12 = k[20] & 255 | (k[21] & 255) << 8 | (k[22] & 255) << 16 | (k[23] & 255) << 24, j13 = k[24] & 255 | (k[25] & 255) << 8 | (k[26] & 255) << 16 | (k[27] & 255) << 24, j14 = k[28] & 255 | (k[29] & 255) << 8 | (k[30] & 255) << 16 | (k[31] & 255) << 24, j15 = c[12] & 255 | (c[13] & 255) << 8 | (c[14] & 255) << 16 | (c[15] & 255) << 24;
			var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;
			for (var i = 0; i < 20; i += 2) {
				u = x0 + x12 | 0;
				x4 ^= u << 7 | u >>> 25;
				u = x4 + x0 | 0;
				x8 ^= u << 9 | u >>> 23;
				u = x8 + x4 | 0;
				x12 ^= u << 13 | u >>> 19;
				u = x12 + x8 | 0;
				x0 ^= u << 18 | u >>> 14;
				u = x5 + x1 | 0;
				x9 ^= u << 7 | u >>> 25;
				u = x9 + x5 | 0;
				x13 ^= u << 9 | u >>> 23;
				u = x13 + x9 | 0;
				x1 ^= u << 13 | u >>> 19;
				u = x1 + x13 | 0;
				x5 ^= u << 18 | u >>> 14;
				u = x10 + x6 | 0;
				x14 ^= u << 7 | u >>> 25;
				u = x14 + x10 | 0;
				x2 ^= u << 9 | u >>> 23;
				u = x2 + x14 | 0;
				x6 ^= u << 13 | u >>> 19;
				u = x6 + x2 | 0;
				x10 ^= u << 18 | u >>> 14;
				u = x15 + x11 | 0;
				x3 ^= u << 7 | u >>> 25;
				u = x3 + x15 | 0;
				x7 ^= u << 9 | u >>> 23;
				u = x7 + x3 | 0;
				x11 ^= u << 13 | u >>> 19;
				u = x11 + x7 | 0;
				x15 ^= u << 18 | u >>> 14;
				u = x0 + x3 | 0;
				x1 ^= u << 7 | u >>> 25;
				u = x1 + x0 | 0;
				x2 ^= u << 9 | u >>> 23;
				u = x2 + x1 | 0;
				x3 ^= u << 13 | u >>> 19;
				u = x3 + x2 | 0;
				x0 ^= u << 18 | u >>> 14;
				u = x5 + x4 | 0;
				x6 ^= u << 7 | u >>> 25;
				u = x6 + x5 | 0;
				x7 ^= u << 9 | u >>> 23;
				u = x7 + x6 | 0;
				x4 ^= u << 13 | u >>> 19;
				u = x4 + x7 | 0;
				x5 ^= u << 18 | u >>> 14;
				u = x10 + x9 | 0;
				x11 ^= u << 7 | u >>> 25;
				u = x11 + x10 | 0;
				x8 ^= u << 9 | u >>> 23;
				u = x8 + x11 | 0;
				x9 ^= u << 13 | u >>> 19;
				u = x9 + x8 | 0;
				x10 ^= u << 18 | u >>> 14;
				u = x15 + x14 | 0;
				x12 ^= u << 7 | u >>> 25;
				u = x12 + x15 | 0;
				x13 ^= u << 9 | u >>> 23;
				u = x13 + x12 | 0;
				x14 ^= u << 13 | u >>> 19;
				u = x14 + x13 | 0;
				x15 ^= u << 18 | u >>> 14;
			}
			o[0] = x0 >>> 0 & 255;
			o[1] = x0 >>> 8 & 255;
			o[2] = x0 >>> 16 & 255;
			o[3] = x0 >>> 24 & 255;
			o[4] = x5 >>> 0 & 255;
			o[5] = x5 >>> 8 & 255;
			o[6] = x5 >>> 16 & 255;
			o[7] = x5 >>> 24 & 255;
			o[8] = x10 >>> 0 & 255;
			o[9] = x10 >>> 8 & 255;
			o[10] = x10 >>> 16 & 255;
			o[11] = x10 >>> 24 & 255;
			o[12] = x15 >>> 0 & 255;
			o[13] = x15 >>> 8 & 255;
			o[14] = x15 >>> 16 & 255;
			o[15] = x15 >>> 24 & 255;
			o[16] = x6 >>> 0 & 255;
			o[17] = x6 >>> 8 & 255;
			o[18] = x6 >>> 16 & 255;
			o[19] = x6 >>> 24 & 255;
			o[20] = x7 >>> 0 & 255;
			o[21] = x7 >>> 8 & 255;
			o[22] = x7 >>> 16 & 255;
			o[23] = x7 >>> 24 & 255;
			o[24] = x8 >>> 0 & 255;
			o[25] = x8 >>> 8 & 255;
			o[26] = x8 >>> 16 & 255;
			o[27] = x8 >>> 24 & 255;
			o[28] = x9 >>> 0 & 255;
			o[29] = x9 >>> 8 & 255;
			o[30] = x9 >>> 16 & 255;
			o[31] = x9 >>> 24 & 255;
		}
		function crypto_core_salsa20(out, inp, k, c) {
			core_salsa20(out, inp, k, c);
		}
		function crypto_core_hsalsa20(out, inp, k, c) {
			core_hsalsa20(out, inp, k, c);
		}
		var sigma = new Uint8Array([
			101,
			120,
			112,
			97,
			110,
			100,
			32,
			51,
			50,
			45,
			98,
			121,
			116,
			101,
			32,
			107
		]);
		function crypto_stream_salsa20_xor(c, cpos, m, mpos, b, n, k) {
			var z = /* @__PURE__ */ new Uint8Array(16), x = /* @__PURE__ */ new Uint8Array(64);
			var u, i = 0;
			for (; i < 16; i++) z[i] = 0;
			for (i = 0; i < 8; i++) z[i] = n[i];
			while (b >= 64) {
				crypto_core_salsa20(x, z, k, sigma);
				for (i = 0; i < 64; i++) c[cpos + i] = m[mpos + i] ^ x[i];
				u = 1;
				for (i = 8; i < 16; i++) {
					u = u + (z[i] & 255) | 0;
					z[i] = u & 255;
					u >>>= 8;
				}
				b -= 64;
				cpos += 64;
				mpos += 64;
			}
			if (b > 0) {
				crypto_core_salsa20(x, z, k, sigma);
				for (i = 0; i < b; i++) c[cpos + i] = m[mpos + i] ^ x[i];
			}
			return 0;
		}
		function crypto_stream_salsa20(c, cpos, b, n, k) {
			var z = /* @__PURE__ */ new Uint8Array(16), x = /* @__PURE__ */ new Uint8Array(64);
			var u, i = 0;
			for (; i < 16; i++) z[i] = 0;
			for (i = 0; i < 8; i++) z[i] = n[i];
			while (b >= 64) {
				crypto_core_salsa20(x, z, k, sigma);
				for (i = 0; i < 64; i++) c[cpos + i] = x[i];
				u = 1;
				for (i = 8; i < 16; i++) {
					u = u + (z[i] & 255) | 0;
					z[i] = u & 255;
					u >>>= 8;
				}
				b -= 64;
				cpos += 64;
			}
			if (b > 0) {
				crypto_core_salsa20(x, z, k, sigma);
				for (i = 0; i < b; i++) c[cpos + i] = x[i];
			}
			return 0;
		}
		function crypto_stream(c, cpos, d, n, k) {
			var s = /* @__PURE__ */ new Uint8Array(32);
			crypto_core_hsalsa20(s, n, k, sigma);
			var sn = /* @__PURE__ */ new Uint8Array(8);
			for (var i = 0; i < 8; i++) sn[i] = n[i + 16];
			return crypto_stream_salsa20(c, cpos, d, sn, s);
		}
		function crypto_stream_xor(c, cpos, m, mpos, d, n, k) {
			var s = /* @__PURE__ */ new Uint8Array(32);
			crypto_core_hsalsa20(s, n, k, sigma);
			var sn = /* @__PURE__ */ new Uint8Array(8);
			for (var i = 0; i < 8; i++) sn[i] = n[i + 16];
			return crypto_stream_salsa20_xor(c, cpos, m, mpos, d, sn, s);
		}
		var poly1305 = function(key) {
			this.buffer = /* @__PURE__ */ new Uint8Array(16);
			this.r = /* @__PURE__ */ new Uint16Array(10);
			this.h = /* @__PURE__ */ new Uint16Array(10);
			this.pad = /* @__PURE__ */ new Uint16Array(8);
			this.leftover = 0;
			this.fin = 0;
			var t0 = key[0] & 255 | (key[1] & 255) << 8, t1, t2, t3, t4, t5, t6, t7;
			this.r[0] = t0 & 8191;
			t1 = key[2] & 255 | (key[3] & 255) << 8;
			this.r[1] = (t0 >>> 13 | t1 << 3) & 8191;
			t2 = key[4] & 255 | (key[5] & 255) << 8;
			this.r[2] = (t1 >>> 10 | t2 << 6) & 7939;
			t3 = key[6] & 255 | (key[7] & 255) << 8;
			this.r[3] = (t2 >>> 7 | t3 << 9) & 8191;
			t4 = key[8] & 255 | (key[9] & 255) << 8;
			this.r[4] = (t3 >>> 4 | t4 << 12) & 255;
			this.r[5] = t4 >>> 1 & 8190;
			t5 = key[10] & 255 | (key[11] & 255) << 8;
			this.r[6] = (t4 >>> 14 | t5 << 2) & 8191;
			t6 = key[12] & 255 | (key[13] & 255) << 8;
			this.r[7] = (t5 >>> 11 | t6 << 5) & 8065;
			t7 = key[14] & 255 | (key[15] & 255) << 8;
			this.r[8] = (t6 >>> 8 | t7 << 8) & 8191;
			this.r[9] = t7 >>> 5 & 127;
			this.pad[0] = key[16] & 255 | (key[17] & 255) << 8;
			this.pad[1] = key[18] & 255 | (key[19] & 255) << 8;
			this.pad[2] = key[20] & 255 | (key[21] & 255) << 8;
			this.pad[3] = key[22] & 255 | (key[23] & 255) << 8;
			this.pad[4] = key[24] & 255 | (key[25] & 255) << 8;
			this.pad[5] = key[26] & 255 | (key[27] & 255) << 8;
			this.pad[6] = key[28] & 255 | (key[29] & 255) << 8;
			this.pad[7] = key[30] & 255 | (key[31] & 255) << 8;
		};
		poly1305.prototype.blocks = function(m, mpos, bytes) {
			var hibit = this.fin ? 0 : 2048;
			var t0, t1, t2, t3, t4, t5, t6, t7, c;
			var d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;
			var h0 = this.h[0], h1 = this.h[1], h2 = this.h[2], h3 = this.h[3], h4 = this.h[4], h5 = this.h[5], h6 = this.h[6], h7 = this.h[7], h8 = this.h[8], h9 = this.h[9];
			var r0 = this.r[0], r1 = this.r[1], r2 = this.r[2], r3 = this.r[3], r4 = this.r[4], r5 = this.r[5], r6 = this.r[6], r7 = this.r[7], r8 = this.r[8], r9 = this.r[9];
			while (bytes >= 16) {
				t0 = m[mpos + 0] & 255 | (m[mpos + 1] & 255) << 8;
				h0 += t0 & 8191;
				t1 = m[mpos + 2] & 255 | (m[mpos + 3] & 255) << 8;
				h1 += (t0 >>> 13 | t1 << 3) & 8191;
				t2 = m[mpos + 4] & 255 | (m[mpos + 5] & 255) << 8;
				h2 += (t1 >>> 10 | t2 << 6) & 8191;
				t3 = m[mpos + 6] & 255 | (m[mpos + 7] & 255) << 8;
				h3 += (t2 >>> 7 | t3 << 9) & 8191;
				t4 = m[mpos + 8] & 255 | (m[mpos + 9] & 255) << 8;
				h4 += (t3 >>> 4 | t4 << 12) & 8191;
				h5 += t4 >>> 1 & 8191;
				t5 = m[mpos + 10] & 255 | (m[mpos + 11] & 255) << 8;
				h6 += (t4 >>> 14 | t5 << 2) & 8191;
				t6 = m[mpos + 12] & 255 | (m[mpos + 13] & 255) << 8;
				h7 += (t5 >>> 11 | t6 << 5) & 8191;
				t7 = m[mpos + 14] & 255 | (m[mpos + 15] & 255) << 8;
				h8 += (t6 >>> 8 | t7 << 8) & 8191;
				h9 += t7 >>> 5 | hibit;
				c = 0;
				d0 = c;
				d0 += h0 * r0;
				d0 += h1 * (5 * r9);
				d0 += h2 * (5 * r8);
				d0 += h3 * (5 * r7);
				d0 += h4 * (5 * r6);
				c = d0 >>> 13;
				d0 &= 8191;
				d0 += h5 * (5 * r5);
				d0 += h6 * (5 * r4);
				d0 += h7 * (5 * r3);
				d0 += h8 * (5 * r2);
				d0 += h9 * (5 * r1);
				c += d0 >>> 13;
				d0 &= 8191;
				d1 = c;
				d1 += h0 * r1;
				d1 += h1 * r0;
				d1 += h2 * (5 * r9);
				d1 += h3 * (5 * r8);
				d1 += h4 * (5 * r7);
				c = d1 >>> 13;
				d1 &= 8191;
				d1 += h5 * (5 * r6);
				d1 += h6 * (5 * r5);
				d1 += h7 * (5 * r4);
				d1 += h8 * (5 * r3);
				d1 += h9 * (5 * r2);
				c += d1 >>> 13;
				d1 &= 8191;
				d2 = c;
				d2 += h0 * r2;
				d2 += h1 * r1;
				d2 += h2 * r0;
				d2 += h3 * (5 * r9);
				d2 += h4 * (5 * r8);
				c = d2 >>> 13;
				d2 &= 8191;
				d2 += h5 * (5 * r7);
				d2 += h6 * (5 * r6);
				d2 += h7 * (5 * r5);
				d2 += h8 * (5 * r4);
				d2 += h9 * (5 * r3);
				c += d2 >>> 13;
				d2 &= 8191;
				d3 = c;
				d3 += h0 * r3;
				d3 += h1 * r2;
				d3 += h2 * r1;
				d3 += h3 * r0;
				d3 += h4 * (5 * r9);
				c = d3 >>> 13;
				d3 &= 8191;
				d3 += h5 * (5 * r8);
				d3 += h6 * (5 * r7);
				d3 += h7 * (5 * r6);
				d3 += h8 * (5 * r5);
				d3 += h9 * (5 * r4);
				c += d3 >>> 13;
				d3 &= 8191;
				d4 = c;
				d4 += h0 * r4;
				d4 += h1 * r3;
				d4 += h2 * r2;
				d4 += h3 * r1;
				d4 += h4 * r0;
				c = d4 >>> 13;
				d4 &= 8191;
				d4 += h5 * (5 * r9);
				d4 += h6 * (5 * r8);
				d4 += h7 * (5 * r7);
				d4 += h8 * (5 * r6);
				d4 += h9 * (5 * r5);
				c += d4 >>> 13;
				d4 &= 8191;
				d5 = c;
				d5 += h0 * r5;
				d5 += h1 * r4;
				d5 += h2 * r3;
				d5 += h3 * r2;
				d5 += h4 * r1;
				c = d5 >>> 13;
				d5 &= 8191;
				d5 += h5 * r0;
				d5 += h6 * (5 * r9);
				d5 += h7 * (5 * r8);
				d5 += h8 * (5 * r7);
				d5 += h9 * (5 * r6);
				c += d5 >>> 13;
				d5 &= 8191;
				d6 = c;
				d6 += h0 * r6;
				d6 += h1 * r5;
				d6 += h2 * r4;
				d6 += h3 * r3;
				d6 += h4 * r2;
				c = d6 >>> 13;
				d6 &= 8191;
				d6 += h5 * r1;
				d6 += h6 * r0;
				d6 += h7 * (5 * r9);
				d6 += h8 * (5 * r8);
				d6 += h9 * (5 * r7);
				c += d6 >>> 13;
				d6 &= 8191;
				d7 = c;
				d7 += h0 * r7;
				d7 += h1 * r6;
				d7 += h2 * r5;
				d7 += h3 * r4;
				d7 += h4 * r3;
				c = d7 >>> 13;
				d7 &= 8191;
				d7 += h5 * r2;
				d7 += h6 * r1;
				d7 += h7 * r0;
				d7 += h8 * (5 * r9);
				d7 += h9 * (5 * r8);
				c += d7 >>> 13;
				d7 &= 8191;
				d8 = c;
				d8 += h0 * r8;
				d8 += h1 * r7;
				d8 += h2 * r6;
				d8 += h3 * r5;
				d8 += h4 * r4;
				c = d8 >>> 13;
				d8 &= 8191;
				d8 += h5 * r3;
				d8 += h6 * r2;
				d8 += h7 * r1;
				d8 += h8 * r0;
				d8 += h9 * (5 * r9);
				c += d8 >>> 13;
				d8 &= 8191;
				d9 = c;
				d9 += h0 * r9;
				d9 += h1 * r8;
				d9 += h2 * r7;
				d9 += h3 * r6;
				d9 += h4 * r5;
				c = d9 >>> 13;
				d9 &= 8191;
				d9 += h5 * r4;
				d9 += h6 * r3;
				d9 += h7 * r2;
				d9 += h8 * r1;
				d9 += h9 * r0;
				c += d9 >>> 13;
				d9 &= 8191;
				c = (c << 2) + c | 0;
				c = c + d0 | 0;
				d0 = c & 8191;
				c = c >>> 13;
				d1 += c;
				h0 = d0;
				h1 = d1;
				h2 = d2;
				h3 = d3;
				h4 = d4;
				h5 = d5;
				h6 = d6;
				h7 = d7;
				h8 = d8;
				h9 = d9;
				mpos += 16;
				bytes -= 16;
			}
			this.h[0] = h0;
			this.h[1] = h1;
			this.h[2] = h2;
			this.h[3] = h3;
			this.h[4] = h4;
			this.h[5] = h5;
			this.h[6] = h6;
			this.h[7] = h7;
			this.h[8] = h8;
			this.h[9] = h9;
		};
		poly1305.prototype.finish = function(mac, macpos) {
			var g = /* @__PURE__ */ new Uint16Array(10);
			var c, mask, f, i;
			if (this.leftover) {
				i = this.leftover;
				this.buffer[i++] = 1;
				for (; i < 16; i++) this.buffer[i] = 0;
				this.fin = 1;
				this.blocks(this.buffer, 0, 16);
			}
			c = this.h[1] >>> 13;
			this.h[1] &= 8191;
			for (i = 2; i < 10; i++) {
				this.h[i] += c;
				c = this.h[i] >>> 13;
				this.h[i] &= 8191;
			}
			this.h[0] += c * 5;
			c = this.h[0] >>> 13;
			this.h[0] &= 8191;
			this.h[1] += c;
			c = this.h[1] >>> 13;
			this.h[1] &= 8191;
			this.h[2] += c;
			g[0] = this.h[0] + 5;
			c = g[0] >>> 13;
			g[0] &= 8191;
			for (i = 1; i < 10; i++) {
				g[i] = this.h[i] + c;
				c = g[i] >>> 13;
				g[i] &= 8191;
			}
			g[9] -= 8192;
			mask = (c ^ 1) - 1;
			for (i = 0; i < 10; i++) g[i] &= mask;
			mask = ~mask;
			for (i = 0; i < 10; i++) this.h[i] = this.h[i] & mask | g[i];
			this.h[0] = (this.h[0] | this.h[1] << 13) & 65535;
			this.h[1] = (this.h[1] >>> 3 | this.h[2] << 10) & 65535;
			this.h[2] = (this.h[2] >>> 6 | this.h[3] << 7) & 65535;
			this.h[3] = (this.h[3] >>> 9 | this.h[4] << 4) & 65535;
			this.h[4] = (this.h[4] >>> 12 | this.h[5] << 1 | this.h[6] << 14) & 65535;
			this.h[5] = (this.h[6] >>> 2 | this.h[7] << 11) & 65535;
			this.h[6] = (this.h[7] >>> 5 | this.h[8] << 8) & 65535;
			this.h[7] = (this.h[8] >>> 8 | this.h[9] << 5) & 65535;
			f = this.h[0] + this.pad[0];
			this.h[0] = f & 65535;
			for (i = 1; i < 8; i++) {
				f = (this.h[i] + this.pad[i] | 0) + (f >>> 16) | 0;
				this.h[i] = f & 65535;
			}
			mac[macpos + 0] = this.h[0] >>> 0 & 255;
			mac[macpos + 1] = this.h[0] >>> 8 & 255;
			mac[macpos + 2] = this.h[1] >>> 0 & 255;
			mac[macpos + 3] = this.h[1] >>> 8 & 255;
			mac[macpos + 4] = this.h[2] >>> 0 & 255;
			mac[macpos + 5] = this.h[2] >>> 8 & 255;
			mac[macpos + 6] = this.h[3] >>> 0 & 255;
			mac[macpos + 7] = this.h[3] >>> 8 & 255;
			mac[macpos + 8] = this.h[4] >>> 0 & 255;
			mac[macpos + 9] = this.h[4] >>> 8 & 255;
			mac[macpos + 10] = this.h[5] >>> 0 & 255;
			mac[macpos + 11] = this.h[5] >>> 8 & 255;
			mac[macpos + 12] = this.h[6] >>> 0 & 255;
			mac[macpos + 13] = this.h[6] >>> 8 & 255;
			mac[macpos + 14] = this.h[7] >>> 0 & 255;
			mac[macpos + 15] = this.h[7] >>> 8 & 255;
		};
		poly1305.prototype.update = function(m, mpos, bytes) {
			var i, want;
			if (this.leftover) {
				want = 16 - this.leftover;
				if (want > bytes) want = bytes;
				for (i = 0; i < want; i++) this.buffer[this.leftover + i] = m[mpos + i];
				bytes -= want;
				mpos += want;
				this.leftover += want;
				if (this.leftover < 16) return;
				this.blocks(this.buffer, 0, 16);
				this.leftover = 0;
			}
			if (bytes >= 16) {
				want = bytes - bytes % 16;
				this.blocks(m, mpos, want);
				mpos += want;
				bytes -= want;
			}
			if (bytes) {
				for (i = 0; i < bytes; i++) this.buffer[this.leftover + i] = m[mpos + i];
				this.leftover += bytes;
			}
		};
		function crypto_onetimeauth(out, outpos, m, mpos, n, k) {
			var s = new poly1305(k);
			s.update(m, mpos, n);
			s.finish(out, outpos);
			return 0;
		}
		function crypto_onetimeauth_verify(h, hpos, m, mpos, n, k) {
			var x = /* @__PURE__ */ new Uint8Array(16);
			crypto_onetimeauth(x, 0, m, mpos, n, k);
			return crypto_verify_16(h, hpos, x, 0);
		}
		function crypto_secretbox(c, m, d, n, k) {
			var i;
			if (d < 32) return -1;
			crypto_stream_xor(c, 0, m, 0, d, n, k);
			crypto_onetimeauth(c, 16, c, 32, d - 32, c);
			for (i = 0; i < 16; i++) c[i] = 0;
			return 0;
		}
		function crypto_secretbox_open(m, c, d, n, k) {
			var i;
			var x = /* @__PURE__ */ new Uint8Array(32);
			if (d < 32) return -1;
			crypto_stream(x, 0, 32, n, k);
			if (crypto_onetimeauth_verify(c, 16, c, 32, d - 32, x) !== 0) return -1;
			crypto_stream_xor(m, 0, c, 0, d, n, k);
			for (i = 0; i < 32; i++) m[i] = 0;
			return 0;
		}
		function set25519(r, a) {
			var i = 0;
			for (; i < 16; i++) r[i] = a[i] | 0;
		}
		function car25519(o) {
			var i, v, c = 1;
			for (i = 0; i < 16; i++) {
				v = o[i] + c + 65535;
				c = Math.floor(v / 65536);
				o[i] = v - c * 65536;
			}
			o[0] += c - 1 + 37 * (c - 1);
		}
		function sel25519(p, q, b) {
			var t, c = ~(b - 1);
			for (var i = 0; i < 16; i++) {
				t = c & (p[i] ^ q[i]);
				p[i] ^= t;
				q[i] ^= t;
			}
		}
		function pack25519(o, n) {
			var i, j, b;
			var m = gf(), t = gf();
			for (i = 0; i < 16; i++) t[i] = n[i];
			car25519(t);
			car25519(t);
			car25519(t);
			for (j = 0; j < 2; j++) {
				m[0] = t[0] - 65517;
				for (i = 1; i < 15; i++) {
					m[i] = t[i] - 65535 - (m[i - 1] >> 16 & 1);
					m[i - 1] &= 65535;
				}
				m[15] = t[15] - 32767 - (m[14] >> 16 & 1);
				b = m[15] >> 16 & 1;
				m[14] &= 65535;
				sel25519(t, m, 1 - b);
			}
			for (i = 0; i < 16; i++) {
				o[2 * i] = t[i] & 255;
				o[2 * i + 1] = t[i] >> 8;
			}
		}
		function neq25519(a, b) {
			var c = /* @__PURE__ */ new Uint8Array(32), d = /* @__PURE__ */ new Uint8Array(32);
			pack25519(c, a);
			pack25519(d, b);
			return crypto_verify_32(c, 0, d, 0);
		}
		function par25519(a) {
			var d = /* @__PURE__ */ new Uint8Array(32);
			pack25519(d, a);
			return d[0] & 1;
		}
		function unpack25519(o, n) {
			var i = 0;
			for (; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
			o[15] &= 32767;
		}
		function A(o, a, b) {
			for (var i = 0; i < 16; i++) o[i] = a[i] + b[i];
		}
		function Z(o, a, b) {
			for (var i = 0; i < 16; i++) o[i] = a[i] - b[i];
		}
		function M(o, a, b) {
			var v, c, t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0, t16 = 0, t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0, t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0, b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4], b5 = b[5], b6 = b[6], b7 = b[7], b8 = b[8], b9 = b[9], b10 = b[10], b11 = b[11], b12 = b[12], b13 = b[13], b14 = b[14], b15 = b[15];
			v = a[0];
			t0 += v * b0;
			t1 += v * b1;
			t2 += v * b2;
			t3 += v * b3;
			t4 += v * b4;
			t5 += v * b5;
			t6 += v * b6;
			t7 += v * b7;
			t8 += v * b8;
			t9 += v * b9;
			t10 += v * b10;
			t11 += v * b11;
			t12 += v * b12;
			t13 += v * b13;
			t14 += v * b14;
			t15 += v * b15;
			v = a[1];
			t1 += v * b0;
			t2 += v * b1;
			t3 += v * b2;
			t4 += v * b3;
			t5 += v * b4;
			t6 += v * b5;
			t7 += v * b6;
			t8 += v * b7;
			t9 += v * b8;
			t10 += v * b9;
			t11 += v * b10;
			t12 += v * b11;
			t13 += v * b12;
			t14 += v * b13;
			t15 += v * b14;
			t16 += v * b15;
			v = a[2];
			t2 += v * b0;
			t3 += v * b1;
			t4 += v * b2;
			t5 += v * b3;
			t6 += v * b4;
			t7 += v * b5;
			t8 += v * b6;
			t9 += v * b7;
			t10 += v * b8;
			t11 += v * b9;
			t12 += v * b10;
			t13 += v * b11;
			t14 += v * b12;
			t15 += v * b13;
			t16 += v * b14;
			t17 += v * b15;
			v = a[3];
			t3 += v * b0;
			t4 += v * b1;
			t5 += v * b2;
			t6 += v * b3;
			t7 += v * b4;
			t8 += v * b5;
			t9 += v * b6;
			t10 += v * b7;
			t11 += v * b8;
			t12 += v * b9;
			t13 += v * b10;
			t14 += v * b11;
			t15 += v * b12;
			t16 += v * b13;
			t17 += v * b14;
			t18 += v * b15;
			v = a[4];
			t4 += v * b0;
			t5 += v * b1;
			t6 += v * b2;
			t7 += v * b3;
			t8 += v * b4;
			t9 += v * b5;
			t10 += v * b6;
			t11 += v * b7;
			t12 += v * b8;
			t13 += v * b9;
			t14 += v * b10;
			t15 += v * b11;
			t16 += v * b12;
			t17 += v * b13;
			t18 += v * b14;
			t19 += v * b15;
			v = a[5];
			t5 += v * b0;
			t6 += v * b1;
			t7 += v * b2;
			t8 += v * b3;
			t9 += v * b4;
			t10 += v * b5;
			t11 += v * b6;
			t12 += v * b7;
			t13 += v * b8;
			t14 += v * b9;
			t15 += v * b10;
			t16 += v * b11;
			t17 += v * b12;
			t18 += v * b13;
			t19 += v * b14;
			t20 += v * b15;
			v = a[6];
			t6 += v * b0;
			t7 += v * b1;
			t8 += v * b2;
			t9 += v * b3;
			t10 += v * b4;
			t11 += v * b5;
			t12 += v * b6;
			t13 += v * b7;
			t14 += v * b8;
			t15 += v * b9;
			t16 += v * b10;
			t17 += v * b11;
			t18 += v * b12;
			t19 += v * b13;
			t20 += v * b14;
			t21 += v * b15;
			v = a[7];
			t7 += v * b0;
			t8 += v * b1;
			t9 += v * b2;
			t10 += v * b3;
			t11 += v * b4;
			t12 += v * b5;
			t13 += v * b6;
			t14 += v * b7;
			t15 += v * b8;
			t16 += v * b9;
			t17 += v * b10;
			t18 += v * b11;
			t19 += v * b12;
			t20 += v * b13;
			t21 += v * b14;
			t22 += v * b15;
			v = a[8];
			t8 += v * b0;
			t9 += v * b1;
			t10 += v * b2;
			t11 += v * b3;
			t12 += v * b4;
			t13 += v * b5;
			t14 += v * b6;
			t15 += v * b7;
			t16 += v * b8;
			t17 += v * b9;
			t18 += v * b10;
			t19 += v * b11;
			t20 += v * b12;
			t21 += v * b13;
			t22 += v * b14;
			t23 += v * b15;
			v = a[9];
			t9 += v * b0;
			t10 += v * b1;
			t11 += v * b2;
			t12 += v * b3;
			t13 += v * b4;
			t14 += v * b5;
			t15 += v * b6;
			t16 += v * b7;
			t17 += v * b8;
			t18 += v * b9;
			t19 += v * b10;
			t20 += v * b11;
			t21 += v * b12;
			t22 += v * b13;
			t23 += v * b14;
			t24 += v * b15;
			v = a[10];
			t10 += v * b0;
			t11 += v * b1;
			t12 += v * b2;
			t13 += v * b3;
			t14 += v * b4;
			t15 += v * b5;
			t16 += v * b6;
			t17 += v * b7;
			t18 += v * b8;
			t19 += v * b9;
			t20 += v * b10;
			t21 += v * b11;
			t22 += v * b12;
			t23 += v * b13;
			t24 += v * b14;
			t25 += v * b15;
			v = a[11];
			t11 += v * b0;
			t12 += v * b1;
			t13 += v * b2;
			t14 += v * b3;
			t15 += v * b4;
			t16 += v * b5;
			t17 += v * b6;
			t18 += v * b7;
			t19 += v * b8;
			t20 += v * b9;
			t21 += v * b10;
			t22 += v * b11;
			t23 += v * b12;
			t24 += v * b13;
			t25 += v * b14;
			t26 += v * b15;
			v = a[12];
			t12 += v * b0;
			t13 += v * b1;
			t14 += v * b2;
			t15 += v * b3;
			t16 += v * b4;
			t17 += v * b5;
			t18 += v * b6;
			t19 += v * b7;
			t20 += v * b8;
			t21 += v * b9;
			t22 += v * b10;
			t23 += v * b11;
			t24 += v * b12;
			t25 += v * b13;
			t26 += v * b14;
			t27 += v * b15;
			v = a[13];
			t13 += v * b0;
			t14 += v * b1;
			t15 += v * b2;
			t16 += v * b3;
			t17 += v * b4;
			t18 += v * b5;
			t19 += v * b6;
			t20 += v * b7;
			t21 += v * b8;
			t22 += v * b9;
			t23 += v * b10;
			t24 += v * b11;
			t25 += v * b12;
			t26 += v * b13;
			t27 += v * b14;
			t28 += v * b15;
			v = a[14];
			t14 += v * b0;
			t15 += v * b1;
			t16 += v * b2;
			t17 += v * b3;
			t18 += v * b4;
			t19 += v * b5;
			t20 += v * b6;
			t21 += v * b7;
			t22 += v * b8;
			t23 += v * b9;
			t24 += v * b10;
			t25 += v * b11;
			t26 += v * b12;
			t27 += v * b13;
			t28 += v * b14;
			t29 += v * b15;
			v = a[15];
			t15 += v * b0;
			t16 += v * b1;
			t17 += v * b2;
			t18 += v * b3;
			t19 += v * b4;
			t20 += v * b5;
			t21 += v * b6;
			t22 += v * b7;
			t23 += v * b8;
			t24 += v * b9;
			t25 += v * b10;
			t26 += v * b11;
			t27 += v * b12;
			t28 += v * b13;
			t29 += v * b14;
			t30 += v * b15;
			t0 += 38 * t16;
			t1 += 38 * t17;
			t2 += 38 * t18;
			t3 += 38 * t19;
			t4 += 38 * t20;
			t5 += 38 * t21;
			t6 += 38 * t22;
			t7 += 38 * t23;
			t8 += 38 * t24;
			t9 += 38 * t25;
			t10 += 38 * t26;
			t11 += 38 * t27;
			t12 += 38 * t28;
			t13 += 38 * t29;
			t14 += 38 * t30;
			c = 1;
			v = t0 + c + 65535;
			c = Math.floor(v / 65536);
			t0 = v - c * 65536;
			v = t1 + c + 65535;
			c = Math.floor(v / 65536);
			t1 = v - c * 65536;
			v = t2 + c + 65535;
			c = Math.floor(v / 65536);
			t2 = v - c * 65536;
			v = t3 + c + 65535;
			c = Math.floor(v / 65536);
			t3 = v - c * 65536;
			v = t4 + c + 65535;
			c = Math.floor(v / 65536);
			t4 = v - c * 65536;
			v = t5 + c + 65535;
			c = Math.floor(v / 65536);
			t5 = v - c * 65536;
			v = t6 + c + 65535;
			c = Math.floor(v / 65536);
			t6 = v - c * 65536;
			v = t7 + c + 65535;
			c = Math.floor(v / 65536);
			t7 = v - c * 65536;
			v = t8 + c + 65535;
			c = Math.floor(v / 65536);
			t8 = v - c * 65536;
			v = t9 + c + 65535;
			c = Math.floor(v / 65536);
			t9 = v - c * 65536;
			v = t10 + c + 65535;
			c = Math.floor(v / 65536);
			t10 = v - c * 65536;
			v = t11 + c + 65535;
			c = Math.floor(v / 65536);
			t11 = v - c * 65536;
			v = t12 + c + 65535;
			c = Math.floor(v / 65536);
			t12 = v - c * 65536;
			v = t13 + c + 65535;
			c = Math.floor(v / 65536);
			t13 = v - c * 65536;
			v = t14 + c + 65535;
			c = Math.floor(v / 65536);
			t14 = v - c * 65536;
			v = t15 + c + 65535;
			c = Math.floor(v / 65536);
			t15 = v - c * 65536;
			t0 += c - 1 + 37 * (c - 1);
			c = 1;
			v = t0 + c + 65535;
			c = Math.floor(v / 65536);
			t0 = v - c * 65536;
			v = t1 + c + 65535;
			c = Math.floor(v / 65536);
			t1 = v - c * 65536;
			v = t2 + c + 65535;
			c = Math.floor(v / 65536);
			t2 = v - c * 65536;
			v = t3 + c + 65535;
			c = Math.floor(v / 65536);
			t3 = v - c * 65536;
			v = t4 + c + 65535;
			c = Math.floor(v / 65536);
			t4 = v - c * 65536;
			v = t5 + c + 65535;
			c = Math.floor(v / 65536);
			t5 = v - c * 65536;
			v = t6 + c + 65535;
			c = Math.floor(v / 65536);
			t6 = v - c * 65536;
			v = t7 + c + 65535;
			c = Math.floor(v / 65536);
			t7 = v - c * 65536;
			v = t8 + c + 65535;
			c = Math.floor(v / 65536);
			t8 = v - c * 65536;
			v = t9 + c + 65535;
			c = Math.floor(v / 65536);
			t9 = v - c * 65536;
			v = t10 + c + 65535;
			c = Math.floor(v / 65536);
			t10 = v - c * 65536;
			v = t11 + c + 65535;
			c = Math.floor(v / 65536);
			t11 = v - c * 65536;
			v = t12 + c + 65535;
			c = Math.floor(v / 65536);
			t12 = v - c * 65536;
			v = t13 + c + 65535;
			c = Math.floor(v / 65536);
			t13 = v - c * 65536;
			v = t14 + c + 65535;
			c = Math.floor(v / 65536);
			t14 = v - c * 65536;
			v = t15 + c + 65535;
			c = Math.floor(v / 65536);
			t15 = v - c * 65536;
			t0 += c - 1 + 37 * (c - 1);
			o[0] = t0;
			o[1] = t1;
			o[2] = t2;
			o[3] = t3;
			o[4] = t4;
			o[5] = t5;
			o[6] = t6;
			o[7] = t7;
			o[8] = t8;
			o[9] = t9;
			o[10] = t10;
			o[11] = t11;
			o[12] = t12;
			o[13] = t13;
			o[14] = t14;
			o[15] = t15;
		}
		function S(o, a) {
			M(o, a, a);
		}
		function inv25519(o, i) {
			var c = gf();
			var a = 0;
			for (; a < 16; a++) c[a] = i[a];
			for (a = 253; a >= 0; a--) {
				S(c, c);
				if (a !== 2 && a !== 4) M(c, c, i);
			}
			for (a = 0; a < 16; a++) o[a] = c[a];
		}
		function pow2523(o, i) {
			var c = gf();
			var a = 0;
			for (; a < 16; a++) c[a] = i[a];
			for (a = 250; a >= 0; a--) {
				S(c, c);
				if (a !== 1) M(c, c, i);
			}
			for (a = 0; a < 16; a++) o[a] = c[a];
		}
		function crypto_scalarmult(q, n, p) {
			var z = /* @__PURE__ */ new Uint8Array(32);
			var x = /* @__PURE__ */ new Float64Array(80), r, i;
			var a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf();
			for (i = 0; i < 31; i++) z[i] = n[i];
			z[31] = n[31] & 127 | 64;
			z[0] &= 248;
			unpack25519(x, p);
			for (i = 0; i < 16; i++) {
				b[i] = x[i];
				d[i] = a[i] = c[i] = 0;
			}
			a[0] = d[0] = 1;
			for (i = 254; i >= 0; --i) {
				r = z[i >>> 3] >>> (i & 7) & 1;
				sel25519(a, b, r);
				sel25519(c, d, r);
				A(e, a, c);
				Z(a, a, c);
				A(c, b, d);
				Z(b, b, d);
				S(d, e);
				S(f, a);
				M(a, c, a);
				M(c, b, e);
				A(e, a, c);
				Z(a, a, c);
				S(b, a);
				Z(c, d, f);
				M(a, c, _121665);
				A(a, a, d);
				M(c, c, a);
				M(a, d, f);
				M(d, b, x);
				S(b, e);
				sel25519(a, b, r);
				sel25519(c, d, r);
			}
			for (i = 0; i < 16; i++) {
				x[i + 16] = a[i];
				x[i + 32] = c[i];
				x[i + 48] = b[i];
				x[i + 64] = d[i];
			}
			var x32 = x.subarray(32);
			var x16 = x.subarray(16);
			inv25519(x32, x32);
			M(x16, x16, x32);
			pack25519(q, x16);
			return 0;
		}
		function crypto_scalarmult_base(q, n) {
			return crypto_scalarmult(q, n, _9);
		}
		function crypto_box_keypair(y, x) {
			randombytes(x, 32);
			return crypto_scalarmult_base(y, x);
		}
		function crypto_box_beforenm(k, y, x) {
			var s = /* @__PURE__ */ new Uint8Array(32);
			crypto_scalarmult(s, x, y);
			return crypto_core_hsalsa20(k, _0, s, sigma);
		}
		var crypto_box_afternm = crypto_secretbox;
		var crypto_box_open_afternm = crypto_secretbox_open;
		function crypto_box(c, m, d, n, y, x) {
			var k = /* @__PURE__ */ new Uint8Array(32);
			crypto_box_beforenm(k, y, x);
			return crypto_box_afternm(c, m, d, n, k);
		}
		function crypto_box_open(m, c, d, n, y, x) {
			var k = /* @__PURE__ */ new Uint8Array(32);
			crypto_box_beforenm(k, y, x);
			return crypto_box_open_afternm(m, c, d, n, k);
		}
		var K = [
			1116352408,
			3609767458,
			1899447441,
			602891725,
			3049323471,
			3964484399,
			3921009573,
			2173295548,
			961987163,
			4081628472,
			1508970993,
			3053834265,
			2453635748,
			2937671579,
			2870763221,
			3664609560,
			3624381080,
			2734883394,
			310598401,
			1164996542,
			607225278,
			1323610764,
			1426881987,
			3590304994,
			1925078388,
			4068182383,
			2162078206,
			991336113,
			2614888103,
			633803317,
			3248222580,
			3479774868,
			3835390401,
			2666613458,
			4022224774,
			944711139,
			264347078,
			2341262773,
			604807628,
			2007800933,
			770255983,
			1495990901,
			1249150122,
			1856431235,
			1555081692,
			3175218132,
			1996064986,
			2198950837,
			2554220882,
			3999719339,
			2821834349,
			766784016,
			2952996808,
			2566594879,
			3210313671,
			3203337956,
			3336571891,
			1034457026,
			3584528711,
			2466948901,
			113926993,
			3758326383,
			338241895,
			168717936,
			666307205,
			1188179964,
			773529912,
			1546045734,
			1294757372,
			1522805485,
			1396182291,
			2643833823,
			1695183700,
			2343527390,
			1986661051,
			1014477480,
			2177026350,
			1206759142,
			2456956037,
			344077627,
			2730485921,
			1290863460,
			2820302411,
			3158454273,
			3259730800,
			3505952657,
			3345764771,
			106217008,
			3516065817,
			3606008344,
			3600352804,
			1432725776,
			4094571909,
			1467031594,
			275423344,
			851169720,
			430227734,
			3100823752,
			506948616,
			1363258195,
			659060556,
			3750685593,
			883997877,
			3785050280,
			958139571,
			3318307427,
			1322822218,
			3812723403,
			1537002063,
			2003034995,
			1747873779,
			3602036899,
			1955562222,
			1575990012,
			2024104815,
			1125592928,
			2227730452,
			2716904306,
			2361852424,
			442776044,
			2428436474,
			593698344,
			2756734187,
			3733110249,
			3204031479,
			2999351573,
			3329325298,
			3815920427,
			3391569614,
			3928383900,
			3515267271,
			566280711,
			3940187606,
			3454069534,
			4118630271,
			4000239992,
			116418474,
			1914138554,
			174292421,
			2731055270,
			289380356,
			3203993006,
			460393269,
			320620315,
			685471733,
			587496836,
			852142971,
			1086792851,
			1017036298,
			365543100,
			1126000580,
			2618297676,
			1288033470,
			3409855158,
			1501505948,
			4234509866,
			1607167915,
			987167468,
			1816402316,
			1246189591
		];
		function crypto_hashblocks_hl(hh, hl, m, n) {
			var wh = /* @__PURE__ */ new Int32Array(16), wl = /* @__PURE__ */ new Int32Array(16), bh0, bh1, bh2, bh3, bh4, bh5, bh6, bh7, bl0, bl1, bl2, bl3, bl4, bl5, bl6, bl7, th, tl, i, j, h, l, a, b, c, d;
			var ah0 = hh[0], ah1 = hh[1], ah2 = hh[2], ah3 = hh[3], ah4 = hh[4], ah5 = hh[5], ah6 = hh[6], ah7 = hh[7], al0 = hl[0], al1 = hl[1], al2 = hl[2], al3 = hl[3], al4 = hl[4], al5 = hl[5], al6 = hl[6], al7 = hl[7];
			var pos = 0;
			while (n >= 128) {
				for (i = 0; i < 16; i++) {
					j = 8 * i + pos;
					wh[i] = m[j + 0] << 24 | m[j + 1] << 16 | m[j + 2] << 8 | m[j + 3];
					wl[i] = m[j + 4] << 24 | m[j + 5] << 16 | m[j + 6] << 8 | m[j + 7];
				}
				for (i = 0; i < 80; i++) {
					bh0 = ah0;
					bh1 = ah1;
					bh2 = ah2;
					bh3 = ah3;
					bh4 = ah4;
					bh5 = ah5;
					bh6 = ah6;
					bh7 = ah7;
					bl0 = al0;
					bl1 = al1;
					bl2 = al2;
					bl3 = al3;
					bl4 = al4;
					bl5 = al5;
					bl6 = al6;
					bl7 = al7;
					h = ah7;
					l = al7;
					a = l & 65535;
					b = l >>> 16;
					c = h & 65535;
					d = h >>> 16;
					h = (ah4 >>> 14 | al4 << 18) ^ (ah4 >>> 18 | al4 << 14) ^ (al4 >>> 9 | ah4 << 23);
					l = (al4 >>> 14 | ah4 << 18) ^ (al4 >>> 18 | ah4 << 14) ^ (ah4 >>> 9 | al4 << 23);
					a += l & 65535;
					b += l >>> 16;
					c += h & 65535;
					d += h >>> 16;
					h = ah4 & ah5 ^ ~ah4 & ah6;
					l = al4 & al5 ^ ~al4 & al6;
					a += l & 65535;
					b += l >>> 16;
					c += h & 65535;
					d += h >>> 16;
					h = K[i * 2];
					l = K[i * 2 + 1];
					a += l & 65535;
					b += l >>> 16;
					c += h & 65535;
					d += h >>> 16;
					h = wh[i % 16];
					l = wl[i % 16];
					a += l & 65535;
					b += l >>> 16;
					c += h & 65535;
					d += h >>> 16;
					b += a >>> 16;
					c += b >>> 16;
					d += c >>> 16;
					th = c & 65535 | d << 16;
					tl = a & 65535 | b << 16;
					h = th;
					l = tl;
					a = l & 65535;
					b = l >>> 16;
					c = h & 65535;
					d = h >>> 16;
					h = (ah0 >>> 28 | al0 << 4) ^ (al0 >>> 2 | ah0 << 30) ^ (al0 >>> 7 | ah0 << 25);
					l = (al0 >>> 28 | ah0 << 4) ^ (ah0 >>> 2 | al0 << 30) ^ (ah0 >>> 7 | al0 << 25);
					a += l & 65535;
					b += l >>> 16;
					c += h & 65535;
					d += h >>> 16;
					h = ah0 & ah1 ^ ah0 & ah2 ^ ah1 & ah2;
					l = al0 & al1 ^ al0 & al2 ^ al1 & al2;
					a += l & 65535;
					b += l >>> 16;
					c += h & 65535;
					d += h >>> 16;
					b += a >>> 16;
					c += b >>> 16;
					d += c >>> 16;
					bh7 = c & 65535 | d << 16;
					bl7 = a & 65535 | b << 16;
					h = bh3;
					l = bl3;
					a = l & 65535;
					b = l >>> 16;
					c = h & 65535;
					d = h >>> 16;
					h = th;
					l = tl;
					a += l & 65535;
					b += l >>> 16;
					c += h & 65535;
					d += h >>> 16;
					b += a >>> 16;
					c += b >>> 16;
					d += c >>> 16;
					bh3 = c & 65535 | d << 16;
					bl3 = a & 65535 | b << 16;
					ah1 = bh0;
					ah2 = bh1;
					ah3 = bh2;
					ah4 = bh3;
					ah5 = bh4;
					ah6 = bh5;
					ah7 = bh6;
					ah0 = bh7;
					al1 = bl0;
					al2 = bl1;
					al3 = bl2;
					al4 = bl3;
					al5 = bl4;
					al6 = bl5;
					al7 = bl6;
					al0 = bl7;
					if (i % 16 === 15) for (j = 0; j < 16; j++) {
						h = wh[j];
						l = wl[j];
						a = l & 65535;
						b = l >>> 16;
						c = h & 65535;
						d = h >>> 16;
						h = wh[(j + 9) % 16];
						l = wl[(j + 9) % 16];
						a += l & 65535;
						b += l >>> 16;
						c += h & 65535;
						d += h >>> 16;
						th = wh[(j + 1) % 16];
						tl = wl[(j + 1) % 16];
						h = (th >>> 1 | tl << 31) ^ (th >>> 8 | tl << 24) ^ th >>> 7;
						l = (tl >>> 1 | th << 31) ^ (tl >>> 8 | th << 24) ^ (tl >>> 7 | th << 25);
						a += l & 65535;
						b += l >>> 16;
						c += h & 65535;
						d += h >>> 16;
						th = wh[(j + 14) % 16];
						tl = wl[(j + 14) % 16];
						h = (th >>> 19 | tl << 13) ^ (tl >>> 29 | th << 3) ^ th >>> 6;
						l = (tl >>> 19 | th << 13) ^ (th >>> 29 | tl << 3) ^ (tl >>> 6 | th << 26);
						a += l & 65535;
						b += l >>> 16;
						c += h & 65535;
						d += h >>> 16;
						b += a >>> 16;
						c += b >>> 16;
						d += c >>> 16;
						wh[j] = c & 65535 | d << 16;
						wl[j] = a & 65535 | b << 16;
					}
				}
				h = ah0;
				l = al0;
				a = l & 65535;
				b = l >>> 16;
				c = h & 65535;
				d = h >>> 16;
				h = hh[0];
				l = hl[0];
				a += l & 65535;
				b += l >>> 16;
				c += h & 65535;
				d += h >>> 16;
				b += a >>> 16;
				c += b >>> 16;
				d += c >>> 16;
				hh[0] = ah0 = c & 65535 | d << 16;
				hl[0] = al0 = a & 65535 | b << 16;
				h = ah1;
				l = al1;
				a = l & 65535;
				b = l >>> 16;
				c = h & 65535;
				d = h >>> 16;
				h = hh[1];
				l = hl[1];
				a += l & 65535;
				b += l >>> 16;
				c += h & 65535;
				d += h >>> 16;
				b += a >>> 16;
				c += b >>> 16;
				d += c >>> 16;
				hh[1] = ah1 = c & 65535 | d << 16;
				hl[1] = al1 = a & 65535 | b << 16;
				h = ah2;
				l = al2;
				a = l & 65535;
				b = l >>> 16;
				c = h & 65535;
				d = h >>> 16;
				h = hh[2];
				l = hl[2];
				a += l & 65535;
				b += l >>> 16;
				c += h & 65535;
				d += h >>> 16;
				b += a >>> 16;
				c += b >>> 16;
				d += c >>> 16;
				hh[2] = ah2 = c & 65535 | d << 16;
				hl[2] = al2 = a & 65535 | b << 16;
				h = ah3;
				l = al3;
				a = l & 65535;
				b = l >>> 16;
				c = h & 65535;
				d = h >>> 16;
				h = hh[3];
				l = hl[3];
				a += l & 65535;
				b += l >>> 16;
				c += h & 65535;
				d += h >>> 16;
				b += a >>> 16;
				c += b >>> 16;
				d += c >>> 16;
				hh[3] = ah3 = c & 65535 | d << 16;
				hl[3] = al3 = a & 65535 | b << 16;
				h = ah4;
				l = al4;
				a = l & 65535;
				b = l >>> 16;
				c = h & 65535;
				d = h >>> 16;
				h = hh[4];
				l = hl[4];
				a += l & 65535;
				b += l >>> 16;
				c += h & 65535;
				d += h >>> 16;
				b += a >>> 16;
				c += b >>> 16;
				d += c >>> 16;
				hh[4] = ah4 = c & 65535 | d << 16;
				hl[4] = al4 = a & 65535 | b << 16;
				h = ah5;
				l = al5;
				a = l & 65535;
				b = l >>> 16;
				c = h & 65535;
				d = h >>> 16;
				h = hh[5];
				l = hl[5];
				a += l & 65535;
				b += l >>> 16;
				c += h & 65535;
				d += h >>> 16;
				b += a >>> 16;
				c += b >>> 16;
				d += c >>> 16;
				hh[5] = ah5 = c & 65535 | d << 16;
				hl[5] = al5 = a & 65535 | b << 16;
				h = ah6;
				l = al6;
				a = l & 65535;
				b = l >>> 16;
				c = h & 65535;
				d = h >>> 16;
				h = hh[6];
				l = hl[6];
				a += l & 65535;
				b += l >>> 16;
				c += h & 65535;
				d += h >>> 16;
				b += a >>> 16;
				c += b >>> 16;
				d += c >>> 16;
				hh[6] = ah6 = c & 65535 | d << 16;
				hl[6] = al6 = a & 65535 | b << 16;
				h = ah7;
				l = al7;
				a = l & 65535;
				b = l >>> 16;
				c = h & 65535;
				d = h >>> 16;
				h = hh[7];
				l = hl[7];
				a += l & 65535;
				b += l >>> 16;
				c += h & 65535;
				d += h >>> 16;
				b += a >>> 16;
				c += b >>> 16;
				d += c >>> 16;
				hh[7] = ah7 = c & 65535 | d << 16;
				hl[7] = al7 = a & 65535 | b << 16;
				pos += 128;
				n -= 128;
			}
			return n;
		}
		function crypto_hash(out, m, n) {
			var hh = /* @__PURE__ */ new Int32Array(8), hl = /* @__PURE__ */ new Int32Array(8), x = /* @__PURE__ */ new Uint8Array(256), i, b = n;
			hh[0] = 1779033703;
			hh[1] = 3144134277;
			hh[2] = 1013904242;
			hh[3] = 2773480762;
			hh[4] = 1359893119;
			hh[5] = 2600822924;
			hh[6] = 528734635;
			hh[7] = 1541459225;
			hl[0] = 4089235720;
			hl[1] = 2227873595;
			hl[2] = 4271175723;
			hl[3] = 1595750129;
			hl[4] = 2917565137;
			hl[5] = 725511199;
			hl[6] = 4215389547;
			hl[7] = 327033209;
			crypto_hashblocks_hl(hh, hl, m, n);
			n %= 128;
			for (i = 0; i < n; i++) x[i] = m[b - n + i];
			x[n] = 128;
			n = 256 - 128 * (n < 112 ? 1 : 0);
			x[n - 9] = 0;
			ts64(x, n - 8, b / 536870912 | 0, b << 3);
			crypto_hashblocks_hl(hh, hl, x, n);
			for (i = 0; i < 8; i++) ts64(out, 8 * i, hh[i], hl[i]);
			return 0;
		}
		function add(p, q) {
			var a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf(), g = gf(), h = gf(), t = gf();
			Z(a, p[1], p[0]);
			Z(t, q[1], q[0]);
			M(a, a, t);
			A(b, p[0], p[1]);
			A(t, q[0], q[1]);
			M(b, b, t);
			M(c, p[3], q[3]);
			M(c, c, D2);
			M(d, p[2], q[2]);
			A(d, d, d);
			Z(e, b, a);
			Z(f, d, c);
			A(g, d, c);
			A(h, b, a);
			M(p[0], e, f);
			M(p[1], h, g);
			M(p[2], g, f);
			M(p[3], e, h);
		}
		function cswap(p, q, b) {
			var i = 0;
			for (; i < 4; i++) sel25519(p[i], q[i], b);
		}
		function pack(r, p) {
			var tx = gf(), ty = gf(), zi = gf();
			inv25519(zi, p[2]);
			M(tx, p[0], zi);
			M(ty, p[1], zi);
			pack25519(r, ty);
			r[31] ^= par25519(tx) << 7;
		}
		function scalarmult(p, q, s) {
			var b, i;
			set25519(p[0], gf0);
			set25519(p[1], gf1);
			set25519(p[2], gf1);
			set25519(p[3], gf0);
			for (i = 255; i >= 0; --i) {
				b = s[i / 8 | 0] >> (i & 7) & 1;
				cswap(p, q, b);
				add(q, p);
				add(p, p);
				cswap(p, q, b);
			}
		}
		function scalarbase(p, s) {
			var q = [
				gf(),
				gf(),
				gf(),
				gf()
			];
			set25519(q[0], X);
			set25519(q[1], Y);
			set25519(q[2], gf1);
			M(q[3], X, Y);
			scalarmult(p, q, s);
		}
		function crypto_sign_keypair(pk, sk, seeded) {
			var d = /* @__PURE__ */ new Uint8Array(64);
			var p = [
				gf(),
				gf(),
				gf(),
				gf()
			];
			var i;
			if (!seeded) randombytes(sk, 32);
			crypto_hash(d, sk, 32);
			d[0] &= 248;
			d[31] &= 127;
			d[31] |= 64;
			scalarbase(p, d);
			pack(pk, p);
			for (i = 0; i < 32; i++) sk[i + 32] = pk[i];
			return 0;
		}
		var L = new Float64Array([
			237,
			211,
			245,
			92,
			26,
			99,
			18,
			88,
			214,
			156,
			247,
			162,
			222,
			249,
			222,
			20,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			16
		]);
		function modL(r, x) {
			var carry, i = 63, j, k;
			for (; i >= 32; --i) {
				carry = 0;
				for (j = i - 32, k = i - 12; j < k; ++j) {
					x[j] += carry - 16 * x[i] * L[j - (i - 32)];
					carry = x[j] + 128 >> 8;
					x[j] -= carry * 256;
				}
				x[j] += carry;
				x[i] = 0;
			}
			carry = 0;
			for (j = 0; j < 32; j++) {
				x[j] += carry - (x[31] >> 4) * L[j];
				carry = x[j] >> 8;
				x[j] &= 255;
			}
			for (j = 0; j < 32; j++) x[j] -= carry * L[j];
			for (i = 0; i < 32; i++) {
				x[i + 1] += x[i] >> 8;
				r[i] = x[i] & 255;
			}
		}
		function reduce(r) {
			var x = /* @__PURE__ */ new Float64Array(64), i = 0;
			for (; i < 64; i++) x[i] = r[i];
			for (i = 0; i < 64; i++) r[i] = 0;
			modL(r, x);
		}
		function crypto_sign(sm, m, n, sk) {
			var d = /* @__PURE__ */ new Uint8Array(64), h = /* @__PURE__ */ new Uint8Array(64), r = /* @__PURE__ */ new Uint8Array(64);
			var i, j, x = /* @__PURE__ */ new Float64Array(64);
			var p = [
				gf(),
				gf(),
				gf(),
				gf()
			];
			crypto_hash(d, sk, 32);
			d[0] &= 248;
			d[31] &= 127;
			d[31] |= 64;
			var smlen = n + 64;
			for (i = 0; i < n; i++) sm[64 + i] = m[i];
			for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];
			crypto_hash(r, sm.subarray(32), n + 32);
			reduce(r);
			scalarbase(p, r);
			pack(sm, p);
			for (i = 32; i < 64; i++) sm[i] = sk[i];
			crypto_hash(h, sm, n + 64);
			reduce(h);
			for (i = 0; i < 64; i++) x[i] = 0;
			for (i = 0; i < 32; i++) x[i] = r[i];
			for (i = 0; i < 32; i++) for (j = 0; j < 32; j++) x[i + j] += h[i] * d[j];
			modL(sm.subarray(32), x);
			return smlen;
		}
		function unpackneg(r, p) {
			var t = gf(), chk = gf(), num = gf(), den = gf(), den2 = gf(), den4 = gf(), den6 = gf();
			set25519(r[2], gf1);
			unpack25519(r[1], p);
			S(num, r[1]);
			M(den, num, D);
			Z(num, num, r[2]);
			A(den, r[2], den);
			S(den2, den);
			S(den4, den2);
			M(den6, den4, den2);
			M(t, den6, num);
			M(t, t, den);
			pow2523(t, t);
			M(t, t, num);
			M(t, t, den);
			M(t, t, den);
			M(r[0], t, den);
			S(chk, r[0]);
			M(chk, chk, den);
			if (neq25519(chk, num)) M(r[0], r[0], I);
			S(chk, r[0]);
			M(chk, chk, den);
			if (neq25519(chk, num)) return -1;
			if (par25519(r[0]) === p[31] >> 7) Z(r[0], gf0, r[0]);
			M(r[3], r[0], r[1]);
			return 0;
		}
		function crypto_sign_open(m, sm, n, pk) {
			var i, mlen;
			var t = /* @__PURE__ */ new Uint8Array(32), h = /* @__PURE__ */ new Uint8Array(64);
			var p = [
				gf(),
				gf(),
				gf(),
				gf()
			], q = [
				gf(),
				gf(),
				gf(),
				gf()
			];
			mlen = -1;
			if (n < 64) return -1;
			if (unpackneg(q, pk)) return -1;
			for (i = 0; i < n; i++) m[i] = sm[i];
			for (i = 0; i < 32; i++) m[i + 32] = pk[i];
			crypto_hash(h, m, n);
			reduce(h);
			scalarmult(p, q, h);
			scalarbase(q, sm.subarray(32));
			add(p, q);
			pack(t, p);
			n -= 64;
			if (crypto_verify_32(sm, 0, t, 0)) {
				for (i = 0; i < n; i++) m[i] = 0;
				return -1;
			}
			for (i = 0; i < n; i++) m[i] = sm[i + 64];
			mlen = n;
			return mlen;
		}
		var crypto_secretbox_KEYBYTES = 32, crypto_secretbox_NONCEBYTES = 24, crypto_secretbox_ZEROBYTES = 32, crypto_secretbox_BOXZEROBYTES = 16, crypto_scalarmult_BYTES = 32, crypto_scalarmult_SCALARBYTES = 32, crypto_box_PUBLICKEYBYTES = 32, crypto_box_SECRETKEYBYTES = 32, crypto_box_BEFORENMBYTES = 32, crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES, crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES, crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES, crypto_sign_BYTES = 64, crypto_sign_PUBLICKEYBYTES = 32, crypto_sign_SECRETKEYBYTES = 64, crypto_sign_SEEDBYTES = 32, crypto_hash_BYTES = 64;
		nacl.lowlevel = {
			crypto_core_hsalsa20,
			crypto_stream_xor,
			crypto_stream,
			crypto_stream_salsa20_xor,
			crypto_stream_salsa20,
			crypto_onetimeauth,
			crypto_onetimeauth_verify,
			crypto_verify_16,
			crypto_verify_32,
			crypto_secretbox,
			crypto_secretbox_open,
			crypto_scalarmult,
			crypto_scalarmult_base,
			crypto_box_beforenm,
			crypto_box_afternm,
			crypto_box,
			crypto_box_open,
			crypto_box_keypair,
			crypto_hash,
			crypto_sign,
			crypto_sign_keypair,
			crypto_sign_open,
			crypto_secretbox_KEYBYTES,
			crypto_secretbox_NONCEBYTES,
			crypto_secretbox_ZEROBYTES,
			crypto_secretbox_BOXZEROBYTES,
			crypto_scalarmult_BYTES,
			crypto_scalarmult_SCALARBYTES,
			crypto_box_PUBLICKEYBYTES,
			crypto_box_SECRETKEYBYTES,
			crypto_box_BEFORENMBYTES,
			crypto_box_NONCEBYTES,
			crypto_box_ZEROBYTES,
			crypto_box_BOXZEROBYTES,
			crypto_sign_BYTES,
			crypto_sign_PUBLICKEYBYTES,
			crypto_sign_SECRETKEYBYTES,
			crypto_sign_SEEDBYTES,
			crypto_hash_BYTES
		};
		function checkLengths(k, n) {
			if (k.length !== crypto_secretbox_KEYBYTES) throw new Error("bad key size");
			if (n.length !== crypto_secretbox_NONCEBYTES) throw new Error("bad nonce size");
		}
		function checkBoxLengths(pk, sk) {
			if (pk.length !== crypto_box_PUBLICKEYBYTES) throw new Error("bad public key size");
			if (sk.length !== crypto_box_SECRETKEYBYTES) throw new Error("bad secret key size");
		}
		function checkArrayTypes() {
			var t, i = 0;
			for (; i < arguments.length; i++) if ((t = Object.prototype.toString.call(arguments[i])) !== "[object Uint8Array]") throw new TypeError("unexpected type " + t + ", use Uint8Array");
		}
		function cleanup(arr) {
			for (var i = 0; i < arr.length; i++) arr[i] = 0;
		}
		if (!nacl.util) {
			nacl.util = {};
			nacl.util.decodeUTF8 = nacl.util.encodeUTF8 = nacl.util.encodeBase64 = nacl.util.decodeBase64 = function() {
				throw new Error("nacl.util moved into separate package: https://github.com/dchest/tweetnacl-util-js");
			};
		}
		nacl.randomBytes = function(n) {
			var b = new Uint8Array(n);
			randombytes(b, n);
			return b;
		};
		nacl.secretbox = function(msg, nonce, key) {
			checkArrayTypes(msg, nonce, key);
			checkLengths(key, nonce);
			var m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.length);
			var c = new Uint8Array(m.length);
			for (var i = 0; i < msg.length; i++) m[i + crypto_secretbox_ZEROBYTES] = msg[i];
			crypto_secretbox(c, m, m.length, nonce, key);
			return c.subarray(crypto_secretbox_BOXZEROBYTES);
		};
		nacl.secretbox.open = function(box, nonce, key) {
			checkArrayTypes(box, nonce, key);
			checkLengths(key, nonce);
			var c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.length);
			var m = new Uint8Array(c.length);
			for (var i = 0; i < box.length; i++) c[i + crypto_secretbox_BOXZEROBYTES] = box[i];
			if (c.length < 32) return false;
			if (crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) return false;
			return m.subarray(crypto_secretbox_ZEROBYTES);
		};
		nacl.secretbox.keyLength = crypto_secretbox_KEYBYTES;
		nacl.secretbox.nonceLength = crypto_secretbox_NONCEBYTES;
		nacl.secretbox.overheadLength = crypto_secretbox_BOXZEROBYTES;
		nacl.scalarMult = function(n, p) {
			checkArrayTypes(n, p);
			if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error("bad n size");
			if (p.length !== crypto_scalarmult_BYTES) throw new Error("bad p size");
			var q = new Uint8Array(crypto_scalarmult_BYTES);
			crypto_scalarmult(q, n, p);
			return q;
		};
		nacl.scalarMult.base = function(n) {
			checkArrayTypes(n);
			if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error("bad n size");
			var q = new Uint8Array(crypto_scalarmult_BYTES);
			crypto_scalarmult_base(q, n);
			return q;
		};
		nacl.scalarMult.scalarLength = crypto_scalarmult_SCALARBYTES;
		nacl.scalarMult.groupElementLength = crypto_scalarmult_BYTES;
		nacl.box = function(msg, nonce, publicKey, secretKey) {
			var k = nacl.box.before(publicKey, secretKey);
			return nacl.secretbox(msg, nonce, k);
		};
		nacl.box.before = function(publicKey, secretKey) {
			checkArrayTypes(publicKey, secretKey);
			checkBoxLengths(publicKey, secretKey);
			var k = new Uint8Array(crypto_box_BEFORENMBYTES);
			crypto_box_beforenm(k, publicKey, secretKey);
			return k;
		};
		nacl.box.after = nacl.secretbox;
		nacl.box.open = function(msg, nonce, publicKey, secretKey) {
			var k = nacl.box.before(publicKey, secretKey);
			return nacl.secretbox.open(msg, nonce, k);
		};
		nacl.box.open.after = nacl.secretbox.open;
		nacl.box.keyPair = function() {
			var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
			var sk = new Uint8Array(crypto_box_SECRETKEYBYTES);
			crypto_box_keypair(pk, sk);
			return {
				publicKey: pk,
				secretKey: sk
			};
		};
		nacl.box.keyPair.fromSecretKey = function(secretKey) {
			checkArrayTypes(secretKey);
			if (secretKey.length !== crypto_box_SECRETKEYBYTES) throw new Error("bad secret key size");
			var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
			crypto_scalarmult_base(pk, secretKey);
			return {
				publicKey: pk,
				secretKey: new Uint8Array(secretKey)
			};
		};
		nacl.box.publicKeyLength = crypto_box_PUBLICKEYBYTES;
		nacl.box.secretKeyLength = crypto_box_SECRETKEYBYTES;
		nacl.box.sharedKeyLength = crypto_box_BEFORENMBYTES;
		nacl.box.nonceLength = crypto_box_NONCEBYTES;
		nacl.box.overheadLength = nacl.secretbox.overheadLength;
		nacl.sign = function(msg, secretKey) {
			checkArrayTypes(msg, secretKey);
			if (secretKey.length !== crypto_sign_SECRETKEYBYTES) throw new Error("bad secret key size");
			var signedMsg = new Uint8Array(crypto_sign_BYTES + msg.length);
			crypto_sign(signedMsg, msg, msg.length, secretKey);
			return signedMsg;
		};
		nacl.sign.open = function(signedMsg, publicKey) {
			if (arguments.length !== 2) throw new Error("nacl.sign.open accepts 2 arguments; did you mean to use nacl.sign.detached.verify?");
			checkArrayTypes(signedMsg, publicKey);
			if (publicKey.length !== crypto_sign_PUBLICKEYBYTES) throw new Error("bad public key size");
			var tmp = new Uint8Array(signedMsg.length);
			var mlen = crypto_sign_open(tmp, signedMsg, signedMsg.length, publicKey);
			if (mlen < 0) return null;
			var m = new Uint8Array(mlen);
			for (var i = 0; i < m.length; i++) m[i] = tmp[i];
			return m;
		};
		nacl.sign.detached = function(msg, secretKey) {
			var signedMsg = nacl.sign(msg, secretKey);
			var sig = new Uint8Array(crypto_sign_BYTES);
			for (var i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
			return sig;
		};
		nacl.sign.detached.verify = function(msg, sig, publicKey) {
			checkArrayTypes(msg, sig, publicKey);
			if (sig.length !== crypto_sign_BYTES) throw new Error("bad signature size");
			if (publicKey.length !== crypto_sign_PUBLICKEYBYTES) throw new Error("bad public key size");
			var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
			var m = new Uint8Array(crypto_sign_BYTES + msg.length);
			var i = 0;
			for (; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
			for (i = 0; i < msg.length; i++) sm[i + crypto_sign_BYTES] = msg[i];
			return crypto_sign_open(m, sm, sm.length, publicKey) >= 0;
		};
		nacl.sign.keyPair = function() {
			var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
			var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
			crypto_sign_keypair(pk, sk);
			return {
				publicKey: pk,
				secretKey: sk
			};
		};
		nacl.sign.keyPair.fromSecretKey = function(secretKey) {
			checkArrayTypes(secretKey);
			if (secretKey.length !== crypto_sign_SECRETKEYBYTES) throw new Error("bad secret key size");
			var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
			for (var i = 0; i < pk.length; i++) pk[i] = secretKey[32 + i];
			return {
				publicKey: pk,
				secretKey: new Uint8Array(secretKey)
			};
		};
		nacl.sign.keyPair.fromSeed = function(seed) {
			checkArrayTypes(seed);
			if (seed.length !== crypto_sign_SEEDBYTES) throw new Error("bad seed size");
			var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
			var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
			for (var i = 0; i < 32; i++) sk[i] = seed[i];
			crypto_sign_keypair(pk, sk, true);
			return {
				publicKey: pk,
				secretKey: sk
			};
		};
		nacl.sign.publicKeyLength = crypto_sign_PUBLICKEYBYTES;
		nacl.sign.secretKeyLength = crypto_sign_SECRETKEYBYTES;
		nacl.sign.seedLength = crypto_sign_SEEDBYTES;
		nacl.sign.signatureLength = crypto_sign_BYTES;
		nacl.hash = function(msg) {
			checkArrayTypes(msg);
			var h = new Uint8Array(crypto_hash_BYTES);
			crypto_hash(h, msg, msg.length);
			return h;
		};
		nacl.hash.hashLength = crypto_hash_BYTES;
		nacl.verify = function(x, y) {
			checkArrayTypes(x, y);
			if (x.length === 0 || y.length === 0) return false;
			if (x.length !== y.length) return false;
			return vn(x, 0, y, 0, x.length) === 0 ? true : false;
		};
		nacl.setPRNG = function(fn) {
			randombytes = fn;
		};
		(function() {
			var crypto = typeof self !== "undefined" ? self.crypto || self.msCrypto : null;
			if (crypto && crypto.getRandomValues) {
				var QUOTA = 65536;
				nacl.setPRNG(function(x, n) {
					var i, v = new Uint8Array(n);
					for (i = 0; i < n; i += QUOTA) crypto.getRandomValues(v.subarray(i, i + Math.min(n - i, QUOTA)));
					for (i = 0; i < n; i++) x[i] = v[i];
					cleanup(v);
				});
			} else if (typeof __require !== "undefined") {
				crypto = __require("crypto");
				if (crypto && crypto.randomBytes) nacl.setPRNG(function(x, n) {
					var i, v = crypto.randomBytes(n);
					for (i = 0; i < n; i++) x[i] = v[i];
					cleanup(v);
				});
			}
		})();
	})(typeof module !== "undefined" && module.exports ? module.exports : self.nacl = self.nacl || {});
}));
//#endregion
//#region node_modules/.pnpm/bcrypt-pbkdf@1.0.2/node_modules/bcrypt-pbkdf/index.js
var require_bcrypt_pbkdf = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var crypto_hash_sha512 = require_nacl_fast().lowlevel.crypto_hash;
	var BLF_J = 0;
	var Blowfish = function() {
		this.S = [
			new Uint32Array([
				3509652390,
				2564797868,
				805139163,
				3491422135,
				3101798381,
				1780907670,
				3128725573,
				4046225305,
				614570311,
				3012652279,
				134345442,
				2240740374,
				1667834072,
				1901547113,
				2757295779,
				4103290238,
				227898511,
				1921955416,
				1904987480,
				2182433518,
				2069144605,
				3260701109,
				2620446009,
				720527379,
				3318853667,
				677414384,
				3393288472,
				3101374703,
				2390351024,
				1614419982,
				1822297739,
				2954791486,
				3608508353,
				3174124327,
				2024746970,
				1432378464,
				3864339955,
				2857741204,
				1464375394,
				1676153920,
				1439316330,
				715854006,
				3033291828,
				289532110,
				2706671279,
				2087905683,
				3018724369,
				1668267050,
				732546397,
				1947742710,
				3462151702,
				2609353502,
				2950085171,
				1814351708,
				2050118529,
				680887927,
				999245976,
				1800124847,
				3300911131,
				1713906067,
				1641548236,
				4213287313,
				1216130144,
				1575780402,
				4018429277,
				3917837745,
				3693486850,
				3949271944,
				596196993,
				3549867205,
				258830323,
				2213823033,
				772490370,
				2760122372,
				1774776394,
				2652871518,
				566650946,
				4142492826,
				1728879713,
				2882767088,
				1783734482,
				3629395816,
				2517608232,
				2874225571,
				1861159788,
				326777828,
				3124490320,
				2130389656,
				2716951837,
				967770486,
				1724537150,
				2185432712,
				2364442137,
				1164943284,
				2105845187,
				998989502,
				3765401048,
				2244026483,
				1075463327,
				1455516326,
				1322494562,
				910128902,
				469688178,
				1117454909,
				936433444,
				3490320968,
				3675253459,
				1240580251,
				122909385,
				2157517691,
				634681816,
				4142456567,
				3825094682,
				3061402683,
				2540495037,
				79693498,
				3249098678,
				1084186820,
				1583128258,
				426386531,
				1761308591,
				1047286709,
				322548459,
				995290223,
				1845252383,
				2603652396,
				3431023940,
				2942221577,
				3202600964,
				3727903485,
				1712269319,
				422464435,
				3234572375,
				1170764815,
				3523960633,
				3117677531,
				1434042557,
				442511882,
				3600875718,
				1076654713,
				1738483198,
				4213154764,
				2393238008,
				3677496056,
				1014306527,
				4251020053,
				793779912,
				2902807211,
				842905082,
				4246964064,
				1395751752,
				1040244610,
				2656851899,
				3396308128,
				445077038,
				3742853595,
				3577915638,
				679411651,
				2892444358,
				2354009459,
				1767581616,
				3150600392,
				3791627101,
				3102740896,
				284835224,
				4246832056,
				1258075500,
				768725851,
				2589189241,
				3069724005,
				3532540348,
				1274779536,
				3789419226,
				2764799539,
				1660621633,
				3471099624,
				4011903706,
				913787905,
				3497959166,
				737222580,
				2514213453,
				2928710040,
				3937242737,
				1804850592,
				3499020752,
				2949064160,
				2386320175,
				2390070455,
				2415321851,
				4061277028,
				2290661394,
				2416832540,
				1336762016,
				1754252060,
				3520065937,
				3014181293,
				791618072,
				3188594551,
				3933548030,
				2332172193,
				3852520463,
				3043980520,
				413987798,
				3465142937,
				3030929376,
				4245938359,
				2093235073,
				3534596313,
				375366246,
				2157278981,
				2479649556,
				555357303,
				3870105701,
				2008414854,
				3344188149,
				4221384143,
				3956125452,
				2067696032,
				3594591187,
				2921233993,
				2428461,
				544322398,
				577241275,
				1471733935,
				610547355,
				4027169054,
				1432588573,
				1507829418,
				2025931657,
				3646575487,
				545086370,
				48609733,
				2200306550,
				1653985193,
				298326376,
				1316178497,
				3007786442,
				2064951626,
				458293330,
				2589141269,
				3591329599,
				3164325604,
				727753846,
				2179363840,
				146436021,
				1461446943,
				4069977195,
				705550613,
				3059967265,
				3887724982,
				4281599278,
				3313849956,
				1404054877,
				2845806497,
				146425753,
				1854211946
			]),
			new Uint32Array([
				1266315497,
				3048417604,
				3681880366,
				3289982499,
				290971e4,
				1235738493,
				2632868024,
				2414719590,
				3970600049,
				1771706367,
				1449415276,
				3266420449,
				422970021,
				1963543593,
				2690192192,
				3826793022,
				1062508698,
				1531092325,
				1804592342,
				2583117782,
				2714934279,
				4024971509,
				1294809318,
				4028980673,
				1289560198,
				2221992742,
				1669523910,
				35572830,
				157838143,
				1052438473,
				1016535060,
				1802137761,
				1753167236,
				1386275462,
				3080475397,
				2857371447,
				1040679964,
				2145300060,
				2390574316,
				1461121720,
				2956646967,
				4031777805,
				4028374788,
				33600511,
				2920084762,
				1018524850,
				629373528,
				3691585981,
				3515945977,
				2091462646,
				2486323059,
				586499841,
				988145025,
				935516892,
				3367335476,
				2599673255,
				2839830854,
				265290510,
				3972581182,
				2759138881,
				3795373465,
				1005194799,
				847297441,
				406762289,
				1314163512,
				1332590856,
				1866599683,
				4127851711,
				750260880,
				613907577,
				1450815602,
				3165620655,
				3734664991,
				3650291728,
				3012275730,
				3704569646,
				1427272223,
				778793252,
				1343938022,
				2676280711,
				2052605720,
				1946737175,
				3164576444,
				3914038668,
				3967478842,
				3682934266,
				1661551462,
				3294938066,
				4011595847,
				840292616,
				3712170807,
				616741398,
				312560963,
				711312465,
				1351876610,
				322626781,
				1910503582,
				271666773,
				2175563734,
				1594956187,
				70604529,
				3617834859,
				1007753275,
				1495573769,
				4069517037,
				2549218298,
				2663038764,
				504708206,
				2263041392,
				3941167025,
				2249088522,
				1514023603,
				1998579484,
				1312622330,
				694541497,
				2582060303,
				2151582166,
				1382467621,
				776784248,
				2618340202,
				3323268794,
				2497899128,
				2784771155,
				503983604,
				4076293799,
				907881277,
				423175695,
				432175456,
				1378068232,
				4145222326,
				3954048622,
				3938656102,
				3820766613,
				2793130115,
				2977904593,
				26017576,
				3274890735,
				3194772133,
				1700274565,
				1756076034,
				4006520079,
				3677328699,
				720338349,
				1533947780,
				354530856,
				688349552,
				3973924725,
				1637815568,
				332179504,
				3949051286,
				53804574,
				2852348879,
				3044236432,
				1282449977,
				3583942155,
				3416972820,
				4006381244,
				1617046695,
				2628476075,
				3002303598,
				1686838959,
				431878346,
				2686675385,
				1700445008,
				1080580658,
				1009431731,
				832498133,
				3223435511,
				2605976345,
				2271191193,
				2516031870,
				1648197032,
				4164389018,
				2548247927,
				300782431,
				375919233,
				238389289,
				3353747414,
				2531188641,
				2019080857,
				1475708069,
				455242339,
				2609103871,
				448939670,
				3451063019,
				1395535956,
				2413381860,
				1841049896,
				1491858159,
				885456874,
				4264095073,
				4001119347,
				1565136089,
				3898914787,
				1108368660,
				540939232,
				1173283510,
				2745871338,
				3681308437,
				4207628240,
				3343053890,
				4016749493,
				1699691293,
				1103962373,
				3625875870,
				2256883143,
				3830138730,
				1031889488,
				3479347698,
				1535977030,
				4236805024,
				3251091107,
				2132092099,
				1774941330,
				1199868427,
				1452454533,
				157007616,
				2904115357,
				342012276,
				595725824,
				1480756522,
				206960106,
				497939518,
				591360097,
				863170706,
				2375253569,
				3596610801,
				1814182875,
				2094937945,
				3421402208,
				1082520231,
				3463918190,
				2785509508,
				435703966,
				3908032597,
				1641649973,
				2842273706,
				3305899714,
				1510255612,
				2148256476,
				2655287854,
				3276092548,
				4258621189,
				236887753,
				3681803219,
				274041037,
				1734335097,
				3815195456,
				3317970021,
				1899903192,
				1026095262,
				4050517792,
				356393447,
				2410691914,
				3873677099,
				3682840055
			]),
			new Uint32Array([
				3913112168,
				2491498743,
				4132185628,
				2489919796,
				1091903735,
				1979897079,
				3170134830,
				3567386728,
				3557303409,
				857797738,
				1136121015,
				1342202287,
				507115054,
				2535736646,
				337727348,
				3213592640,
				1301675037,
				2528481711,
				1895095763,
				1721773893,
				3216771564,
				62756741,
				2142006736,
				835421444,
				2531993523,
				1442658625,
				3659876326,
				2882144922,
				676362277,
				1392781812,
				170690266,
				3921047035,
				1759253602,
				3611846912,
				1745797284,
				664899054,
				1329594018,
				3901205900,
				3045908486,
				2062866102,
				2865634940,
				3543621612,
				3464012697,
				1080764994,
				553557557,
				3656615353,
				3996768171,
				991055499,
				499776247,
				1265440854,
				648242737,
				3940784050,
				980351604,
				3713745714,
				1749149687,
				3396870395,
				4211799374,
				3640570775,
				1161844396,
				3125318951,
				1431517754,
				545492359,
				4268468663,
				3499529547,
				1437099964,
				2702547544,
				3433638243,
				2581715763,
				2787789398,
				1060185593,
				1593081372,
				2418618748,
				4260947970,
				69676912,
				2159744348,
				86519011,
				2512459080,
				3838209314,
				1220612927,
				3339683548,
				133810670,
				1090789135,
				1078426020,
				1569222167,
				845107691,
				3583754449,
				4072456591,
				1091646820,
				628848692,
				1613405280,
				3757631651,
				526609435,
				236106946,
				48312990,
				2942717905,
				3402727701,
				1797494240,
				859738849,
				992217954,
				4005476642,
				2243076622,
				3870952857,
				3732016268,
				765654824,
				3490871365,
				2511836413,
				1685915746,
				3888969200,
				1414112111,
				2273134842,
				3281911079,
				4080962846,
				172450625,
				2569994100,
				980381355,
				4109958455,
				2819808352,
				2716589560,
				2568741196,
				3681446669,
				3329971472,
				1835478071,
				660984891,
				3704678404,
				4045999559,
				3422617507,
				3040415634,
				1762651403,
				1719377915,
				3470491036,
				2693910283,
				3642056355,
				3138596744,
				1364962596,
				2073328063,
				1983633131,
				926494387,
				3423689081,
				2150032023,
				4096667949,
				1749200295,
				3328846651,
				309677260,
				2016342300,
				1779581495,
				3079819751,
				111262694,
				1274766160,
				443224088,
				298511866,
				1025883608,
				3806446537,
				1145181785,
				168956806,
				3641502830,
				3584813610,
				1689216846,
				3666258015,
				3200248200,
				1692713982,
				2646376535,
				4042768518,
				1618508792,
				1610833997,
				3523052358,
				4130873264,
				2001055236,
				3610705100,
				2202168115,
				4028541809,
				2961195399,
				1006657119,
				2006996926,
				3186142756,
				1430667929,
				3210227297,
				1314452623,
				4074634658,
				4101304120,
				2273951170,
				1399257539,
				3367210612,
				3027628629,
				1190975929,
				2062231137,
				2333990788,
				2221543033,
				2438960610,
				1181637006,
				548689776,
				2362791313,
				3372408396,
				3104550113,
				3145860560,
				296247880,
				1970579870,
				3078560182,
				3769228297,
				1714227617,
				3291629107,
				3898220290,
				166772364,
				1251581989,
				493813264,
				448347421,
				195405023,
				2709975567,
				677966185,
				3703036547,
				1463355134,
				2715995803,
				1338867538,
				1343315457,
				2802222074,
				2684532164,
				233230375,
				2599980071,
				2000651841,
				3277868038,
				1638401717,
				4028070440,
				3237316320,
				6314154,
				819756386,
				300326615,
				590932579,
				1405279636,
				3267499572,
				3150704214,
				2428286686,
				3959192993,
				3461946742,
				1862657033,
				1266418056,
				963775037,
				2089974820,
				2263052895,
				1917689273,
				448879540,
				3550394620,
				3981727096,
				150775221,
				3627908307,
				1303187396,
				508620638,
				2975983352,
				2726630617,
				1817252668,
				1876281319,
				1457606340,
				908771278,
				3720792119,
				3617206836,
				2455994898,
				1729034894,
				1080033504
			]),
			new Uint32Array([
				976866871,
				3556439503,
				2881648439,
				1522871579,
				1555064734,
				1336096578,
				3548522304,
				2579274686,
				3574697629,
				3205460757,
				3593280638,
				3338716283,
				3079412587,
				564236357,
				2993598910,
				1781952180,
				1464380207,
				3163844217,
				3332601554,
				1699332808,
				1393555694,
				1183702653,
				3581086237,
				1288719814,
				691649499,
				2847557200,
				2895455976,
				3193889540,
				2717570544,
				1781354906,
				1676643554,
				2592534050,
				3230253752,
				1126444790,
				2770207658,
				2633158820,
				2210423226,
				2615765581,
				2414155088,
				3127139286,
				673620729,
				2805611233,
				1269405062,
				4015350505,
				3341807571,
				4149409754,
				1057255273,
				2012875353,
				2162469141,
				2276492801,
				2601117357,
				993977747,
				3918593370,
				2654263191,
				753973209,
				36408145,
				2530585658,
				25011837,
				3520020182,
				2088578344,
				530523599,
				2918365339,
				1524020338,
				1518925132,
				3760827505,
				3759777254,
				1202760957,
				3985898139,
				3906192525,
				674977740,
				4174734889,
				2031300136,
				2019492241,
				3983892565,
				4153806404,
				3822280332,
				352677332,
				2297720250,
				60907813,
				90501309,
				3286998549,
				1016092578,
				2535922412,
				2839152426,
				457141659,
				509813237,
				4120667899,
				652014361,
				1966332200,
				2975202805,
				55981186,
				2327461051,
				676427537,
				3255491064,
				2882294119,
				3433927263,
				1307055953,
				942726286,
				933058658,
				2468411793,
				3933900994,
				4215176142,
				1361170020,
				2001714738,
				2830558078,
				3274259782,
				1222529897,
				1679025792,
				2729314320,
				3714953764,
				1770335741,
				151462246,
				3013232138,
				1682292957,
				1483529935,
				471910574,
				1539241949,
				458788160,
				3436315007,
				1807016891,
				3718408830,
				978976581,
				1043663428,
				3165965781,
				1927990952,
				4200891579,
				2372276910,
				3208408903,
				3533431907,
				1412390302,
				2931980059,
				4132332400,
				1947078029,
				3881505623,
				4168226417,
				2941484381,
				1077988104,
				1320477388,
				886195818,
				18198404,
				3786409e3,
				2509781533,
				112762804,
				3463356488,
				1866414978,
				891333506,
				18488651,
				661792760,
				1628790961,
				3885187036,
				3141171499,
				876946877,
				2693282273,
				1372485963,
				791857591,
				2686433993,
				3759982718,
				3167212022,
				3472953795,
				2716379847,
				445679433,
				3561995674,
				3504004811,
				3574258232,
				54117162,
				3331405415,
				2381918588,
				3769707343,
				4154350007,
				1140177722,
				4074052095,
				668550556,
				3214352940,
				367459370,
				261225585,
				2610173221,
				4209349473,
				3468074219,
				3265815641,
				314222801,
				3066103646,
				3808782860,
				282218597,
				3406013506,
				3773591054,
				379116347,
				1285071038,
				846784868,
				2669647154,
				3771962079,
				3550491691,
				2305946142,
				453669953,
				1268987020,
				3317592352,
				3279303384,
				3744833421,
				2610507566,
				3859509063,
				266596637,
				3847019092,
				517658769,
				3462560207,
				3443424879,
				370717030,
				4247526661,
				2224018117,
				4143653529,
				4112773975,
				2788324899,
				2477274417,
				1456262402,
				2901442914,
				1517677493,
				1846949527,
				2295493580,
				3734397586,
				2176403920,
				1280348187,
				1908823572,
				3871786941,
				846861322,
				1172426758,
				3287448474,
				3383383037,
				1655181056,
				3139813346,
				901632758,
				1897031941,
				2986607138,
				3066810236,
				3447102507,
				1393639104,
				373351379,
				950779232,
				625454576,
				3124240540,
				4148612726,
				2007998917,
				544563296,
				2244738638,
				2330496472,
				2058025392,
				1291430526,
				424198748,
				50039436,
				29584100,
				3605783033,
				2429876329,
				2791104160,
				1057563949,
				3255363231,
				3075367218,
				3463963227,
				1469046755,
				985887462
			])
		];
		this.P = new Uint32Array([
			608135816,
			2242054355,
			320440878,
			57701188,
			2752067618,
			698298832,
			137296536,
			3964562569,
			1160258022,
			953160567,
			3193202383,
			887688300,
			3232508343,
			3380367581,
			1065670069,
			3041331479,
			2450970073,
			2306472731
		]);
	};
	function F(S, x8, i) {
		return (S[0][x8[i + 3]] + S[1][x8[i + 2]] ^ S[2][x8[i + 1]]) + S[3][x8[i]];
	}
	Blowfish.prototype.encipher = function(x, x8) {
		if (x8 === void 0) {
			x8 = new Uint8Array(x.buffer);
			if (x.byteOffset !== 0) x8 = x8.subarray(x.byteOffset);
		}
		x[0] ^= this.P[0];
		for (var i = 1; i < 16; i += 2) {
			x[1] ^= F(this.S, x8, 0) ^ this.P[i];
			x[0] ^= F(this.S, x8, 4) ^ this.P[i + 1];
		}
		var t = x[0];
		x[0] = x[1] ^ this.P[17];
		x[1] = t;
	};
	Blowfish.prototype.decipher = function(x) {
		var x8 = new Uint8Array(x.buffer);
		if (x.byteOffset !== 0) x8 = x8.subarray(x.byteOffset);
		x[0] ^= this.P[17];
		for (var i = 16; i > 0; i -= 2) {
			x[1] ^= F(this.S, x8, 0) ^ this.P[i];
			x[0] ^= F(this.S, x8, 4) ^ this.P[i - 1];
		}
		var t = x[0];
		x[0] = x[1] ^ this.P[0];
		x[1] = t;
	};
	function stream2word(data, databytes) {
		var i, temp = 0;
		for (i = 0; i < 4; i++, BLF_J++) {
			if (BLF_J >= databytes) BLF_J = 0;
			temp = temp << 8 | data[BLF_J];
		}
		return temp;
	}
	Blowfish.prototype.expand0state = function(key, keybytes) {
		var d = /* @__PURE__ */ new Uint32Array(2), i, k;
		var d8 = new Uint8Array(d.buffer);
		for (i = 0, BLF_J = 0; i < 18; i++) this.P[i] ^= stream2word(key, keybytes);
		BLF_J = 0;
		for (i = 0; i < 18; i += 2) {
			this.encipher(d, d8);
			this.P[i] = d[0];
			this.P[i + 1] = d[1];
		}
		for (i = 0; i < 4; i++) for (k = 0; k < 256; k += 2) {
			this.encipher(d, d8);
			this.S[i][k] = d[0];
			this.S[i][k + 1] = d[1];
		}
	};
	Blowfish.prototype.expandstate = function(data, databytes, key, keybytes) {
		var d = /* @__PURE__ */ new Uint32Array(2), i = 0, k;
		for (BLF_J = 0; i < 18; i++) this.P[i] ^= stream2word(key, keybytes);
		for (i = 0, BLF_J = 0; i < 18; i += 2) {
			d[0] ^= stream2word(data, databytes);
			d[1] ^= stream2word(data, databytes);
			this.encipher(d);
			this.P[i] = d[0];
			this.P[i + 1] = d[1];
		}
		for (i = 0; i < 4; i++) for (k = 0; k < 256; k += 2) {
			d[0] ^= stream2word(data, databytes);
			d[1] ^= stream2word(data, databytes);
			this.encipher(d);
			this.S[i][k] = d[0];
			this.S[i][k + 1] = d[1];
		}
		BLF_J = 0;
	};
	Blowfish.prototype.enc = function(data, blocks) {
		for (var i = 0; i < blocks; i++) this.encipher(data.subarray(i * 2));
	};
	Blowfish.prototype.dec = function(data, blocks) {
		for (var i = 0; i < blocks; i++) this.decipher(data.subarray(i * 2));
	};
	var BCRYPT_BLOCKS = 8;
	var BCRYPT_HASHSIZE = 32;
	function bcrypt_hash(sha2pass, sha2salt, out) {
		var state = new Blowfish(), cdata = new Uint32Array(BCRYPT_BLOCKS), i, ciphertext = new Uint8Array([
			79,
			120,
			121,
			99,
			104,
			114,
			111,
			109,
			97,
			116,
			105,
			99,
			66,
			108,
			111,
			119,
			102,
			105,
			115,
			104,
			83,
			119,
			97,
			116,
			68,
			121,
			110,
			97,
			109,
			105,
			116,
			101
		]);
		state.expandstate(sha2salt, 64, sha2pass, 64);
		for (i = 0; i < 64; i++) {
			state.expand0state(sha2salt, 64);
			state.expand0state(sha2pass, 64);
		}
		for (i = 0; i < BCRYPT_BLOCKS; i++) cdata[i] = stream2word(ciphertext, ciphertext.byteLength);
		for (i = 0; i < 64; i++) state.enc(cdata, cdata.byteLength / 8);
		for (i = 0; i < BCRYPT_BLOCKS; i++) {
			out[4 * i + 3] = cdata[i] >>> 24;
			out[4 * i + 2] = cdata[i] >>> 16;
			out[4 * i + 1] = cdata[i] >>> 8;
			out[4 * i + 0] = cdata[i];
		}
	}
	function bcrypt_pbkdf(pass, passlen, salt, saltlen, key, keylen, rounds) {
		var sha2pass = /* @__PURE__ */ new Uint8Array(64), sha2salt = /* @__PURE__ */ new Uint8Array(64), out = new Uint8Array(BCRYPT_HASHSIZE), tmpout = new Uint8Array(BCRYPT_HASHSIZE), countsalt = new Uint8Array(saltlen + 4), i, j, amt, stride, dest, count, origkeylen = keylen;
		if (rounds < 1) return -1;
		if (passlen === 0 || saltlen === 0 || keylen === 0 || keylen > out.byteLength * out.byteLength || saltlen > 1 << 20) return -1;
		stride = Math.floor((keylen + out.byteLength - 1) / out.byteLength);
		amt = Math.floor((keylen + stride - 1) / stride);
		for (i = 0; i < saltlen; i++) countsalt[i] = salt[i];
		crypto_hash_sha512(sha2pass, pass, passlen);
		for (count = 1; keylen > 0; count++) {
			countsalt[saltlen + 0] = count >>> 24;
			countsalt[saltlen + 1] = count >>> 16;
			countsalt[saltlen + 2] = count >>> 8;
			countsalt[saltlen + 3] = count;
			crypto_hash_sha512(sha2salt, countsalt, saltlen + 4);
			bcrypt_hash(sha2pass, sha2salt, tmpout);
			for (i = out.byteLength; i--;) out[i] = tmpout[i];
			for (i = 1; i < rounds; i++) {
				crypto_hash_sha512(sha2salt, tmpout, tmpout.byteLength);
				bcrypt_hash(sha2pass, sha2salt, tmpout);
				for (j = 0; j < out.byteLength; j++) out[j] ^= tmpout[j];
			}
			amt = Math.min(amt, keylen);
			for (i = 0; i < amt; i++) {
				dest = i * stride + (count - 1);
				if (dest >= origkeylen) break;
				key[dest] = out[i];
			}
			keylen -= i;
		}
		return 0;
	}
	module.exports = {
		BLOCKS: BCRYPT_BLOCKS,
		HASHSIZE: BCRYPT_HASHSIZE,
		hash: bcrypt_hash,
		pbkdf: bcrypt_pbkdf
	};
}));
//#endregion
//#region \0rdv-native-stub
var require__rdv_native_stub = /* @__PURE__ */ __commonJSMin((() => {
	throw new Error("optional native accelerator is not bundled; ssh2 uses its pure-JS path");
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/constants.js
var require_constants = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const crypto = __require("crypto");
	let cpuInfo;
	try {
		cpuInfo = require__rdv_native_stub()();
	} catch {}
	const { bindingAvailable, CIPHER_INFO, MAC_INFO } = require_crypto();
	const eddsaSupported = (() => {
		if (typeof crypto.sign === "function" && typeof crypto.verify === "function") {
			const key = "-----BEGIN PRIVATE KEY-----\r\nMC4CAQAwBQYDK2VwBCIEIHKj+sVa9WcD/q2DJUJaf43Kptc8xYuUQA4bOFj9vC8T\r\n-----END PRIVATE KEY-----";
			const data = Buffer.from("a");
			let sig;
			let verified;
			try {
				sig = crypto.sign(null, data, key);
				verified = crypto.verify(null, data, key, sig);
			} catch {}
			return Buffer.isBuffer(sig) && sig.length === 64 && verified === true;
		}
		return false;
	})();
	const curve25519Supported = typeof crypto.diffieHellman === "function" && typeof crypto.generateKeyPairSync === "function" && typeof crypto.createPublicKey === "function";
	const DEFAULT_KEX = [
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group15-sha512",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group17-sha512",
		"diffie-hellman-group18-sha512"
	];
	if (curve25519Supported) {
		DEFAULT_KEX.unshift("curve25519-sha256");
		DEFAULT_KEX.unshift("curve25519-sha256@libssh.org");
	}
	const SUPPORTED_KEX = DEFAULT_KEX.concat([
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1"
	]);
	const DEFAULT_SERVER_HOST_KEY = [
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"rsa-sha2-512",
		"rsa-sha2-256",
		"ssh-rsa"
	];
	if (eddsaSupported) DEFAULT_SERVER_HOST_KEY.unshift("ssh-ed25519");
	const SUPPORTED_SERVER_HOST_KEY = DEFAULT_SERVER_HOST_KEY.concat(["ssh-dss"]);
	const canUseCipher = (() => {
		const ciphers = crypto.getCiphers();
		return (name) => ciphers.includes(CIPHER_INFO[name].sslName);
	})();
	let DEFAULT_CIPHER = [
		"aes128-gcm@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr"
	];
	if (cpuInfo && cpuInfo.flags && !cpuInfo.flags.aes) {
		if (bindingAvailable) DEFAULT_CIPHER.unshift("chacha20-poly1305@openssh.com");
		else DEFAULT_CIPHER.push("chacha20-poly1305@openssh.com");
	} else if (bindingAvailable && cpuInfo && cpuInfo.arch === "x86") DEFAULT_CIPHER.splice(4, 0, "chacha20-poly1305@openssh.com");
	else DEFAULT_CIPHER.push("chacha20-poly1305@openssh.com");
	DEFAULT_CIPHER = DEFAULT_CIPHER.filter(canUseCipher);
	const SUPPORTED_CIPHER = DEFAULT_CIPHER.concat([
		"aes256-cbc",
		"aes192-cbc",
		"aes128-cbc",
		"blowfish-cbc",
		"3des-cbc",
		"aes128-gcm",
		"aes256-gcm",
		"arcfour256",
		"arcfour128",
		"cast128-cbc",
		"arcfour"
	].filter(canUseCipher));
	const canUseMAC = (() => {
		const hashes = crypto.getHashes();
		return (name) => hashes.includes(MAC_INFO[name].sslName);
	})();
	const DEFAULT_MAC = [
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"hmac-sha1-etm@openssh.com",
		"hmac-sha2-256",
		"hmac-sha2-512",
		"hmac-sha1"
	].filter(canUseMAC);
	const SUPPORTED_MAC = DEFAULT_MAC.concat([
		"hmac-md5",
		"hmac-sha2-256-96",
		"hmac-sha2-512-96",
		"hmac-ripemd160",
		"hmac-sha1-96",
		"hmac-md5-96"
	].filter(canUseMAC));
	const DEFAULT_COMPRESSION = [
		"none",
		"zlib@openssh.com",
		"zlib"
	];
	const SUPPORTED_COMPRESSION = DEFAULT_COMPRESSION.concat([]);
	const COMPAT = {
		BAD_DHGEX: 1,
		OLD_EXIT: 2,
		DYN_RPORT_BUG: 4,
		BUG_DHGEX_LARGE: 8,
		IMPLY_RSA_SHA2_SIGALGS: 16
	};
	module.exports = {
		MESSAGE: {
			DISCONNECT: 1,
			IGNORE: 2,
			UNIMPLEMENTED: 3,
			DEBUG: 4,
			SERVICE_REQUEST: 5,
			SERVICE_ACCEPT: 6,
			EXT_INFO: 7,
			KEXINIT: 20,
			NEWKEYS: 21,
			KEXDH_INIT: 30,
			KEXDH_REPLY: 31,
			KEXDH_GEX_GROUP: 31,
			KEXDH_GEX_INIT: 32,
			KEXDH_GEX_REPLY: 33,
			KEXDH_GEX_REQUEST: 34,
			KEXECDH_INIT: 30,
			KEXECDH_REPLY: 31,
			USERAUTH_REQUEST: 50,
			USERAUTH_FAILURE: 51,
			USERAUTH_SUCCESS: 52,
			USERAUTH_BANNER: 53,
			USERAUTH_PASSWD_CHANGEREQ: 60,
			USERAUTH_PK_OK: 60,
			USERAUTH_INFO_REQUEST: 60,
			USERAUTH_INFO_RESPONSE: 61,
			GLOBAL_REQUEST: 80,
			REQUEST_SUCCESS: 81,
			REQUEST_FAILURE: 82,
			CHANNEL_OPEN: 90,
			CHANNEL_OPEN_CONFIRMATION: 91,
			CHANNEL_OPEN_FAILURE: 92,
			CHANNEL_WINDOW_ADJUST: 93,
			CHANNEL_DATA: 94,
			CHANNEL_EXTENDED_DATA: 95,
			CHANNEL_EOF: 96,
			CHANNEL_CLOSE: 97,
			CHANNEL_REQUEST: 98,
			CHANNEL_SUCCESS: 99,
			CHANNEL_FAILURE: 100
		},
		DISCONNECT_REASON: {
			HOST_NOT_ALLOWED_TO_CONNECT: 1,
			PROTOCOL_ERROR: 2,
			KEY_EXCHANGE_FAILED: 3,
			RESERVED: 4,
			MAC_ERROR: 5,
			COMPRESSION_ERROR: 6,
			SERVICE_NOT_AVAILABLE: 7,
			PROTOCOL_VERSION_NOT_SUPPORTED: 8,
			HOST_KEY_NOT_VERIFIABLE: 9,
			CONNECTION_LOST: 10,
			BY_APPLICATION: 11,
			TOO_MANY_CONNECTIONS: 12,
			AUTH_CANCELED_BY_USER: 13,
			NO_MORE_AUTH_METHODS_AVAILABLE: 14,
			ILLEGAL_USER_NAME: 15
		},
		DISCONNECT_REASON_STR: void 0,
		CHANNEL_OPEN_FAILURE: {
			ADMINISTRATIVELY_PROHIBITED: 1,
			CONNECT_FAILED: 2,
			UNKNOWN_CHANNEL_TYPE: 3,
			RESOURCE_SHORTAGE: 4
		},
		TERMINAL_MODE: {
			TTY_OP_END: 0,
			VINTR: 1,
			VQUIT: 2,
			VERASE: 3,
			VKILL: 4,
			VEOF: 5,
			VEOL: 6,
			VEOL2: 7,
			VSTART: 8,
			VSTOP: 9,
			VSUSP: 10,
			VDSUSP: 11,
			VREPRINT: 12,
			VWERASE: 13,
			VLNEXT: 14,
			VFLUSH: 15,
			VSWTCH: 16,
			VSTATUS: 17,
			VDISCARD: 18,
			IGNPAR: 30,
			PARMRK: 31,
			INPCK: 32,
			ISTRIP: 33,
			INLCR: 34,
			IGNCR: 35,
			ICRNL: 36,
			IUCLC: 37,
			IXON: 38,
			IXANY: 39,
			IXOFF: 40,
			IMAXBEL: 41,
			ISIG: 50,
			ICANON: 51,
			XCASE: 52,
			ECHO: 53,
			ECHOE: 54,
			ECHOK: 55,
			ECHONL: 56,
			NOFLSH: 57,
			TOSTOP: 58,
			IEXTEN: 59,
			ECHOCTL: 60,
			ECHOKE: 61,
			PENDIN: 62,
			OPOST: 70,
			OLCUC: 71,
			ONLCR: 72,
			OCRNL: 73,
			ONOCR: 74,
			ONLRET: 75,
			CS7: 90,
			CS8: 91,
			PARENB: 92,
			PARODD: 93,
			TTY_OP_ISPEED: 128,
			TTY_OP_OSPEED: 129
		},
		CHANNEL_EXTENDED_DATATYPE: { STDERR: 1 },
		SIGNALS: [
			"ABRT",
			"ALRM",
			"FPE",
			"HUP",
			"ILL",
			"INT",
			"QUIT",
			"SEGV",
			"TERM",
			"USR1",
			"USR2",
			"KILL",
			"PIPE"
		].reduce((cur, val) => ({
			...cur,
			[val]: 1
		}), {}),
		COMPAT,
		COMPAT_CHECKS: [
			["Cisco-1.25", COMPAT.BAD_DHGEX],
			[/^Cisco-1[.]/, COMPAT.BUG_DHGEX_LARGE],
			[/^[0-9.]+$/, COMPAT.OLD_EXIT],
			[/^OpenSSH_5[.][0-9]+/, COMPAT.DYN_RPORT_BUG],
			[/^OpenSSH_7[.]4/, COMPAT.IMPLY_RSA_SHA2_SIGALGS]
		],
		DEFAULT_KEX,
		SUPPORTED_KEX,
		DEFAULT_SERVER_HOST_KEY,
		SUPPORTED_SERVER_HOST_KEY,
		DEFAULT_CIPHER,
		SUPPORTED_CIPHER,
		DEFAULT_MAC,
		SUPPORTED_MAC,
		DEFAULT_COMPRESSION,
		SUPPORTED_COMPRESSION,
		curve25519Supported,
		eddsaSupported
	};
	module.exports.DISCONNECT_REASON_BY_VALUE = Array.from(Object.entries(module.exports.DISCONNECT_REASON)).reduce((obj, [key, value]) => ({
		...obj,
		[value]: key
	}), {});
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/utils.js
var require_utils$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const Ber = require_lib$1().Ber;
	let DISCONNECT_REASON;
	const FastBuffer = Buffer[Symbol.species];
	const TypedArrayFill = Object.getPrototypeOf(Uint8Array.prototype).fill;
	function readUInt32BE(buf, offset) {
		return buf[offset++] * 16777216 + buf[offset++] * 65536 + buf[offset++] * 256 + buf[offset];
	}
	function bufferCopy(src, dest, srcStart, srcEnd, destStart) {
		if (!destStart) destStart = 0;
		if (srcEnd > src.length) srcEnd = src.length;
		let nb = srcEnd - srcStart;
		const destLeft = dest.length - destStart;
		if (nb > destLeft) nb = destLeft;
		dest.set(new Uint8Array(src.buffer, src.byteOffset + srcStart, nb), destStart);
		return nb;
	}
	function bufferSlice(buf, start, end) {
		if (end === void 0) end = buf.length;
		return new FastBuffer(buf.buffer, buf.byteOffset + start, end - start);
	}
	function makeBufferParser() {
		let pos = 0;
		let buffer;
		const self = {
			init: (buf, start) => {
				buffer = buf;
				pos = typeof start === "number" ? start : 0;
			},
			pos: () => pos,
			length: () => buffer ? buffer.length : 0,
			avail: () => buffer && pos < buffer.length ? buffer.length - pos : 0,
			clear: () => {
				buffer = void 0;
			},
			readUInt32BE: () => {
				if (!buffer || pos + 3 >= buffer.length) return;
				return buffer[pos++] * 16777216 + buffer[pos++] * 65536 + buffer[pos++] * 256 + buffer[pos++];
			},
			readUInt64BE: (behavior) => {
				if (!buffer || pos + 7 >= buffer.length) return;
				switch (behavior) {
					case "always": return BigInt(`0x${buffer.hexSlice(pos, pos += 8)}`);
					case "maybe": if (buffer[pos] > 31) return BigInt(`0x${buffer.hexSlice(pos, pos += 8)}`);
					default: return buffer[pos++] * 72057594037927940 + buffer[pos++] * 281474976710656 + buffer[pos++] * 1099511627776 + buffer[pos++] * 4294967296 + buffer[pos++] * 16777216 + buffer[pos++] * 65536 + buffer[pos++] * 256 + buffer[pos++];
				}
			},
			skip: (n) => {
				if (buffer && n > 0) pos += n;
			},
			skipString: () => {
				const len = self.readUInt32BE();
				if (len === void 0) return;
				pos += len;
				return pos <= buffer.length ? len : void 0;
			},
			readByte: () => {
				if (buffer && pos < buffer.length) return buffer[pos++];
			},
			readBool: () => {
				if (buffer && pos < buffer.length) return !!buffer[pos++];
			},
			readList: () => {
				const list = self.readString(true);
				if (list === void 0) return;
				return list ? list.split(",") : [];
			},
			readString: (dest, maxLen) => {
				if (typeof dest === "number") {
					maxLen = dest;
					dest = void 0;
				}
				const len = self.readUInt32BE();
				if (len === void 0) return;
				if (buffer.length - pos < len || typeof maxLen === "number" && len > maxLen) return;
				if (dest) {
					if (Buffer.isBuffer(dest)) return bufferCopy(buffer, dest, pos, pos += len);
					return buffer.utf8Slice(pos, pos += len);
				}
				return bufferSlice(buffer, pos, pos += len);
			},
			readRaw: (len) => {
				if (!buffer) return;
				if (typeof len !== "number") return bufferSlice(buffer, pos, pos += buffer.length - pos);
				if (buffer.length - pos >= len) return bufferSlice(buffer, pos, pos += len);
			}
		};
		return self;
	}
	function makeError(msg, level, fatal) {
		const err = new Error(msg);
		if (typeof level === "boolean") {
			fatal = level;
			err.level = "protocol";
		} else err.level = level || "protocol";
		err.fatal = !!fatal;
		return err;
	}
	function writeUInt32BE(buf, value, offset) {
		buf[offset++] = value >>> 24;
		buf[offset++] = value >>> 16;
		buf[offset++] = value >>> 8;
		buf[offset++] = value;
		return offset;
	}
	const utilBufferParser = makeBufferParser();
	module.exports = {
		bufferCopy,
		bufferSlice,
		FastBuffer,
		bufferFill: (buf, value, start, end) => {
			return TypedArrayFill.call(buf, value, start, end);
		},
		makeError,
		doFatalError: (protocol, msg, level, reason) => {
			let err;
			if (DISCONNECT_REASON === void 0) ({DISCONNECT_REASON} = require_constants());
			if (msg instanceof Error) {
				err = msg;
				if (typeof level !== "number") reason = DISCONNECT_REASON.PROTOCOL_ERROR;
				else reason = level;
			} else err = makeError(msg, level, true);
			if (typeof reason !== "number") reason = DISCONNECT_REASON.PROTOCOL_ERROR;
			protocol.disconnect(reason);
			protocol._destruct();
			protocol._onError(err);
			return Infinity;
		},
		readUInt32BE,
		writeUInt32BE,
		writeUInt32LE: (buf, value, offset) => {
			buf[offset++] = value;
			buf[offset++] = value >>> 8;
			buf[offset++] = value >>> 16;
			buf[offset++] = value >>> 24;
			return offset;
		},
		makeBufferParser,
		bufferParser: makeBufferParser(),
		readString: (buffer, start, dest, maxLen) => {
			if (typeof dest === "number") {
				maxLen = dest;
				dest = void 0;
			}
			if (start === void 0) start = 0;
			const left = buffer.length - start;
			if (start < 0 || start >= buffer.length || left < 4) return;
			const len = readUInt32BE(buffer, start);
			if (left < 4 + len || typeof maxLen === "number" && len > maxLen) return;
			start += 4;
			const end = start + len;
			buffer._pos = end;
			if (dest) {
				if (Buffer.isBuffer(dest)) return bufferCopy(buffer, dest, start, end);
				return buffer.utf8Slice(start, end);
			}
			return bufferSlice(buffer, start, end);
		},
		sigSSHToASN1: (sig, type) => {
			switch (type) {
				case "ssh-dss": {
					if (sig.length > 40) return sig;
					const asnWriter = new Ber.Writer();
					asnWriter.startSequence();
					let r = sig.slice(0, 20);
					let s = sig.slice(20);
					if (r[0] & 128) {
						const rNew = Buffer.allocUnsafe(21);
						rNew[0] = 0;
						r.copy(rNew, 1);
						r = rNew;
					} else if (r[0] === 0 && !(r[1] & 128)) r = r.slice(1);
					if (s[0] & 128) {
						const sNew = Buffer.allocUnsafe(21);
						sNew[0] = 0;
						s.copy(sNew, 1);
						s = sNew;
					} else if (s[0] === 0 && !(s[1] & 128)) s = s.slice(1);
					asnWriter.writeBuffer(r, Ber.Integer);
					asnWriter.writeBuffer(s, Ber.Integer);
					asnWriter.endSequence();
					return asnWriter.buffer;
				}
				case "ecdsa-sha2-nistp256":
				case "ecdsa-sha2-nistp384":
				case "ecdsa-sha2-nistp521": {
					utilBufferParser.init(sig, 0);
					const r = utilBufferParser.readString();
					const s = utilBufferParser.readString();
					utilBufferParser.clear();
					if (r === void 0 || s === void 0) return;
					const asnWriter = new Ber.Writer();
					asnWriter.startSequence();
					asnWriter.writeBuffer(r, Ber.Integer);
					asnWriter.writeBuffer(s, Ber.Integer);
					asnWriter.endSequence();
					return asnWriter.buffer;
				}
				default: return sig;
			}
		},
		convertSignature: (signature, keyType) => {
			switch (keyType) {
				case "ssh-dss": {
					if (signature.length <= 40) return signature;
					const asnReader = new Ber.Reader(signature);
					asnReader.readSequence();
					let r = asnReader.readString(Ber.Integer, true);
					let s = asnReader.readString(Ber.Integer, true);
					let rOffset = 0;
					let sOffset = 0;
					if (r.length < 20) {
						const rNew = Buffer.allocUnsafe(20);
						rNew.set(r, 1);
						r = rNew;
						r[0] = 0;
					}
					if (s.length < 20) {
						const sNew = Buffer.allocUnsafe(20);
						sNew.set(s, 1);
						s = sNew;
						s[0] = 0;
					}
					if (r.length > 20 && r[0] === 0) rOffset = 1;
					if (s.length > 20 && s[0] === 0) sOffset = 1;
					const newSig = Buffer.allocUnsafe(r.length - rOffset + (s.length - sOffset));
					bufferCopy(r, newSig, rOffset, r.length, 0);
					bufferCopy(s, newSig, sOffset, s.length, r.length - rOffset);
					return newSig;
				}
				case "ecdsa-sha2-nistp256":
				case "ecdsa-sha2-nistp384":
				case "ecdsa-sha2-nistp521": {
					if (signature[0] === 0) return signature;
					const asnReader = new Ber.Reader(signature);
					asnReader.readSequence();
					const r = asnReader.readString(Ber.Integer, true);
					const s = asnReader.readString(Ber.Integer, true);
					if (r === null || s === null) return;
					const newSig = Buffer.allocUnsafe(4 + r.length + 4 + s.length);
					writeUInt32BE(newSig, r.length, 0);
					newSig.set(r, 4);
					writeUInt32BE(newSig, s.length, 4 + r.length);
					newSig.set(s, 8 + r.length);
					return newSig;
				}
			}
			return signature;
		},
		sendPacket: (proto, packet, bypass) => {
			if (!bypass && proto._kexinit !== void 0) {
				if (proto._queue === void 0) proto._queue = [];
				proto._queue.push(packet);
				proto._debug && proto._debug("Outbound: ... packet queued");
				return false;
			}
			proto._cipher.encrypt(packet);
			return true;
		}
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/crypto/poly1305.js
var require_poly1305 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var createPoly1305 = (function() {
		var _scriptDir = typeof document !== "undefined" && document.currentScript ? document.currentScript.src : void 0;
		if (typeof __filename !== "undefined") _scriptDir = _scriptDir || __filename;
		return (function(createPoly1305) {
			createPoly1305 = createPoly1305 || {};
			var b;
			b || (b = typeof createPoly1305 !== "undefined" ? createPoly1305 : {});
			var q, r;
			b.ready = new Promise(function(a, c) {
				q = a;
				r = c;
			});
			var u = {}, w;
			for (w in b) b.hasOwnProperty(w) && (u[w] = b[w]);
			var x = "object" === typeof window, y = "function" === typeof importScripts, z = "object" === typeof process && "object" === typeof process.versions && "string" === typeof process.versions.node, B = "", C, D, E, F, G;
			if (z) B = y ? __require("path").dirname(B) + "/" : __dirname + "/", C = function(a, c) {
				var d = H(a);
				if (d) return c ? d : d.toString();
				F || (F = __require("fs"));
				G || (G = __require("path"));
				a = G.normalize(a);
				return F.readFileSync(a, c ? null : "utf8");
			}, E = function(a) {
				a = C(a, !0);
				a.buffer || (a = new Uint8Array(a));
				assert(a.buffer);
				return a;
			}, D = function(a, c, d) {
				var e = H(a);
				e && c(e);
				F || (F = __require("fs"));
				G || (G = __require("path"));
				a = G.normalize(a);
				F.readFile(a, function(f, l) {
					f ? d(f) : c(l.buffer);
				});
			}, 1 < process.argv.length && process.argv[1].replace(/\\/g, "/"), process.argv.slice(2), b.inspect = function() {
				return "[Emscripten Module object]";
			};
			else if (x || y) y ? B = self.location.href : "undefined" !== typeof document && document.currentScript && (B = document.currentScript.src), _scriptDir && (B = _scriptDir), 0 !== B.indexOf("blob:") ? B = B.substr(0, B.lastIndexOf("/") + 1) : B = "", C = function(a) {
				try {
					var c = new XMLHttpRequest();
					c.open("GET", a, !1);
					c.send(null);
					return c.responseText;
				} catch (f) {
					if (a = H(a)) {
						c = [];
						for (var d = 0; d < a.length; d++) {
							var e = a[d];
							255 < e && (ba && assert(!1, "Character code " + e + " (" + String.fromCharCode(e) + ")  at offset " + d + " not in 0x00-0xFF."), e &= 255);
							c.push(String.fromCharCode(e));
						}
						return c.join("");
					}
					throw f;
				}
			}, y && (E = function(a) {
				try {
					var c = new XMLHttpRequest();
					c.open("GET", a, !1);
					c.responseType = "arraybuffer";
					c.send(null);
					return new Uint8Array(c.response);
				} catch (d) {
					if (a = H(a)) return a;
					throw d;
				}
			}), D = function(a, c, d) {
				var e = new XMLHttpRequest();
				e.open("GET", a, !0);
				e.responseType = "arraybuffer";
				e.onload = function() {
					if (200 == e.status || 0 == e.status && e.response) c(e.response);
					else {
						var f = H(a);
						f ? c(f.buffer) : d();
					}
				};
				e.onerror = d;
				e.send(null);
			};
			b.print || console.log.bind(console);
			var I = b.printErr || console.warn.bind(console);
			for (w in u) u.hasOwnProperty(w) && (b[w] = u[w]);
			u = null;
			var J;
			b.wasmBinary && (J = b.wasmBinary);
			b.noExitRuntime;
			"object" !== typeof WebAssembly && K("no native wasm support detected");
			var L, M = !1;
			function assert(a, c) {
				a || K("Assertion failed: " + c);
			}
			function N(a) {
				var c = b["_" + a];
				assert(c, "Cannot call unknown function " + a + ", make sure it is exported");
				return c;
			}
			function ca(a, c, d, e) {
				var f = {
					string: function(g) {
						var p = 0;
						if (null !== g && void 0 !== g && 0 !== g) {
							var n = (g.length << 2) + 1;
							p = O(n);
							var k = p, h = P;
							if (0 < n) {
								n = k + n - 1;
								for (var v = 0; v < g.length; ++v) {
									var m = g.charCodeAt(v);
									if (55296 <= m && 57343 >= m) {
										var oa = g.charCodeAt(++v);
										m = 65536 + ((m & 1023) << 10) | oa & 1023;
									}
									if (127 >= m) {
										if (k >= n) break;
										h[k++] = m;
									} else {
										if (2047 >= m) {
											if (k + 1 >= n) break;
											h[k++] = 192 | m >> 6;
										} else {
											if (65535 >= m) {
												if (k + 2 >= n) break;
												h[k++] = 224 | m >> 12;
											} else {
												if (k + 3 >= n) break;
												h[k++] = 240 | m >> 18;
												h[k++] = 128 | m >> 12 & 63;
											}
											h[k++] = 128 | m >> 6 & 63;
										}
										h[k++] = 128 | m & 63;
									}
								}
								h[k] = 0;
							}
						}
						return p;
					},
					array: function(g) {
						var p = O(g.length);
						Q.set(g, p);
						return p;
					}
				}, l = N(a), A = [];
				a = 0;
				if (e) for (var t = 0; t < e.length; t++) {
					var aa = f[d[t]];
					aa ? (0 === a && (a = da()), A[t] = aa(e[t])) : A[t] = e[t];
				}
				d = l.apply(null, A);
				d = function(g) {
					if ("string" === c) if (g) {
						for (var p = P, n = g + NaN, k = g; p[k] && !(k >= n);) ++k;
						if (16 < k - g && p.subarray && ea) g = ea.decode(p.subarray(g, k));
						else {
							for (n = ""; g < k;) {
								var h = p[g++];
								if (h & 128) {
									var v = p[g++] & 63;
									if (192 == (h & 224)) n += String.fromCharCode((h & 31) << 6 | v);
									else {
										var m = p[g++] & 63;
										h = 224 == (h & 240) ? (h & 15) << 12 | v << 6 | m : (h & 7) << 18 | v << 12 | m << 6 | p[g++] & 63;
										65536 > h ? n += String.fromCharCode(h) : (h -= 65536, n += String.fromCharCode(55296 | h >> 10, 56320 | h & 1023));
									}
								} else n += String.fromCharCode(h);
							}
							g = n;
						}
					} else g = "";
					else g = "boolean" === c ? !!g : g;
					return g;
				}(d);
				0 !== a && fa(a);
				return d;
			}
			var ea = "undefined" !== typeof TextDecoder ? new TextDecoder("utf8") : void 0, ha, Q, P;
			function ia() {
				var a = L.buffer;
				ha = a;
				b.HEAP8 = Q = new Int8Array(a);
				b.HEAP16 = new Int16Array(a);
				b.HEAP32 = new Int32Array(a);
				b.HEAPU8 = P = new Uint8Array(a);
				b.HEAPU16 = new Uint16Array(a);
				b.HEAPU32 = new Uint32Array(a);
				b.HEAPF32 = new Float32Array(a);
				b.HEAPF64 = new Float64Array(a);
			}
			var R, ja = [], ka = [], la = [];
			function ma() {
				var a = b.preRun.shift();
				ja.unshift(a);
			}
			var S = 0, T = null, U = null;
			b.preloadedImages = {};
			b.preloadedAudios = {};
			function K(a) {
				if (b.onAbort) b.onAbort(a);
				I(a);
				M = !0;
				a = new WebAssembly.RuntimeError("abort(" + a + "). Build with -s ASSERTIONS=1 for more info.");
				r(a);
				throw a;
			}
			var V = "data:application/octet-stream;base64,", W = "data:application/octet-stream;base64,AGFzbQEAAAABIAZgAX8Bf2ADf39/AGABfwBgAABgAAF/YAZ/f39/f38AAgcBAWEBYQAAAwsKAAEDAQAAAgQFAgQFAXABAQEFBwEBgAKAgAIGCQF/AUGAjMACCwclCQFiAgABYwADAWQACQFlAAgBZgAHAWcABgFoAAUBaQAKAWoBAAqGTQpPAQJ/QYAIKAIAIgEgAEEDakF8cSICaiEAAkAgAkEAIAAgAU0bDQAgAD8AQRB0SwRAIAAQAEUNAQtBgAggADYCACABDwtBhAhBMDYCAEF/C4wFAg5+Cn8gACgCJCEUIAAoAiAhFSAAKAIcIREgACgCGCESIAAoAhQhEyACQRBPBEAgAC0ATEVBGHQhFyAAKAIEIhZBBWytIQ8gACgCCCIYQQVsrSENIAAoAgwiGUEFbK0hCyAAKAIQIhpBBWytIQkgADUCACEIIBqtIRAgGa0hDiAYrSEMIBatIQoDQCASIAEtAAMiEiABLQAEQQh0ciABLQAFQRB0ciABLQAGIhZBGHRyQQJ2Qf///x9xaq0iAyAOfiABLwAAIAEtAAJBEHRyIBNqIBJBGHRBgICAGHFqrSIEIBB+fCARIAEtAAdBCHQgFnIgAS0ACEEQdHIgAS0ACSIRQRh0ckEEdkH///8fcWqtIgUgDH58IAEtAApBCHQgEXIgAS0AC0EQdHIgAS0ADEEYdHJBBnYgFWqtIgYgCn58IBQgF2ogAS8ADSABLQAPQRB0cmqtIgcgCH58IAMgDH4gBCAOfnwgBSAKfnwgBiAIfnwgByAJfnwgAyAKfiAEIAx+fCAFIAh+fCAGIAl+fCAHIAt+fCADIAh+IAQgCn58IAUgCX58IAYgC358IAcgDX58IAMgCX4gBCAIfnwgBSALfnwgBiANfnwgByAPfnwiA0IaiEL/////D4N8IgRCGohC/////w+DfCIFQhqIQv////8Pg3wiBkIaiEL/////D4N8IgdCGoinQQVsIAOnQf///x9xaiITQRp2IASnQf///x9xaiESIAWnQf///x9xIREgBqdB////H3EhFSAHp0H///8fcSEUIBNB////H3EhEyABQRBqIQEgAkEQayICQQ9LDQALCyAAIBQ2AiQgACAVNgIgIAAgETYCHCAAIBI2AhggACATNgIUCwMAAQu2BAEGfwJAIAAoAjgiBARAIABBPGohBQJAIAJBECAEayIDIAIgA0kbIgZFDQAgBkEDcSEHAkAgBkEBa0EDSQRAQQAhAwwBCyAGQXxxIQhBACEDA0AgBSADIARqaiABIANqLQAAOgAAIAUgA0EBciIEIAAoAjhqaiABIARqLQAAOgAAIAUgA0ECciIEIAAoAjhqaiABIARqLQAAOgAAIAUgA0EDciIEIAAoAjhqaiABIARqLQAAOgAAIANBBGohAyAAKAI4IQQgCEEEayIIDQALCyAHRQ0AA0AgBSADIARqaiABIANqLQAAOgAAIANBAWohAyAAKAI4IQQgB0EBayIHDQALCyAAIAQgBmoiAzYCOCADQRBJDQEgACAFQRAQAiAAQQA2AjggAiAGayECIAEgBmohAQsgAkEQTwRAIAAgASACQXBxIgMQAiACQQ9xIQIgASADaiEBCyACRQ0AIAJBA3EhBCAAQTxqIQVBACEDIAJBAWtBA08EQCACQXxxIQcDQCAFIAAoAjggA2pqIAEgA2otAAA6AAAgBSADQQFyIgYgACgCOGpqIAEgBmotAAA6AAAgBSADQQJyIgYgACgCOGpqIAEgBmotAAA6AAAgBSADQQNyIgYgACgCOGpqIAEgBmotAAA6AAAgA0EEaiEDIAdBBGsiBw0ACwsgBARAA0AgBSAAKAI4IANqaiABIANqLQAAOgAAIANBAWohAyAEQQFrIgQNAAsLIAAgACgCOCACajYCOAsLoS0BDH8jAEEQayIMJAACQAJAAkACQAJAAkACQAJAAkACQAJAAkAgAEH0AU0EQEGICCgCACIFQRAgAEELakF4cSAAQQtJGyIIQQN2IgJ2IgFBA3EEQCABQX9zQQFxIAJqIgNBA3QiAUG4CGooAgAiBEEIaiEAAkAgBCgCCCICIAFBsAhqIgFGBEBBiAggBUF+IAN3cTYCAAwBCyACIAE2AgwgASACNgIICyAEIANBA3QiAUEDcjYCBCABIARqIgEgASgCBEEBcjYCBAwNCyAIQZAIKAIAIgpNDQEgAQRAAkBBAiACdCIAQQAgAGtyIAEgAnRxIgBBACAAa3FBAWsiACAAQQx2QRBxIgJ2IgFBBXZBCHEiACACciABIAB2IgFBAnZBBHEiAHIgASAAdiIBQQF2QQJxIgByIAEgAHYiAUEBdkEBcSIAciABIAB2aiIDQQN0IgBBuAhqKAIAIgQoAggiASAAQbAIaiIARgRAQYgIIAVBfiADd3EiBTYCAAwBCyABIAA2AgwgACABNgIICyAEQQhqIQAgBCAIQQNyNgIEIAQgCGoiAiADQQN0IgEgCGsiA0EBcjYCBCABIARqIAM2AgAgCgRAIApBA3YiAUEDdEGwCGohB0GcCCgCACEEAn8gBUEBIAF0IgFxRQRAQYgIIAEgBXI2AgAgBwwBCyAHKAIICyEBIAcgBDYCCCABIAQ2AgwgBCAHNgIMIAQgATYCCAtBnAggAjYCAEGQCCADNgIADA0LQYwIKAIAIgZFDQEgBkEAIAZrcUEBayIAIABBDHZBEHEiAnYiAUEFdkEIcSIAIAJyIAEgAHYiAUECdkEEcSIAciABIAB2IgFBAXZBAnEiAHIgASAAdiIBQQF2QQFxIgByIAEgAHZqQQJ0QbgKaigCACIBKAIEQXhxIAhrIQMgASECA0ACQCACKAIQIgBFBEAgAigCFCIARQ0BCyAAKAIEQXhxIAhrIgIgAyACIANJIgIbIQMgACABIAIbIQEgACECDAELCyABIAhqIgkgAU0NAiABKAIYIQsgASABKAIMIgRHBEAgASgCCCIAQZgIKAIASRogACAENgIMIAQgADYCCAwMCyABQRRqIgIoAgAiAEUEQCABKAIQIgBFDQQgAUEQaiECCwNAIAIhByAAIgRBFGoiAigCACIADQAgBEEQaiECIAQoAhAiAA0ACyAHQQA2AgAMCwtBfyEIIABBv39LDQAgAEELaiIAQXhxIQhBjAgoAgAiCUUNAEEAIAhrIQMCQAJAAkACf0EAIAhBgAJJDQAaQR8gCEH///8HSw0AGiAAQQh2IgAgAEGA/j9qQRB2QQhxIgJ0IgAgAEGA4B9qQRB2QQRxIgF0IgAgAEGAgA9qQRB2QQJxIgB0QQ92IAEgAnIgAHJrIgBBAXQgCCAAQRVqdkEBcXJBHGoLIgVBAnRBuApqKAIAIgJFBEBBACEADAELQQAhACAIQQBBGSAFQQF2ayAFQR9GG3QhAQNAAkAgAigCBEF4cSAIayIHIANPDQAgAiEEIAciAw0AQQAhAyACIQAMAwsgACACKAIUIgcgByACIAFBHXZBBHFqKAIQIgJGGyAAIAcbIQAgAUEBdCEBIAINAAsLIAAgBHJFBEBBACEEQQIgBXQiAEEAIABrciAJcSIARQ0DIABBACAAa3FBAWsiACAAQQx2QRBxIgJ2IgFBBXZBCHEiACACciABIAB2IgFBAnZBBHEiAHIgASAAdiIBQQF2QQJxIgByIAEgAHYiAUEBdkEBcSIAciABIAB2akECdEG4CmooAgAhAAsgAEUNAQsDQCAAKAIEQXhxIAhrIgEgA0khAiABIAMgAhshAyAAIAQgAhshBCAAKAIQIgEEfyABBSAAKAIUCyIADQALCyAERQ0AIANBkAgoAgAgCGtPDQAgBCAIaiIGIARNDQEgBCgCGCEFIAQgBCgCDCIBRwRAIAQoAggiAEGYCCgCAEkaIAAgATYCDCABIAA2AggMCgsgBEEUaiICKAIAIgBFBEAgBCgCECIARQ0EIARBEGohAgsDQCACIQcgACIBQRRqIgIoAgAiAA0AIAFBEGohAiABKAIQIgANAAsgB0EANgIADAkLIAhBkAgoAgAiAk0EQEGcCCgCACEDAkAgAiAIayIBQRBPBEBBkAggATYCAEGcCCADIAhqIgA2AgAgACABQQFyNgIEIAIgA2ogATYCACADIAhBA3I2AgQMAQtBnAhBADYCAEGQCEEANgIAIAMgAkEDcjYCBCACIANqIgAgACgCBEEBcjYCBAsgA0EIaiEADAsLIAhBlAgoAgAiBkkEQEGUCCAGIAhrIgE2AgBBoAhBoAgoAgAiAiAIaiIANgIAIAAgAUEBcjYCBCACIAhBA3I2AgQgAkEIaiEADAsLQQAhACAIQS9qIgkCf0HgCygCAARAQegLKAIADAELQewLQn83AgBB5AtCgKCAgICABDcCAEHgCyAMQQxqQXBxQdiq1aoFczYCAEH0C0EANgIAQcQLQQA2AgBBgCALIgFqIgVBACABayIHcSICIAhNDQpBwAsoAgAiBARAQbgLKAIAIgMgAmoiASADTQ0LIAEgBEsNCwtBxAstAABBBHENBQJAAkBBoAgoAgAiAwRAQcgLIQADQCADIAAoAgAiAU8EQCABIAAoAgRqIANLDQMLIAAoAggiAA0ACwtBABABIgFBf0YNBiACIQVB5AsoAgAiA0EBayIAIAFxBEAgAiABayAAIAFqQQAgA2txaiEFCyAFIAhNDQYgBUH+////B0sNBkHACygCACIEBEBBuAsoAgAiAyAFaiIAIANNDQcgACAESw0HCyAFEAEiACABRw0BDAgLIAUgBmsgB3EiBUH+////B0sNBSAFEAEiASAAKAIAIAAoAgRqRg0EIAEhAAsCQCAAQX9GDQAgCEEwaiAFTQ0AQegLKAIAIgEgCSAFa2pBACABa3EiAUH+////B0sEQCAAIQEMCAsgARABQX9HBEAgASAFaiEFIAAhAQwIC0EAIAVrEAEaDAULIAAiAUF/Rw0GDAQLAAtBACEEDAcLQQAhAQwFCyABQX9HDQILQcQLQcQLKAIAQQRyNgIACyACQf7///8HSw0BIAIQASEBQQAQASEAIAFBf0YNASAAQX9GDQEgACABTQ0BIAAgAWsiBSAIQShqTQ0BC0G4C0G4CygCACAFaiIANgIAQbwLKAIAIABJBEBBvAsgADYCAAsCQAJAAkBBoAgoAgAiBwRAQcgLIQADQCABIAAoAgAiAyAAKAIEIgJqRg0CIAAoAggiAA0ACwwCC0GYCCgCACIAQQAgACABTRtFBEBBmAggATYCAAtBACEAQcwLIAU2AgBByAsgATYCAEGoCEF/NgIAQawIQeALKAIANgIAQdQLQQA2AgADQCAAQQN0IgNBuAhqIANBsAhqIgI2AgAgA0G8CGogAjYCACAAQQFqIgBBIEcNAAtBlAggBUEoayIDQXggAWtBB3FBACABQQhqQQdxGyIAayICNgIAQaAIIAAgAWoiADYCACAAIAJBAXI2AgQgASADakEoNgIEQaQIQfALKAIANgIADAILIAAtAAxBCHENACADIAdLDQAgASAHTQ0AIAAgAiAFajYCBEGgCCAHQXggB2tBB3FBACAHQQhqQQdxGyIAaiICNgIAQZQIQZQIKAIAIAVqIgEgAGsiADYCACACIABBAXI2AgQgASAHakEoNgIEQaQIQfALKAIANgIADAELQZgIKAIAIAFLBEBBmAggATYCAAsgASAFaiECQcgLIQACQAJAAkACQAJAAkADQCACIAAoAgBHBEAgACgCCCIADQEMAgsLIAAtAAxBCHFFDQELQcgLIQADQCAHIAAoAgAiAk8EQCACIAAoAgRqIgQgB0sNAwsgACgCCCEADAALAAsgACABNgIAIAAgACgCBCAFajYCBCABQXggAWtBB3FBACABQQhqQQdxG2oiCSAIQQNyNgIEIAJBeCACa0EHcUEAIAJBCGpBB3EbaiIFIAggCWoiBmshAiAFIAdGBEBBoAggBjYCAEGUCEGUCCgCACACaiIANgIAIAYgAEEBcjYCBAwDCyAFQZwIKAIARgRAQZwIIAY2AgBBkAhBkAgoAgAgAmoiADYCACAGIABBAXI2AgQgACAGaiAANgIADAMLIAUoAgQiAEEDcUEBRgRAIABBeHEhBwJAIABB/wFNBEAgBSgCCCIDIABBA3YiAEEDdEGwCGpGGiADIAUoAgwiAUYEQEGICEGICCgCAEF+IAB3cTYCAAwCCyADIAE2AgwgASADNgIIDAELIAUoAhghCAJAIAUgBSgCDCIBRwRAIAUoAggiACABNgIMIAEgADYCCAwBCwJAIAVBFGoiACgCACIDDQAgBUEQaiIAKAIAIgMNAEEAIQEMAQsDQCAAIQQgAyIBQRRqIgAoAgAiAw0AIAFBEGohACABKAIQIgMNAAsgBEEANgIACyAIRQ0AAkAgBSAFKAIcIgNBAnRBuApqIgAoAgBGBEAgACABNgIAIAENAUGMCEGMCCgCAEF+IAN3cTYCAAwCCyAIQRBBFCAIKAIQIAVGG2ogATYCACABRQ0BCyABIAg2AhggBSgCECIABEAgASAANgIQIAAgATYCGAsgBSgCFCIARQ0AIAEgADYCFCAAIAE2AhgLIAUgB2ohBSACIAdqIQILIAUgBSgCBEF+cTYCBCAGIAJBAXI2AgQgAiAGaiACNgIAIAJB/wFNBEAgAkEDdiIAQQN0QbAIaiECAn9BiAgoAgAiAUEBIAB0IgBxRQRAQYgIIAAgAXI2AgAgAgwBCyACKAIICyEAIAIgBjYCCCAAIAY2AgwgBiACNgIMIAYgADYCCAwDC0EfIQAgAkH///8HTQRAIAJBCHYiACAAQYD+P2pBEHZBCHEiA3QiACAAQYDgH2pBEHZBBHEiAXQiACAAQYCAD2pBEHZBAnEiAHRBD3YgASADciAAcmsiAEEBdCACIABBFWp2QQFxckEcaiEACyAGIAA2AhwgBkIANwIQIABBAnRBuApqIQQCQEGMCCgCACIDQQEgAHQiAXFFBEBBjAggASADcjYCACAEIAY2AgAgBiAENgIYDAELIAJBAEEZIABBAXZrIABBH0YbdCEAIAQoAgAhAQNAIAEiAygCBEF4cSACRg0DIABBHXYhASAAQQF0IQAgAyABQQRxaiIEKAIQIgENAAsgBCAGNgIQIAYgAzYCGAsgBiAGNgIMIAYgBjYCCAwCC0GUCCAFQShrIgNBeCABa0EHcUEAIAFBCGpBB3EbIgBrIgI2AgBBoAggACABaiIANgIAIAAgAkEBcjYCBCABIANqQSg2AgRBpAhB8AsoAgA2AgAgByAEQScgBGtBB3FBACAEQSdrQQdxG2pBL2siACAAIAdBEGpJGyICQRs2AgQgAkHQCykCADcCECACQcgLKQIANwIIQdALIAJBCGo2AgBBzAsgBTYCAEHICyABNgIAQdQLQQA2AgAgAkEYaiEAA0AgAEEHNgIEIABBCGohASAAQQRqIQAgASAESQ0ACyACIAdGDQMgAiACKAIEQX5xNgIEIAcgAiAHayIEQQFyNgIEIAIgBDYCACAEQf8BTQRAIARBA3YiAEEDdEGwCGohAgJ/QYgIKAIAIgFBASAAdCIAcUUEQEGICCAAIAFyNgIAIAIMAQsgAigCCAshACACIAc2AgggACAHNgIMIAcgAjYCDCAHIAA2AggMBAtBHyEAIAdCADcCECAEQf///wdNBEAgBEEIdiIAIABBgP4/akEQdkEIcSICdCIAIABBgOAfakEQdkEEcSIBdCIAIABBgIAPakEQdkECcSIAdEEPdiABIAJyIAByayIAQQF0IAQgAEEVanZBAXFyQRxqIQALIAcgADYCHCAAQQJ0QbgKaiEDAkBBjAgoAgAiAkEBIAB0IgFxRQRAQYwIIAEgAnI2AgAgAyAHNgIAIAcgAzYCGAwBCyAEQQBBGSAAQQF2ayAAQR9GG3QhACADKAIAIQEDQCABIgIoAgRBeHEgBEYNBCAAQR12IQEgAEEBdCEAIAIgAUEEcWoiAygCECIBDQALIAMgBzYCECAHIAI2AhgLIAcgBzYCDCAHIAc2AggMAwsgAygCCCIAIAY2AgwgAyAGNgIIIAZBADYCGCAGIAM2AgwgBiAANgIICyAJQQhqIQAMBQsgAigCCCIAIAc2AgwgAiAHNgIIIAdBADYCGCAHIAI2AgwgByAANgIIC0GUCCgCACIAIAhNDQBBlAggACAIayIBNgIAQaAIQaAIKAIAIgIgCGoiADYCACAAIAFBAXI2AgQgAiAIQQNyNgIEIAJBCGohAAwDC0GECEEwNgIAQQAhAAwCCwJAIAVFDQACQCAEKAIcIgJBAnRBuApqIgAoAgAgBEYEQCAAIAE2AgAgAQ0BQYwIIAlBfiACd3EiCTYCAAwCCyAFQRBBFCAFKAIQIARGG2ogATYCACABRQ0BCyABIAU2AhggBCgCECIABEAgASAANgIQIAAgATYCGAsgBCgCFCIARQ0AIAEgADYCFCAAIAE2AhgLAkAgA0EPTQRAIAQgAyAIaiIAQQNyNgIEIAAgBGoiACAAKAIEQQFyNgIEDAELIAQgCEEDcjYCBCAGIANBAXI2AgQgAyAGaiADNgIAIANB/wFNBEAgA0EDdiIAQQN0QbAIaiECAn9BiAgoAgAiAUEBIAB0IgBxRQRAQYgIIAAgAXI2AgAgAgwBCyACKAIICyEAIAIgBjYCCCAAIAY2AgwgBiACNgIMIAYgADYCCAwBC0EfIQAgA0H///8HTQRAIANBCHYiACAAQYD+P2pBEHZBCHEiAnQiACAAQYDgH2pBEHZBBHEiAXQiACAAQYCAD2pBEHZBAnEiAHRBD3YgASACciAAcmsiAEEBdCADIABBFWp2QQFxckEcaiEACyAGIAA2AhwgBkIANwIQIABBAnRBuApqIQICQAJAIAlBASAAdCIBcUUEQEGMCCABIAlyNgIAIAIgBjYCACAGIAI2AhgMAQsgA0EAQRkgAEEBdmsgAEEfRht0IQAgAigCACEIA0AgCCIBKAIEQXhxIANGDQIgAEEddiECIABBAXQhACABIAJBBHFqIgIoAhAiCA0ACyACIAY2AhAgBiABNgIYCyAGIAY2AgwgBiAGNgIIDAELIAEoAggiACAGNgIMIAEgBjYCCCAGQQA2AhggBiABNgIMIAYgADYCCAsgBEEIaiEADAELAkAgC0UNAAJAIAEoAhwiAkECdEG4CmoiACgCACABRgRAIAAgBDYCACAEDQFBjAggBkF+IAJ3cTYCAAwCCyALQRBBFCALKAIQIAFGG2ogBDYCACAERQ0BCyAEIAs2AhggASgCECIABEAgBCAANgIQIAAgBDYCGAsgASgCFCIARQ0AIAQgADYCFCAAIAQ2AhgLAkAgA0EPTQRAIAEgAyAIaiIAQQNyNgIEIAAgAWoiACAAKAIEQQFyNgIEDAELIAEgCEEDcjYCBCAJIANBAXI2AgQgAyAJaiADNgIAIAoEQCAKQQN2IgBBA3RBsAhqIQRBnAgoAgAhAgJ/QQEgAHQiACAFcUUEQEGICCAAIAVyNgIAIAQMAQsgBCgCCAshACAEIAI2AgggACACNgIMIAIgBDYCDCACIAA2AggLQZwIIAk2AgBBkAggAzYCAAsgAUEIaiEACyAMQRBqJAAgAAsQACMAIABrQXBxIgAkACAACwYAIAAkAAsEACMAC4AJAgh/BH4jAEGQAWsiBiQAIAYgBS0AA0EYdEGAgIAYcSAFLwAAIAUtAAJBEHRycjYCACAGIAUoAANBAnZBg/7/H3E2AgQgBiAFKAAGQQR2Qf+B/x9xNgIIIAYgBSgACUEGdkH//8AfcTYCDCAFLwANIQggBS0ADyEJIAZCADcCFCAGQgA3AhwgBkEANgIkIAYgCCAJQRB0QYCAPHFyNgIQIAYgBSgAEDYCKCAGIAUoABQ2AiwgBiAFKAAYNgIwIAUoABwhBSAGQQA6AEwgBkEANgI4IAYgBTYCNCAGIAEgAhAEIAQEQCAGIAMgBBAECyAGKAI4IgEEQCAGQTxqIgIgAWpBAToAACABQQFqQQ9NBEAgASAGakE9aiEEAkBBDyABayIDRQ0AIAMgBGoiAUEBa0EAOgAAIARBADoAACADQQNJDQAgAUECa0EAOgAAIARBADoAASABQQNrQQA6AAAgBEEAOgACIANBB0kNACABQQRrQQA6AAAgBEEAOgADIANBCUkNACAEQQAgBGtBA3EiAWoiBEEANgIAIAQgAyABa0F8cSIBaiIDQQRrQQA2AgAgAUEJSQ0AIARBADYCCCAEQQA2AgQgA0EIa0EANgIAIANBDGtBADYCACABQRlJDQAgBEEANgIYIARBADYCFCAEQQA2AhAgBEEANgIMIANBEGtBADYCACADQRRrQQA2AgAgA0EYa0EANgIAIANBHGtBADYCACABIARBBHFBGHIiAWsiA0EgSQ0AIAEgBGohAQNAIAFCADcDGCABQgA3AxAgAUIANwMIIAFCADcDACABQSBqIQEgA0EgayIDQR9LDQALCwsgBkEBOgBMIAYgAkEQEAILIAY1AjQhECAGNQIwIREgBjUCLCEOIAAgBjUCKCAGKAIkIAYoAiAgBigCHCAGKAIYIgNBGnZqIgJBGnZqIgFBGnZqIgtBgICAYHIgAUH///8fcSINIAJB////H3EiCCAGKAIUIAtBGnZBBWxqIgFB////H3EiCUEFaiIFQRp2IANB////H3EgAUEadmoiA2oiAUEadmoiAkEadmoiBEEadmoiDEEfdSIHIANxIAEgDEEfdkEBayIDQf///x9xIgpxciIBQRp0IAUgCnEgByAJcXJyrXwiDzwAACAAIA9CGIg8AAMgACAPQhCIPAACIAAgD0IIiDwAASAAIA4gByAIcSACIApxciICQRR0IAFBBnZyrXwgD0IgiHwiDjwABCAAIA5CGIg8AAcgACAOQhCIPAAGIAAgDkIIiDwABSAAIBEgByANcSAEIApxciIBQQ50IAJBDHZyrXwgDkIgiHwiDjwACCAAIA5CGIg8AAsgACAOQhCIPAAKIAAgDkIIiDwACSAAIBAgAyAMcSAHIAtxckEIdCABQRJ2cq18IA5CIIh8Ig48AAwgACAOQhiIPAAPIAAgDkIQiDwADiAAIA5CCIg8AA0gBkIANwIwIAZCADcCKCAGQgA3AiAgBkIANwIYIAZCADcCECAGQgA3AgggBkIANwIAIAZBkAFqJAALpwwBB38CQCAARQ0AIABBCGsiAyAAQQRrKAIAIgFBeHEiAGohBQJAIAFBAXENACABQQNxRQ0BIAMgAygCACIBayIDQZgIKAIASQ0BIAAgAWohACADQZwIKAIARwRAIAFB/wFNBEAgAygCCCICIAFBA3YiBEEDdEGwCGpGGiACIAMoAgwiAUYEQEGICEGICCgCAEF+IAR3cTYCAAwDCyACIAE2AgwgASACNgIIDAILIAMoAhghBgJAIAMgAygCDCIBRwRAIAMoAggiAiABNgIMIAEgAjYCCAwBCwJAIANBFGoiAigCACIEDQAgA0EQaiICKAIAIgQNAEEAIQEMAQsDQCACIQcgBCIBQRRqIgIoAgAiBA0AIAFBEGohAiABKAIQIgQNAAsgB0EANgIACyAGRQ0BAkAgAyADKAIcIgJBAnRBuApqIgQoAgBGBEAgBCABNgIAIAENAUGMCEGMCCgCAEF+IAJ3cTYCAAwDCyAGQRBBFCAGKAIQIANGG2ogATYCACABRQ0CCyABIAY2AhggAygCECICBEAgASACNgIQIAIgATYCGAsgAygCFCICRQ0BIAEgAjYCFCACIAE2AhgMAQsgBSgCBCIBQQNxQQNHDQBBkAggADYCACAFIAFBfnE2AgQgAyAAQQFyNgIEIAAgA2ogADYCAA8LIAMgBU8NACAFKAIEIgFBAXFFDQACQCABQQJxRQRAIAVBoAgoAgBGBEBBoAggAzYCAEGUCEGUCCgCACAAaiIANgIAIAMgAEEBcjYCBCADQZwIKAIARw0DQZAIQQA2AgBBnAhBADYCAA8LIAVBnAgoAgBGBEBBnAggAzYCAEGQCEGQCCgCACAAaiIANgIAIAMgAEEBcjYCBCAAIANqIAA2AgAPCyABQXhxIABqIQACQCABQf8BTQRAIAUoAggiAiABQQN2IgRBA3RBsAhqRhogAiAFKAIMIgFGBEBBiAhBiAgoAgBBfiAEd3E2AgAMAgsgAiABNgIMIAEgAjYCCAwBCyAFKAIYIQYCQCAFIAUoAgwiAUcEQCAFKAIIIgJBmAgoAgBJGiACIAE2AgwgASACNgIIDAELAkAgBUEUaiICKAIAIgQNACAFQRBqIgIoAgAiBA0AQQAhAQwBCwNAIAIhByAEIgFBFGoiAigCACIEDQAgAUEQaiECIAEoAhAiBA0ACyAHQQA2AgALIAZFDQACQCAFIAUoAhwiAkECdEG4CmoiBCgCAEYEQCAEIAE2AgAgAQ0BQYwIQYwIKAIAQX4gAndxNgIADAILIAZBEEEUIAYoAhAgBUYbaiABNgIAIAFFDQELIAEgBjYCGCAFKAIQIgIEQCABIAI2AhAgAiABNgIYCyAFKAIUIgJFDQAgASACNgIUIAIgATYCGAsgAyAAQQFyNgIEIAAgA2ogADYCACADQZwIKAIARw0BQZAIIAA2AgAPCyAFIAFBfnE2AgQgAyAAQQFyNgIEIAAgA2ogADYCAAsgAEH/AU0EQCAAQQN2IgFBA3RBsAhqIQACf0GICCgCACICQQEgAXQiAXFFBEBBiAggASACcjYCACAADAELIAAoAggLIQIgACADNgIIIAIgAzYCDCADIAA2AgwgAyACNgIIDwtBHyECIANCADcCECAAQf///wdNBEAgAEEIdiIBIAFBgP4/akEQdkEIcSIBdCICIAJBgOAfakEQdkEEcSICdCIEIARBgIAPakEQdkECcSIEdEEPdiABIAJyIARyayIBQQF0IAAgAUEVanZBAXFyQRxqIQILIAMgAjYCHCACQQJ0QbgKaiEBAkACQAJAQYwIKAIAIgRBASACdCIHcUUEQEGMCCAEIAdyNgIAIAEgAzYCACADIAE2AhgMAQsgAEEAQRkgAkEBdmsgAkEfRht0IQIgASgCACEBA0AgASIEKAIEQXhxIABGDQIgAkEddiEBIAJBAXQhAiAEIAFBBHFqIgdBEGooAgAiAQ0ACyAHIAM2AhAgAyAENgIYCyADIAM2AgwgAyADNgIIDAELIAQoAggiACADNgIMIAQgAzYCCCADQQA2AhggAyAENgIMIAMgADYCCAtBqAhBqAgoAgBBAWsiAEF/IAAbNgIACwsLCQEAQYEICwIGUA==";
			if (!W.startsWith(V)) {
				var na = W;
				W = b.locateFile ? b.locateFile(na, B) : B + na;
			}
			function pa() {
				var a = W;
				try {
					if (a == W && J) return new Uint8Array(J);
					var c = H(a);
					if (c) return c;
					if (E) return E(a);
					throw "both async and sync fetching of the wasm failed";
				} catch (d) {
					K(d);
				}
			}
			function qa() {
				if (!J && (x || y)) {
					if ("function" === typeof fetch && !W.startsWith("file://")) return fetch(W, { credentials: "same-origin" }).then(function(a) {
						if (!a.ok) throw "failed to load wasm binary file at '" + W + "'";
						return a.arrayBuffer();
					}).catch(function() {
						return pa();
					});
					if (D) return new Promise(function(a, c) {
						D(W, function(d) {
							a(new Uint8Array(d));
						}, c);
					});
				}
				return Promise.resolve().then(function() {
					return pa();
				});
			}
			function X(a) {
				for (; 0 < a.length;) {
					var c = a.shift();
					if ("function" == typeof c) c(b);
					else {
						var d = c.m;
						"number" === typeof d ? void 0 === c.l ? R.get(d)() : R.get(d)(c.l) : d(void 0 === c.l ? null : c.l);
					}
				}
			}
			var ba = !1, ra = "function" === typeof atob ? atob : function(a) {
				var c = "", d = 0;
				a = a.replace(/[^A-Za-z0-9\+\/=]/g, "");
				do {
					var e = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(a.charAt(d++));
					var f = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(a.charAt(d++));
					var l = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(a.charAt(d++));
					var A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(a.charAt(d++));
					e = e << 2 | f >> 4;
					f = (f & 15) << 4 | l >> 2;
					var t = (l & 3) << 6 | A;
					c += String.fromCharCode(e);
					64 !== l && (c += String.fromCharCode(f));
					64 !== A && (c += String.fromCharCode(t));
				} while (d < a.length);
				return c;
			};
			function H(a) {
				if (a.startsWith(V)) {
					a = a.slice(V.length);
					if ("boolean" === typeof z && z) {
						var c = Buffer.from(a, "base64");
						c = new Uint8Array(c.buffer, c.byteOffset, c.byteLength);
					} else try {
						var d = ra(a), e = new Uint8Array(d.length);
						for (a = 0; a < d.length; ++a) e[a] = d.charCodeAt(a);
						c = e;
					} catch (f) {
						throw Error("Converting base64 string to bytes failed.");
					}
					return c;
				}
			}
			var sa = { a: function(a) {
				var c = P.length;
				a >>>= 0;
				if (2147483648 < a) return !1;
				for (var d = 1; 4 >= d; d *= 2) {
					var e = c * (1 + .2 / d);
					e = Math.min(e, a + 100663296);
					e = Math.max(a, e);
					0 < e % 65536 && (e += 65536 - e % 65536);
					a: {
						try {
							L.grow(Math.min(2147483648, e) - ha.byteLength + 65535 >>> 16);
							ia();
							var f = 1;
							break a;
						} catch (l) {}
						f = void 0;
					}
					if (f) return !0;
				}
				return !1;
			} };
			(function() {
				function a(f) {
					b.asm = f.exports;
					L = b.asm.b;
					ia();
					R = b.asm.j;
					ka.unshift(b.asm.c);
					S--;
					b.monitorRunDependencies && b.monitorRunDependencies(S);
					0 == S && (null !== T && (clearInterval(T), T = null), U && (f = U, U = null, f()));
				}
				function c(f) {
					a(f.instance);
				}
				function d(f) {
					return qa().then(function(l) {
						return WebAssembly.instantiate(l, e);
					}).then(f, function(l) {
						I("failed to asynchronously prepare wasm: " + l);
						K(l);
					});
				}
				var e = { a: sa };
				S++;
				b.monitorRunDependencies && b.monitorRunDependencies(S);
				if (b.instantiateWasm) try {
					return b.instantiateWasm(e, a);
				} catch (f) {
					return I("Module.instantiateWasm callback failed with error: " + f), !1;
				}
				(function() {
					return J || "function" !== typeof WebAssembly.instantiateStreaming || W.startsWith(V) || W.startsWith("file://") || "function" !== typeof fetch ? d(c) : fetch(W, { credentials: "same-origin" }).then(function(f) {
						return WebAssembly.instantiateStreaming(f, e).then(c, function(l) {
							I("wasm streaming compile failed: " + l);
							I("falling back to ArrayBuffer instantiation");
							return d(c);
						});
					});
				})().catch(r);
				return {};
			})();
			b.___wasm_call_ctors = function() {
				return (b.___wasm_call_ctors = b.asm.c).apply(null, arguments);
			};
			b._poly1305_auth = function() {
				return (b._poly1305_auth = b.asm.d).apply(null, arguments);
			};
			var da = b.stackSave = function() {
				return (da = b.stackSave = b.asm.e).apply(null, arguments);
			}, fa = b.stackRestore = function() {
				return (fa = b.stackRestore = b.asm.f).apply(null, arguments);
			}, O = b.stackAlloc = function() {
				return (O = b.stackAlloc = b.asm.g).apply(null, arguments);
			};
			b._malloc = function() {
				return (b._malloc = b.asm.h).apply(null, arguments);
			};
			b._free = function() {
				return (b._free = b.asm.i).apply(null, arguments);
			};
			b.cwrap = function(a, c, d, e) {
				d = d || [];
				var f = d.every(function(l) {
					return "number" === l;
				});
				return "string" !== c && f && !e ? N(a) : function() {
					return ca(a, c, d, arguments);
				};
			};
			var Y;
			U = function ta() {
				Y || Z();
				Y || (U = ta);
			};
			function Z() {
				function a() {
					if (!Y && (Y = !0, b.calledRun = !0, !M)) {
						X(ka);
						q(b);
						if (b.onRuntimeInitialized) b.onRuntimeInitialized();
						if (b.postRun) for ("function" == typeof b.postRun && (b.postRun = [b.postRun]); b.postRun.length;) {
							var c = b.postRun.shift();
							la.unshift(c);
						}
						X(la);
					}
				}
				if (!(0 < S)) {
					if (b.preRun) for ("function" == typeof b.preRun && (b.preRun = [b.preRun]); b.preRun.length;) ma();
					X(ja);
					0 < S || (b.setStatus ? (b.setStatus("Running..."), setTimeout(function() {
						setTimeout(function() {
							b.setStatus("");
						}, 1);
						a();
					}, 1)) : a());
				}
			}
			b.run = Z;
			if (b.preInit) for ("function" == typeof b.preInit && (b.preInit = [b.preInit]); 0 < b.preInit.length;) b.preInit.pop()();
			Z();
			return createPoly1305.ready;
		});
	})();
	if (typeof exports === "object" && typeof module === "object") module.exports = createPoly1305;
	else if (typeof define === "function" && define["amd"]) define([], function() {
		return createPoly1305;
	});
	else if (typeof exports === "object") exports["createPoly1305"] = createPoly1305;
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/crypto.js
var require_crypto = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { createCipheriv: createCipheriv$1, createDecipheriv: createDecipheriv$1, createHmac: createHmac$1, randomFillSync: randomFillSync$2, timingSafeEqual } = __require("crypto");
	const { readUInt32BE, writeUInt32BE } = require_utils$1();
	const FastBuffer = Buffer[Symbol.species];
	const MAX_SEQNO = 2 ** 32 - 1;
	const EMPTY_BUFFER = Buffer.alloc(0);
	const BUF_INT = Buffer.alloc(4);
	const DISCARD_CACHE = /* @__PURE__ */ new Map();
	const MAX_PACKET_SIZE = 35e3;
	let binding;
	let AESGCMCipher;
	let ChaChaPolyCipher;
	let GenericCipher;
	let AESGCMDecipher;
	let ChaChaPolyDecipher;
	let GenericDecipher;
	try {
		binding = require__rdv_native_stub();
		({AESGCMCipher, ChaChaPolyCipher, GenericCipher, AESGCMDecipher, ChaChaPolyDecipher, GenericDecipher} = binding);
	} catch {}
	const CIPHER_STREAM = 1;
	const CIPHER_INFO = (() => {
		function info(sslName, blockLen, keyLen, ivLen, authLen, discardLen, flags) {
			return {
				sslName,
				blockLen,
				keyLen,
				ivLen: ivLen !== 0 || flags & CIPHER_STREAM ? ivLen : blockLen,
				authLen,
				discardLen,
				stream: !!(flags & CIPHER_STREAM)
			};
		}
		return {
			"chacha20-poly1305@openssh.com": info("chacha20", 8, 64, 0, 16, 0, CIPHER_STREAM),
			"aes128-gcm": info("aes-128-gcm", 16, 16, 12, 16, 0, CIPHER_STREAM),
			"aes256-gcm": info("aes-256-gcm", 16, 32, 12, 16, 0, CIPHER_STREAM),
			"aes128-gcm@openssh.com": info("aes-128-gcm", 16, 16, 12, 16, 0, CIPHER_STREAM),
			"aes256-gcm@openssh.com": info("aes-256-gcm", 16, 32, 12, 16, 0, CIPHER_STREAM),
			"aes128-cbc": info("aes-128-cbc", 16, 16, 0, 0, 0, 0),
			"aes192-cbc": info("aes-192-cbc", 16, 24, 0, 0, 0, 0),
			"aes256-cbc": info("aes-256-cbc", 16, 32, 0, 0, 0, 0),
			"rijndael-cbc@lysator.liu.se": info("aes-256-cbc", 16, 32, 0, 0, 0, 0),
			"3des-cbc": info("des-ede3-cbc", 8, 24, 0, 0, 0, 0),
			"blowfish-cbc": info("bf-cbc", 8, 16, 0, 0, 0, 0),
			"idea-cbc": info("idea-cbc", 8, 16, 0, 0, 0, 0),
			"cast128-cbc": info("cast-cbc", 8, 16, 0, 0, 0, 0),
			"aes128-ctr": info("aes-128-ctr", 16, 16, 16, 0, 0, CIPHER_STREAM),
			"aes192-ctr": info("aes-192-ctr", 16, 24, 16, 0, 0, CIPHER_STREAM),
			"aes256-ctr": info("aes-256-ctr", 16, 32, 16, 0, 0, CIPHER_STREAM),
			"3des-ctr": info("des-ede3", 8, 24, 8, 0, 0, CIPHER_STREAM),
			"blowfish-ctr": info("bf-ecb", 8, 16, 8, 0, 0, CIPHER_STREAM),
			"cast128-ctr": info("cast5-ecb", 8, 16, 8, 0, 0, CIPHER_STREAM),
			"arcfour": info("rc4", 8, 16, 0, 0, 1536, CIPHER_STREAM),
			"arcfour128": info("rc4", 8, 16, 0, 0, 1536, CIPHER_STREAM),
			"arcfour256": info("rc4", 8, 32, 0, 0, 1536, CIPHER_STREAM),
			"arcfour512": info("rc4", 8, 64, 0, 0, 1536, CIPHER_STREAM)
		};
	})();
	const MAC_INFO = (() => {
		function info(sslName, len, actualLen, isETM) {
			return {
				sslName,
				len,
				actualLen,
				isETM
			};
		}
		return {
			"hmac-md5": info("md5", 16, 16, false),
			"hmac-md5-96": info("md5", 16, 12, false),
			"hmac-ripemd160": info("ripemd160", 20, 20, false),
			"hmac-sha1": info("sha1", 20, 20, false),
			"hmac-sha1-etm@openssh.com": info("sha1", 20, 20, true),
			"hmac-sha1-96": info("sha1", 20, 12, false),
			"hmac-sha2-256": info("sha256", 32, 32, false),
			"hmac-sha2-256-etm@openssh.com": info("sha256", 32, 32, true),
			"hmac-sha2-256-96": info("sha256", 32, 12, false),
			"hmac-sha2-512": info("sha512", 64, 64, false),
			"hmac-sha2-512-etm@openssh.com": info("sha512", 64, 64, true),
			"hmac-sha2-512-96": info("sha512", 64, 12, false)
		};
	})();
	var NullCipher = class {
		constructor(seqno, onWrite) {
			this.outSeqno = seqno;
			this._onWrite = onWrite;
			this._dead = false;
		}
		free() {
			this._dead = true;
		}
		allocPacket(payloadLen) {
			let pktLen = 5 + payloadLen;
			let padLen = 8 - (pktLen & 7);
			if (padLen < 4) padLen += 8;
			pktLen += padLen;
			const packet = Buffer.allocUnsafe(pktLen);
			writeUInt32BE(packet, pktLen - 4, 0);
			packet[4] = padLen;
			randomFillSync$2(packet, 5 + payloadLen, padLen);
			return packet;
		}
		encrypt(packet) {
			if (this._dead) return;
			this._onWrite(packet);
			this.outSeqno = this.outSeqno + 1 >>> 0;
		}
	};
	const POLY1305_ZEROS = Buffer.alloc(32);
	const POLY1305_OUT_COMPUTE = Buffer.alloc(16);
	let POLY1305_WASM_MODULE;
	let POLY1305_RESULT_MALLOC;
	let poly1305_auth;
	var ChaChaPolyCipherNative = class {
		constructor(config) {
			const enc = config.outbound;
			this.outSeqno = enc.seqno;
			this._onWrite = enc.onWrite;
			this._encKeyMain = enc.cipherKey.slice(0, 32);
			this._encKeyPktLen = enc.cipherKey.slice(32);
			this._dead = false;
		}
		free() {
			this._dead = true;
		}
		allocPacket(payloadLen) {
			let pktLen = 5 + payloadLen;
			let padLen = 8 - (pktLen - 4 & 7);
			if (padLen < 4) padLen += 8;
			pktLen += padLen;
			const packet = Buffer.allocUnsafe(pktLen);
			writeUInt32BE(packet, pktLen - 4, 0);
			packet[4] = padLen;
			randomFillSync$2(packet, 5 + payloadLen, padLen);
			return packet;
		}
		encrypt(packet) {
			if (this._dead) return;
			POLY1305_OUT_COMPUTE[0] = 0;
			writeUInt32BE(POLY1305_OUT_COMPUTE, this.outSeqno, 12);
			const polyKey = createCipheriv$1("chacha20", this._encKeyMain, POLY1305_OUT_COMPUTE).update(POLY1305_ZEROS);
			const pktLenEnc = createCipheriv$1("chacha20", this._encKeyPktLen, POLY1305_OUT_COMPUTE).update(packet.slice(0, 4));
			this._onWrite(pktLenEnc);
			POLY1305_OUT_COMPUTE[0] = 1;
			const payloadEnc = createCipheriv$1("chacha20", this._encKeyMain, POLY1305_OUT_COMPUTE).update(packet.slice(4));
			this._onWrite(payloadEnc);
			poly1305_auth(POLY1305_RESULT_MALLOC, pktLenEnc, pktLenEnc.length, payloadEnc, payloadEnc.length, polyKey);
			const mac = Buffer.allocUnsafe(16);
			mac.set(new Uint8Array(POLY1305_WASM_MODULE.HEAPU8.buffer, POLY1305_RESULT_MALLOC, 16), 0);
			this._onWrite(mac);
			this.outSeqno = this.outSeqno + 1 >>> 0;
		}
	};
	var ChaChaPolyCipherBinding = class {
		constructor(config) {
			const enc = config.outbound;
			this.outSeqno = enc.seqno;
			this._onWrite = enc.onWrite;
			this._instance = new ChaChaPolyCipher(enc.cipherKey);
			this._dead = false;
		}
		free() {
			this._dead = true;
			this._instance.free();
		}
		allocPacket(payloadLen) {
			let pktLen = 5 + payloadLen;
			let padLen = 8 - (pktLen - 4 & 7);
			if (padLen < 4) padLen += 8;
			pktLen += padLen;
			const packet = Buffer.allocUnsafe(pktLen + 16);
			writeUInt32BE(packet, pktLen - 4, 0);
			packet[4] = padLen;
			randomFillSync$2(packet, 5 + payloadLen, padLen);
			return packet;
		}
		encrypt(packet) {
			if (this._dead) return;
			this._instance.encrypt(packet, this.outSeqno);
			this._onWrite(packet);
			this.outSeqno = this.outSeqno + 1 >>> 0;
		}
	};
	var AESGCMCipherNative = class {
		constructor(config) {
			const enc = config.outbound;
			this.outSeqno = enc.seqno;
			this._onWrite = enc.onWrite;
			this._encSSLName = enc.cipherInfo.sslName;
			this._encKey = enc.cipherKey;
			this._encIV = enc.cipherIV;
			this._dead = false;
		}
		free() {
			this._dead = true;
		}
		allocPacket(payloadLen) {
			let pktLen = 5 + payloadLen;
			let padLen = 16 - (pktLen - 4 & 15);
			if (padLen < 4) padLen += 16;
			pktLen += padLen;
			const packet = Buffer.allocUnsafe(pktLen);
			writeUInt32BE(packet, pktLen - 4, 0);
			packet[4] = padLen;
			randomFillSync$2(packet, 5 + payloadLen, padLen);
			return packet;
		}
		encrypt(packet) {
			if (this._dead) return;
			const cipher = createCipheriv$1(this._encSSLName, this._encKey, this._encIV);
			cipher.setAutoPadding(false);
			const lenData = packet.slice(0, 4);
			cipher.setAAD(lenData);
			this._onWrite(lenData);
			const encrypted = cipher.update(packet.slice(4));
			this._onWrite(encrypted);
			const final = cipher.final();
			if (final.length) this._onWrite(final);
			const tag = cipher.getAuthTag();
			this._onWrite(tag);
			ivIncrement(this._encIV);
			this.outSeqno = this.outSeqno + 1 >>> 0;
		}
	};
	var AESGCMCipherBinding = class {
		constructor(config) {
			const enc = config.outbound;
			this.outSeqno = enc.seqno;
			this._onWrite = enc.onWrite;
			this._instance = new AESGCMCipher(enc.cipherInfo.sslName, enc.cipherKey, enc.cipherIV);
			this._dead = false;
		}
		free() {
			this._dead = true;
			this._instance.free();
		}
		allocPacket(payloadLen) {
			let pktLen = 5 + payloadLen;
			let padLen = 16 - (pktLen - 4 & 15);
			if (padLen < 4) padLen += 16;
			pktLen += padLen;
			const packet = Buffer.allocUnsafe(pktLen + 16);
			writeUInt32BE(packet, pktLen - 4, 0);
			packet[4] = padLen;
			randomFillSync$2(packet, 5 + payloadLen, padLen);
			return packet;
		}
		encrypt(packet) {
			if (this._dead) return;
			this._instance.encrypt(packet);
			this._onWrite(packet);
			this.outSeqno = this.outSeqno + 1 >>> 0;
		}
	};
	var GenericCipherNative = class {
		constructor(config) {
			const enc = config.outbound;
			this.outSeqno = enc.seqno;
			this._onWrite = enc.onWrite;
			this._encBlockLen = enc.cipherInfo.blockLen;
			this._cipherInstance = createCipheriv$1(enc.cipherInfo.sslName, enc.cipherKey, enc.cipherIV);
			this._macSSLName = enc.macInfo.sslName;
			this._macKey = enc.macKey;
			this._macActualLen = enc.macInfo.actualLen;
			this._macETM = enc.macInfo.isETM;
			this._aadLen = this._macETM ? 4 : 0;
			this._dead = false;
			const discardLen = enc.cipherInfo.discardLen;
			if (discardLen) {
				let discard = DISCARD_CACHE.get(discardLen);
				if (discard === void 0) {
					discard = Buffer.alloc(discardLen);
					DISCARD_CACHE.set(discardLen, discard);
				}
				this._cipherInstance.update(discard);
			}
		}
		free() {
			this._dead = true;
		}
		allocPacket(payloadLen) {
			const blockLen = this._encBlockLen;
			let pktLen = 5 + payloadLen;
			let padLen = blockLen - (pktLen - this._aadLen & blockLen - 1);
			if (padLen < 4) padLen += blockLen;
			pktLen += padLen;
			const packet = Buffer.allocUnsafe(pktLen);
			writeUInt32BE(packet, pktLen - 4, 0);
			packet[4] = padLen;
			randomFillSync$2(packet, 5 + payloadLen, padLen);
			return packet;
		}
		encrypt(packet) {
			if (this._dead) return;
			let mac;
			if (this._macETM) {
				const lenBytes = new Uint8Array(packet.buffer, packet.byteOffset, 4);
				const encrypted = this._cipherInstance.update(new Uint8Array(packet.buffer, packet.byteOffset + 4, packet.length - 4));
				this._onWrite(lenBytes);
				this._onWrite(encrypted);
				mac = createHmac$1(this._macSSLName, this._macKey);
				writeUInt32BE(BUF_INT, this.outSeqno, 0);
				mac.update(BUF_INT);
				mac.update(lenBytes);
				mac.update(encrypted);
			} else {
				const encrypted = this._cipherInstance.update(packet);
				this._onWrite(encrypted);
				mac = createHmac$1(this._macSSLName, this._macKey);
				writeUInt32BE(BUF_INT, this.outSeqno, 0);
				mac.update(BUF_INT);
				mac.update(packet);
			}
			let digest = mac.digest();
			if (digest.length > this._macActualLen) digest = digest.slice(0, this._macActualLen);
			this._onWrite(digest);
			this.outSeqno = this.outSeqno + 1 >>> 0;
		}
	};
	var GenericCipherBinding = class {
		constructor(config) {
			const enc = config.outbound;
			this.outSeqno = enc.seqno;
			this._onWrite = enc.onWrite;
			this._encBlockLen = enc.cipherInfo.blockLen;
			this._macLen = enc.macInfo.len;
			this._macActualLen = enc.macInfo.actualLen;
			this._aadLen = enc.macInfo.isETM ? 4 : 0;
			this._instance = new GenericCipher(enc.cipherInfo.sslName, enc.cipherKey, enc.cipherIV, enc.macInfo.sslName, enc.macKey, enc.macInfo.isETM);
			this._dead = false;
		}
		free() {
			this._dead = true;
			this._instance.free();
		}
		allocPacket(payloadLen) {
			const blockLen = this._encBlockLen;
			let pktLen = 5 + payloadLen;
			let padLen = blockLen - (pktLen - this._aadLen & blockLen - 1);
			if (padLen < 4) padLen += blockLen;
			pktLen += padLen;
			const packet = Buffer.allocUnsafe(pktLen + this._macLen);
			writeUInt32BE(packet, pktLen - 4, 0);
			packet[4] = padLen;
			randomFillSync$2(packet, 5 + payloadLen, padLen);
			return packet;
		}
		encrypt(packet) {
			if (this._dead) return;
			this._instance.encrypt(packet, this.outSeqno);
			if (this._macActualLen < this._macLen) packet = new FastBuffer(packet.buffer, packet.byteOffset, packet.length - (this._macLen - this._macActualLen));
			this._onWrite(packet);
			this.outSeqno = this.outSeqno + 1 >>> 0;
		}
	};
	var NullDecipher = class {
		constructor(seqno, onPayload) {
			this.inSeqno = seqno;
			this._onPayload = onPayload;
			this._len = 0;
			this._lenBytes = 0;
			this._packet = null;
			this._packetPos = 0;
		}
		free() {}
		decrypt(data, p, dataLen) {
			while (p < dataLen) {
				if (this._lenBytes < 4) {
					let nb = Math.min(4 - this._lenBytes, dataLen - p);
					this._lenBytes += nb;
					while (nb--) this._len = (this._len << 8) + data[p++];
					if (this._lenBytes < 4) return;
					if (this._len > MAX_PACKET_SIZE || this._len < 8 || (4 + this._len & 7) !== 0) throw new Error("Bad packet length");
					if (p >= dataLen) return;
				}
				if (this._packetPos < this._len) {
					const nb = Math.min(this._len - this._packetPos, dataLen - p);
					let chunk;
					if (p !== 0 || nb !== dataLen) chunk = new Uint8Array(data.buffer, data.byteOffset + p, nb);
					else chunk = data;
					if (nb === this._len) this._packet = chunk;
					else {
						if (!this._packet) this._packet = Buffer.allocUnsafe(this._len);
						this._packet.set(chunk, this._packetPos);
					}
					p += nb;
					this._packetPos += nb;
					if (this._packetPos < this._len) return;
				}
				const payload = !this._packet ? EMPTY_BUFFER : new FastBuffer(this._packet.buffer, this._packet.byteOffset + 1, this._packet.length - this._packet[0] - 1);
				this.inSeqno = this.inSeqno + 1 >>> 0;
				this._len = 0;
				this._lenBytes = 0;
				this._packet = null;
				this._packetPos = 0;
				{
					const ret = this._onPayload(payload);
					if (ret !== void 0) return ret === false ? p : ret;
				}
			}
		}
	};
	var ChaChaPolyDecipherNative = class {
		constructor(config) {
			const dec = config.inbound;
			this.inSeqno = dec.seqno;
			this._onPayload = dec.onPayload;
			this._decKeyMain = dec.decipherKey.slice(0, 32);
			this._decKeyPktLen = dec.decipherKey.slice(32);
			this._len = 0;
			this._lenBuf = Buffer.alloc(4);
			this._lenPos = 0;
			this._packet = null;
			this._pktLen = 0;
			this._mac = Buffer.allocUnsafe(16);
			this._calcMac = Buffer.allocUnsafe(16);
			this._macPos = 0;
		}
		free() {}
		decrypt(data, p, dataLen) {
			while (p < dataLen) {
				if (this._lenPos < 4) {
					let nb = Math.min(4 - this._lenPos, dataLen - p);
					while (nb--) this._lenBuf[this._lenPos++] = data[p++];
					if (this._lenPos < 4) return;
					POLY1305_OUT_COMPUTE[0] = 0;
					writeUInt32BE(POLY1305_OUT_COMPUTE, this.inSeqno, 12);
					const decLenBytes = createDecipheriv$1("chacha20", this._decKeyPktLen, POLY1305_OUT_COMPUTE).update(this._lenBuf);
					this._len = readUInt32BE(decLenBytes, 0);
					if (this._len > MAX_PACKET_SIZE || this._len < 8 || (this._len & 7) !== 0) throw new Error("Bad packet length");
				}
				if (this._pktLen < this._len) {
					if (p >= dataLen) return;
					const nb = Math.min(this._len - this._pktLen, dataLen - p);
					let encrypted;
					if (p !== 0 || nb !== dataLen) encrypted = new Uint8Array(data.buffer, data.byteOffset + p, nb);
					else encrypted = data;
					if (nb === this._len) this._packet = encrypted;
					else {
						if (!this._packet) this._packet = Buffer.allocUnsafe(this._len);
						this._packet.set(encrypted, this._pktLen);
					}
					p += nb;
					this._pktLen += nb;
					if (this._pktLen < this._len || p >= dataLen) return;
				}
				{
					const nb = Math.min(16 - this._macPos, dataLen - p);
					if (p !== 0 || nb !== dataLen) this._mac.set(new Uint8Array(data.buffer, data.byteOffset + p, nb), this._macPos);
					else this._mac.set(data, this._macPos);
					p += nb;
					this._macPos += nb;
					if (this._macPos < 16) return;
				}
				POLY1305_OUT_COMPUTE[0] = 0;
				writeUInt32BE(POLY1305_OUT_COMPUTE, this.inSeqno, 12);
				const polyKey = createCipheriv$1("chacha20", this._decKeyMain, POLY1305_OUT_COMPUTE).update(POLY1305_ZEROS);
				poly1305_auth(POLY1305_RESULT_MALLOC, this._lenBuf, 4, this._packet, this._packet.length, polyKey);
				this._calcMac.set(new Uint8Array(POLY1305_WASM_MODULE.HEAPU8.buffer, POLY1305_RESULT_MALLOC, 16), 0);
				if (!timingSafeEqual(this._calcMac, this._mac)) throw new Error("Invalid MAC");
				POLY1305_OUT_COMPUTE[0] = 1;
				const packet = createDecipheriv$1("chacha20", this._decKeyMain, POLY1305_OUT_COMPUTE).update(this._packet);
				const payload = new FastBuffer(packet.buffer, packet.byteOffset + 1, packet.length - packet[0] - 1);
				this.inSeqno = this.inSeqno + 1 >>> 0;
				this._len = 0;
				this._lenPos = 0;
				this._packet = null;
				this._pktLen = 0;
				this._macPos = 0;
				{
					const ret = this._onPayload(payload);
					if (ret !== void 0) return ret === false ? p : ret;
				}
			}
		}
	};
	var ChaChaPolyDecipherBinding = class {
		constructor(config) {
			const dec = config.inbound;
			this.inSeqno = dec.seqno;
			this._onPayload = dec.onPayload;
			this._instance = new ChaChaPolyDecipher(dec.decipherKey);
			this._len = 0;
			this._lenBuf = Buffer.alloc(4);
			this._lenPos = 0;
			this._packet = null;
			this._pktLen = 0;
			this._mac = Buffer.allocUnsafe(16);
			this._macPos = 0;
		}
		free() {
			this._instance.free();
		}
		decrypt(data, p, dataLen) {
			while (p < dataLen) {
				if (this._lenPos < 4) {
					let nb = Math.min(4 - this._lenPos, dataLen - p);
					while (nb--) this._lenBuf[this._lenPos++] = data[p++];
					if (this._lenPos < 4) return;
					this._len = this._instance.decryptLen(this._lenBuf, this.inSeqno);
					if (this._len > MAX_PACKET_SIZE || this._len < 8 || (this._len & 7) !== 0) throw new Error("Bad packet length");
					if (p >= dataLen) return;
				}
				if (this._pktLen < this._len) {
					const nb = Math.min(this._len - this._pktLen, dataLen - p);
					let encrypted;
					if (p !== 0 || nb !== dataLen) encrypted = new Uint8Array(data.buffer, data.byteOffset + p, nb);
					else encrypted = data;
					if (nb === this._len) this._packet = encrypted;
					else {
						if (!this._packet) this._packet = Buffer.allocUnsafe(this._len);
						this._packet.set(encrypted, this._pktLen);
					}
					p += nb;
					this._pktLen += nb;
					if (this._pktLen < this._len || p >= dataLen) return;
				}
				{
					const nb = Math.min(16 - this._macPos, dataLen - p);
					if (p !== 0 || nb !== dataLen) this._mac.set(new Uint8Array(data.buffer, data.byteOffset + p, nb), this._macPos);
					else this._mac.set(data, this._macPos);
					p += nb;
					this._macPos += nb;
					if (this._macPos < 16) return;
				}
				this._instance.decrypt(this._packet, this._mac, this.inSeqno);
				const payload = new FastBuffer(this._packet.buffer, this._packet.byteOffset + 1, this._packet.length - this._packet[0] - 1);
				this.inSeqno = this.inSeqno + 1 >>> 0;
				this._len = 0;
				this._lenPos = 0;
				this._packet = null;
				this._pktLen = 0;
				this._macPos = 0;
				{
					const ret = this._onPayload(payload);
					if (ret !== void 0) return ret === false ? p : ret;
				}
			}
		}
	};
	var AESGCMDecipherNative = class {
		constructor(config) {
			const dec = config.inbound;
			this.inSeqno = dec.seqno;
			this._onPayload = dec.onPayload;
			this._decipherInstance = null;
			this._decipherSSLName = dec.decipherInfo.sslName;
			this._decipherKey = dec.decipherKey;
			this._decipherIV = dec.decipherIV;
			this._len = 0;
			this._lenBytes = 0;
			this._packet = null;
			this._packetPos = 0;
			this._pktLen = 0;
			this._tag = Buffer.allocUnsafe(16);
			this._tagPos = 0;
		}
		free() {}
		decrypt(data, p, dataLen) {
			while (p < dataLen) {
				if (this._lenBytes < 4) {
					let nb = Math.min(4 - this._lenBytes, dataLen - p);
					this._lenBytes += nb;
					while (nb--) this._len = (this._len << 8) + data[p++];
					if (this._lenBytes < 4) return;
					if (this._len + 20 > MAX_PACKET_SIZE || this._len < 16 || (this._len & 15) !== 0) throw new Error("Bad packet length");
					this._decipherInstance = createDecipheriv$1(this._decipherSSLName, this._decipherKey, this._decipherIV);
					this._decipherInstance.setAutoPadding(false);
					this._decipherInstance.setAAD(intToBytes(this._len));
				}
				if (this._pktLen < this._len) {
					if (p >= dataLen) return;
					const nb = Math.min(this._len - this._pktLen, dataLen - p);
					let decrypted;
					if (p !== 0 || nb !== dataLen) decrypted = this._decipherInstance.update(new Uint8Array(data.buffer, data.byteOffset + p, nb));
					else decrypted = this._decipherInstance.update(data);
					if (decrypted.length) {
						if (nb === this._len) this._packet = decrypted;
						else {
							if (!this._packet) this._packet = Buffer.allocUnsafe(this._len);
							this._packet.set(decrypted, this._packetPos);
						}
						this._packetPos += decrypted.length;
					}
					p += nb;
					this._pktLen += nb;
					if (this._pktLen < this._len || p >= dataLen) return;
				}
				{
					const nb = Math.min(16 - this._tagPos, dataLen - p);
					if (p !== 0 || nb !== dataLen) this._tag.set(new Uint8Array(data.buffer, data.byteOffset + p, nb), this._tagPos);
					else this._tag.set(data, this._tagPos);
					p += nb;
					this._tagPos += nb;
					if (this._tagPos < 16) return;
				}
				{
					this._decipherInstance.setAuthTag(this._tag);
					const decrypted = this._decipherInstance.final();
					if (decrypted.length) {
						if (this._packet) this._packet.set(decrypted, this._packetPos);
						else this._packet = decrypted;
					}
				}
				const payload = !this._packet ? EMPTY_BUFFER : new FastBuffer(this._packet.buffer, this._packet.byteOffset + 1, this._packet.length - this._packet[0] - 1);
				this.inSeqno = this.inSeqno + 1 >>> 0;
				ivIncrement(this._decipherIV);
				this._len = 0;
				this._lenBytes = 0;
				this._packet = null;
				this._packetPos = 0;
				this._pktLen = 0;
				this._tagPos = 0;
				{
					const ret = this._onPayload(payload);
					if (ret !== void 0) return ret === false ? p : ret;
				}
			}
		}
	};
	var AESGCMDecipherBinding = class {
		constructor(config) {
			const dec = config.inbound;
			this.inSeqno = dec.seqno;
			this._onPayload = dec.onPayload;
			this._instance = new AESGCMDecipher(dec.decipherInfo.sslName, dec.decipherKey, dec.decipherIV);
			this._len = 0;
			this._lenBytes = 0;
			this._packet = null;
			this._pktLen = 0;
			this._tag = Buffer.allocUnsafe(16);
			this._tagPos = 0;
		}
		free() {}
		decrypt(data, p, dataLen) {
			while (p < dataLen) {
				if (this._lenBytes < 4) {
					let nb = Math.min(4 - this._lenBytes, dataLen - p);
					this._lenBytes += nb;
					while (nb--) this._len = (this._len << 8) + data[p++];
					if (this._lenBytes < 4) return;
					if (this._len + 20 > MAX_PACKET_SIZE || this._len < 16 || (this._len & 15) !== 0) throw new Error(`Bad packet length: ${this._len}`);
				}
				if (this._pktLen < this._len) {
					if (p >= dataLen) return;
					const nb = Math.min(this._len - this._pktLen, dataLen - p);
					let encrypted;
					if (p !== 0 || nb !== dataLen) encrypted = new Uint8Array(data.buffer, data.byteOffset + p, nb);
					else encrypted = data;
					if (nb === this._len) this._packet = encrypted;
					else {
						if (!this._packet) this._packet = Buffer.allocUnsafe(this._len);
						this._packet.set(encrypted, this._pktLen);
					}
					p += nb;
					this._pktLen += nb;
					if (this._pktLen < this._len || p >= dataLen) return;
				}
				{
					const nb = Math.min(16 - this._tagPos, dataLen - p);
					if (p !== 0 || nb !== dataLen) this._tag.set(new Uint8Array(data.buffer, data.byteOffset + p, nb), this._tagPos);
					else this._tag.set(data, this._tagPos);
					p += nb;
					this._tagPos += nb;
					if (this._tagPos < 16) return;
				}
				this._instance.decrypt(this._packet, this._len, this._tag);
				const payload = new FastBuffer(this._packet.buffer, this._packet.byteOffset + 1, this._packet.length - this._packet[0] - 1);
				this.inSeqno = this.inSeqno + 1 >>> 0;
				this._len = 0;
				this._lenBytes = 0;
				this._packet = null;
				this._pktLen = 0;
				this._tagPos = 0;
				{
					const ret = this._onPayload(payload);
					if (ret !== void 0) return ret === false ? p : ret;
				}
			}
		}
	};
	var GenericDecipherNative = class {
		constructor(config) {
			const dec = config.inbound;
			this.inSeqno = dec.seqno;
			this._onPayload = dec.onPayload;
			this._decipherInstance = createDecipheriv$1(dec.decipherInfo.sslName, dec.decipherKey, dec.decipherIV);
			this._decipherInstance.setAutoPadding(false);
			this._block = Buffer.allocUnsafe(dec.macInfo.isETM ? 4 : dec.decipherInfo.blockLen);
			this._blockSize = dec.decipherInfo.blockLen;
			this._blockPos = 0;
			this._len = 0;
			this._packet = null;
			this._packetPos = 0;
			this._pktLen = 0;
			this._mac = Buffer.allocUnsafe(dec.macInfo.actualLen);
			this._macPos = 0;
			this._macSSLName = dec.macInfo.sslName;
			this._macKey = dec.macKey;
			this._macActualLen = dec.macInfo.actualLen;
			this._macETM = dec.macInfo.isETM;
			this._macInstance = null;
			const discardLen = dec.decipherInfo.discardLen;
			if (discardLen) {
				let discard = DISCARD_CACHE.get(discardLen);
				if (discard === void 0) {
					discard = Buffer.alloc(discardLen);
					DISCARD_CACHE.set(discardLen, discard);
				}
				this._decipherInstance.update(discard);
			}
		}
		free() {}
		decrypt(data, p, dataLen) {
			while (p < dataLen) {
				if (this._blockPos < this._block.length) {
					const nb = Math.min(this._block.length - this._blockPos, dataLen - p);
					if (p !== 0 || nb !== dataLen || nb < data.length) this._block.set(new Uint8Array(data.buffer, data.byteOffset + p, nb), this._blockPos);
					else this._block.set(data, this._blockPos);
					p += nb;
					this._blockPos += nb;
					if (this._blockPos < this._block.length) return;
					let decrypted;
					let need;
					if (this._macETM) this._len = need = readUInt32BE(this._block, 0);
					else {
						decrypted = this._decipherInstance.update(this._block);
						this._len = readUInt32BE(decrypted, 0);
						need = 4 + this._len - this._blockSize;
					}
					if (this._len > MAX_PACKET_SIZE || this._len < 5 || (need & this._blockSize - 1) !== 0) throw new Error("Bad packet length");
					this._macInstance = createHmac$1(this._macSSLName, this._macKey);
					writeUInt32BE(BUF_INT, this.inSeqno, 0);
					this._macInstance.update(BUF_INT);
					if (this._macETM) this._macInstance.update(this._block);
					else {
						this._macInstance.update(new Uint8Array(decrypted.buffer, decrypted.byteOffset, 4));
						this._pktLen = decrypted.length - 4;
						this._packetPos = this._pktLen;
						this._packet = Buffer.allocUnsafe(this._len);
						this._packet.set(new Uint8Array(decrypted.buffer, decrypted.byteOffset + 4, this._packetPos), 0);
					}
					if (p >= dataLen) return;
				}
				if (this._pktLen < this._len) {
					const nb = Math.min(this._len - this._pktLen, dataLen - p);
					let encrypted;
					if (p !== 0 || nb !== dataLen) encrypted = new Uint8Array(data.buffer, data.byteOffset + p, nb);
					else encrypted = data;
					if (this._macETM) this._macInstance.update(encrypted);
					const decrypted = this._decipherInstance.update(encrypted);
					if (decrypted.length) {
						if (nb === this._len) this._packet = decrypted;
						else {
							if (!this._packet) this._packet = Buffer.allocUnsafe(this._len);
							this._packet.set(decrypted, this._packetPos);
						}
						this._packetPos += decrypted.length;
					}
					p += nb;
					this._pktLen += nb;
					if (this._pktLen < this._len || p >= dataLen) return;
				}
				{
					const nb = Math.min(this._macActualLen - this._macPos, dataLen - p);
					if (p !== 0 || nb !== dataLen) this._mac.set(new Uint8Array(data.buffer, data.byteOffset + p, nb), this._macPos);
					else this._mac.set(data, this._macPos);
					p += nb;
					this._macPos += nb;
					if (this._macPos < this._macActualLen) return;
				}
				if (!this._macETM) this._macInstance.update(this._packet);
				let calculated = this._macInstance.digest();
				if (this._macActualLen < calculated.length) calculated = new Uint8Array(calculated.buffer, calculated.byteOffset, this._macActualLen);
				if (!timingSafeEquals(calculated, this._mac)) throw new Error("Invalid MAC");
				const payload = new FastBuffer(this._packet.buffer, this._packet.byteOffset + 1, this._packet.length - this._packet[0] - 1);
				this.inSeqno = this.inSeqno + 1 >>> 0;
				this._blockPos = 0;
				this._len = 0;
				this._packet = null;
				this._packetPos = 0;
				this._pktLen = 0;
				this._macPos = 0;
				this._macInstance = null;
				{
					const ret = this._onPayload(payload);
					if (ret !== void 0) return ret === false ? p : ret;
				}
			}
		}
	};
	var GenericDecipherBinding = class {
		constructor(config) {
			const dec = config.inbound;
			this.inSeqno = dec.seqno;
			this._onPayload = dec.onPayload;
			this._instance = new GenericDecipher(dec.decipherInfo.sslName, dec.decipherKey, dec.decipherIV, dec.macInfo.sslName, dec.macKey, dec.macInfo.isETM, dec.macInfo.actualLen);
			this._block = Buffer.allocUnsafe(dec.macInfo.isETM || dec.decipherInfo.stream ? 4 : dec.decipherInfo.blockLen);
			this._blockPos = 0;
			this._len = 0;
			this._packet = null;
			this._pktLen = 0;
			this._mac = Buffer.allocUnsafe(dec.macInfo.actualLen);
			this._macPos = 0;
			this._macActualLen = dec.macInfo.actualLen;
			this._macETM = dec.macInfo.isETM;
		}
		free() {
			this._instance.free();
		}
		decrypt(data, p, dataLen) {
			while (p < dataLen) {
				if (this._blockPos < this._block.length) {
					const nb = Math.min(this._block.length - this._blockPos, dataLen - p);
					if (p !== 0 || nb !== dataLen || nb < data.length) this._block.set(new Uint8Array(data.buffer, data.byteOffset + p, nb), this._blockPos);
					else this._block.set(data, this._blockPos);
					p += nb;
					this._blockPos += nb;
					if (this._blockPos < this._block.length) return;
					let need;
					if (this._macETM) this._len = need = readUInt32BE(this._block, 0);
					else {
						this._instance.decryptBlock(this._block);
						this._len = readUInt32BE(this._block, 0);
						need = 4 + this._len - this._block.length;
					}
					if (this._len > MAX_PACKET_SIZE || this._len < 5 || (need & this._block.length - 1) !== 0) throw new Error("Bad packet length");
					if (!this._macETM) {
						this._pktLen = this._block.length - 4;
						if (this._pktLen) {
							this._packet = Buffer.allocUnsafe(this._len);
							this._packet.set(new Uint8Array(this._block.buffer, this._block.byteOffset + 4, this._pktLen), 0);
						}
					}
					if (p >= dataLen) return;
				}
				if (this._pktLen < this._len) {
					const nb = Math.min(this._len - this._pktLen, dataLen - p);
					let encrypted;
					if (p !== 0 || nb !== dataLen) encrypted = new Uint8Array(data.buffer, data.byteOffset + p, nb);
					else encrypted = data;
					if (nb === this._len) this._packet = encrypted;
					else {
						if (!this._packet) this._packet = Buffer.allocUnsafe(this._len);
						this._packet.set(encrypted, this._pktLen);
					}
					p += nb;
					this._pktLen += nb;
					if (this._pktLen < this._len || p >= dataLen) return;
				}
				{
					const nb = Math.min(this._macActualLen - this._macPos, dataLen - p);
					if (p !== 0 || nb !== dataLen) this._mac.set(new Uint8Array(data.buffer, data.byteOffset + p, nb), this._macPos);
					else this._mac.set(data, this._macPos);
					p += nb;
					this._macPos += nb;
					if (this._macPos < this._macActualLen) return;
				}
				this._instance.decrypt(this._packet, this.inSeqno, this._block, this._mac);
				const payload = new FastBuffer(this._packet.buffer, this._packet.byteOffset + 1, this._packet.length - this._packet[0] - 1);
				this.inSeqno = this.inSeqno + 1 >>> 0;
				this._blockPos = 0;
				this._len = 0;
				this._packet = null;
				this._pktLen = 0;
				this._macPos = 0;
				this._macInstance = null;
				{
					const ret = this._onPayload(payload);
					if (ret !== void 0) return ret === false ? p : ret;
				}
			}
		}
	};
	function ivIncrement(iv) {
		++iv[11] >>> 8 && ++iv[10] >>> 8 && ++iv[9] >>> 8 && ++iv[8] >>> 8 && ++iv[7] >>> 8 && ++iv[6] >>> 8 && ++iv[5] >>> 8 && ++iv[4] >>> 8;
	}
	const intToBytes = (() => {
		const ret = Buffer.alloc(4);
		return (n) => {
			ret[0] = n >>> 24;
			ret[1] = n >>> 16;
			ret[2] = n >>> 8;
			ret[3] = n;
			return ret;
		};
	})();
	function timingSafeEquals(a, b) {
		if (a.length !== b.length) {
			timingSafeEqual(a, a);
			return false;
		}
		return timingSafeEqual(a, b);
	}
	function createCipher(config) {
		if (typeof config !== "object" || config === null) throw new Error("Invalid config");
		if (typeof config.outbound !== "object" || config.outbound === null) throw new Error("Invalid outbound");
		const outbound = config.outbound;
		if (typeof outbound.onWrite !== "function") throw new Error("Invalid outbound.onWrite");
		if (typeof outbound.cipherInfo !== "object" || outbound.cipherInfo === null) throw new Error("Invalid outbound.cipherInfo");
		if (!Buffer.isBuffer(outbound.cipherKey) || outbound.cipherKey.length !== outbound.cipherInfo.keyLen) throw new Error("Invalid outbound.cipherKey");
		if (outbound.cipherInfo.ivLen && (!Buffer.isBuffer(outbound.cipherIV) || outbound.cipherIV.length !== outbound.cipherInfo.ivLen)) throw new Error("Invalid outbound.cipherIV");
		if (typeof outbound.seqno !== "number" || outbound.seqno < 0 || outbound.seqno > MAX_SEQNO) throw new Error("Invalid outbound.seqno");
		const forceNative = !!outbound.forceNative;
		switch (outbound.cipherInfo.sslName) {
			case "aes-128-gcm":
			case "aes-256-gcm": return AESGCMCipher && !forceNative ? new AESGCMCipherBinding(config) : new AESGCMCipherNative(config);
			case "chacha20": return ChaChaPolyCipher && !forceNative ? new ChaChaPolyCipherBinding(config) : new ChaChaPolyCipherNative(config);
			default:
				if (typeof outbound.macInfo !== "object" || outbound.macInfo === null) throw new Error("Invalid outbound.macInfo");
				if (!Buffer.isBuffer(outbound.macKey) || outbound.macKey.length !== outbound.macInfo.len) throw new Error("Invalid outbound.macKey");
				return GenericCipher && !forceNative ? new GenericCipherBinding(config) : new GenericCipherNative(config);
		}
	}
	function createDecipher(config) {
		if (typeof config !== "object" || config === null) throw new Error("Invalid config");
		if (typeof config.inbound !== "object" || config.inbound === null) throw new Error("Invalid inbound");
		const inbound = config.inbound;
		if (typeof inbound.onPayload !== "function") throw new Error("Invalid inbound.onPayload");
		if (typeof inbound.decipherInfo !== "object" || inbound.decipherInfo === null) throw new Error("Invalid inbound.decipherInfo");
		if (!Buffer.isBuffer(inbound.decipherKey) || inbound.decipherKey.length !== inbound.decipherInfo.keyLen) throw new Error("Invalid inbound.decipherKey");
		if (inbound.decipherInfo.ivLen && (!Buffer.isBuffer(inbound.decipherIV) || inbound.decipherIV.length !== inbound.decipherInfo.ivLen)) throw new Error("Invalid inbound.decipherIV");
		if (typeof inbound.seqno !== "number" || inbound.seqno < 0 || inbound.seqno > MAX_SEQNO) throw new Error("Invalid inbound.seqno");
		const forceNative = !!inbound.forceNative;
		switch (inbound.decipherInfo.sslName) {
			case "aes-128-gcm":
			case "aes-256-gcm": return AESGCMDecipher && !forceNative ? new AESGCMDecipherBinding(config) : new AESGCMDecipherNative(config);
			case "chacha20": return ChaChaPolyDecipher && !forceNative ? new ChaChaPolyDecipherBinding(config) : new ChaChaPolyDecipherNative(config);
			default:
				if (typeof inbound.macInfo !== "object" || inbound.macInfo === null) throw new Error("Invalid inbound.macInfo");
				if (!Buffer.isBuffer(inbound.macKey) || inbound.macKey.length !== inbound.macInfo.len) throw new Error("Invalid inbound.macKey");
				return GenericDecipher && !forceNative ? new GenericDecipherBinding(config) : new GenericDecipherNative(config);
		}
	}
	module.exports = {
		CIPHER_INFO,
		MAC_INFO,
		bindingAvailable: !!binding,
		init: (() => {
			return new Promise(async (resolve, reject) => {
				try {
					POLY1305_WASM_MODULE = await require_poly1305()();
					POLY1305_RESULT_MALLOC = POLY1305_WASM_MODULE._malloc(16);
					poly1305_auth = POLY1305_WASM_MODULE.cwrap("poly1305_auth", null, [
						"number",
						"array",
						"number",
						"array",
						"number",
						"array"
					]);
				} catch (ex) {
					return reject(ex);
				}
				resolve();
			});
		})(),
		NullCipher,
		createCipher,
		NullDecipher,
		createDecipher
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/keyParser.js
var require_keyParser = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { createDecipheriv, createECDH: createECDH$1, createHash: createHash$3, createHmac, createSign, createVerify, getCiphers, sign: sign_, verify: verify_ } = __require("crypto");
	const supportedOpenSSLCiphers = getCiphers();
	const { Ber } = require_lib$1();
	const bcrypt_pbkdf = require_bcrypt_pbkdf().pbkdf;
	const { CIPHER_INFO } = require_crypto();
	const { eddsaSupported, SUPPORTED_CIPHER } = require_constants();
	const { bufferSlice, makeBufferParser, readString, readUInt32BE, writeUInt32BE } = require_utils$1();
	const SYM_HASH_ALGO = Symbol("Hash Algorithm");
	const SYM_PRIV_PEM = Symbol("Private key PEM");
	const SYM_PUB_PEM = Symbol("Public key PEM");
	const SYM_PUB_SSH = Symbol("Public key SSH");
	const SYM_DECRYPTED = Symbol("Decrypted Key");
	const CIPHER_INFO_OPENSSL = Object.create(null);
	{
		const keys = Object.keys(CIPHER_INFO);
		for (let i = 0; i < keys.length; ++i) {
			const cipherName = CIPHER_INFO[keys[i]].sslName;
			if (!cipherName || CIPHER_INFO_OPENSSL[cipherName]) continue;
			CIPHER_INFO_OPENSSL[cipherName] = CIPHER_INFO[keys[i]];
		}
	}
	const binaryKeyParser = makeBufferParser();
	function makePEM(type, data) {
		data = data.base64Slice(0, data.length);
		let formatted = data.replace(/.{64}/g, "$&\n");
		if (data.length & 63) formatted += "\n";
		return `-----BEGIN ${type} KEY-----\n${formatted}-----END ${type} KEY-----`;
	}
	function combineBuffers(buf1, buf2) {
		const result = Buffer.allocUnsafe(buf1.length + buf2.length);
		result.set(buf1, 0);
		result.set(buf2, buf1.length);
		return result;
	}
	function skipFields(buf, nfields) {
		const bufLen = buf.length;
		let pos = buf._pos || 0;
		for (let i = 0; i < nfields; ++i) {
			const left = bufLen - pos;
			if (pos >= bufLen || left < 4) return false;
			const len = readUInt32BE(buf, pos);
			if (left < 4 + len) return false;
			pos += 4 + len;
		}
		buf._pos = pos;
		return true;
	}
	function genOpenSSLRSAPub(n, e) {
		const asnWriter = new Ber.Writer();
		asnWriter.startSequence();
		asnWriter.startSequence();
		asnWriter.writeOID("1.2.840.113549.1.1.1");
		asnWriter.writeNull();
		asnWriter.endSequence();
		asnWriter.startSequence(Ber.BitString);
		asnWriter.writeByte(0);
		asnWriter.startSequence();
		asnWriter.writeBuffer(n, Ber.Integer);
		asnWriter.writeBuffer(e, Ber.Integer);
		asnWriter.endSequence();
		asnWriter.endSequence();
		asnWriter.endSequence();
		return makePEM("PUBLIC", asnWriter.buffer);
	}
	function genOpenSSHRSAPub(n, e) {
		const publicKey = Buffer.allocUnsafe(15 + e.length + 4 + n.length);
		writeUInt32BE(publicKey, 7, 0);
		publicKey.utf8Write("ssh-rsa", 4, 7);
		let i = 11;
		writeUInt32BE(publicKey, e.length, i);
		publicKey.set(e, i += 4);
		writeUInt32BE(publicKey, n.length, i += e.length);
		publicKey.set(n, i + 4);
		return publicKey;
	}
	const genOpenSSLRSAPriv = (() => {
		function genRSAASN1Buf(n, e, d, p, q, dmp1, dmq1, iqmp) {
			const asnWriter = new Ber.Writer();
			asnWriter.startSequence();
			asnWriter.writeInt(0, Ber.Integer);
			asnWriter.writeBuffer(n, Ber.Integer);
			asnWriter.writeBuffer(e, Ber.Integer);
			asnWriter.writeBuffer(d, Ber.Integer);
			asnWriter.writeBuffer(p, Ber.Integer);
			asnWriter.writeBuffer(q, Ber.Integer);
			asnWriter.writeBuffer(dmp1, Ber.Integer);
			asnWriter.writeBuffer(dmq1, Ber.Integer);
			asnWriter.writeBuffer(iqmp, Ber.Integer);
			asnWriter.endSequence();
			return asnWriter.buffer;
		}
		function bigIntFromBuffer(buf) {
			return BigInt(`0x${buf.hexSlice(0, buf.length)}`);
		}
		function bigIntToBuffer(bn) {
			let hex = bn.toString(16);
			if ((hex.length & 1) !== 0) hex = `0${hex}`;
			else {
				const sigbit = hex.charCodeAt(0);
				if (sigbit === 56 || sigbit === 57 || sigbit >= 97 && sigbit <= 102) hex = `00${hex}`;
			}
			return Buffer.from(hex, "hex");
		}
		return function genOpenSSLRSAPriv(n, e, d, iqmp, p, q) {
			const bn_d = bigIntFromBuffer(d);
			return makePEM("RSA PRIVATE", genRSAASN1Buf(n, e, d, p, q, bigIntToBuffer(bn_d % (bigIntFromBuffer(p) - 1n)), bigIntToBuffer(bn_d % (bigIntFromBuffer(q) - 1n)), iqmp));
		};
	})();
	function genOpenSSLDSAPub(p, q, g, y) {
		const asnWriter = new Ber.Writer();
		asnWriter.startSequence();
		asnWriter.startSequence();
		asnWriter.writeOID("1.2.840.10040.4.1");
		asnWriter.startSequence();
		asnWriter.writeBuffer(p, Ber.Integer);
		asnWriter.writeBuffer(q, Ber.Integer);
		asnWriter.writeBuffer(g, Ber.Integer);
		asnWriter.endSequence();
		asnWriter.endSequence();
		asnWriter.startSequence(Ber.BitString);
		asnWriter.writeByte(0);
		asnWriter.writeBuffer(y, Ber.Integer);
		asnWriter.endSequence();
		asnWriter.endSequence();
		return makePEM("PUBLIC", asnWriter.buffer);
	}
	function genOpenSSHDSAPub(p, q, g, y) {
		const publicKey = Buffer.allocUnsafe(15 + p.length + 4 + q.length + 4 + g.length + 4 + y.length);
		writeUInt32BE(publicKey, 7, 0);
		publicKey.utf8Write("ssh-dss", 4, 7);
		let i = 11;
		writeUInt32BE(publicKey, p.length, i);
		publicKey.set(p, i += 4);
		writeUInt32BE(publicKey, q.length, i += p.length);
		publicKey.set(q, i += 4);
		writeUInt32BE(publicKey, g.length, i += q.length);
		publicKey.set(g, i += 4);
		writeUInt32BE(publicKey, y.length, i += g.length);
		publicKey.set(y, i + 4);
		return publicKey;
	}
	function genOpenSSLDSAPriv(p, q, g, y, x) {
		const asnWriter = new Ber.Writer();
		asnWriter.startSequence();
		asnWriter.writeInt(0, Ber.Integer);
		asnWriter.writeBuffer(p, Ber.Integer);
		asnWriter.writeBuffer(q, Ber.Integer);
		asnWriter.writeBuffer(g, Ber.Integer);
		asnWriter.writeBuffer(y, Ber.Integer);
		asnWriter.writeBuffer(x, Ber.Integer);
		asnWriter.endSequence();
		return makePEM("DSA PRIVATE", asnWriter.buffer);
	}
	function genOpenSSLEdPub(pub) {
		const asnWriter = new Ber.Writer();
		asnWriter.startSequence();
		asnWriter.startSequence();
		asnWriter.writeOID("1.3.101.112");
		asnWriter.endSequence();
		asnWriter.startSequence(Ber.BitString);
		asnWriter.writeByte(0);
		asnWriter._ensure(pub.length);
		asnWriter._buf.set(pub, asnWriter._offset);
		asnWriter._offset += pub.length;
		asnWriter.endSequence();
		asnWriter.endSequence();
		return makePEM("PUBLIC", asnWriter.buffer);
	}
	function genOpenSSHEdPub(pub) {
		const publicKey = Buffer.allocUnsafe(19 + pub.length);
		writeUInt32BE(publicKey, 11, 0);
		publicKey.utf8Write("ssh-ed25519", 4, 11);
		writeUInt32BE(publicKey, pub.length, 15);
		publicKey.set(pub, 19);
		return publicKey;
	}
	function genOpenSSLEdPriv(priv) {
		const asnWriter = new Ber.Writer();
		asnWriter.startSequence();
		asnWriter.writeInt(0, Ber.Integer);
		asnWriter.startSequence();
		asnWriter.writeOID("1.3.101.112");
		asnWriter.endSequence();
		asnWriter.startSequence(Ber.OctetString);
		asnWriter.writeBuffer(priv, Ber.OctetString);
		asnWriter.endSequence();
		asnWriter.endSequence();
		return makePEM("PRIVATE", asnWriter.buffer);
	}
	function genOpenSSLECDSAPub(oid, Q) {
		const asnWriter = new Ber.Writer();
		asnWriter.startSequence();
		asnWriter.startSequence();
		asnWriter.writeOID("1.2.840.10045.2.1");
		asnWriter.writeOID(oid);
		asnWriter.endSequence();
		asnWriter.startSequence(Ber.BitString);
		asnWriter.writeByte(0);
		asnWriter._ensure(Q.length);
		asnWriter._buf.set(Q, asnWriter._offset);
		asnWriter._offset += Q.length;
		asnWriter.endSequence();
		asnWriter.endSequence();
		return makePEM("PUBLIC", asnWriter.buffer);
	}
	function genOpenSSHECDSAPub(oid, Q) {
		let curveName;
		switch (oid) {
			case "1.2.840.10045.3.1.7":
				curveName = "nistp256";
				break;
			case "1.3.132.0.34":
				curveName = "nistp384";
				break;
			case "1.3.132.0.35":
				curveName = "nistp521";
				break;
			default: return;
		}
		const publicKey = Buffer.allocUnsafe(39 + Q.length);
		writeUInt32BE(publicKey, 19, 0);
		publicKey.utf8Write(`ecdsa-sha2-${curveName}`, 4, 19);
		writeUInt32BE(publicKey, 8, 23);
		publicKey.utf8Write(curveName, 27, 8);
		writeUInt32BE(publicKey, Q.length, 35);
		publicKey.set(Q, 39);
		return publicKey;
	}
	function genOpenSSLECDSAPriv(oid, pub, priv) {
		const asnWriter = new Ber.Writer();
		asnWriter.startSequence();
		asnWriter.writeInt(1, Ber.Integer);
		asnWriter.writeBuffer(priv, Ber.OctetString);
		asnWriter.startSequence(160);
		asnWriter.writeOID(oid);
		asnWriter.endSequence();
		asnWriter.startSequence(161);
		asnWriter.startSequence(Ber.BitString);
		asnWriter.writeByte(0);
		asnWriter._ensure(pub.length);
		asnWriter._buf.set(pub, asnWriter._offset);
		asnWriter._offset += pub.length;
		asnWriter.endSequence();
		asnWriter.endSequence();
		asnWriter.endSequence();
		return makePEM("EC PRIVATE", asnWriter.buffer);
	}
	function genOpenSSLECDSAPubFromPriv(curveName, priv) {
		const tempECDH = createECDH$1(curveName);
		tempECDH.setPrivateKey(priv);
		return tempECDH.getPublicKey();
	}
	const BaseKey = {
		sign: (() => {
			if (typeof sign_ === "function") return function sign(data, algo) {
				const pem = this[SYM_PRIV_PEM];
				if (pem === null) return /* @__PURE__ */ new Error("No private key available");
				if (!algo || typeof algo !== "string") algo = this[SYM_HASH_ALGO];
				try {
					return sign_(algo, data, pem);
				} catch (ex) {
					return ex;
				}
			};
			return function sign(data, algo) {
				const pem = this[SYM_PRIV_PEM];
				if (pem === null) return /* @__PURE__ */ new Error("No private key available");
				if (!algo || typeof algo !== "string") algo = this[SYM_HASH_ALGO];
				const signature = createSign(algo);
				signature.update(data);
				try {
					return signature.sign(pem);
				} catch (ex) {
					return ex;
				}
			};
		})(),
		verify: (() => {
			if (typeof verify_ === "function") return function verify(data, signature, algo) {
				const pem = this[SYM_PUB_PEM];
				if (pem === null) return /* @__PURE__ */ new Error("No public key available");
				if (!algo || typeof algo !== "string") algo = this[SYM_HASH_ALGO];
				try {
					return verify_(algo, data, pem, signature);
				} catch (ex) {
					return ex;
				}
			};
			return function verify(data, signature, algo) {
				const pem = this[SYM_PUB_PEM];
				if (pem === null) return /* @__PURE__ */ new Error("No public key available");
				if (!algo || typeof algo !== "string") algo = this[SYM_HASH_ALGO];
				const verifier = createVerify(algo);
				verifier.update(data);
				try {
					return verifier.verify(pem, signature);
				} catch (ex) {
					return ex;
				}
			};
		})(),
		isPrivateKey: function isPrivateKey() {
			return this[SYM_PRIV_PEM] !== null;
		},
		getPrivatePEM: function getPrivatePEM() {
			return this[SYM_PRIV_PEM];
		},
		getPublicPEM: function getPublicPEM() {
			return this[SYM_PUB_PEM];
		},
		getPublicSSH: function getPublicSSH() {
			return this[SYM_PUB_SSH];
		},
		equals: function equals(key) {
			const parsed = parseKey(key);
			if (parsed instanceof Error) return false;
			return this.type === parsed.type && this[SYM_PRIV_PEM] === parsed[SYM_PRIV_PEM] && this[SYM_PUB_PEM] === parsed[SYM_PUB_PEM] && this[SYM_PUB_SSH].equals(parsed[SYM_PUB_SSH]);
		}
	};
	function OpenSSH_Private(type, comment, privPEM, pubPEM, pubSSH, algo, decrypted) {
		this.type = type;
		this.comment = comment;
		this[SYM_PRIV_PEM] = privPEM;
		this[SYM_PUB_PEM] = pubPEM;
		this[SYM_PUB_SSH] = pubSSH;
		this[SYM_HASH_ALGO] = algo;
		this[SYM_DECRYPTED] = decrypted;
	}
	OpenSSH_Private.prototype = BaseKey;
	{
		const regexp = /^-----BEGIN OPENSSH PRIVATE KEY-----(?:\r\n|\n)([\s\S]+)(?:\r\n|\n)-----END OPENSSH PRIVATE KEY-----$/;
		OpenSSH_Private.parse = (str, passphrase) => {
			const m = regexp.exec(str);
			if (m === null) return null;
			let ret;
			const data = Buffer.from(m[1], "base64");
			if (data.length < 31) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
			const magic = data.utf8Slice(0, 15);
			if (magic !== "openssh-key-v1\0") return /* @__PURE__ */ new Error(`Unsupported OpenSSH key magic: ${magic}`);
			const cipherName = readString(data, 15, true);
			if (cipherName === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
			if (cipherName !== "none" && SUPPORTED_CIPHER.indexOf(cipherName) === -1) return /* @__PURE__ */ new Error(`Unsupported cipher for OpenSSH key: ${cipherName}`);
			const kdfName = readString(data, data._pos, true);
			if (kdfName === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
			if (kdfName !== "none") {
				if (cipherName === "none") return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
				if (kdfName !== "bcrypt") return /* @__PURE__ */ new Error(`Unsupported kdf name for OpenSSH key: ${kdfName}`);
				if (!passphrase) return /* @__PURE__ */ new Error("Encrypted private OpenSSH key detected, but no passphrase given");
			} else if (cipherName !== "none") return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
			let encInfo;
			let cipherKey;
			let cipherIV;
			if (cipherName !== "none") encInfo = CIPHER_INFO[cipherName];
			const kdfOptions = readString(data, data._pos);
			if (kdfOptions === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
			if (kdfOptions.length) switch (kdfName) {
				case "none": return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
				case "bcrypt": {
					const salt = readString(kdfOptions, 0);
					if (salt === void 0 || kdfOptions._pos + 4 > kdfOptions.length) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
					const rounds = readUInt32BE(kdfOptions, kdfOptions._pos);
					const gen = Buffer.allocUnsafe(encInfo.keyLen + encInfo.ivLen);
					if (bcrypt_pbkdf(passphrase, passphrase.length, salt, salt.length, gen, gen.length, rounds) !== 0) return /* @__PURE__ */ new Error("Failed to generate information to decrypt key");
					cipherKey = bufferSlice(gen, 0, encInfo.keyLen);
					cipherIV = bufferSlice(gen, encInfo.keyLen, gen.length);
					break;
				}
			}
			else if (kdfName !== "none") return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
			if (data._pos + 3 >= data.length) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
			const keyCount = readUInt32BE(data, data._pos);
			data._pos += 4;
			if (keyCount > 0) {
				for (let i = 0; i < keyCount; ++i) {
					const pubData = readString(data, data._pos);
					if (pubData === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
					if (readString(pubData, 0, true) === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
				}
				let privBlob = readString(data, data._pos);
				if (privBlob === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
				if (cipherKey !== void 0) {
					if (privBlob.length < encInfo.blockLen || privBlob.length % encInfo.blockLen !== 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
					try {
						const options = { authTagLength: encInfo.authLen };
						const decipher = createDecipheriv(encInfo.sslName, cipherKey, cipherIV, options);
						decipher.setAutoPadding(false);
						if (encInfo.authLen > 0) {
							if (data.length - data._pos < encInfo.authLen) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
							decipher.setAuthTag(bufferSlice(data, data._pos, data._pos += encInfo.authLen));
						}
						privBlob = combineBuffers(decipher.update(privBlob), decipher.final());
					} catch (ex) {
						return ex;
					}
				}
				if (data._pos !== data.length) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
				ret = parseOpenSSHPrivKeys(privBlob, keyCount, cipherKey !== void 0);
			} else ret = [];
			if (ret instanceof Error) return ret;
			return ret[0];
		};
		function parseOpenSSHPrivKeys(data, nkeys, decrypted) {
			const keys = [];
			if (data.length < 8) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
			if (readUInt32BE(data, 0) !== readUInt32BE(data, 4)) {
				if (decrypted) return /* @__PURE__ */ new Error("OpenSSH key integrity check failed -- bad passphrase?");
				return /* @__PURE__ */ new Error("OpenSSH key integrity check failed");
			}
			data._pos = 8;
			let i;
			let oid;
			for (i = 0; i < nkeys; ++i) {
				let algo;
				let privPEM;
				let pubPEM;
				let pubSSH;
				const type = readString(data, data._pos, true);
				if (type === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
				switch (type) {
					case "ssh-rsa": {
						const n = readString(data, data._pos);
						if (n === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const e = readString(data, data._pos);
						if (e === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const d = readString(data, data._pos);
						if (d === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const iqmp = readString(data, data._pos);
						if (iqmp === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const p = readString(data, data._pos);
						if (p === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const q = readString(data, data._pos);
						if (q === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						pubPEM = genOpenSSLRSAPub(n, e);
						pubSSH = genOpenSSHRSAPub(n, e);
						privPEM = genOpenSSLRSAPriv(n, e, d, iqmp, p, q);
						algo = "sha1";
						break;
					}
					case "ssh-dss": {
						const p = readString(data, data._pos);
						if (p === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const q = readString(data, data._pos);
						if (q === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const g = readString(data, data._pos);
						if (g === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const y = readString(data, data._pos);
						if (y === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const x = readString(data, data._pos);
						if (x === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						pubPEM = genOpenSSLDSAPub(p, q, g, y);
						pubSSH = genOpenSSHDSAPub(p, q, g, y);
						privPEM = genOpenSSLDSAPriv(p, q, g, y, x);
						algo = "sha1";
						break;
					}
					case "ssh-ed25519": {
						if (!eddsaSupported) return /* @__PURE__ */ new Error(`Unsupported OpenSSH private key type: ${type}`);
						const edpub = readString(data, data._pos);
						if (edpub === void 0 || edpub.length !== 32) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const edpriv = readString(data, data._pos);
						if (edpriv === void 0 || edpriv.length !== 64) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						pubPEM = genOpenSSLEdPub(edpub);
						pubSSH = genOpenSSHEdPub(edpub);
						privPEM = genOpenSSLEdPriv(bufferSlice(edpriv, 0, 32));
						algo = null;
						break;
					}
					case "ecdsa-sha2-nistp256":
						algo = "sha256";
						oid = "1.2.840.10045.3.1.7";
					case "ecdsa-sha2-nistp384": if (algo === void 0) {
						algo = "sha384";
						oid = "1.3.132.0.34";
					}
					case "ecdsa-sha2-nistp521": {
						if (algo === void 0) {
							algo = "sha512";
							oid = "1.3.132.0.35";
						}
						if (!skipFields(data, 1)) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const ecpub = readString(data, data._pos);
						if (ecpub === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						const ecpriv = readString(data, data._pos);
						if (ecpriv === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
						pubPEM = genOpenSSLECDSAPub(oid, ecpub);
						pubSSH = genOpenSSHECDSAPub(oid, ecpub);
						privPEM = genOpenSSLECDSAPriv(oid, ecpub, ecpriv);
						break;
					}
					default: return /* @__PURE__ */ new Error(`Unsupported OpenSSH private key type: ${type}`);
				}
				const privComment = readString(data, data._pos, true);
				if (privComment === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
				keys.push(new OpenSSH_Private(type, privComment, privPEM, pubPEM, pubSSH, algo, decrypted));
			}
			let cnt = 0;
			for (i = data._pos; i < data.length; ++i) if (data[i] !== ++cnt % 255) return /* @__PURE__ */ new Error("Malformed OpenSSH private key");
			return keys;
		}
	}
	function OpenSSH_Old_Private(type, comment, privPEM, pubPEM, pubSSH, algo, decrypted) {
		this.type = type;
		this.comment = comment;
		this[SYM_PRIV_PEM] = privPEM;
		this[SYM_PUB_PEM] = pubPEM;
		this[SYM_PUB_SSH] = pubSSH;
		this[SYM_HASH_ALGO] = algo;
		this[SYM_DECRYPTED] = decrypted;
	}
	OpenSSH_Old_Private.prototype = BaseKey;
	{
		const regexp = /^-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----(?:\r\n|\n)((?:[^:]+:\s*[\S].*(?:\r\n|\n))*)([\s\S]+)(?:\r\n|\n)-----END (RSA|DSA|EC) PRIVATE KEY-----$/;
		OpenSSH_Old_Private.parse = (str, passphrase) => {
			const m = regexp.exec(str);
			if (m === null) return null;
			let privBlob = Buffer.from(m[3], "base64");
			let headers = m[2];
			let decrypted = false;
			if (headers !== void 0) {
				headers = headers.split(/\r\n|\n/g);
				for (let i = 0; i < headers.length; ++i) {
					const header = headers[i];
					let sepIdx = header.indexOf(":");
					if (header.slice(0, sepIdx) === "DEK-Info") {
						const val = header.slice(sepIdx + 2);
						sepIdx = val.indexOf(",");
						if (sepIdx === -1) continue;
						const cipherName = val.slice(0, sepIdx).toLowerCase();
						if (supportedOpenSSLCiphers.indexOf(cipherName) === -1) return /* @__PURE__ */ new Error(`Cipher (${cipherName}) not supported for encrypted OpenSSH private key`);
						const encInfo = CIPHER_INFO_OPENSSL[cipherName];
						if (!encInfo) return /* @__PURE__ */ new Error(`Cipher (${cipherName}) not supported for encrypted OpenSSH private key`);
						const cipherIV = Buffer.from(val.slice(sepIdx + 1), "hex");
						if (cipherIV.length !== encInfo.ivLen) return /* @__PURE__ */ new Error("Malformed encrypted OpenSSH private key");
						if (!passphrase) return /* @__PURE__ */ new Error("Encrypted OpenSSH private key detected, but no passphrase given");
						const ivSlice = bufferSlice(cipherIV, 0, 8);
						let cipherKey = createHash$3("md5").update(passphrase).update(ivSlice).digest();
						while (cipherKey.length < encInfo.keyLen) cipherKey = combineBuffers(cipherKey, createHash$3("md5").update(cipherKey).update(passphrase).update(ivSlice).digest());
						if (cipherKey.length > encInfo.keyLen) cipherKey = bufferSlice(cipherKey, 0, encInfo.keyLen);
						try {
							const decipher = createDecipheriv(cipherName, cipherKey, cipherIV);
							decipher.setAutoPadding(false);
							privBlob = combineBuffers(decipher.update(privBlob), decipher.final());
							decrypted = true;
						} catch (ex) {
							return ex;
						}
					}
				}
			}
			let type;
			let privPEM;
			let pubPEM;
			let pubSSH;
			let algo;
			let reader;
			let errMsg = "Malformed OpenSSH private key";
			if (decrypted) errMsg += ". Bad passphrase?";
			switch (m[1]) {
				case "RSA":
					type = "ssh-rsa";
					privPEM = makePEM("RSA PRIVATE", privBlob);
					try {
						reader = new Ber.Reader(privBlob);
						reader.readSequence();
						reader.readInt();
						const n = reader.readString(Ber.Integer, true);
						if (n === null) return new Error(errMsg);
						const e = reader.readString(Ber.Integer, true);
						if (e === null) return new Error(errMsg);
						pubPEM = genOpenSSLRSAPub(n, e);
						pubSSH = genOpenSSHRSAPub(n, e);
					} catch {
						return new Error(errMsg);
					}
					algo = "sha1";
					break;
				case "DSA":
					type = "ssh-dss";
					privPEM = makePEM("DSA PRIVATE", privBlob);
					try {
						reader = new Ber.Reader(privBlob);
						reader.readSequence();
						reader.readInt();
						const p = reader.readString(Ber.Integer, true);
						if (p === null) return new Error(errMsg);
						const q = reader.readString(Ber.Integer, true);
						if (q === null) return new Error(errMsg);
						const g = reader.readString(Ber.Integer, true);
						if (g === null) return new Error(errMsg);
						const y = reader.readString(Ber.Integer, true);
						if (y === null) return new Error(errMsg);
						pubPEM = genOpenSSLDSAPub(p, q, g, y);
						pubSSH = genOpenSSHDSAPub(p, q, g, y);
					} catch {
						return new Error(errMsg);
					}
					algo = "sha1";
					break;
				case "EC": {
					let ecSSLName;
					let ecPriv;
					let ecOID;
					try {
						reader = new Ber.Reader(privBlob);
						reader.readSequence();
						reader.readInt();
						ecPriv = reader.readString(Ber.OctetString, true);
						reader.readByte();
						const offset = reader.readLength();
						if (offset !== null) {
							reader._offset = offset;
							ecOID = reader.readOID();
							if (ecOID === null) return new Error(errMsg);
							switch (ecOID) {
								case "1.2.840.10045.3.1.7":
									ecSSLName = "prime256v1";
									type = "ecdsa-sha2-nistp256";
									algo = "sha256";
									break;
								case "1.3.132.0.34":
									ecSSLName = "secp384r1";
									type = "ecdsa-sha2-nistp384";
									algo = "sha384";
									break;
								case "1.3.132.0.35":
									ecSSLName = "secp521r1";
									type = "ecdsa-sha2-nistp521";
									algo = "sha512";
									break;
								default: return /* @__PURE__ */ new Error(`Unsupported private key EC OID: ${ecOID}`);
							}
						} else return new Error(errMsg);
					} catch {
						return new Error(errMsg);
					}
					privPEM = makePEM("EC PRIVATE", privBlob);
					const pubBlob = genOpenSSLECDSAPubFromPriv(ecSSLName, ecPriv);
					pubPEM = genOpenSSLECDSAPub(ecOID, pubBlob);
					pubSSH = genOpenSSHECDSAPub(ecOID, pubBlob);
					break;
				}
			}
			return new OpenSSH_Old_Private(type, "", privPEM, pubPEM, pubSSH, algo, decrypted);
		};
	}
	function PPK_Private(type, comment, privPEM, pubPEM, pubSSH, algo, decrypted) {
		this.type = type;
		this.comment = comment;
		this[SYM_PRIV_PEM] = privPEM;
		this[SYM_PUB_PEM] = pubPEM;
		this[SYM_PUB_SSH] = pubSSH;
		this[SYM_HASH_ALGO] = algo;
		this[SYM_DECRYPTED] = decrypted;
	}
	PPK_Private.prototype = BaseKey;
	{
		const EMPTY_PASSPHRASE = Buffer.alloc(0);
		const PPK_IV = Buffer.from([
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0
		]);
		const PPK_PP1 = Buffer.from([
			0,
			0,
			0,
			0
		]);
		const PPK_PP2 = Buffer.from([
			0,
			0,
			0,
			1
		]);
		const regexp = /^PuTTY-User-Key-File-2: (ssh-(?:rsa|dss))\r?\nEncryption: (aes256-cbc|none)\r?\nComment: ([^\r\n]*)\r?\nPublic-Lines: \d+\r?\n([\s\S]+?)\r?\nPrivate-Lines: \d+\r?\n([\s\S]+?)\r?\nPrivate-MAC: ([^\r\n]+)/;
		PPK_Private.parse = (str, passphrase) => {
			const m = regexp.exec(str);
			if (m === null) return null;
			const cipherName = m[2];
			const encrypted = cipherName !== "none";
			if (encrypted && !passphrase) return /* @__PURE__ */ new Error("Encrypted PPK private key detected, but no passphrase given");
			let privBlob = Buffer.from(m[5], "base64");
			if (encrypted) {
				const encInfo = CIPHER_INFO[cipherName];
				let cipherKey = combineBuffers(createHash$3("sha1").update(PPK_PP1).update(passphrase).digest(), createHash$3("sha1").update(PPK_PP2).update(passphrase).digest());
				if (cipherKey.length > encInfo.keyLen) cipherKey = bufferSlice(cipherKey, 0, encInfo.keyLen);
				try {
					const decipher = createDecipheriv(encInfo.sslName, cipherKey, PPK_IV);
					decipher.setAutoPadding(false);
					privBlob = combineBuffers(decipher.update(privBlob), decipher.final());
				} catch (ex) {
					return ex;
				}
			}
			const type = m[1];
			const comment = m[3];
			const pubBlob = Buffer.from(m[4], "base64");
			const mac = m[6];
			const typeLen = type.length;
			const cipherNameLen = cipherName.length;
			const commentLen = Buffer.byteLength(comment);
			const pubLen = pubBlob.length;
			const privLen = privBlob.length;
			const macData = Buffer.allocUnsafe(4 + typeLen + 4 + cipherNameLen + 4 + commentLen + 4 + pubLen + 4 + privLen);
			let p = 0;
			writeUInt32BE(macData, typeLen, p);
			macData.utf8Write(type, p += 4, typeLen);
			writeUInt32BE(macData, cipherNameLen, p += typeLen);
			macData.utf8Write(cipherName, p += 4, cipherNameLen);
			writeUInt32BE(macData, commentLen, p += cipherNameLen);
			macData.utf8Write(comment, p += 4, commentLen);
			writeUInt32BE(macData, pubLen, p += commentLen);
			macData.set(pubBlob, p += 4);
			writeUInt32BE(macData, privLen, p += pubLen);
			macData.set(privBlob, p + 4);
			if (!passphrase) passphrase = EMPTY_PASSPHRASE;
			if (createHmac("sha1", createHash$3("sha1").update("putty-private-key-file-mac-key").update(passphrase).digest()).update(macData).digest("hex") !== mac) {
				if (encrypted) return /* @__PURE__ */ new Error("PPK private key integrity check failed -- bad passphrase?");
				return /* @__PURE__ */ new Error("PPK private key integrity check failed");
			}
			let pubPEM;
			let pubSSH;
			let privPEM;
			pubBlob._pos = 0;
			skipFields(pubBlob, 1);
			switch (type) {
				case "ssh-rsa": {
					const e = readString(pubBlob, pubBlob._pos);
					if (e === void 0) return /* @__PURE__ */ new Error("Malformed PPK public key");
					const n = readString(pubBlob, pubBlob._pos);
					if (n === void 0) return /* @__PURE__ */ new Error("Malformed PPK public key");
					const d = readString(privBlob, 0);
					if (d === void 0) return /* @__PURE__ */ new Error("Malformed PPK private key");
					const p = readString(privBlob, privBlob._pos);
					if (p === void 0) return /* @__PURE__ */ new Error("Malformed PPK private key");
					const q = readString(privBlob, privBlob._pos);
					if (q === void 0) return /* @__PURE__ */ new Error("Malformed PPK private key");
					const iqmp = readString(privBlob, privBlob._pos);
					if (iqmp === void 0) return /* @__PURE__ */ new Error("Malformed PPK private key");
					pubPEM = genOpenSSLRSAPub(n, e);
					pubSSH = genOpenSSHRSAPub(n, e);
					privPEM = genOpenSSLRSAPriv(n, e, d, iqmp, p, q);
					break;
				}
				case "ssh-dss": {
					const p = readString(pubBlob, pubBlob._pos);
					if (p === void 0) return /* @__PURE__ */ new Error("Malformed PPK public key");
					const q = readString(pubBlob, pubBlob._pos);
					if (q === void 0) return /* @__PURE__ */ new Error("Malformed PPK public key");
					const g = readString(pubBlob, pubBlob._pos);
					if (g === void 0) return /* @__PURE__ */ new Error("Malformed PPK public key");
					const y = readString(pubBlob, pubBlob._pos);
					if (y === void 0) return /* @__PURE__ */ new Error("Malformed PPK public key");
					const x = readString(privBlob, 0);
					if (x === void 0) return /* @__PURE__ */ new Error("Malformed PPK private key");
					pubPEM = genOpenSSLDSAPub(p, q, g, y);
					pubSSH = genOpenSSHDSAPub(p, q, g, y);
					privPEM = genOpenSSLDSAPriv(p, q, g, y, x);
					break;
				}
			}
			return new PPK_Private(type, comment, privPEM, pubPEM, pubSSH, "sha1", encrypted);
		};
	}
	function OpenSSH_Public(type, comment, pubPEM, pubSSH, algo) {
		this.type = type;
		this.comment = comment;
		this[SYM_PRIV_PEM] = null;
		this[SYM_PUB_PEM] = pubPEM;
		this[SYM_PUB_SSH] = pubSSH;
		this[SYM_HASH_ALGO] = algo;
		this[SYM_DECRYPTED] = false;
	}
	OpenSSH_Public.prototype = BaseKey;
	{
		let regexp;
		if (eddsaSupported) regexp = /^(((?:ssh-(?:rsa|dss|ed25519))|ecdsa-sha2-nistp(?:256|384|521))(?:-cert-v0[01]@openssh.com)?) ([A-Z0-9a-z/+=]+)(?:$|\s+([\S].*)?)$/;
		else regexp = /^(((?:ssh-(?:rsa|dss))|ecdsa-sha2-nistp(?:256|384|521))(?:-cert-v0[01]@openssh.com)?) ([A-Z0-9a-z/+=]+)(?:$|\s+([\S].*)?)$/;
		OpenSSH_Public.parse = (str) => {
			const m = regexp.exec(str);
			if (m === null) return null;
			const fullType = m[1];
			const baseType = m[2];
			const data = Buffer.from(m[3], "base64");
			const comment = m[4] || "";
			const type = readString(data, data._pos, true);
			if (type === void 0 || type.indexOf(baseType) !== 0) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
			return parseDER(data, baseType, comment, fullType);
		};
	}
	function RFC4716_Public(type, comment, pubPEM, pubSSH, algo) {
		this.type = type;
		this.comment = comment;
		this[SYM_PRIV_PEM] = null;
		this[SYM_PUB_PEM] = pubPEM;
		this[SYM_PUB_SSH] = pubSSH;
		this[SYM_HASH_ALGO] = algo;
		this[SYM_DECRYPTED] = false;
	}
	RFC4716_Public.prototype = BaseKey;
	{
		const regexp = /^---- BEGIN SSH2 PUBLIC KEY ----(?:\r?\n)((?:.{0,72}\r?\n)+)---- END SSH2 PUBLIC KEY ----$/;
		const RE_DATA = /^[A-Z0-9a-z/+=\r\n]+$/;
		const RE_HEADER = /^([\x21-\x39\x3B-\x7E]{1,64}): ((?:[^\\]*\\\r?\n)*[^\r\n]+)\r?\n/gm;
		const RE_HEADER_ENDS = /\\\r?\n/g;
		RFC4716_Public.parse = (str) => {
			let m = regexp.exec(str);
			if (m === null) return null;
			const body = m[1];
			let dataStart = 0;
			let comment = "";
			while (m = RE_HEADER.exec(body)) {
				const headerName = m[1];
				const headerValue = m[2].replace(RE_HEADER_ENDS, "");
				if (headerValue.length > 1024) {
					RE_HEADER.lastIndex = 0;
					return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
				}
				dataStart = RE_HEADER.lastIndex;
				if (headerName.toLowerCase() === "comment") {
					comment = headerValue;
					if (comment.length > 1 && comment.charCodeAt(0) === 34 && comment.charCodeAt(comment.length - 1) === 34) comment = comment.slice(1, -1);
				}
			}
			let data = body.slice(dataStart);
			if (!RE_DATA.test(data)) return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
			data = Buffer.from(data, "base64");
			const type = readString(data, 0, true);
			if (type === void 0) return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
			let pubPEM = null;
			let pubSSH = null;
			switch (type) {
				case "ssh-rsa": {
					const e = readString(data, data._pos);
					if (e === void 0) return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
					const n = readString(data, data._pos);
					if (n === void 0) return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
					pubPEM = genOpenSSLRSAPub(n, e);
					pubSSH = genOpenSSHRSAPub(n, e);
					break;
				}
				case "ssh-dss": {
					const p = readString(data, data._pos);
					if (p === void 0) return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
					const q = readString(data, data._pos);
					if (q === void 0) return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
					const g = readString(data, data._pos);
					if (g === void 0) return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
					const y = readString(data, data._pos);
					if (y === void 0) return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
					pubPEM = genOpenSSLDSAPub(p, q, g, y);
					pubSSH = genOpenSSHDSAPub(p, q, g, y);
					break;
				}
				default: return /* @__PURE__ */ new Error("Malformed RFC4716 public key");
			}
			return new RFC4716_Public(type, comment, pubPEM, pubSSH, "sha1");
		};
	}
	function parseDER(data, baseType, comment, fullType) {
		if (!isSupportedKeyType(baseType)) return /* @__PURE__ */ new Error(`Unsupported OpenSSH public key type: ${baseType}`);
		let algo;
		let oid;
		let pubPEM = null;
		let pubSSH = null;
		switch (baseType) {
			case "ssh-rsa": {
				const e = readString(data, data._pos || 0);
				if (e === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
				const n = readString(data, data._pos);
				if (n === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
				pubPEM = genOpenSSLRSAPub(n, e);
				pubSSH = genOpenSSHRSAPub(n, e);
				algo = "sha1";
				break;
			}
			case "ssh-dss": {
				const p = readString(data, data._pos || 0);
				if (p === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
				const q = readString(data, data._pos);
				if (q === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
				const g = readString(data, data._pos);
				if (g === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
				const y = readString(data, data._pos);
				if (y === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
				pubPEM = genOpenSSLDSAPub(p, q, g, y);
				pubSSH = genOpenSSHDSAPub(p, q, g, y);
				algo = "sha1";
				break;
			}
			case "ssh-ed25519": {
				const edpub = readString(data, data._pos || 0);
				if (edpub === void 0 || edpub.length !== 32) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
				pubPEM = genOpenSSLEdPub(edpub);
				pubSSH = genOpenSSHEdPub(edpub);
				algo = null;
				break;
			}
			case "ecdsa-sha2-nistp256":
				algo = "sha256";
				oid = "1.2.840.10045.3.1.7";
			case "ecdsa-sha2-nistp384": if (algo === void 0) {
				algo = "sha384";
				oid = "1.3.132.0.34";
			}
			case "ecdsa-sha2-nistp521": {
				if (algo === void 0) {
					algo = "sha512";
					oid = "1.3.132.0.35";
				}
				if (!skipFields(data, 1)) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
				const ecpub = readString(data, data._pos || 0);
				if (ecpub === void 0) return /* @__PURE__ */ new Error("Malformed OpenSSH public key");
				pubPEM = genOpenSSLECDSAPub(oid, ecpub);
				pubSSH = genOpenSSHECDSAPub(oid, ecpub);
				break;
			}
			default: return /* @__PURE__ */ new Error(`Unsupported OpenSSH public key type: ${baseType}`);
		}
		return new OpenSSH_Public(fullType, comment, pubPEM, pubSSH, algo);
	}
	function isSupportedKeyType(type) {
		switch (type) {
			case "ssh-rsa":
			case "ssh-dss":
			case "ecdsa-sha2-nistp256":
			case "ecdsa-sha2-nistp384":
			case "ecdsa-sha2-nistp521": return true;
			case "ssh-ed25519": if (eddsaSupported) return true;
			default: return false;
		}
	}
	function isParsedKey(val) {
		if (!val) return false;
		return typeof val[SYM_DECRYPTED] === "boolean";
	}
	function parseKey(data, passphrase) {
		if (isParsedKey(data)) return data;
		let origBuffer;
		if (Buffer.isBuffer(data)) {
			origBuffer = data;
			data = data.utf8Slice(0, data.length).trim();
		} else if (typeof data === "string") data = data.trim();
		else return /* @__PURE__ */ new Error("Key data must be a Buffer or string");
		if (passphrase != void 0) {
			if (typeof passphrase === "string") passphrase = Buffer.from(passphrase);
			else if (!Buffer.isBuffer(passphrase)) return /* @__PURE__ */ new Error("Passphrase must be a string or Buffer when supplied");
		}
		let ret;
		if ((ret = OpenSSH_Private.parse(data, passphrase)) !== null) return ret;
		if ((ret = OpenSSH_Old_Private.parse(data, passphrase)) !== null) return ret;
		if ((ret = PPK_Private.parse(data, passphrase)) !== null) return ret;
		if ((ret = OpenSSH_Public.parse(data)) !== null) return ret;
		if ((ret = RFC4716_Public.parse(data)) !== null) return ret;
		if (origBuffer) {
			binaryKeyParser.init(origBuffer, 0);
			const type = binaryKeyParser.readString(true);
			if (type !== void 0) {
				data = binaryKeyParser.readRaw();
				if (data !== void 0) {
					ret = parseDER(data, type, "", type);
					if (ret instanceof Error) ret = null;
				}
			}
			binaryKeyParser.clear();
		}
		if (ret) return ret;
		return /* @__PURE__ */ new Error("Unsupported key format");
	}
	module.exports = {
		isParsedKey,
		isSupportedKeyType,
		parseDERKey: (data, type) => parseDER(data, type, "", type),
		parseKey
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/agent.js
var require_agent = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { Socket: Socket$1 } = __require("net");
	const { Duplex } = __require("stream");
	const { resolve } = __require("path");
	const { readFile } = __require("fs");
	const { execFile, spawn } = __require("child_process");
	const { isParsedKey, parseKey } = require_keyParser();
	const { makeBufferParser, readUInt32BE, writeUInt32BE, writeUInt32LE } = require_utils$1();
	function once(cb) {
		let called = false;
		return (...args) => {
			if (called) return;
			called = true;
			cb(...args);
		};
	}
	function concat(buf1, buf2) {
		const combined = Buffer.allocUnsafe(buf1.length + buf2.length);
		buf1.copy(combined, 0);
		buf2.copy(combined, buf1.length);
		return combined;
	}
	function noop() {}
	const EMPTY_BUF = Buffer.alloc(0);
	const binaryParser = makeBufferParser();
	var BaseAgent = class {
		getIdentities(cb) {
			cb(/* @__PURE__ */ new Error("Missing getIdentities() implementation"));
		}
		sign(pubKey, data, options, cb) {
			if (typeof options === "function") cb = options;
			cb(/* @__PURE__ */ new Error("Missing sign() implementation"));
		}
	};
	var OpenSSHAgent = class extends BaseAgent {
		constructor(socketPath) {
			super();
			this.socketPath = socketPath;
		}
		getStream(cb) {
			cb = once(cb);
			const sock = new Socket$1();
			sock.on("connect", () => {
				cb(null, sock);
			});
			sock.on("close", onFail).on("end", onFail).on("error", onFail);
			sock.connect(this.socketPath);
			function onFail() {
				try {
					sock.destroy();
				} catch {}
				cb(/* @__PURE__ */ new Error("Failed to connect to agent"));
			}
		}
		getIdentities(cb) {
			cb = once(cb);
			this.getStream((err, stream) => {
				function onFail(err) {
					if (stream) try {
						stream.destroy();
					} catch {}
					if (!err) err = /* @__PURE__ */ new Error("Failed to retrieve identities from agent");
					cb(err);
				}
				if (err) return onFail(err);
				const protocol = new AgentProtocol(true);
				protocol.on("error", onFail);
				protocol.pipe(stream).pipe(protocol);
				stream.on("close", onFail).on("end", onFail).on("error", onFail);
				protocol.getIdentities((err, keys) => {
					if (err) return onFail(err);
					try {
						stream.destroy();
					} catch {}
					cb(null, keys);
				});
			});
		}
		sign(pubKey, data, options, cb) {
			if (typeof options === "function") {
				cb = options;
				options = void 0;
			} else if (typeof options !== "object" || options === null) options = void 0;
			cb = once(cb);
			this.getStream((err, stream) => {
				function onFail(err) {
					if (stream) try {
						stream.destroy();
					} catch {}
					if (!err) err = /* @__PURE__ */ new Error("Failed to sign data with agent");
					cb(err);
				}
				if (err) return onFail(err);
				const protocol = new AgentProtocol(true);
				protocol.on("error", onFail);
				protocol.pipe(stream).pipe(protocol);
				stream.on("close", onFail).on("end", onFail).on("error", onFail);
				protocol.sign(pubKey, data, options, (err, sig) => {
					if (err) return onFail(err);
					try {
						stream.destroy();
					} catch {}
					cb(null, sig);
				});
			});
		}
	};
	const PageantAgent = (() => {
		const RET_ERR_BADARGS = 10;
		const RET_ERR_UNAVAILABLE = 11;
		const RET_ERR_NOMAP = 12;
		const RET_ERR_BINSTDIN = 13;
		const RET_ERR_BINSTDOUT = 14;
		const RET_ERR_BADLEN = 15;
		const EXEPATH = resolve(__dirname, "..", "util/pagent.exe");
		const ERROR = {
			[RET_ERR_BADARGS]: /* @__PURE__ */ new Error("Invalid pagent.exe arguments"),
			[RET_ERR_UNAVAILABLE]: /* @__PURE__ */ new Error("Pageant is not running"),
			[RET_ERR_NOMAP]: /* @__PURE__ */ new Error("pagent.exe could not create an mmap"),
			[RET_ERR_BINSTDIN]: /* @__PURE__ */ new Error("pagent.exe could not set mode for stdin"),
			[RET_ERR_BINSTDOUT]: /* @__PURE__ */ new Error("pagent.exe could not set mode for stdout"),
			[RET_ERR_BADLEN]: /* @__PURE__ */ new Error("pagent.exe did not get expected input payload")
		};
		function destroy(stream) {
			stream.buffer = null;
			if (stream.proc) {
				stream.proc.kill();
				stream.proc = void 0;
			}
		}
		class PageantSocket extends Duplex {
			constructor() {
				super();
				this.proc = void 0;
				this.buffer = null;
			}
			_read(n) {}
			_write(data, encoding, cb) {
				if (this.buffer === null) this.buffer = data;
				else {
					const newBuffer = Buffer.allocUnsafe(this.buffer.length + data.length);
					this.buffer.copy(newBuffer, 0);
					data.copy(newBuffer, this.buffer.length);
					this.buffer = newBuffer;
				}
				if (this.buffer.length < 4) return cb();
				const len = readUInt32BE(this.buffer, 0);
				if (this.buffer.length - 4 < len) return cb();
				data = this.buffer.slice(0, 4 + len);
				if (this.buffer.length > 4 + len) return cb(/* @__PURE__ */ new Error("Unexpected multiple agent requests"));
				this.buffer = null;
				let error;
				const proc = this.proc = spawn(EXEPATH, [data.length]);
				proc.stdout.on("data", (data) => {
					this.push(data);
				});
				proc.on("error", (err) => {
					error = err;
					cb(error);
				});
				proc.on("close", (code) => {
					this.proc = void 0;
					if (!error) {
						if (error = ERROR[code]) return cb(error);
						cb();
					}
				});
				proc.stdin.end(data);
			}
			_final(cb) {
				destroy(this);
				cb();
			}
			_destroy(err, cb) {
				destroy(this);
				cb();
			}
		}
		return class PageantAgent extends OpenSSHAgent {
			getStream(cb) {
				cb(null, new PageantSocket());
			}
		};
	})();
	const CygwinAgent = (() => {
		const RE_CYGWIN_SOCK = /^!<socket >(\d+) s ([A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8})/;
		return class CygwinAgent extends OpenSSHAgent {
			getStream(cb) {
				cb = once(cb);
				let socketPath = this.socketPath;
				let triedCygpath = false;
				readFile(socketPath, function readCygsocket(err, data) {
					if (err) {
						if (triedCygpath) return cb(/* @__PURE__ */ new Error("Invalid cygwin unix socket path"));
						execFile("cygpath", ["-w", socketPath], (err, stdout, stderr) => {
							if (err || stdout.length === 0) return cb(/* @__PURE__ */ new Error("Invalid cygwin unix socket path"));
							triedCygpath = true;
							socketPath = stdout.toString().replace(/[\r\n]/g, "");
							readFile(socketPath, readCygsocket);
						});
						return;
					}
					const m = RE_CYGWIN_SOCK.exec(data.toString("ascii"));
					if (!m) return cb(/* @__PURE__ */ new Error("Malformed cygwin unix socket file"));
					let state;
					let bc = 0;
					let isRetrying = false;
					const inBuf = [];
					let sock;
					let credsBuf = Buffer.alloc(12);
					const port = parseInt(m[1], 10);
					const secret = m[2].replace(/-/g, "");
					const secretBuf = Buffer.allocUnsafe(16);
					for (let i = 0, j = 0; j < 32; ++i, j += 2) secretBuf[i] = parseInt(secret.substring(j, j + 2), 16);
					for (let i = 0; i < 16; i += 4) writeUInt32LE(secretBuf, readUInt32BE(secretBuf, i), i);
					tryConnect();
					function _onconnect() {
						bc = 0;
						state = "secret";
						sock.write(secretBuf);
					}
					function _ondata(data) {
						bc += data.length;
						if (state === "secret") {
							if (bc === 16) {
								bc = 0;
								state = "creds";
								sock.write(credsBuf);
							}
							return;
						}
						if (state === "creds") {
							if (!isRetrying) inBuf.push(data);
							if (bc === 12) {
								sock.removeListener("connect", _onconnect);
								sock.removeListener("data", _ondata);
								sock.removeListener("error", onFail);
								sock.removeListener("end", onFail);
								sock.removeListener("close", onFail);
								if (isRetrying) return cb(null, sock);
								isRetrying = true;
								credsBuf = Buffer.concat(inBuf);
								writeUInt32LE(credsBuf, process.pid, 0);
								sock.on("error", () => {});
								sock.destroy();
								tryConnect();
							}
						}
					}
					function onFail() {
						cb(/* @__PURE__ */ new Error("Problem negotiating cygwin unix socket security"));
					}
					function tryConnect() {
						sock = new Socket$1();
						sock.on("connect", _onconnect);
						sock.on("data", _ondata);
						sock.on("error", onFail);
						sock.on("end", onFail);
						sock.on("close", onFail);
						sock.connect(port);
					}
				});
			}
		};
	})();
	const WINDOWS_PIPE_REGEX = /^[/\\][/\\]\.[/\\]pipe[/\\].+/;
	function createAgent(path) {
		if (process.platform === "win32" && !WINDOWS_PIPE_REGEX.test(path)) return path === "pageant" ? new PageantAgent() : new CygwinAgent(path);
		return new OpenSSHAgent(path);
	}
	const AgentProtocol = (() => {
		const SSH_AGENTC_REQUEST_IDENTITIES = 11;
		const SSH_AGENTC_SIGN_REQUEST = 13;
		const SSH_AGENT_FAILURE = 5;
		const SSH_AGENT_IDENTITIES_ANSWER = 12;
		const SSH_AGENT_SIGN_RESPONSE = 14;
		const SSH_AGENT_RSA_SHA2_256 = 2;
		const SSH_AGENT_RSA_SHA2_512 = 4;
		const ROLE_CLIENT = 0;
		const ROLE_SERVER = 1;
		function processResponses(protocol) {
			let ret;
			while (protocol[SYM_REQS].length) {
				const nextResponse = protocol[SYM_REQS][0][SYM_RESP];
				if (nextResponse === void 0) break;
				protocol[SYM_REQS].shift();
				ret = protocol.push(nextResponse);
			}
			return ret;
		}
		const SYM_TYPE = Symbol("Inbound Request Type");
		const SYM_RESP = Symbol("Inbound Request Response");
		const SYM_CTX = Symbol("Inbound Request Context");
		class AgentInboundRequest {
			constructor(type, ctx) {
				this[SYM_TYPE] = type;
				this[SYM_RESP] = void 0;
				this[SYM_CTX] = ctx;
			}
			hasResponded() {
				return this[SYM_RESP] !== void 0;
			}
			getType() {
				return this[SYM_TYPE];
			}
			getContext() {
				return this[SYM_CTX];
			}
		}
		function respond(protocol, req, data) {
			req[SYM_RESP] = data;
			return processResponses(protocol);
		}
		function cleanup(protocol) {
			protocol[SYM_BUFFER] = null;
			if (protocol[SYM_MODE] === ROLE_CLIENT) {
				const reqs = protocol[SYM_REQS];
				if (reqs && reqs.length) {
					protocol[SYM_REQS] = [];
					for (const req of reqs) req.cb(/* @__PURE__ */ new Error("No reply from server"));
				}
			}
			try {
				protocol.end();
			} catch {}
			setImmediate(() => {
				if (!protocol[SYM_ENDED]) protocol.emit("end");
				if (!protocol[SYM_CLOSED]) protocol.emit("close");
			});
		}
		function onClose() {
			this[SYM_CLOSED] = true;
		}
		function onEnd() {
			this[SYM_ENDED] = true;
		}
		const SYM_REQS = Symbol("Requests");
		const SYM_MODE = Symbol("Agent Protocol Role");
		const SYM_BUFFER = Symbol("Agent Protocol Buffer");
		const SYM_MSGLEN = Symbol("Agent Protocol Current Message Length");
		const SYM_CLOSED = Symbol("Agent Protocol Closed");
		const SYM_ENDED = Symbol("Agent Protocol Ended");
		return class AgentProtocol extends Duplex {
			constructor(isClient) {
				super({
					autoDestroy: true,
					emitClose: false
				});
				this[SYM_MODE] = isClient ? ROLE_CLIENT : ROLE_SERVER;
				this[SYM_REQS] = [];
				this[SYM_BUFFER] = null;
				this[SYM_MSGLEN] = -1;
				this.once("end", onEnd);
				this.once("close", onClose);
			}
			_read(n) {}
			_write(data, encoding, cb) {
				if (this[SYM_BUFFER] === null) this[SYM_BUFFER] = data;
				else this[SYM_BUFFER] = concat(this[SYM_BUFFER], data);
				let buffer = this[SYM_BUFFER];
				let bufferLen = buffer.length;
				let p = 0;
				while (p < bufferLen) {
					if (bufferLen < 5) break;
					if (this[SYM_MSGLEN] === -1) this[SYM_MSGLEN] = readUInt32BE(buffer, p);
					if (bufferLen < 4 + this[SYM_MSGLEN]) break;
					const msgType = buffer[p += 4];
					++p;
					if (this[SYM_MODE] === ROLE_CLIENT) {
						if (this[SYM_REQS].length === 0) return cb(/* @__PURE__ */ new Error("Received unexpected message from server"));
						const req = this[SYM_REQS].shift();
						switch (msgType) {
							case SSH_AGENT_FAILURE:
								req.cb(/* @__PURE__ */ new Error("Agent responded with failure"));
								break;
							case SSH_AGENT_IDENTITIES_ANSWER: {
								if (req.type !== SSH_AGENTC_REQUEST_IDENTITIES) return cb(/* @__PURE__ */ new Error("Agent responded with wrong message type"));
								binaryParser.init(buffer, p);
								const numKeys = binaryParser.readUInt32BE();
								if (numKeys === void 0) {
									binaryParser.clear();
									return cb(/* @__PURE__ */ new Error("Malformed agent response"));
								}
								const keys = [];
								for (let i = 0; i < numKeys; ++i) {
									let pubKey = binaryParser.readString();
									if (pubKey === void 0) {
										binaryParser.clear();
										return cb(/* @__PURE__ */ new Error("Malformed agent response"));
									}
									const comment = binaryParser.readString(true);
									if (comment === void 0) {
										binaryParser.clear();
										return cb(/* @__PURE__ */ new Error("Malformed agent response"));
									}
									pubKey = parseKey(pubKey);
									if (pubKey instanceof Error) continue;
									pubKey.comment = pubKey.comment || comment;
									keys.push(pubKey);
								}
								p = binaryParser.pos();
								binaryParser.clear();
								req.cb(null, keys);
								break;
							}
							case SSH_AGENT_SIGN_RESPONSE: {
								if (req.type !== SSH_AGENTC_SIGN_REQUEST) return cb(/* @__PURE__ */ new Error("Agent responded with wrong message type"));
								binaryParser.init(buffer, p);
								let signature = binaryParser.readString();
								p = binaryParser.pos();
								binaryParser.clear();
								if (signature === void 0) return cb(/* @__PURE__ */ new Error("Malformed agent response"));
								binaryParser.init(signature, 0);
								binaryParser.readString(true);
								signature = binaryParser.readString();
								binaryParser.clear();
								if (signature === void 0) return cb(/* @__PURE__ */ new Error("Malformed OpenSSH signature format"));
								req.cb(null, signature);
								break;
							}
							default: return cb(/* @__PURE__ */ new Error("Agent responded with unsupported message type"));
						}
					} else switch (msgType) {
						case SSH_AGENTC_REQUEST_IDENTITIES: {
							const req = new AgentInboundRequest(msgType);
							this[SYM_REQS].push(req);
							this.emit("identities", req);
							break;
						}
						case SSH_AGENTC_SIGN_REQUEST: {
							binaryParser.init(buffer, p);
							let pubKey = binaryParser.readString();
							const data = binaryParser.readString();
							const flagsVal = binaryParser.readUInt32BE();
							p = binaryParser.pos();
							binaryParser.clear();
							if (flagsVal === void 0) {
								const req = new AgentInboundRequest(msgType);
								this[SYM_REQS].push(req);
								return this.failureReply(req);
							}
							pubKey = parseKey(pubKey);
							if (pubKey instanceof Error) {
								const req = new AgentInboundRequest(msgType);
								this[SYM_REQS].push(req);
								return this.failureReply(req);
							}
							const flags = { hash: void 0 };
							let ctx;
							if (pubKey.type === "ssh-rsa") {
								if (flagsVal & SSH_AGENT_RSA_SHA2_256) {
									ctx = "rsa-sha2-256";
									flags.hash = "sha256";
								} else if (flagsVal & SSH_AGENT_RSA_SHA2_512) {
									ctx = "rsa-sha2-512";
									flags.hash = "sha512";
								}
							}
							if (ctx === void 0) ctx = pubKey.type;
							const req = new AgentInboundRequest(msgType, ctx);
							this[SYM_REQS].push(req);
							this.emit("sign", req, pubKey, data, flags);
							break;
						}
						default: {
							const req = new AgentInboundRequest(msgType);
							this[SYM_REQS].push(req);
							this.failureReply(req);
						}
					}
					this[SYM_MSGLEN] = -1;
					if (p === bufferLen) {
						this[SYM_BUFFER] = null;
						break;
					} else {
						this[SYM_BUFFER] = buffer = buffer.slice(p);
						bufferLen = buffer.length;
						p = 0;
					}
				}
				cb();
			}
			_destroy(err, cb) {
				cleanup(this);
				cb();
			}
			_final(cb) {
				cleanup(this);
				cb();
			}
			sign(pubKey, data, options, cb) {
				if (this[SYM_MODE] !== ROLE_CLIENT) throw new Error("Client-only method called with server role");
				if (typeof options === "function") {
					cb = options;
					options = void 0;
				} else if (typeof options !== "object" || options === null) options = void 0;
				let flags = 0;
				pubKey = parseKey(pubKey);
				if (pubKey instanceof Error) throw new Error("Invalid public key argument");
				if (pubKey.type === "ssh-rsa" && options) switch (options.hash) {
					case "sha256":
						flags = SSH_AGENT_RSA_SHA2_256;
						break;
					case "sha512": flags = SSH_AGENT_RSA_SHA2_512;
				}
				pubKey = pubKey.getPublicSSH();
				const type = SSH_AGENTC_SIGN_REQUEST;
				const keyLen = pubKey.length;
				const dataLen = data.length;
				let p = 0;
				const buf = Buffer.allocUnsafe(9 + keyLen + 4 + dataLen + 4);
				writeUInt32BE(buf, buf.length - 4, p);
				buf[p += 4] = type;
				writeUInt32BE(buf, keyLen, ++p);
				pubKey.copy(buf, p += 4);
				writeUInt32BE(buf, dataLen, p += keyLen);
				data.copy(buf, p += 4);
				writeUInt32BE(buf, flags, p += dataLen);
				if (typeof cb !== "function") cb = noop;
				this[SYM_REQS].push({
					type,
					cb
				});
				return this.push(buf);
			}
			getIdentities(cb) {
				if (this[SYM_MODE] !== ROLE_CLIENT) throw new Error("Client-only method called with server role");
				const type = SSH_AGENTC_REQUEST_IDENTITIES;
				let p = 0;
				const buf = Buffer.allocUnsafe(5);
				writeUInt32BE(buf, buf.length - 4, p);
				buf[p += 4] = type;
				if (typeof cb !== "function") cb = noop;
				this[SYM_REQS].push({
					type,
					cb
				});
				return this.push(buf);
			}
			failureReply(req) {
				if (this[SYM_MODE] !== ROLE_SERVER) throw new Error("Server-only method called with client role");
				if (!(req instanceof AgentInboundRequest)) throw new Error("Wrong request argument");
				if (req.hasResponded()) return true;
				let p = 0;
				const buf = Buffer.allocUnsafe(5);
				writeUInt32BE(buf, buf.length - 4, p);
				buf[p += 4] = SSH_AGENT_FAILURE;
				return respond(this, req, buf);
			}
			getIdentitiesReply(req, keys) {
				if (this[SYM_MODE] !== ROLE_SERVER) throw new Error("Server-only method called with client role");
				if (!(req instanceof AgentInboundRequest)) throw new Error("Wrong request argument");
				if (req.hasResponded()) return true;
				if (req.getType() !== SSH_AGENTC_REQUEST_IDENTITIES) throw new Error("Invalid response to request");
				if (!Array.isArray(keys)) throw new Error("Keys argument must be an array");
				let totalKeysLen = 4;
				const newKeys = [];
				for (let i = 0; i < keys.length; ++i) {
					const entry = keys[i];
					if (typeof entry !== "object" || entry === null) throw new Error(`Invalid key entry: ${entry}`);
					let pubKey;
					let comment;
					if (isParsedKey(entry)) pubKey = entry;
					else if (isParsedKey(entry.pubKey)) pubKey = entry.pubKey;
					else {
						if (typeof entry.pubKey !== "object" || entry.pubKey === null) continue;
						({pubKey, comment} = entry.pubKey);
						pubKey = parseKey(pubKey);
						if (pubKey instanceof Error) continue;
					}
					comment = pubKey.comment || comment;
					pubKey = pubKey.getPublicSSH();
					totalKeysLen += 4 + pubKey.length;
					if (comment && typeof comment === "string") comment = Buffer.from(comment);
					else if (!Buffer.isBuffer(comment)) comment = EMPTY_BUF;
					totalKeysLen += 4 + comment.length;
					newKeys.push({
						pubKey,
						comment
					});
				}
				let p = 0;
				const buf = Buffer.allocUnsafe(5 + totalKeysLen);
				writeUInt32BE(buf, buf.length - 4, p);
				buf[p += 4] = SSH_AGENT_IDENTITIES_ANSWER;
				writeUInt32BE(buf, newKeys.length, ++p);
				p += 4;
				for (let i = 0; i < newKeys.length; ++i) {
					const { pubKey, comment } = newKeys[i];
					writeUInt32BE(buf, pubKey.length, p);
					pubKey.copy(buf, p += 4);
					writeUInt32BE(buf, comment.length, p += pubKey.length);
					p += 4;
					if (comment.length) {
						comment.copy(buf, p);
						p += comment.length;
					}
				}
				return respond(this, req, buf);
			}
			signReply(req, signature) {
				if (this[SYM_MODE] !== ROLE_SERVER) throw new Error("Server-only method called with client role");
				if (!(req instanceof AgentInboundRequest)) throw new Error("Wrong request argument");
				if (req.hasResponded()) return true;
				if (req.getType() !== SSH_AGENTC_SIGN_REQUEST) throw new Error("Invalid response to request");
				if (!Buffer.isBuffer(signature)) throw new Error("Signature argument must be a Buffer");
				if (signature.length === 0) throw new Error("Signature argument must be non-empty");
				let p = 0;
				const sigFormat = req.getContext();
				const sigFormatLen = Buffer.byteLength(sigFormat);
				const buf = Buffer.allocUnsafe(13 + sigFormatLen + 4 + signature.length);
				writeUInt32BE(buf, buf.length - 4, p);
				buf[p += 4] = SSH_AGENT_SIGN_RESPONSE;
				writeUInt32BE(buf, 4 + sigFormatLen + 4 + signature.length, ++p);
				writeUInt32BE(buf, sigFormatLen, p += 4);
				buf.utf8Write(sigFormat, p += 4, sigFormatLen);
				writeUInt32BE(buf, signature.length, p += sigFormatLen);
				signature.copy(buf, p += 4);
				return respond(this, req, buf);
			}
		};
	})();
	const SYM_AGENT = Symbol("Agent");
	const SYM_AGENT_KEYS = Symbol("Agent Keys");
	const SYM_AGENT_KEYS_IDX = Symbol("Agent Keys Index");
	const SYM_AGENT_CBS = Symbol("Agent Init Callbacks");
	var AgentContext = class {
		constructor(agent) {
			if (typeof agent === "string") agent = createAgent(agent);
			else if (!isAgent(agent)) throw new Error("Invalid agent argument");
			this[SYM_AGENT] = agent;
			this[SYM_AGENT_KEYS] = null;
			this[SYM_AGENT_KEYS_IDX] = -1;
			this[SYM_AGENT_CBS] = null;
		}
		init(cb) {
			if (typeof cb !== "function") cb = noop;
			if (this[SYM_AGENT_KEYS] === null) {
				if (this[SYM_AGENT_CBS] === null) {
					this[SYM_AGENT_CBS] = [cb];
					const doCbs = (...args) => {
						process.nextTick(() => {
							const cbs = this[SYM_AGENT_CBS];
							this[SYM_AGENT_CBS] = null;
							for (const cb of cbs) cb(...args);
						});
					};
					this[SYM_AGENT].getIdentities(once((err, keys) => {
						if (err) return doCbs(err);
						if (!Array.isArray(keys)) return doCbs(/* @__PURE__ */ new Error("Agent implementation failed to provide keys"));
						const newKeys = [];
						for (let key of keys) {
							key = parseKey(key);
							if (key instanceof Error) continue;
							newKeys.push(key);
						}
						this[SYM_AGENT_KEYS] = newKeys;
						this[SYM_AGENT_KEYS_IDX] = -1;
						doCbs();
					}));
				} else this[SYM_AGENT_CBS].push(cb);
			} else process.nextTick(cb);
		}
		nextKey() {
			if (this[SYM_AGENT_KEYS] === null || ++this[SYM_AGENT_KEYS_IDX] >= this[SYM_AGENT_KEYS].length) return false;
			return this[SYM_AGENT_KEYS][this[SYM_AGENT_KEYS_IDX]];
		}
		currentKey() {
			if (this[SYM_AGENT_KEYS] === null || this[SYM_AGENT_KEYS_IDX] >= this[SYM_AGENT_KEYS].length) return null;
			return this[SYM_AGENT_KEYS][this[SYM_AGENT_KEYS_IDX]];
		}
		pos() {
			if (this[SYM_AGENT_KEYS] === null || this[SYM_AGENT_KEYS_IDX] >= this[SYM_AGENT_KEYS].length) return -1;
			return this[SYM_AGENT_KEYS_IDX];
		}
		reset() {
			this[SYM_AGENT_KEYS_IDX] = -1;
		}
		sign(...args) {
			this[SYM_AGENT].sign(...args);
		}
	};
	function isAgent(val) {
		return val instanceof BaseAgent;
	}
	module.exports = {
		AgentContext,
		AgentProtocol,
		BaseAgent,
		createAgent,
		CygwinAgent,
		isAgent,
		OpenSSHAgent,
		PageantAgent
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/zlib.js
var require_zlib = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { kMaxLength } = __require("buffer");
	const { createInflate, constants: { DEFLATE, INFLATE, Z_DEFAULT_CHUNK, Z_DEFAULT_COMPRESSION, Z_DEFAULT_MEMLEVEL, Z_DEFAULT_STRATEGY, Z_DEFAULT_WINDOWBITS, Z_PARTIAL_FLUSH } } = __require("zlib");
	const ZlibHandle = createInflate()._handle.constructor;
	function processCallback() {
		throw new Error("Should not get here");
	}
	function zlibOnError(message, errno, code) {
		const self = this._owner;
		const error = new Error(message);
		error.errno = errno;
		error.code = code;
		self._err = error;
	}
	function _close(engine) {
		if (!engine._handle) return;
		engine._handle.close();
		engine._handle = null;
	}
	var Zlib = class {
		constructor(mode) {
			const windowBits = Z_DEFAULT_WINDOWBITS;
			const level = Z_DEFAULT_COMPRESSION;
			const memLevel = Z_DEFAULT_MEMLEVEL;
			const strategy = Z_DEFAULT_STRATEGY;
			const dictionary = void 0;
			this._err = void 0;
			this._writeState = /* @__PURE__ */ new Uint32Array(2);
			this._chunkSize = Z_DEFAULT_CHUNK;
			this._maxOutputLength = kMaxLength;
			this._outBuffer = Buffer.allocUnsafe(this._chunkSize);
			this._outOffset = 0;
			this._handle = new ZlibHandle(mode);
			this._handle._owner = this;
			this._handle.onerror = zlibOnError;
			this._handle.init(windowBits, level, memLevel, strategy, this._writeState, processCallback, dictionary);
		}
		writeSync(chunk, retChunks) {
			const handle = this._handle;
			if (!handle) throw new Error("Invalid Zlib instance");
			let availInBefore = chunk.length;
			let availOutBefore = this._chunkSize - this._outOffset;
			let inOff = 0;
			let availOutAfter;
			let availInAfter;
			let buffers;
			let nread = 0;
			const state = this._writeState;
			let buffer = this._outBuffer;
			let offset = this._outOffset;
			const chunkSize = this._chunkSize;
			while (true) {
				handle.writeSync(Z_PARTIAL_FLUSH, chunk, inOff, availInBefore, buffer, offset, availOutBefore);
				if (this._err) throw this._err;
				availOutAfter = state[0];
				availInAfter = state[1];
				const inDelta = availInBefore - availInAfter;
				const have = availOutBefore - availOutAfter;
				if (have > 0) {
					const out = offset === 0 && have === buffer.length ? buffer : buffer.slice(offset, offset + have);
					offset += have;
					if (!buffers) buffers = out;
					else if (buffers.push === void 0) buffers = [buffers, out];
					else buffers.push(out);
					nread += out.byteLength;
					if (nread > this._maxOutputLength) {
						_close(this);
						throw new Error(`Output length exceeded maximum of ${this._maxOutputLength}`);
					}
				} else if (have !== 0) throw new Error("have should not go down");
				if (availOutAfter === 0 || offset >= chunkSize) {
					availOutBefore = chunkSize;
					offset = 0;
					buffer = Buffer.allocUnsafe(chunkSize);
				}
				if (availOutAfter === 0) {
					inOff += inDelta;
					availInBefore = availInAfter;
				} else break;
			}
			this._outBuffer = buffer;
			this._outOffset = offset;
			if (nread === 0) buffers = Buffer.alloc(0);
			if (retChunks) {
				buffers.totalLen = nread;
				return buffers;
			}
			if (buffers.push === void 0) return buffers;
			const output = Buffer.allocUnsafe(nread);
			for (let i = 0, p = 0; i < buffers.length; ++i) {
				const buf = buffers[i];
				output.set(buf, p);
				p += buf.length;
			}
			return output;
		}
	};
	var ZlibPacketWriter = class {
		constructor(protocol) {
			this.allocStart = 0;
			this.allocStartKEX = 0;
			this._protocol = protocol;
			this._zlib = new Zlib(DEFLATE);
		}
		cleanup() {
			if (this._zlib) _close(this._zlib);
		}
		alloc(payloadSize, force) {
			return Buffer.allocUnsafe(payloadSize);
		}
		finalize(payload, force) {
			if (this._protocol._kexinit === void 0 || force) {
				const output = this._zlib.writeSync(payload, true);
				const packet = this._protocol._cipher.allocPacket(output.totalLen);
				if (output.push === void 0) packet.set(output, 5);
				else for (let i = 0, p = 5; i < output.length; ++i) {
					const chunk = output[i];
					packet.set(chunk, p);
					p += chunk.length;
				}
				return packet;
			}
			return payload;
		}
	};
	var PacketWriter = class {
		constructor(protocol) {
			this.allocStart = 5;
			this.allocStartKEX = 5;
			this._protocol = protocol;
		}
		cleanup() {}
		alloc(payloadSize, force) {
			if (this._protocol._kexinit === void 0 || force) return this._protocol._cipher.allocPacket(payloadSize);
			return Buffer.allocUnsafe(payloadSize);
		}
		finalize(packet, force) {
			return packet;
		}
	};
	var ZlibPacketReader = class {
		constructor() {
			this._zlib = new Zlib(INFLATE);
		}
		cleanup() {
			if (this._zlib) _close(this._zlib);
		}
		read(data) {
			return this._zlib.writeSync(data, false);
		}
	};
	var PacketReader = class {
		cleanup() {}
		read(data) {
			return data;
		}
	};
	module.exports = {
		PacketReader,
		PacketWriter,
		ZlibPacketReader,
		ZlibPacketWriter
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/handlers.misc.js
var require_handlers_misc = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { bufferSlice, bufferParser, doFatalError, sigSSHToASN1, writeUInt32BE } = require_utils$1();
	const { CHANNEL_OPEN_FAILURE, COMPAT, MESSAGE, TERMINAL_MODE } = require_constants();
	const { parseKey } = require_keyParser();
	const TERMINAL_MODE_BY_VALUE = Array.from(Object.entries(TERMINAL_MODE)).reduce((obj, [key, value]) => ({
		...obj,
		[key]: value
	}), {});
	module.exports = {
		[MESSAGE.DISCONNECT]: (self, payload) => {
			bufferParser.init(payload, 1);
			const reason = bufferParser.readUInt32BE();
			const desc = bufferParser.readString(true);
			const lang = bufferParser.readString();
			bufferParser.clear();
			if (lang === void 0) return doFatalError(self, "Inbound: Malformed DISCONNECT packet");
			self._debug && self._debug(`Inbound: Received DISCONNECT (${reason}, "${desc}")`);
			const handler = self._handlers.DISCONNECT;
			handler && handler(self, reason, desc);
		},
		[MESSAGE.IGNORE]: (self, payload) => {
			self._debug && self._debug("Inbound: Received IGNORE");
		},
		[MESSAGE.UNIMPLEMENTED]: (self, payload) => {
			bufferParser.init(payload, 1);
			const seqno = bufferParser.readUInt32BE();
			bufferParser.clear();
			if (seqno === void 0) return doFatalError(self, "Inbound: Malformed UNIMPLEMENTED packet");
			self._debug && self._debug(`Inbound: Received UNIMPLEMENTED (seqno ${seqno})`);
		},
		[MESSAGE.DEBUG]: (self, payload) => {
			bufferParser.init(payload, 1);
			const display = bufferParser.readBool();
			const msg = bufferParser.readString(true);
			const lang = bufferParser.readString();
			bufferParser.clear();
			if (lang === void 0) return doFatalError(self, "Inbound: Malformed DEBUG packet");
			self._debug && self._debug("Inbound: Received DEBUG");
			const handler = self._handlers.DEBUG;
			handler && handler(self, display, msg);
		},
		[MESSAGE.SERVICE_REQUEST]: (self, payload) => {
			bufferParser.init(payload, 1);
			const name = bufferParser.readString(true);
			bufferParser.clear();
			if (name === void 0) return doFatalError(self, "Inbound: Malformed SERVICE_REQUEST packet");
			self._debug && self._debug(`Inbound: Received SERVICE_REQUEST (${name})`);
			const handler = self._handlers.SERVICE_REQUEST;
			handler && handler(self, name);
		},
		[MESSAGE.SERVICE_ACCEPT]: (self, payload) => {
			bufferParser.init(payload, 1);
			const name = bufferParser.readString(true);
			bufferParser.clear();
			if (name === void 0) return doFatalError(self, "Inbound: Malformed SERVICE_ACCEPT packet");
			self._debug && self._debug(`Inbound: Received SERVICE_ACCEPT (${name})`);
			const handler = self._handlers.SERVICE_ACCEPT;
			handler && handler(self, name);
		},
		[MESSAGE.EXT_INFO]: (self, payload) => {
			bufferParser.init(payload, 1);
			const numExts = bufferParser.readUInt32BE();
			let exts;
			if (numExts !== void 0) {
				exts = [];
				for (let i = 0; i < numExts; ++i) {
					const name = bufferParser.readString(true);
					const data = bufferParser.readString();
					if (data !== void 0) switch (name) {
						case "server-sig-algs": {
							const algs = data.latin1Slice(0, data.length).split(",");
							exts.push({
								name,
								algs
							});
							continue;
						}
						default: continue;
					}
					exts = void 0;
					break;
				}
			}
			bufferParser.clear();
			if (exts === void 0) return doFatalError(self, "Inbound: Malformed EXT_INFO packet");
			self._debug && self._debug("Inbound: Received EXT_INFO");
			const handler = self._handlers.EXT_INFO;
			handler && handler(self, exts);
		},
		[MESSAGE.USERAUTH_REQUEST]: (self, payload) => {
			bufferParser.init(payload, 1);
			const user = bufferParser.readString(true);
			const service = bufferParser.readString(true);
			const method = bufferParser.readString(true);
			let methodData;
			let methodDesc;
			switch (method) {
				case "none":
					methodData = null;
					break;
				case "password": {
					const isChange = bufferParser.readBool();
					if (isChange !== void 0) {
						methodData = bufferParser.readString(true);
						if (methodData !== void 0 && isChange) {
							const newPassword = bufferParser.readString(true);
							if (newPassword !== void 0) methodData = {
								oldPassword: methodData,
								newPassword
							};
							else methodData = void 0;
						}
					}
					break;
				}
				case "publickey": {
					const hasSig = bufferParser.readBool();
					if (hasSig !== void 0) {
						const keyAlgo = bufferParser.readString(true);
						let realKeyAlgo = keyAlgo;
						const key = bufferParser.readString();
						let hashAlgo;
						switch (keyAlgo) {
							case "rsa-sha2-256":
								realKeyAlgo = "ssh-rsa";
								hashAlgo = "sha256";
								break;
							case "rsa-sha2-512":
								realKeyAlgo = "ssh-rsa";
								hashAlgo = "sha512";
						}
						if (hasSig) {
							const blobEnd = bufferParser.pos();
							let signature = bufferParser.readString();
							if (signature !== void 0) {
								if (signature.length > 4 + keyAlgo.length + 4 && signature.utf8Slice(4, 4 + keyAlgo.length) === keyAlgo) signature = bufferSlice(signature, 4 + keyAlgo.length + 4);
								signature = sigSSHToASN1(signature, realKeyAlgo);
								if (signature) {
									const sessionID = self._kex.sessionID;
									const blob = Buffer.allocUnsafe(4 + sessionID.length + blobEnd);
									writeUInt32BE(blob, sessionID.length, 0);
									blob.set(sessionID, 4);
									blob.set(new Uint8Array(payload.buffer, payload.byteOffset, blobEnd), 4 + sessionID.length);
									methodData = {
										keyAlgo: realKeyAlgo,
										key,
										signature,
										blob,
										hashAlgo
									};
								}
							}
						} else {
							methodData = {
								keyAlgo: realKeyAlgo,
								key,
								hashAlgo
							};
							methodDesc = "publickey -- check";
						}
					}
					break;
				}
				case "hostbased": {
					const keyAlgo = bufferParser.readString(true);
					let realKeyAlgo = keyAlgo;
					const key = bufferParser.readString();
					const localHostname = bufferParser.readString(true);
					const localUsername = bufferParser.readString(true);
					let hashAlgo;
					switch (keyAlgo) {
						case "rsa-sha2-256":
							realKeyAlgo = "ssh-rsa";
							hashAlgo = "sha256";
							break;
						case "rsa-sha2-512":
							realKeyAlgo = "ssh-rsa";
							hashAlgo = "sha512";
					}
					const blobEnd = bufferParser.pos();
					let signature = bufferParser.readString();
					if (signature !== void 0) {
						if (signature.length > 4 + keyAlgo.length + 4 && signature.utf8Slice(4, 4 + keyAlgo.length) === keyAlgo) signature = bufferSlice(signature, 4 + keyAlgo.length + 4);
						signature = sigSSHToASN1(signature, realKeyAlgo);
						if (signature !== void 0) {
							const sessionID = self._kex.sessionID;
							const blob = Buffer.allocUnsafe(4 + sessionID.length + blobEnd);
							writeUInt32BE(blob, sessionID.length, 0);
							blob.set(sessionID, 4);
							blob.set(new Uint8Array(payload.buffer, payload.byteOffset, blobEnd), 4 + sessionID.length);
							methodData = {
								keyAlgo: realKeyAlgo,
								key,
								signature,
								blob,
								localHostname,
								localUsername,
								hashAlgo
							};
						}
					}
					break;
				}
				case "keyboard-interactive":
					bufferParser.skipString();
					methodData = bufferParser.readList();
					break;
				default: if (method !== void 0) methodData = bufferParser.readRaw();
			}
			bufferParser.clear();
			if (methodData === void 0) return doFatalError(self, "Inbound: Malformed USERAUTH_REQUEST packet");
			if (methodDesc === void 0) methodDesc = method;
			self._authsQueue.push(method);
			self._debug && self._debug(`Inbound: Received USERAUTH_REQUEST (${methodDesc})`);
			const handler = self._handlers.USERAUTH_REQUEST;
			handler && handler(self, user, service, method, methodData);
		},
		[MESSAGE.USERAUTH_FAILURE]: (self, payload) => {
			bufferParser.init(payload, 1);
			const authMethods = bufferParser.readList();
			const partialSuccess = bufferParser.readBool();
			bufferParser.clear();
			if (partialSuccess === void 0) return doFatalError(self, "Inbound: Malformed USERAUTH_FAILURE packet");
			self._debug && self._debug(`Inbound: Received USERAUTH_FAILURE (${authMethods})`);
			self._authsQueue.shift();
			const handler = self._handlers.USERAUTH_FAILURE;
			handler && handler(self, authMethods, partialSuccess);
		},
		[MESSAGE.USERAUTH_SUCCESS]: (self, payload) => {
			self._debug && self._debug("Inbound: Received USERAUTH_SUCCESS");
			self._authsQueue.shift();
			const handler = self._handlers.USERAUTH_SUCCESS;
			handler && handler(self);
		},
		[MESSAGE.USERAUTH_BANNER]: (self, payload) => {
			bufferParser.init(payload, 1);
			const msg = bufferParser.readString(true);
			const lang = bufferParser.readString();
			bufferParser.clear();
			if (lang === void 0) return doFatalError(self, "Inbound: Malformed USERAUTH_BANNER packet");
			self._debug && self._debug("Inbound: Received USERAUTH_BANNER");
			const handler = self._handlers.USERAUTH_BANNER;
			handler && handler(self, msg);
		},
		60: (self, payload) => {
			if (!self._authsQueue.length) {
				self._debug && self._debug("Inbound: Received payload type 60 without auth");
				return;
			}
			switch (self._authsQueue[0]) {
				case "password": {
					bufferParser.init(payload, 1);
					const prompt = bufferParser.readString(true);
					const lang = bufferParser.readString();
					bufferParser.clear();
					if (lang === void 0) return doFatalError(self, "Inbound: Malformed USERAUTH_PASSWD_CHANGEREQ packet");
					self._debug && self._debug("Inbound: Received USERAUTH_PASSWD_CHANGEREQ");
					const handler = self._handlers.USERAUTH_PASSWD_CHANGEREQ;
					handler && handler(self, prompt);
					break;
				}
				case "publickey": {
					bufferParser.init(payload, 1);
					const keyAlgo = bufferParser.readString(true);
					const key = bufferParser.readString();
					bufferParser.clear();
					if (key === void 0) return doFatalError(self, "Inbound: Malformed USERAUTH_PK_OK packet");
					self._debug && self._debug("Inbound: Received USERAUTH_PK_OK");
					self._authsQueue.shift();
					const handler = self._handlers.USERAUTH_PK_OK;
					handler && handler(self, keyAlgo, key);
					break;
				}
				case "keyboard-interactive": {
					bufferParser.init(payload, 1);
					const name = bufferParser.readString(true);
					const instructions = bufferParser.readString(true);
					bufferParser.readString();
					const numPrompts = bufferParser.readUInt32BE();
					let prompts;
					if (numPrompts !== void 0) {
						prompts = new Array(numPrompts);
						let i = 0;
						for (; i < numPrompts; ++i) {
							const prompt = bufferParser.readString(true);
							const echo = bufferParser.readBool();
							if (echo === void 0) break;
							prompts[i] = {
								prompt,
								echo
							};
						}
						if (i !== numPrompts) prompts = void 0;
					}
					bufferParser.clear();
					if (prompts === void 0) return doFatalError(self, "Inbound: Malformed USERAUTH_INFO_REQUEST packet");
					self._debug && self._debug("Inbound: Received USERAUTH_INFO_REQUEST");
					const handler = self._handlers.USERAUTH_INFO_REQUEST;
					handler && handler(self, name, instructions, prompts);
					break;
				}
				default: self._debug && self._debug("Inbound: Received unexpected payload type 60");
			}
		},
		61: (self, payload) => {
			if (!self._authsQueue.length) {
				self._debug && self._debug("Inbound: Received payload type 61 without auth");
				return;
			}
			if (self._authsQueue[0] !== "keyboard-interactive") return doFatalError(self, "Inbound: Received unexpected payload type 61");
			bufferParser.init(payload, 1);
			const numResponses = bufferParser.readUInt32BE();
			let responses;
			if (numResponses !== void 0) {
				responses = new Array(numResponses);
				let i = 0;
				for (; i < numResponses; ++i) {
					const response = bufferParser.readString(true);
					if (response === void 0) break;
					responses[i] = response;
				}
				if (i !== numResponses) responses = void 0;
			}
			bufferParser.clear();
			if (responses === void 0) return doFatalError(self, "Inbound: Malformed USERAUTH_INFO_RESPONSE packet");
			self._debug && self._debug("Inbound: Received USERAUTH_INFO_RESPONSE");
			const handler = self._handlers.USERAUTH_INFO_RESPONSE;
			handler && handler(self, responses);
		},
		[MESSAGE.GLOBAL_REQUEST]: (self, payload) => {
			bufferParser.init(payload, 1);
			const name = bufferParser.readString(true);
			const wantReply = bufferParser.readBool();
			let data;
			if (wantReply !== void 0) switch (name) {
				case "tcpip-forward":
				case "cancel-tcpip-forward": {
					const bindAddr = bufferParser.readString(true);
					const bindPort = bufferParser.readUInt32BE();
					if (bindPort !== void 0) data = {
						bindAddr,
						bindPort
					};
					break;
				}
				case "streamlocal-forward@openssh.com":
				case "cancel-streamlocal-forward@openssh.com": {
					const socketPath = bufferParser.readString(true);
					if (socketPath !== void 0) data = { socketPath };
					break;
				}
				case "no-more-sessions@openssh.com":
					data = null;
					break;
				case "hostkeys-00@openssh.com":
					data = [];
					while (bufferParser.avail() > 0) {
						const keyRaw = bufferParser.readString();
						if (keyRaw === void 0) {
							data = void 0;
							break;
						}
						const key = parseKey(keyRaw);
						if (!(key instanceof Error)) data.push(key);
					}
					break;
				default: data = bufferParser.readRaw();
			}
			bufferParser.clear();
			if (data === void 0) return doFatalError(self, "Inbound: Malformed GLOBAL_REQUEST packet");
			self._debug && self._debug(`Inbound: GLOBAL_REQUEST (${name})`);
			const handler = self._handlers.GLOBAL_REQUEST;
			if (handler) handler(self, name, wantReply, data);
			else self.requestFailure();
		},
		[MESSAGE.REQUEST_SUCCESS]: (self, payload) => {
			const data = payload.length > 1 ? bufferSlice(payload, 1) : null;
			self._debug && self._debug("Inbound: REQUEST_SUCCESS");
			const handler = self._handlers.REQUEST_SUCCESS;
			handler && handler(self, data);
		},
		[MESSAGE.REQUEST_FAILURE]: (self, payload) => {
			self._debug && self._debug("Inbound: Received REQUEST_FAILURE");
			const handler = self._handlers.REQUEST_FAILURE;
			handler && handler(self);
		},
		[MESSAGE.CHANNEL_OPEN]: (self, payload) => {
			bufferParser.init(payload, 1);
			const type = bufferParser.readString(true);
			const sender = bufferParser.readUInt32BE();
			const window = bufferParser.readUInt32BE();
			const packetSize = bufferParser.readUInt32BE();
			let channelInfo;
			switch (type) {
				case "forwarded-tcpip":
				case "direct-tcpip": {
					const destIP = bufferParser.readString(true);
					const destPort = bufferParser.readUInt32BE();
					const srcIP = bufferParser.readString(true);
					const srcPort = bufferParser.readUInt32BE();
					if (srcPort !== void 0) channelInfo = {
						type,
						sender,
						window,
						packetSize,
						data: {
							destIP,
							destPort,
							srcIP,
							srcPort
						}
					};
					break;
				}
				case "forwarded-streamlocal@openssh.com":
				case "direct-streamlocal@openssh.com": {
					const socketPath = bufferParser.readString(true);
					if (socketPath !== void 0) channelInfo = {
						type,
						sender,
						window,
						packetSize,
						data: { socketPath }
					};
					break;
				}
				case "x11": {
					const srcIP = bufferParser.readString(true);
					const srcPort = bufferParser.readUInt32BE();
					if (srcPort !== void 0) channelInfo = {
						type,
						sender,
						window,
						packetSize,
						data: {
							srcIP,
							srcPort
						}
					};
					break;
				}
				default: channelInfo = {
					type,
					sender,
					window,
					packetSize,
					data: {}
				};
			}
			bufferParser.clear();
			if (channelInfo === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_OPEN packet");
			self._debug && self._debug(`Inbound: CHANNEL_OPEN (s:${sender}, ${type})`);
			const handler = self._handlers.CHANNEL_OPEN;
			if (handler) handler(self, channelInfo);
			else self.channelOpenFail(channelInfo.sender, CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED, "", "");
		},
		[MESSAGE.CHANNEL_OPEN_CONFIRMATION]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			const sender = bufferParser.readUInt32BE();
			const window = bufferParser.readUInt32BE();
			const packetSize = bufferParser.readUInt32BE();
			const data = bufferParser.avail() ? bufferParser.readRaw() : void 0;
			bufferParser.clear();
			if (packetSize === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_OPEN_CONFIRMATION packet");
			self._debug && self._debug(`Inbound: CHANNEL_OPEN_CONFIRMATION (r:${recipient}, s:${sender})`);
			const handler = self._handlers.CHANNEL_OPEN_CONFIRMATION;
			if (handler) handler(self, {
				recipient,
				sender,
				window,
				packetSize,
				data
			});
		},
		[MESSAGE.CHANNEL_OPEN_FAILURE]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			const reason = bufferParser.readUInt32BE();
			const description = bufferParser.readString(true);
			const lang = bufferParser.readString();
			bufferParser.clear();
			if (lang === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_OPEN_FAILURE packet");
			self._debug && self._debug(`Inbound: CHANNEL_OPEN_FAILURE (r:${recipient})`);
			const handler = self._handlers.CHANNEL_OPEN_FAILURE;
			handler && handler(self, recipient, reason, description);
		},
		[MESSAGE.CHANNEL_WINDOW_ADJUST]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			const bytesToAdd = bufferParser.readUInt32BE();
			bufferParser.clear();
			if (bytesToAdd === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_WINDOW_ADJUST packet");
			self._debug && self._debug(`Inbound: CHANNEL_WINDOW_ADJUST (r:${recipient}, ${bytesToAdd})`);
			const handler = self._handlers.CHANNEL_WINDOW_ADJUST;
			handler && handler(self, recipient, bytesToAdd);
		},
		[MESSAGE.CHANNEL_DATA]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			const data = bufferParser.readString();
			bufferParser.clear();
			if (data === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_DATA packet");
			self._debug && self._debug(`Inbound: CHANNEL_DATA (r:${recipient}, ${data.length})`);
			const handler = self._handlers.CHANNEL_DATA;
			handler && handler(self, recipient, data);
		},
		[MESSAGE.CHANNEL_EXTENDED_DATA]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			const type = bufferParser.readUInt32BE();
			const data = bufferParser.readString();
			bufferParser.clear();
			if (data === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_EXTENDED_DATA packet");
			self._debug && self._debug(`Inbound: CHANNEL_EXTENDED_DATA (r:${recipient}, ${data.length})`);
			const handler = self._handlers.CHANNEL_EXTENDED_DATA;
			handler && handler(self, recipient, data, type);
		},
		[MESSAGE.CHANNEL_EOF]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			bufferParser.clear();
			if (recipient === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_EOF packet");
			self._debug && self._debug(`Inbound: CHANNEL_EOF (r:${recipient})`);
			const handler = self._handlers.CHANNEL_EOF;
			handler && handler(self, recipient);
		},
		[MESSAGE.CHANNEL_CLOSE]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			bufferParser.clear();
			if (recipient === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_CLOSE packet");
			self._debug && self._debug(`Inbound: CHANNEL_CLOSE (r:${recipient})`);
			const handler = self._handlers.CHANNEL_CLOSE;
			handler && handler(self, recipient);
		},
		[MESSAGE.CHANNEL_REQUEST]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			const type = bufferParser.readString(true);
			const wantReply = bufferParser.readBool();
			let data;
			if (wantReply !== void 0) switch (type) {
				case "exit-status":
					data = bufferParser.readUInt32BE();
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`);
					break;
				case "exit-signal": {
					let signal;
					let coreDumped;
					if (self._compatFlags & COMPAT.OLD_EXIT) {
						const num = bufferParser.readUInt32BE();
						switch (num) {
							case 1:
								signal = "HUP";
								break;
							case 2:
								signal = "INT";
								break;
							case 3:
								signal = "QUIT";
								break;
							case 6:
								signal = "ABRT";
								break;
							case 9:
								signal = "KILL";
								break;
							case 14:
								signal = "ALRM";
								break;
							case 15:
								signal = "TERM";
								break;
							default: if (num !== void 0) signal = `UNKNOWN (${num})`;
						}
						coreDumped = false;
					} else {
						signal = bufferParser.readString(true);
						coreDumped = bufferParser.readBool();
						if (coreDumped === void 0) signal = void 0;
					}
					const errorMessage = bufferParser.readString(true);
					if (bufferParser.skipString() !== void 0) data = {
						signal,
						coreDumped,
						errorMessage
					};
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${signal})`);
					break;
				}
				case "pty-req": {
					const term = bufferParser.readString(true);
					const cols = bufferParser.readUInt32BE();
					const rows = bufferParser.readUInt32BE();
					const width = bufferParser.readUInt32BE();
					const height = bufferParser.readUInt32BE();
					const modesBinary = bufferParser.readString();
					if (modesBinary !== void 0) {
						bufferParser.init(modesBinary, 1);
						let modes = {};
						while (bufferParser.avail()) {
							const opcode = bufferParser.readByte();
							if (opcode === TERMINAL_MODE.TTY_OP_END) break;
							const name = TERMINAL_MODE_BY_VALUE[opcode];
							const value = bufferParser.readUInt32BE();
							if (opcode === void 0 || name === void 0 || value === void 0) {
								modes = void 0;
								break;
							}
							modes[name] = value;
						}
						if (modes !== void 0) data = {
							term,
							cols,
							rows,
							width,
							height,
							modes
						};
					}
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
					break;
				}
				case "window-change": {
					const cols = bufferParser.readUInt32BE();
					const rows = bufferParser.readUInt32BE();
					const width = bufferParser.readUInt32BE();
					const height = bufferParser.readUInt32BE();
					if (height !== void 0) data = {
						cols,
						rows,
						width,
						height
					};
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
					break;
				}
				case "x11-req": {
					const single = bufferParser.readBool();
					const protocol = bufferParser.readString(true);
					const cookie = bufferParser.readString();
					const screen = bufferParser.readUInt32BE();
					if (screen !== void 0) data = {
						single,
						protocol,
						cookie,
						screen
					};
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
					break;
				}
				case "env": {
					const name = bufferParser.readString(true);
					const value = bufferParser.readString(true);
					if (value !== void 0) data = {
						name,
						value
					};
					if (self._debug) self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${name}=${value})`);
					break;
				}
				case "shell":
					data = null;
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
					break;
				case "exec":
					data = bufferParser.readString(true);
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`);
					break;
				case "subsystem":
					data = bufferParser.readString(true);
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`);
					break;
				case "signal":
					data = bufferParser.readString(true);
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`);
					break;
				case "xon-xoff":
					data = bufferParser.readBool();
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type}: ${data})`);
					break;
				case "auth-agent-req@openssh.com":
					data = null;
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
					break;
				default:
					data = bufferParser.avail() ? bufferParser.readRaw() : null;
					self._debug && self._debug(`Inbound: CHANNEL_REQUEST (r:${recipient}, ${type})`);
			}
			bufferParser.clear();
			if (data === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_REQUEST packet");
			const handler = self._handlers.CHANNEL_REQUEST;
			handler && handler(self, recipient, type, wantReply, data);
		},
		[MESSAGE.CHANNEL_SUCCESS]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			bufferParser.clear();
			if (recipient === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_SUCCESS packet");
			self._debug && self._debug(`Inbound: CHANNEL_SUCCESS (r:${recipient})`);
			const handler = self._handlers.CHANNEL_SUCCESS;
			handler && handler(self, recipient);
		},
		[MESSAGE.CHANNEL_FAILURE]: (self, payload) => {
			bufferParser.init(payload, 1);
			const recipient = bufferParser.readUInt32BE();
			bufferParser.clear();
			if (recipient === void 0) return doFatalError(self, "Inbound: Malformed CHANNEL_FAILURE packet");
			self._debug && self._debug(`Inbound: CHANNEL_FAILURE (r:${recipient})`);
			const handler = self._handlers.CHANNEL_FAILURE;
			handler && handler(self, recipient);
		}
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/handlers.js
var require_handlers = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const MESSAGE_HANDLERS = new Array(256);
	[require_kex().HANDLERS, require_handlers_misc()].forEach((handlers) => {
		for (let [type, handler] of Object.entries(handlers)) {
			type = +type;
			if (isFinite(type) && type >= 0 && type < MESSAGE_HANDLERS.length) MESSAGE_HANDLERS[type] = handler;
		}
	});
	module.exports = MESSAGE_HANDLERS;
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/kex.js
var require_kex = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { createDiffieHellman, createDiffieHellmanGroup, createECDH, createHash: createHash$2, createPublicKey, diffieHellman, generateKeyPairSync, randomFillSync: randomFillSync$1 } = __require("crypto");
	const { Ber } = require_lib$1();
	const { COMPAT, curve25519Supported, DEFAULT_KEX, DEFAULT_SERVER_HOST_KEY, DEFAULT_CIPHER, DEFAULT_MAC, DEFAULT_COMPRESSION, DISCONNECT_REASON, MESSAGE } = require_constants();
	const { CIPHER_INFO, createCipher, createDecipher, MAC_INFO } = require_crypto();
	const { parseDERKey } = require_keyParser();
	const { bufferFill, bufferParser, convertSignature, doFatalError, FastBuffer, sigSSHToASN1, writeUInt32BE } = require_utils$1();
	const { PacketReader, PacketWriter, ZlibPacketReader, ZlibPacketWriter } = require_zlib();
	let MESSAGE_HANDLERS;
	const GEX_MIN_BITS = 2048;
	const GEX_MAX_BITS = 8192;
	const EMPTY_BUFFER = Buffer.alloc(0);
	function kexinit(self) {
		let payload;
		if (self._compatFlags & COMPAT.BAD_DHGEX) {
			const entry = self._offer.lists.kex;
			let kex = entry.array;
			let found = false;
			for (let i = 0; i < kex.length; ++i) if (kex[i].includes("group-exchange")) {
				if (!found) {
					found = true;
					kex = kex.slice();
				}
				kex.splice(i--, 1);
			}
			if (found) {
				let len = 17 + self._offer.totalSize + 1 + 4;
				const newKexBuf = Buffer.from(kex.join(","));
				len -= entry.buffer.length - newKexBuf.length;
				const all = self._offer.lists.all;
				const rest = new Uint8Array(all.buffer, all.byteOffset + 4 + entry.buffer.length, all.length - (4 + entry.buffer.length));
				payload = Buffer.allocUnsafe(len);
				writeUInt32BE(payload, newKexBuf.length, 17);
				payload.set(newKexBuf, 21);
				payload.set(rest, 21 + newKexBuf.length);
			}
		}
		if (payload === void 0) {
			payload = Buffer.allocUnsafe(17 + self._offer.totalSize + 1 + 4);
			self._offer.copyAllTo(payload, 17);
		}
		self._debug && self._debug("Outbound: Sending KEXINIT");
		payload[0] = MESSAGE.KEXINIT;
		randomFillSync$1(payload, 1, 16);
		bufferFill(payload, 0, payload.length - 5);
		self._kexinit = payload;
		self._packetRW.write.allocStart = 0;
		{
			const p = self._packetRW.write.allocStartKEX;
			const packet = self._packetRW.write.alloc(payload.length, true);
			packet.set(payload, p);
			self._cipher.encrypt(self._packetRW.write.finalize(packet, true));
		}
	}
	function handleKexInit(self, payload) {
		const init = {
			kex: void 0,
			serverHostKey: void 0,
			cs: {
				cipher: void 0,
				mac: void 0,
				compress: void 0,
				lang: void 0
			},
			sc: {
				cipher: void 0,
				mac: void 0,
				compress: void 0,
				lang: void 0
			}
		};
		bufferParser.init(payload, 17);
		if ((init.kex = bufferParser.readList()) === void 0 || (init.serverHostKey = bufferParser.readList()) === void 0 || (init.cs.cipher = bufferParser.readList()) === void 0 || (init.sc.cipher = bufferParser.readList()) === void 0 || (init.cs.mac = bufferParser.readList()) === void 0 || (init.sc.mac = bufferParser.readList()) === void 0 || (init.cs.compress = bufferParser.readList()) === void 0 || (init.sc.compress = bufferParser.readList()) === void 0 || (init.cs.lang = bufferParser.readList()) === void 0 || (init.sc.lang = bufferParser.readList()) === void 0) {
			bufferParser.clear();
			return doFatalError(self, "Received malformed KEXINIT", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
		}
		const pos = bufferParser.pos();
		const firstFollows = pos < payload.length && payload[pos] === 1;
		bufferParser.clear();
		const local = self._offer;
		const remote = init;
		let localKex = local.lists.kex.array;
		if (self._compatFlags & COMPAT.BAD_DHGEX) {
			let found = false;
			for (let i = 0; i < localKex.length; ++i) if (localKex[i].indexOf("group-exchange") !== -1) {
				if (!found) {
					found = true;
					localKex = localKex.slice();
				}
				localKex.splice(i--, 1);
			}
		}
		let clientList;
		let serverList;
		let i;
		const debug = self._debug;
		debug && debug("Inbound: Handshake in progress");
		debug && debug(`Handshake: (local) KEX method: ${localKex}`);
		debug && debug(`Handshake: (remote) KEX method: ${remote.kex}`);
		let remoteExtInfoEnabled;
		if (self._server) {
			serverList = localKex;
			clientList = remote.kex;
			remoteExtInfoEnabled = clientList.indexOf("ext-info-c") !== -1;
		} else {
			serverList = remote.kex;
			clientList = localKex;
			remoteExtInfoEnabled = serverList.indexOf("ext-info-s") !== -1;
		}
		if (self._strictMode === void 0) {
			if (self._server) self._strictMode = clientList.indexOf("kex-strict-c-v00@openssh.com") !== -1;
			else self._strictMode = serverList.indexOf("kex-strict-s-v00@openssh.com") !== -1;
			if (self._strictMode) {
				debug && debug("Handshake: strict KEX mode enabled");
				if (self._decipher.inSeqno !== 1) {
					if (debug) debug("Handshake: KEXINIT not first packet in strict KEX mode");
					return doFatalError(self, "Handshake failed: KEXINIT not first packet in strict KEX mode", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
				}
			}
		}
		for (i = 0; i < clientList.length && serverList.indexOf(clientList[i]) === -1; ++i);
		if (i === clientList.length) {
			debug && debug("Handshake: no matching key exchange algorithm");
			return doFatalError(self, "Handshake failed: no matching key exchange algorithm", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
		}
		init.kex = clientList[i];
		debug && debug(`Handshake: KEX algorithm: ${clientList[i]}`);
		if (firstFollows && (!remote.kex.length || clientList[i] !== remote.kex[0])) self._skipNextInboundPacket = true;
		const localSrvHostKey = local.lists.serverHostKey.array;
		debug && debug(`Handshake: (local) Host key format: ${localSrvHostKey}`);
		debug && debug(`Handshake: (remote) Host key format: ${remote.serverHostKey}`);
		if (self._server) {
			serverList = localSrvHostKey;
			clientList = remote.serverHostKey;
		} else {
			serverList = remote.serverHostKey;
			clientList = localSrvHostKey;
		}
		for (i = 0; i < clientList.length && serverList.indexOf(clientList[i]) === -1; ++i);
		if (i === clientList.length) {
			debug && debug("Handshake: No matching host key format");
			return doFatalError(self, "Handshake failed: no matching host key format", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
		}
		init.serverHostKey = clientList[i];
		debug && debug(`Handshake: Host key format: ${clientList[i]}`);
		const localCSCipher = local.lists.cs.cipher.array;
		debug && debug(`Handshake: (local) C->S cipher: ${localCSCipher}`);
		debug && debug(`Handshake: (remote) C->S cipher: ${remote.cs.cipher}`);
		if (self._server) {
			serverList = localCSCipher;
			clientList = remote.cs.cipher;
		} else {
			serverList = remote.cs.cipher;
			clientList = localCSCipher;
		}
		for (i = 0; i < clientList.length && serverList.indexOf(clientList[i]) === -1; ++i);
		if (i === clientList.length) {
			debug && debug("Handshake: No matching C->S cipher");
			return doFatalError(self, "Handshake failed: no matching C->S cipher", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
		}
		init.cs.cipher = clientList[i];
		debug && debug(`Handshake: C->S Cipher: ${clientList[i]}`);
		const localSCCipher = local.lists.sc.cipher.array;
		debug && debug(`Handshake: (local) S->C cipher: ${localSCCipher}`);
		debug && debug(`Handshake: (remote) S->C cipher: ${remote.sc.cipher}`);
		if (self._server) {
			serverList = localSCCipher;
			clientList = remote.sc.cipher;
		} else {
			serverList = remote.sc.cipher;
			clientList = localSCCipher;
		}
		for (i = 0; i < clientList.length && serverList.indexOf(clientList[i]) === -1; ++i);
		if (i === clientList.length) {
			debug && debug("Handshake: No matching S->C cipher");
			return doFatalError(self, "Handshake failed: no matching S->C cipher", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
		}
		init.sc.cipher = clientList[i];
		debug && debug(`Handshake: S->C cipher: ${clientList[i]}`);
		const localCSMAC = local.lists.cs.mac.array;
		debug && debug(`Handshake: (local) C->S MAC: ${localCSMAC}`);
		debug && debug(`Handshake: (remote) C->S MAC: ${remote.cs.mac}`);
		if (CIPHER_INFO[init.cs.cipher].authLen > 0) {
			init.cs.mac = "";
			debug && debug("Handshake: C->S MAC: <implicit>");
		} else {
			if (self._server) {
				serverList = localCSMAC;
				clientList = remote.cs.mac;
			} else {
				serverList = remote.cs.mac;
				clientList = localCSMAC;
			}
			for (i = 0; i < clientList.length && serverList.indexOf(clientList[i]) === -1; ++i);
			if (i === clientList.length) {
				debug && debug("Handshake: No matching C->S MAC");
				return doFatalError(self, "Handshake failed: no matching C->S MAC", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
			}
			init.cs.mac = clientList[i];
			debug && debug(`Handshake: C->S MAC: ${clientList[i]}`);
		}
		const localSCMAC = local.lists.sc.mac.array;
		debug && debug(`Handshake: (local) S->C MAC: ${localSCMAC}`);
		debug && debug(`Handshake: (remote) S->C MAC: ${remote.sc.mac}`);
		if (CIPHER_INFO[init.sc.cipher].authLen > 0) {
			init.sc.mac = "";
			debug && debug("Handshake: S->C MAC: <implicit>");
		} else {
			if (self._server) {
				serverList = localSCMAC;
				clientList = remote.sc.mac;
			} else {
				serverList = remote.sc.mac;
				clientList = localSCMAC;
			}
			for (i = 0; i < clientList.length && serverList.indexOf(clientList[i]) === -1; ++i);
			if (i === clientList.length) {
				debug && debug("Handshake: No matching S->C MAC");
				return doFatalError(self, "Handshake failed: no matching S->C MAC", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
			}
			init.sc.mac = clientList[i];
			debug && debug(`Handshake: S->C MAC: ${clientList[i]}`);
		}
		const localCSCompress = local.lists.cs.compress.array;
		debug && debug(`Handshake: (local) C->S compression: ${localCSCompress}`);
		debug && debug(`Handshake: (remote) C->S compression: ${remote.cs.compress}`);
		if (self._server) {
			serverList = localCSCompress;
			clientList = remote.cs.compress;
		} else {
			serverList = remote.cs.compress;
			clientList = localCSCompress;
		}
		for (i = 0; i < clientList.length && serverList.indexOf(clientList[i]) === -1; ++i);
		if (i === clientList.length) {
			debug && debug("Handshake: No matching C->S compression");
			return doFatalError(self, "Handshake failed: no matching C->S compression", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
		}
		init.cs.compress = clientList[i];
		debug && debug(`Handshake: C->S compression: ${clientList[i]}`);
		const localSCCompress = local.lists.sc.compress.array;
		debug && debug(`Handshake: (local) S->C compression: ${localSCCompress}`);
		debug && debug(`Handshake: (remote) S->C compression: ${remote.sc.compress}`);
		if (self._server) {
			serverList = localSCCompress;
			clientList = remote.sc.compress;
		} else {
			serverList = remote.sc.compress;
			clientList = localSCCompress;
		}
		for (i = 0; i < clientList.length && serverList.indexOf(clientList[i]) === -1; ++i);
		if (i === clientList.length) {
			debug && debug("Handshake: No matching S->C compression");
			return doFatalError(self, "Handshake failed: no matching S->C compression", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
		}
		init.sc.compress = clientList[i];
		debug && debug(`Handshake: S->C compression: ${clientList[i]}`);
		init.cs.lang = "";
		init.sc.lang = "";
		if (self._kex) {
			if (!self._kexinit) kexinit(self);
			self._decipher._onPayload = onKEXPayload.bind(self, { firstPacket: false });
		}
		self._kex = createKeyExchange(init, self, payload);
		self._kex.remoteExtInfoEnabled = remoteExtInfoEnabled;
		self._kex.start();
	}
	const createKeyExchange = (() => {
		function convertToMpint(buf) {
			let idx = 0;
			let length = buf.length;
			while (buf[idx] === 0) {
				++idx;
				--length;
			}
			let newBuf;
			if (buf[idx] & 128) {
				newBuf = Buffer.allocUnsafe(1 + length);
				newBuf[0] = 0;
				buf.copy(newBuf, 1, idx);
				buf = newBuf;
			} else if (length !== buf.length) {
				newBuf = Buffer.allocUnsafe(length);
				buf.copy(newBuf, 0, idx);
				buf = newBuf;
			}
			return buf;
		}
		class KeyExchange {
			constructor(negotiated, protocol, remoteKexinit) {
				this._protocol = protocol;
				this.sessionID = protocol._kex ? protocol._kex.sessionID : void 0;
				this.negotiated = negotiated;
				this.remoteExtInfoEnabled = false;
				this._step = 1;
				this._public = null;
				this._dh = null;
				this._sentNEWKEYS = false;
				this._receivedNEWKEYS = false;
				this._finished = false;
				this._hostVerified = false;
				this._kexinit = protocol._kexinit;
				this._remoteKexinit = remoteKexinit;
				this._identRaw = protocol._identRaw;
				this._remoteIdentRaw = protocol._remoteIdentRaw;
				this._hostKey = void 0;
				this._dhData = void 0;
				this._sig = void 0;
			}
			finish(scOnly) {
				if (this._finished) return false;
				this._finished = true;
				const isServer = this._protocol._server;
				const negotiated = this.negotiated;
				const pubKey = this.convertPublicKey(this._dhData);
				let secret = this.computeSecret(this._dhData);
				if (secret instanceof Error) {
					secret.message = `Error while computing DH secret (${this.type}): ${secret.message}`;
					secret.level = "handshake";
					return doFatalError(this._protocol, secret, DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
				}
				const hash = createHash$2(this.hashName);
				hashString(hash, isServer ? this._remoteIdentRaw : this._identRaw);
				hashString(hash, isServer ? this._identRaw : this._remoteIdentRaw);
				hashString(hash, isServer ? this._remoteKexinit : this._kexinit);
				hashString(hash, isServer ? this._kexinit : this._remoteKexinit);
				const serverPublicHostKey = isServer ? this._hostKey.getPublicSSH() : this._hostKey;
				hashString(hash, serverPublicHostKey);
				if (this.type === "groupex") {
					const params = this.getDHParams();
					const num = Buffer.allocUnsafe(4);
					writeUInt32BE(num, this._minBits, 0);
					hash.update(num);
					writeUInt32BE(num, this._prefBits, 0);
					hash.update(num);
					writeUInt32BE(num, this._maxBits, 0);
					hash.update(num);
					hashString(hash, params.prime);
					hashString(hash, params.generator);
				}
				hashString(hash, isServer ? pubKey : this.getPublicKey());
				const serverPublicKey = isServer ? this.getPublicKey() : pubKey;
				hashString(hash, serverPublicKey);
				hashString(hash, secret);
				const exchangeHash = hash.digest();
				if (!isServer) {
					bufferParser.init(this._sig, 0);
					const sigType = bufferParser.readString(true);
					if (!sigType) return doFatalError(this._protocol, "Malformed packet while reading signature", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
					if (sigType !== negotiated.serverHostKey) return doFatalError(this._protocol, `Wrong signature type: ${sigType}, expected: ${negotiated.serverHostKey}`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
					let sigValue = bufferParser.readString();
					bufferParser.clear();
					if (sigValue === void 0) return doFatalError(this._protocol, "Malformed packet while reading signature", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
					if (!(sigValue = sigSSHToASN1(sigValue, sigType))) return doFatalError(this._protocol, "Malformed signature", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
					let parsedHostKey;
					{
						bufferParser.init(this._hostKey, 0);
						const name = bufferParser.readString(true);
						const hostKey = this._hostKey.slice(bufferParser.pos());
						bufferParser.clear();
						parsedHostKey = parseDERKey(hostKey, name);
						if (parsedHostKey instanceof Error) {
							parsedHostKey.level = "handshake";
							return doFatalError(this._protocol, parsedHostKey, DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
						}
					}
					let hashAlgo;
					switch (this.negotiated.serverHostKey) {
						case "rsa-sha2-256":
							hashAlgo = "sha256";
							break;
						case "rsa-sha2-512": hashAlgo = "sha512";
					}
					this._protocol._debug && this._protocol._debug("Verifying signature ...");
					const verified = parsedHostKey.verify(exchangeHash, sigValue, hashAlgo);
					if (verified !== true) {
						if (verified instanceof Error) this._protocol._debug && this._protocol._debug(`Signature verification failed: ${verified.stack}`);
						else this._protocol._debug && this._protocol._debug("Signature verification failed");
						return doFatalError(this._protocol, "Handshake failed: signature verification failed", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
					}
					this._protocol._debug && this._protocol._debug("Verified signature");
				} else {
					let hashAlgo;
					switch (this.negotiated.serverHostKey) {
						case "rsa-sha2-256":
							hashAlgo = "sha256";
							break;
						case "rsa-sha2-512": hashAlgo = "sha512";
					}
					this._protocol._debug && this._protocol._debug("Generating signature ...");
					let signature = this._hostKey.sign(exchangeHash, hashAlgo);
					if (signature instanceof Error) return doFatalError(this._protocol, `Handshake failed: signature generation failed for ${this._hostKey.type} host key: ${signature.message}`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
					signature = convertSignature(signature, this._hostKey.type);
					if (signature === false) return doFatalError(this._protocol, `Handshake failed: signature conversion failed for ${this._hostKey.type} host key`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
					const sigType = this.negotiated.serverHostKey;
					const sigTypeLen = Buffer.byteLength(sigType);
					const sigLen = 4 + sigTypeLen + 4 + signature.length;
					let p = this._protocol._packetRW.write.allocStartKEX;
					const packet = this._protocol._packetRW.write.alloc(5 + serverPublicHostKey.length + 4 + serverPublicKey.length + 4 + sigLen, true);
					packet[p] = MESSAGE.KEXDH_REPLY;
					writeUInt32BE(packet, serverPublicHostKey.length, ++p);
					packet.set(serverPublicHostKey, p += 4);
					writeUInt32BE(packet, serverPublicKey.length, p += serverPublicHostKey.length);
					packet.set(serverPublicKey, p += 4);
					writeUInt32BE(packet, sigLen, p += serverPublicKey.length);
					writeUInt32BE(packet, sigTypeLen, p += 4);
					packet.utf8Write(sigType, p += 4, sigTypeLen);
					writeUInt32BE(packet, signature.length, p += sigTypeLen);
					packet.set(signature, p += 4);
					if (this._protocol._debug) {
						let type;
						switch (this.type) {
							case "group":
								type = "KEXDH_REPLY";
								break;
							case "groupex":
								type = "KEXDH_GEX_REPLY";
								break;
							default: type = "KEXECDH_REPLY";
						}
						this._protocol._debug(`Outbound: Sending ${type}`);
					}
					this._protocol._cipher.encrypt(this._protocol._packetRW.write.finalize(packet, true));
				}
				if (isServer || !scOnly) trySendNEWKEYS(this);
				let hsCipherConfig;
				let hsWrite;
				const completeHandshake = (partial) => {
					if (hsCipherConfig) {
						trySendNEWKEYS(this);
						hsCipherConfig.outbound.seqno = this._protocol._cipher.outSeqno;
						this._protocol._cipher.free();
						this._protocol._cipher = createCipher(hsCipherConfig);
						this._protocol._packetRW.write = hsWrite;
						hsCipherConfig = void 0;
						hsWrite = void 0;
						this._protocol._onHandshakeComplete(negotiated);
						return false;
					}
					if (!this.sessionID) this.sessionID = exchangeHash;
					{
						const newSecret = Buffer.allocUnsafe(4 + secret.length);
						writeUInt32BE(newSecret, secret.length, 0);
						newSecret.set(secret, 4);
						secret = newSecret;
					}
					const csCipherInfo = CIPHER_INFO[negotiated.cs.cipher];
					const scCipherInfo = CIPHER_INFO[negotiated.sc.cipher];
					const csIV = generateKEXVal(csCipherInfo.ivLen, this.hashName, secret, exchangeHash, this.sessionID, "A");
					const scIV = generateKEXVal(scCipherInfo.ivLen, this.hashName, secret, exchangeHash, this.sessionID, "B");
					const csKey = generateKEXVal(csCipherInfo.keyLen, this.hashName, secret, exchangeHash, this.sessionID, "C");
					const scKey = generateKEXVal(scCipherInfo.keyLen, this.hashName, secret, exchangeHash, this.sessionID, "D");
					let csMacInfo;
					let csMacKey;
					if (!csCipherInfo.authLen) {
						csMacInfo = MAC_INFO[negotiated.cs.mac];
						csMacKey = generateKEXVal(csMacInfo.len, this.hashName, secret, exchangeHash, this.sessionID, "E");
					}
					let scMacInfo;
					let scMacKey;
					if (!scCipherInfo.authLen) {
						scMacInfo = MAC_INFO[negotiated.sc.mac];
						scMacKey = generateKEXVal(scMacInfo.len, this.hashName, secret, exchangeHash, this.sessionID, "F");
					}
					const config = {
						inbound: {
							onPayload: this._protocol._onPayload,
							seqno: this._protocol._decipher.inSeqno,
							decipherInfo: !isServer ? scCipherInfo : csCipherInfo,
							decipherIV: !isServer ? scIV : csIV,
							decipherKey: !isServer ? scKey : csKey,
							macInfo: !isServer ? scMacInfo : csMacInfo,
							macKey: !isServer ? scMacKey : csMacKey
						},
						outbound: {
							onWrite: this._protocol._onWrite,
							seqno: this._protocol._cipher.outSeqno,
							cipherInfo: isServer ? scCipherInfo : csCipherInfo,
							cipherIV: isServer ? scIV : csIV,
							cipherKey: isServer ? scKey : csKey,
							macInfo: isServer ? scMacInfo : csMacInfo,
							macKey: isServer ? scMacKey : csMacKey
						}
					};
					this._protocol._decipher.free();
					hsCipherConfig = config;
					this._protocol._decipher = createDecipher(config);
					const rw = {
						read: void 0,
						write: void 0
					};
					switch (negotiated.cs.compress) {
						case "zlib":
							if (isServer) rw.read = new ZlibPacketReader();
							else rw.write = new ZlibPacketWriter(this._protocol);
							break;
						case "zlib@openssh.com": if (this._protocol._authenticated) {
							if (isServer) rw.read = new ZlibPacketReader();
							else rw.write = new ZlibPacketWriter(this._protocol);
							break;
						}
						default: if (isServer) rw.read = new PacketReader();
						else rw.write = new PacketWriter(this._protocol);
					}
					switch (negotiated.sc.compress) {
						case "zlib":
							if (isServer) rw.write = new ZlibPacketWriter(this._protocol);
							else rw.read = new ZlibPacketReader();
							break;
						case "zlib@openssh.com": if (this._protocol._authenticated) {
							if (isServer) rw.write = new ZlibPacketWriter(this._protocol);
							else rw.read = new ZlibPacketReader();
							break;
						}
						default: if (isServer) rw.write = new PacketWriter(this._protocol);
						else rw.read = new PacketReader();
					}
					this._protocol._packetRW.read.cleanup();
					this._protocol._packetRW.write.cleanup();
					this._protocol._packetRW.read = rw.read;
					hsWrite = rw.write;
					this._public = null;
					this._dh = null;
					this._kexinit = this._protocol._kexinit = void 0;
					this._remoteKexinit = void 0;
					this._identRaw = void 0;
					this._remoteIdentRaw = void 0;
					this._hostKey = void 0;
					this._dhData = void 0;
					this._sig = void 0;
					if (!partial) return completeHandshake();
					return false;
				};
				if (isServer || scOnly) this.finish = completeHandshake;
				if (!isServer) return completeHandshake(scOnly);
			}
			start() {
				if (!this._protocol._server) {
					if (this._protocol._debug) {
						let type;
						switch (this.type) {
							case "group":
								type = "KEXDH_INIT";
								break;
							default: type = "KEXECDH_INIT";
						}
						this._protocol._debug(`Outbound: Sending ${type}`);
					}
					const pubKey = this.getPublicKey();
					let p = this._protocol._packetRW.write.allocStartKEX;
					const packet = this._protocol._packetRW.write.alloc(5 + pubKey.length, true);
					packet[p] = MESSAGE.KEXDH_INIT;
					writeUInt32BE(packet, pubKey.length, ++p);
					packet.set(pubKey, p += 4);
					this._protocol._cipher.encrypt(this._protocol._packetRW.write.finalize(packet, true));
				}
			}
			getPublicKey() {
				this.generateKeys();
				const key = this._public;
				if (key) return this.convertPublicKey(key);
			}
			convertPublicKey(key) {
				let newKey;
				let idx = 0;
				let len = key.length;
				while (key[idx] === 0) {
					++idx;
					--len;
				}
				if (key[idx] & 128) {
					newKey = Buffer.allocUnsafe(1 + len);
					newKey[0] = 0;
					key.copy(newKey, 1, idx);
					return newKey;
				}
				if (len !== key.length) {
					newKey = Buffer.allocUnsafe(len);
					key.copy(newKey, 0, idx);
					key = newKey;
				}
				return key;
			}
			computeSecret(otherPublicKey) {
				this.generateKeys();
				try {
					return convertToMpint(this._dh.computeSecret(otherPublicKey));
				} catch (ex) {
					return ex;
				}
			}
			parse(payload) {
				const type = payload[0];
				switch (this._step) {
					case 1:
						if (this._protocol._server) {
							if (type !== MESSAGE.KEXDH_INIT) return doFatalError(this._protocol, `Received packet ${type} instead of ${MESSAGE.KEXDH_INIT}`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
							this._protocol._debug && this._protocol._debug("Received DH Init");
							bufferParser.init(payload, 1);
							const dhData = bufferParser.readString();
							bufferParser.clear();
							if (dhData === void 0) return doFatalError(this._protocol, "Received malformed KEX*_INIT", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
							this._dhData = dhData;
							let hostKey = this._protocol._hostKeys[this.negotiated.serverHostKey];
							if (Array.isArray(hostKey)) hostKey = hostKey[0];
							this._hostKey = hostKey;
							this.finish();
						} else {
							if (type !== MESSAGE.KEXDH_REPLY) return doFatalError(this._protocol, `Received packet ${type} instead of ${MESSAGE.KEXDH_REPLY}`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
							this._protocol._debug && this._protocol._debug("Received DH Reply");
							bufferParser.init(payload, 1);
							let hostPubKey;
							let dhData;
							let sig;
							if ((hostPubKey = bufferParser.readString()) === void 0 || (dhData = bufferParser.readString()) === void 0 || (sig = bufferParser.readString()) === void 0) {
								bufferParser.clear();
								return doFatalError(this._protocol, "Received malformed KEX*_REPLY", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
							}
							bufferParser.clear();
							bufferParser.init(hostPubKey, 0);
							const hostPubKeyType = bufferParser.readString(true);
							bufferParser.clear();
							if (hostPubKeyType === void 0) return doFatalError(this._protocol, "Received malformed host public key", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
							if (hostPubKeyType !== this.negotiated.serverHostKey) switch (this.negotiated.serverHostKey) {
								case "rsa-sha2-256":
								case "rsa-sha2-512": if (hostPubKeyType === "ssh-rsa") break;
								default: return doFatalError(this._protocol, "Host key does not match negotiated type", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
							}
							this._hostKey = hostPubKey;
							this._dhData = dhData;
							this._sig = sig;
							let checked = false;
							let ret;
							if (this._protocol._hostVerifier === void 0) {
								ret = true;
								this._protocol._debug && this._protocol._debug("Host accepted by default (no verification)");
							} else ret = this._protocol._hostVerifier(hostPubKey, (permitted) => {
								if (checked) return;
								checked = true;
								if (permitted === false) {
									this._protocol._debug && this._protocol._debug("Host denied (verification failed)");
									return doFatalError(this._protocol, "Host denied (verification failed)", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
								}
								this._protocol._debug && this._protocol._debug("Host accepted (verified)");
								this._hostVerified = true;
								if (this._receivedNEWKEYS) this.finish();
								else trySendNEWKEYS(this);
							});
							if (ret === void 0) {
								++this._step;
								return;
							}
							checked = true;
							if (ret === false) {
								this._protocol._debug && this._protocol._debug("Host denied (verification failed)");
								return doFatalError(this._protocol, "Host denied (verification failed)", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
							}
							this._protocol._debug && this._protocol._debug("Host accepted (verified)");
							this._hostVerified = true;
							trySendNEWKEYS(this);
						}
						++this._step;
						break;
					case 2:
						if (type !== MESSAGE.NEWKEYS) return doFatalError(this._protocol, `Received packet ${type} instead of ${MESSAGE.NEWKEYS}`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
						this._protocol._debug && this._protocol._debug("Inbound: NEWKEYS");
						this._receivedNEWKEYS = true;
						if (this._protocol._strictMode) this._protocol._decipher.inSeqno = 0;
						++this._step;
						return this.finish(!this._protocol._server && !this._hostVerified);
					default: return doFatalError(this._protocol, `Received unexpected packet ${type} after NEWKEYS`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
				}
			}
		}
		class Curve25519Exchange extends KeyExchange {
			constructor(hashName, ...args) {
				super(...args);
				this.type = "25519";
				this.hashName = hashName;
				this._keys = null;
			}
			generateKeys() {
				if (!this._keys) this._keys = generateKeyPairSync("x25519");
			}
			getPublicKey() {
				this.generateKeys();
				return this._keys.publicKey.export({
					type: "spki",
					format: "der"
				}).slice(-32);
			}
			convertPublicKey(key) {
				let newKey;
				let idx = 0;
				let len = key.length;
				while (key[idx] === 0) {
					++idx;
					--len;
				}
				if (key.length === 32) return key;
				if (len !== key.length) {
					newKey = Buffer.allocUnsafe(len);
					key.copy(newKey, 0, idx);
					key = newKey;
				}
				return key;
			}
			computeSecret(otherPublicKey) {
				this.generateKeys();
				try {
					const asnWriter = new Ber.Writer();
					asnWriter.startSequence();
					asnWriter.startSequence();
					asnWriter.writeOID("1.3.101.110");
					asnWriter.endSequence();
					asnWriter.startSequence(Ber.BitString);
					asnWriter.writeByte(0);
					asnWriter._ensure(otherPublicKey.length);
					otherPublicKey.copy(asnWriter._buf, asnWriter._offset, 0, otherPublicKey.length);
					asnWriter._offset += otherPublicKey.length;
					asnWriter.endSequence();
					asnWriter.endSequence();
					return convertToMpint(diffieHellman({
						privateKey: this._keys.privateKey,
						publicKey: createPublicKey({
							key: asnWriter.buffer,
							type: "spki",
							format: "der"
						})
					}));
				} catch (ex) {
					return ex;
				}
			}
		}
		class ECDHExchange extends KeyExchange {
			constructor(curveName, hashName, ...args) {
				super(...args);
				this.type = "ecdh";
				this.curveName = curveName;
				this.hashName = hashName;
			}
			generateKeys() {
				if (!this._dh) {
					this._dh = createECDH(this.curveName);
					this._public = this._dh.generateKeys();
				}
			}
		}
		class DHGroupExchange extends KeyExchange {
			constructor(hashName, ...args) {
				super(...args);
				this.type = "groupex";
				this.hashName = hashName;
				this._prime = null;
				this._generator = null;
				this._minBits = GEX_MIN_BITS;
				this._prefBits = dhEstimate(this.negotiated);
				if (this._protocol._compatFlags & COMPAT.BUG_DHGEX_LARGE) this._prefBits = Math.min(this._prefBits, 4096);
				this._maxBits = GEX_MAX_BITS;
			}
			start() {
				if (this._protocol._server) return;
				this._protocol._debug && this._protocol._debug("Outbound: Sending KEXDH_GEX_REQUEST");
				let p = this._protocol._packetRW.write.allocStartKEX;
				const packet = this._protocol._packetRW.write.alloc(13, true);
				packet[p] = MESSAGE.KEXDH_GEX_REQUEST;
				writeUInt32BE(packet, this._minBits, ++p);
				writeUInt32BE(packet, this._prefBits, p += 4);
				writeUInt32BE(packet, this._maxBits, p += 4);
				this._protocol._cipher.encrypt(this._protocol._packetRW.write.finalize(packet, true));
			}
			generateKeys() {
				if (!this._dh && this._prime && this._generator) {
					this._dh = createDiffieHellman(this._prime, this._generator);
					this._public = this._dh.generateKeys();
				}
			}
			setDHParams(prime, generator) {
				if (!Buffer.isBuffer(prime)) throw new Error("Invalid prime value");
				if (!Buffer.isBuffer(generator)) throw new Error("Invalid generator value");
				this._prime = prime;
				this._generator = generator;
			}
			getDHParams() {
				if (this._dh) return {
					prime: convertToMpint(this._dh.getPrime()),
					generator: convertToMpint(this._dh.getGenerator())
				};
			}
			parse(payload) {
				const type = payload[0];
				switch (this._step) {
					case 1: {
						if (this._protocol._server) {
							if (type !== MESSAGE.KEXDH_GEX_REQUEST) return doFatalError(this._protocol, `Received packet ${type} instead of ` + MESSAGE.KEXDH_GEX_REQUEST, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
							return doFatalError(this._protocol, "Group exchange not implemented for server", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
						}
						if (type !== MESSAGE.KEXDH_GEX_GROUP) return doFatalError(this._protocol, `Received packet ${type} instead of ${MESSAGE.KEXDH_GEX_GROUP}`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
						this._protocol._debug && this._protocol._debug("Received DH GEX Group");
						bufferParser.init(payload, 1);
						let prime;
						let gen;
						if ((prime = bufferParser.readString()) === void 0 || (gen = bufferParser.readString()) === void 0) {
							bufferParser.clear();
							return doFatalError(this._protocol, "Received malformed KEXDH_GEX_GROUP", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
						}
						bufferParser.clear();
						this.setDHParams(prime, gen);
						this.generateKeys();
						const pubkey = this.getPublicKey();
						this._protocol._debug && this._protocol._debug("Outbound: Sending KEXDH_GEX_INIT");
						let p = this._protocol._packetRW.write.allocStartKEX;
						const packet = this._protocol._packetRW.write.alloc(5 + pubkey.length, true);
						packet[p] = MESSAGE.KEXDH_GEX_INIT;
						writeUInt32BE(packet, pubkey.length, ++p);
						packet.set(pubkey, p += 4);
						this._protocol._cipher.encrypt(this._protocol._packetRW.write.finalize(packet, true));
						++this._step;
						break;
					}
					case 2:
						if (this._protocol._server) {
							if (type !== MESSAGE.KEXDH_GEX_INIT) return doFatalError(this._protocol, `Received packet ${type} instead of ${MESSAGE.KEXDH_GEX_INIT}`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
							this._protocol._debug && this._protocol._debug("Received DH GEX Init");
							return doFatalError(this._protocol, "Group exchange not implemented for server", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
						} else if (type !== MESSAGE.KEXDH_GEX_REPLY) return doFatalError(this._protocol, `Received packet ${type} instead of ${MESSAGE.KEXDH_GEX_REPLY}`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
						this._protocol._debug && this._protocol._debug("Received DH GEX Reply");
						this._step = 1;
						payload[0] = MESSAGE.KEXDH_REPLY;
						this.parse = KeyExchange.prototype.parse;
						this.parse(payload);
				}
			}
		}
		class DHExchange extends KeyExchange {
			constructor(groupName, hashName, ...args) {
				super(...args);
				this.type = "group";
				this.groupName = groupName;
				this.hashName = hashName;
			}
			start() {
				if (!this._protocol._server) {
					this._protocol._debug && this._protocol._debug("Outbound: Sending KEXDH_INIT");
					const pubKey = this.getPublicKey();
					let p = this._protocol._packetRW.write.allocStartKEX;
					const packet = this._protocol._packetRW.write.alloc(5 + pubKey.length, true);
					packet[p] = MESSAGE.KEXDH_INIT;
					writeUInt32BE(packet, pubKey.length, ++p);
					packet.set(pubKey, p += 4);
					this._protocol._cipher.encrypt(this._protocol._packetRW.write.finalize(packet, true));
				}
			}
			generateKeys() {
				if (!this._dh) {
					this._dh = createDiffieHellmanGroup(this.groupName);
					this._public = this._dh.generateKeys();
				}
			}
			getDHParams() {
				if (this._dh) return {
					prime: convertToMpint(this._dh.getPrime()),
					generator: convertToMpint(this._dh.getGenerator())
				};
			}
		}
		return (negotiated, ...args) => {
			if (typeof negotiated !== "object" || negotiated === null) throw new Error("Invalid negotiated argument");
			const kexType = negotiated.kex;
			if (typeof kexType === "string") {
				args = [negotiated, ...args];
				switch (kexType) {
					case "curve25519-sha256":
					case "curve25519-sha256@libssh.org":
						if (!curve25519Supported) break;
						return new Curve25519Exchange("sha256", ...args);
					case "ecdh-sha2-nistp256": return new ECDHExchange("prime256v1", "sha256", ...args);
					case "ecdh-sha2-nistp384": return new ECDHExchange("secp384r1", "sha384", ...args);
					case "ecdh-sha2-nistp521": return new ECDHExchange("secp521r1", "sha512", ...args);
					case "diffie-hellman-group1-sha1": return new DHExchange("modp2", "sha1", ...args);
					case "diffie-hellman-group14-sha1": return new DHExchange("modp14", "sha1", ...args);
					case "diffie-hellman-group14-sha256": return new DHExchange("modp14", "sha256", ...args);
					case "diffie-hellman-group15-sha512": return new DHExchange("modp15", "sha512", ...args);
					case "diffie-hellman-group16-sha512": return new DHExchange("modp16", "sha512", ...args);
					case "diffie-hellman-group17-sha512": return new DHExchange("modp17", "sha512", ...args);
					case "diffie-hellman-group18-sha512": return new DHExchange("modp18", "sha512", ...args);
					case "diffie-hellman-group-exchange-sha1": return new DHGroupExchange("sha1", ...args);
					case "diffie-hellman-group-exchange-sha256": return new DHGroupExchange("sha256", ...args);
				}
				throw new Error(`Unsupported key exchange algorithm: ${kexType}`);
			}
			throw new Error(`Invalid key exchange type: ${kexType}`);
		};
	})();
	const KexInit = (() => {
		const KEX_PROPERTY_NAMES = [
			"kex",
			"serverHostKey",
			["cs", "cipher"],
			["sc", "cipher"],
			["cs", "mac"],
			["sc", "mac"],
			["cs", "compress"],
			["sc", "compress"],
			["cs", "lang"],
			["sc", "lang"]
		];
		return class KexInit {
			constructor(obj) {
				if (typeof obj !== "object" || obj === null) throw new TypeError("Argument must be an object");
				const lists = {
					kex: void 0,
					serverHostKey: void 0,
					cs: {
						cipher: void 0,
						mac: void 0,
						compress: void 0,
						lang: void 0
					},
					sc: {
						cipher: void 0,
						mac: void 0,
						compress: void 0,
						lang: void 0
					},
					all: void 0
				};
				let totalSize = 0;
				for (const prop of KEX_PROPERTY_NAMES) {
					let base;
					let val;
					let desc;
					let key;
					if (typeof prop === "string") {
						base = lists;
						val = obj[prop];
						desc = key = prop;
					} else {
						const parent = prop[0];
						base = lists[parent];
						key = prop[1];
						val = obj[parent][key];
						desc = `${parent}.${key}`;
					}
					const entry = {
						array: void 0,
						buffer: void 0
					};
					if (Buffer.isBuffer(val)) {
						entry.array = ("" + val).split(",");
						entry.buffer = val;
						totalSize += 4 + val.length;
					} else {
						if (typeof val === "string") val = val.split(",");
						if (Array.isArray(val)) {
							entry.array = val;
							entry.buffer = Buffer.from(val.join(","));
						} else throw new TypeError(`Invalid \`${desc}\` type: ${typeof val}`);
						totalSize += 4 + entry.buffer.length;
					}
					base[key] = entry;
				}
				const all = Buffer.allocUnsafe(totalSize);
				lists.all = all;
				let allPos = 0;
				for (const prop of KEX_PROPERTY_NAMES) {
					let data;
					if (typeof prop === "string") data = lists[prop].buffer;
					else data = lists[prop[0]][prop[1]].buffer;
					allPos = writeUInt32BE(all, data.length, allPos);
					all.set(data, allPos);
					allPos += data.length;
				}
				this.totalSize = totalSize;
				this.lists = lists;
			}
			copyAllTo(buf, offset) {
				const src = this.lists.all;
				if (typeof offset !== "number") throw new TypeError(`Invalid offset value: ${typeof offset}`);
				if (buf.length - offset < src.length) throw new Error("Insufficient space to copy list");
				buf.set(src, offset);
				return src.length;
			}
		};
	})();
	const hashString = (() => {
		const LEN = Buffer.allocUnsafe(4);
		return (hash, buf) => {
			writeUInt32BE(LEN, buf.length, 0);
			hash.update(LEN);
			hash.update(buf);
		};
	})();
	function generateKEXVal(len, hashName, secret, exchangeHash, sessionID, char) {
		let ret;
		if (len) {
			let digest = createHash$2(hashName).update(secret).update(exchangeHash).update(char).update(sessionID).digest();
			while (digest.length < len) {
				const chunk = createHash$2(hashName).update(secret).update(exchangeHash).update(digest).digest();
				const extended = Buffer.allocUnsafe(digest.length + chunk.length);
				extended.set(digest, 0);
				extended.set(chunk, digest.length);
				digest = extended;
			}
			if (digest.length === len) ret = digest;
			else ret = new FastBuffer(digest.buffer, digest.byteOffset, len);
		} else ret = EMPTY_BUFFER;
		return ret;
	}
	function onKEXPayload(state, payload) {
		if (payload.length === 0) {
			this._debug && this._debug("Inbound: Skipping empty packet payload");
			return;
		}
		if (this._skipNextInboundPacket) {
			this._skipNextInboundPacket = false;
			return;
		}
		payload = this._packetRW.read.read(payload);
		const type = payload[0];
		if (!this._strictMode) switch (type) {
			case MESSAGE.IGNORE:
			case MESSAGE.UNIMPLEMENTED:
			case MESSAGE.DEBUG:
				if (!MESSAGE_HANDLERS) MESSAGE_HANDLERS = require_handlers();
				return MESSAGE_HANDLERS[type](this, payload);
		}
		switch (type) {
			case MESSAGE.DISCONNECT:
				if (!MESSAGE_HANDLERS) MESSAGE_HANDLERS = require_handlers();
				return MESSAGE_HANDLERS[type](this, payload);
			case MESSAGE.KEXINIT:
				if (!state.firstPacket) return doFatalError(this, "Received extra KEXINIT during handshake", "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
				state.firstPacket = false;
				return handleKexInit(this, payload);
			default: if (type < 20 || type > 49) return doFatalError(this, `Received unexpected packet type ${type}`, "handshake", DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
		}
		return this._kex.parse(payload);
	}
	function dhEstimate(neg) {
		const csCipher = CIPHER_INFO[neg.cs.cipher];
		const scCipher = CIPHER_INFO[neg.sc.cipher];
		const bits = Math.max(0, csCipher.sslName === "des-ede3-cbc" ? 14 : csCipher.keyLen, csCipher.blockLen, csCipher.ivLen, scCipher.sslName === "des-ede3-cbc" ? 14 : scCipher.keyLen, scCipher.blockLen, scCipher.ivLen) * 8;
		if (bits <= 112) return 2048;
		if (bits <= 128) return 3072;
		if (bits <= 192) return 7680;
		return 8192;
	}
	function trySendNEWKEYS(kex) {
		if (!kex._sentNEWKEYS) {
			kex._protocol._debug && kex._protocol._debug("Outbound: Sending NEWKEYS");
			const p = kex._protocol._packetRW.write.allocStartKEX;
			const packet = kex._protocol._packetRW.write.alloc(1, true);
			packet[p] = MESSAGE.NEWKEYS;
			kex._protocol._cipher.encrypt(kex._protocol._packetRW.write.finalize(packet, true));
			kex._sentNEWKEYS = true;
			if (kex._protocol._strictMode) kex._protocol._cipher.outSeqno = 0;
		}
	}
	module.exports = {
		KexInit,
		kexinit,
		onKEXPayload,
		DEFAULT_KEXINIT_CLIENT: new KexInit({
			kex: DEFAULT_KEX.concat(["ext-info-c", "kex-strict-c-v00@openssh.com"]),
			serverHostKey: DEFAULT_SERVER_HOST_KEY,
			cs: {
				cipher: DEFAULT_CIPHER,
				mac: DEFAULT_MAC,
				compress: DEFAULT_COMPRESSION,
				lang: []
			},
			sc: {
				cipher: DEFAULT_CIPHER,
				mac: DEFAULT_MAC,
				compress: DEFAULT_COMPRESSION,
				lang: []
			}
		}),
		DEFAULT_KEXINIT_SERVER: new KexInit({
			kex: DEFAULT_KEX.concat(["kex-strict-s-v00@openssh.com"]),
			serverHostKey: DEFAULT_SERVER_HOST_KEY,
			cs: {
				cipher: DEFAULT_CIPHER,
				mac: DEFAULT_MAC,
				compress: DEFAULT_COMPRESSION,
				lang: []
			},
			sc: {
				cipher: DEFAULT_CIPHER,
				mac: DEFAULT_MAC,
				compress: DEFAULT_COMPRESSION,
				lang: []
			}
		}),
		HANDLERS: { [MESSAGE.KEXINIT]: handleKexInit }
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/package.json
var require_package = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	module.exports = {
		"name": "ssh2",
		"version": "1.17.0",
		"author": "Brian White <mscdex@mscdex.net>",
		"description": "SSH2 client and server modules written in pure JavaScript for node.js",
		"main": "./lib/index.js",
		"engines": { "node": ">=10.16.0" },
		"dependencies": {
			"asn1": "^0.2.6",
			"bcrypt-pbkdf": "^1.0.2"
		},
		"devDependencies": {
			"@mscdex/eslint-config": "^1.1.0",
			"eslint": "^7.32.0"
		},
		"optionalDependencies": {
			"cpu-features": "~0.0.10",
			"nan": "^2.23.0"
		},
		"scripts": {
			"install": "node install.js",
			"rebuild": "node install.js",
			"test": "node test/test.js",
			"lint": "eslint --cache --report-unused-disable-directives --ext=.js .eslintrc.js examples lib test",
			"lint:fix": "npm run lint -- --fix"
		},
		"keywords": [
			"ssh",
			"ssh2",
			"sftp",
			"secure",
			"shell",
			"exec",
			"remote",
			"client"
		],
		"licenses": [{
			"type": "MIT",
			"url": "http://github.com/mscdex/ssh2/raw/master/LICENSE"
		}],
		"repository": {
			"type": "git",
			"url": "http://github.com/mscdex/ssh2.git"
		}
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/Protocol.js
var require_Protocol = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { inspect: inspect$1 } = __require("util");
	const { bindingAvailable, NullCipher, NullDecipher } = require_crypto();
	const { COMPAT_CHECKS, DISCONNECT_REASON, eddsaSupported, MESSAGE, SIGNALS, TERMINAL_MODE } = require_constants();
	const { DEFAULT_KEXINIT_CLIENT, DEFAULT_KEXINIT_SERVER, KexInit, kexinit, onKEXPayload } = require_kex();
	const { parseKey } = require_keyParser();
	const MESSAGE_HANDLERS = require_handlers();
	const { bufferCopy, bufferFill, bufferSlice, convertSignature, sendPacket, writeUInt32BE } = require_utils$1();
	const { PacketReader, PacketWriter, ZlibPacketReader, ZlibPacketWriter } = require_zlib();
	const MODULE_VER = require_package().version;
	const VALID_DISCONNECT_REASONS = new Map(Object.values(DISCONNECT_REASON).map((n) => [n, 1]));
	const IDENT_RAW = Buffer.from(`SSH-2.0-ssh2js${MODULE_VER}`);
	const IDENT = Buffer.from(`${IDENT_RAW}\r\n`);
	const MAX_LINE_LEN = 8192;
	const MAX_LINES = 1024;
	const PING_PAYLOAD = Buffer.from([
		MESSAGE.GLOBAL_REQUEST,
		0,
		0,
		0,
		21,
		107,
		101,
		101,
		112,
		97,
		108,
		105,
		118,
		101,
		64,
		111,
		112,
		101,
		110,
		115,
		115,
		104,
		46,
		99,
		111,
		109,
		1
	]);
	const NO_TERMINAL_MODES_BUFFER = Buffer.from([TERMINAL_MODE.TTY_OP_END]);
	function noop() {}
	var Protocol = class {
		constructor(config) {
			const onWrite = config.onWrite;
			if (typeof onWrite !== "function") throw new Error("Missing onWrite function");
			this._onWrite = (data) => {
				onWrite(data);
			};
			const onError = config.onError;
			if (typeof onError !== "function") throw new Error("Missing onError function");
			this._onError = (err) => {
				onError(err);
			};
			const debug = config.debug;
			this._debug = typeof debug === "function" ? (msg) => {
				debug(msg);
			} : void 0;
			const onHeader = config.onHeader;
			this._onHeader = typeof onHeader === "function" ? (...args) => {
				onHeader(...args);
			} : noop;
			const onPacket = config.onPacket;
			this._onPacket = typeof onPacket === "function" ? () => {
				onPacket();
			} : noop;
			let onHandshakeComplete = config.onHandshakeComplete;
			if (typeof onHandshakeComplete !== "function") onHandshakeComplete = noop;
			let firstHandshake;
			this._onHandshakeComplete = (...args) => {
				this._debug && this._debug("Handshake completed");
				if (firstHandshake === void 0) firstHandshake = true;
				else firstHandshake = false;
				const oldQueue = this._queue;
				if (oldQueue) {
					this._queue = void 0;
					this._debug && this._debug(`Draining outbound queue (${oldQueue.length}) ...`);
					for (let i = 0; i < oldQueue.length; ++i) {
						const data = oldQueue[i];
						let finalized = this._packetRW.write.finalize(data);
						if (finalized === data) {
							const packet = this._cipher.allocPacket(data.length);
							packet.set(data, 5);
							finalized = packet;
						}
						sendPacket(this, finalized);
					}
					this._debug && this._debug("... finished draining outbound queue");
				}
				if (firstHandshake && this._server && this._kex.remoteExtInfoEnabled) sendExtInfo(this);
				onHandshakeComplete(...args);
			};
			this._queue = void 0;
			const messageHandlers = config.messageHandlers;
			if (typeof messageHandlers === "object" && messageHandlers !== null) this._handlers = messageHandlers;
			else this._handlers = {};
			this._onPayload = onPayload.bind(this);
			this._server = !!config.server;
			this._banner = void 0;
			let greeting;
			if (this._server) {
				if (typeof config.hostKeys !== "object" || config.hostKeys === null) throw new Error("Missing server host key(s)");
				this._hostKeys = config.hostKeys;
				if (typeof config.greeting === "string" && config.greeting.length) greeting = config.greeting.slice(-2) === "\r\n" ? config.greeting : `${config.greeting}\r\n`;
				if (typeof config.banner === "string" && config.banner.length) this._banner = config.banner.slice(-2) === "\r\n" ? config.banner : `${config.banner}\r\n`;
			} else this._hostKeys = void 0;
			let offer = config.offer;
			if (typeof offer !== "object" || offer === null) offer = this._server ? DEFAULT_KEXINIT_SERVER : DEFAULT_KEXINIT_CLIENT;
			else if (offer.constructor !== KexInit) {
				if (this._server) offer.kex = offer.kex.concat(["kex-strict-s-v00@openssh.com"]);
				else offer.kex = offer.kex.concat(["ext-info-c", "kex-strict-c-v00@openssh.com"]);
				offer = new KexInit(offer);
			}
			this._kex = void 0;
			this._strictMode = void 0;
			this._kexinit = void 0;
			this._offer = offer;
			this._cipher = new NullCipher(0, this._onWrite);
			this._decipher = void 0;
			this._skipNextInboundPacket = false;
			this._packetRW = {
				read: new PacketReader(),
				write: new PacketWriter(this)
			};
			this._hostVerifier = !this._server && typeof config.hostVerifier === "function" ? config.hostVerifier : void 0;
			this._parse = parseHeader;
			this._buffer = void 0;
			this._authsQueue = [];
			this._authenticated = false;
			this._remoteIdentRaw = void 0;
			let sentIdent;
			if (typeof config.ident === "string") {
				this._identRaw = Buffer.from(`SSH-2.0-${config.ident}`);
				sentIdent = Buffer.allocUnsafe(this._identRaw.length + 2);
				sentIdent.set(this._identRaw, 0);
				sentIdent[sentIdent.length - 2] = 13;
				sentIdent[sentIdent.length - 1] = 10;
			} else if (Buffer.isBuffer(config.ident)) {
				const fullIdent = Buffer.allocUnsafe(8 + config.ident.length);
				fullIdent.latin1Write("SSH-2.0-", 0, 8);
				fullIdent.set(config.ident, 8);
				this._identRaw = fullIdent;
				sentIdent = Buffer.allocUnsafe(fullIdent.length + 2);
				sentIdent.set(fullIdent, 0);
				sentIdent[sentIdent.length - 2] = 13;
				sentIdent[sentIdent.length - 1] = 10;
			} else {
				this._identRaw = IDENT_RAW;
				sentIdent = IDENT;
			}
			this._compatFlags = 0;
			if (this._debug) {
				if (bindingAvailable) this._debug("Custom crypto binding available");
				else this._debug("Custom crypto binding not available");
			}
			this._debug && this._debug(`Local ident: ${inspect$1(this._identRaw.toString())}`);
			this.start = () => {
				this.start = void 0;
				if (greeting) this._onWrite(greeting);
				this._onWrite(sentIdent);
			};
		}
		_destruct(reason) {
			this._packetRW.read.cleanup();
			this._packetRW.write.cleanup();
			this._cipher && this._cipher.free();
			this._decipher && this._decipher.free();
			if (typeof reason !== "string" || reason.length === 0) reason = "fatal error";
			this.parse = () => {
				throw new Error(`Instance unusable after ${reason}`);
			};
			this._onWrite = () => {
				throw new Error(`Instance unusable after ${reason}`);
			};
			this._destruct = void 0;
		}
		cleanup() {
			this._destruct && this._destruct();
		}
		parse(chunk, i, len) {
			while (i < len) i = this._parse(chunk, i, len);
		}
		disconnect(reason) {
			const pktLen = 13;
			let p = this._packetRW.write.allocStartKEX;
			const packet = this._packetRW.write.alloc(pktLen, true);
			const end = p + pktLen;
			if (!VALID_DISCONNECT_REASONS.has(reason)) reason = DISCONNECT_REASON.PROTOCOL_ERROR;
			packet[p] = MESSAGE.DISCONNECT;
			writeUInt32BE(packet, reason, ++p);
			packet.fill(0, p += 4, end);
			this._debug && this._debug(`Outbound: Sending DISCONNECT (${reason})`);
			sendPacket(this, this._packetRW.write.finalize(packet, true), true);
		}
		ping() {
			const p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(PING_PAYLOAD.length);
			packet.set(PING_PAYLOAD, p);
			this._debug && this._debug("Outbound: Sending ping (GLOBAL_REQUEST: keepalive@openssh.com)");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		rekey() {
			if (this._kexinit === void 0) {
				this._debug && this._debug("Outbound: Initiated explicit rekey");
				this._queue = [];
				kexinit(this);
			} else this._debug && this._debug("Outbound: Ignoring rekey during handshake");
		}
		requestSuccess(data) {
			let p = this._packetRW.write.allocStart;
			let packet;
			if (Buffer.isBuffer(data)) {
				packet = this._packetRW.write.alloc(1 + data.length);
				packet[p] = MESSAGE.REQUEST_SUCCESS;
				packet.set(data, ++p);
			} else {
				packet = this._packetRW.write.alloc(1);
				packet[p] = MESSAGE.REQUEST_SUCCESS;
			}
			this._debug && this._debug("Outbound: Sending REQUEST_SUCCESS");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		requestFailure() {
			const p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(1);
			packet[p] = MESSAGE.REQUEST_FAILURE;
			this._debug && this._debug("Outbound: Sending REQUEST_FAILURE");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		channelSuccess(chan) {
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5);
			packet[p] = MESSAGE.CHANNEL_SUCCESS;
			writeUInt32BE(packet, chan, ++p);
			this._debug && this._debug(`Outbound: Sending CHANNEL_SUCCESS (r:${chan})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		channelFailure(chan) {
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5);
			packet[p] = MESSAGE.CHANNEL_FAILURE;
			writeUInt32BE(packet, chan, ++p);
			this._debug && this._debug(`Outbound: Sending CHANNEL_FAILURE (r:${chan})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		channelEOF(chan) {
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5);
			packet[p] = MESSAGE.CHANNEL_EOF;
			writeUInt32BE(packet, chan, ++p);
			this._debug && this._debug(`Outbound: Sending CHANNEL_EOF (r:${chan})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		channelClose(chan) {
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5);
			packet[p] = MESSAGE.CHANNEL_CLOSE;
			writeUInt32BE(packet, chan, ++p);
			this._debug && this._debug(`Outbound: Sending CHANNEL_CLOSE (r:${chan})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		channelWindowAdjust(chan, amount) {
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(9);
			packet[p] = MESSAGE.CHANNEL_WINDOW_ADJUST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, amount, p += 4);
			this._debug && this._debug(`Outbound: Sending CHANNEL_WINDOW_ADJUST (r:${chan}, ${amount})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		channelData(chan, data) {
			const isBuffer = Buffer.isBuffer(data);
			const dataLen = isBuffer ? data.length : Buffer.byteLength(data);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(9 + dataLen);
			packet[p] = MESSAGE.CHANNEL_DATA;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, dataLen, p += 4);
			if (isBuffer) packet.set(data, p += 4);
			else packet.utf8Write(data, p += 4, dataLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_DATA (r:${chan}, ${dataLen})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		channelExtData(chan, data, type) {
			const isBuffer = Buffer.isBuffer(data);
			const dataLen = isBuffer ? data.length : Buffer.byteLength(data);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(13 + dataLen);
			packet[p] = MESSAGE.CHANNEL_EXTENDED_DATA;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, type, p += 4);
			writeUInt32BE(packet, dataLen, p += 4);
			if (isBuffer) packet.set(data, p += 4);
			else packet.utf8Write(data, p += 4, dataLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_EXTENDED_DATA (r:${chan})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		channelOpenConfirm(remote, local, initWindow, maxPacket) {
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(17);
			packet[p] = MESSAGE.CHANNEL_OPEN_CONFIRMATION;
			writeUInt32BE(packet, remote, ++p);
			writeUInt32BE(packet, local, p += 4);
			writeUInt32BE(packet, initWindow, p += 4);
			writeUInt32BE(packet, maxPacket, p += 4);
			this._debug && this._debug(`Outbound: Sending CHANNEL_OPEN_CONFIRMATION (r:${remote}, l:${local})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		channelOpenFail(remote, reason, desc) {
			if (typeof desc !== "string") desc = "";
			const descLen = Buffer.byteLength(desc);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(13 + descLen + 4);
			packet[p] = MESSAGE.CHANNEL_OPEN_FAILURE;
			writeUInt32BE(packet, remote, ++p);
			writeUInt32BE(packet, reason, p += 4);
			writeUInt32BE(packet, descLen, p += 4);
			p += 4;
			if (descLen) {
				packet.utf8Write(desc, p, descLen);
				p += descLen;
			}
			writeUInt32BE(packet, 0, p);
			this._debug && this._debug(`Outbound: Sending CHANNEL_OPEN_FAILURE (r:${remote})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		service(name) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const nameLen = Buffer.byteLength(name);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + nameLen);
			packet[p] = MESSAGE.SERVICE_REQUEST;
			writeUInt32BE(packet, nameLen, ++p);
			packet.utf8Write(name, p += 4, nameLen);
			this._debug && this._debug(`Outbound: Sending SERVICE_REQUEST (${name})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		authPassword(username, password, newPassword) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const userLen = Buffer.byteLength(username);
			const passLen = Buffer.byteLength(password);
			const newPassLen = newPassword ? Buffer.byteLength(newPassword) : 0;
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + userLen + 4 + 14 + 4 + 8 + 1 + 4 + passLen + (newPassword ? 4 + newPassLen : 0));
			packet[p] = MESSAGE.USERAUTH_REQUEST;
			writeUInt32BE(packet, userLen, ++p);
			packet.utf8Write(username, p += 4, userLen);
			writeUInt32BE(packet, 14, p += userLen);
			packet.utf8Write("ssh-connection", p += 4, 14);
			writeUInt32BE(packet, 8, p += 14);
			packet.utf8Write("password", p += 4, 8);
			packet[p += 8] = newPassword ? 1 : 0;
			writeUInt32BE(packet, passLen, ++p);
			if (Buffer.isBuffer(password)) bufferCopy(password, packet, 0, passLen, p += 4);
			else packet.utf8Write(password, p += 4, passLen);
			if (newPassword) {
				writeUInt32BE(packet, newPassLen, p += passLen);
				if (Buffer.isBuffer(newPassword)) bufferCopy(newPassword, packet, 0, newPassLen, p += 4);
				else packet.utf8Write(newPassword, p += 4, newPassLen);
				this._debug && this._debug("Outbound: Sending USERAUTH_REQUEST (changed password)");
			} else this._debug && this._debug("Outbound: Sending USERAUTH_REQUEST (password)");
			this._authsQueue.push("password");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		authPK(username, pubKey, keyAlgo, cbSign) {
			if (this._server) throw new Error("Client-only method called in server mode");
			pubKey = parseKey(pubKey);
			if (pubKey instanceof Error) throw new Error("Invalid key");
			const keyType = pubKey.type;
			pubKey = pubKey.getPublicSSH();
			if (typeof keyAlgo === "function") {
				cbSign = keyAlgo;
				keyAlgo = void 0;
			}
			if (!keyAlgo) keyAlgo = keyType;
			const userLen = Buffer.byteLength(username);
			const algoLen = Buffer.byteLength(keyAlgo);
			const pubKeyLen = pubKey.length;
			const sessionID = this._kex.sessionID;
			const sesLen = sessionID.length;
			const payloadLen = (cbSign ? 4 + sesLen : 0) + 1 + 4 + userLen + 4 + 14 + 4 + 9 + 1 + 4 + algoLen + 4 + pubKeyLen;
			let packet;
			let p;
			if (cbSign) {
				packet = Buffer.allocUnsafe(payloadLen);
				p = 0;
				writeUInt32BE(packet, sesLen, p);
				packet.set(sessionID, p += 4);
				p += sesLen;
			} else {
				packet = this._packetRW.write.alloc(payloadLen);
				p = this._packetRW.write.allocStart;
			}
			packet[p] = MESSAGE.USERAUTH_REQUEST;
			writeUInt32BE(packet, userLen, ++p);
			packet.utf8Write(username, p += 4, userLen);
			writeUInt32BE(packet, 14, p += userLen);
			packet.utf8Write("ssh-connection", p += 4, 14);
			writeUInt32BE(packet, 9, p += 14);
			packet.utf8Write("publickey", p += 4, 9);
			packet[p += 9] = cbSign ? 1 : 0;
			writeUInt32BE(packet, algoLen, ++p);
			packet.utf8Write(keyAlgo, p += 4, algoLen);
			writeUInt32BE(packet, pubKeyLen, p += algoLen);
			packet.set(pubKey, p += 4);
			if (!cbSign) {
				this._authsQueue.push("publickey");
				this._debug && this._debug("Outbound: Sending USERAUTH_REQUEST (publickey -- check)");
				sendPacket(this, this._packetRW.write.finalize(packet));
				return;
			}
			cbSign(packet, (signature) => {
				signature = convertSignature(signature, keyType);
				if (signature === false) throw new Error("Error while converting handshake signature");
				const sigLen = signature.length;
				p = this._packetRW.write.allocStart;
				packet = this._packetRW.write.alloc(5 + userLen + 4 + 14 + 4 + 9 + 1 + 4 + algoLen + 4 + pubKeyLen + 4 + 4 + algoLen + 4 + sigLen);
				packet[p] = MESSAGE.USERAUTH_REQUEST;
				writeUInt32BE(packet, userLen, ++p);
				packet.utf8Write(username, p += 4, userLen);
				writeUInt32BE(packet, 14, p += userLen);
				packet.utf8Write("ssh-connection", p += 4, 14);
				writeUInt32BE(packet, 9, p += 14);
				packet.utf8Write("publickey", p += 4, 9);
				packet[p += 9] = 1;
				writeUInt32BE(packet, algoLen, ++p);
				packet.utf8Write(keyAlgo, p += 4, algoLen);
				writeUInt32BE(packet, pubKeyLen, p += algoLen);
				packet.set(pubKey, p += 4);
				writeUInt32BE(packet, 4 + algoLen + 4 + sigLen, p += pubKeyLen);
				writeUInt32BE(packet, algoLen, p += 4);
				packet.utf8Write(keyAlgo, p += 4, algoLen);
				writeUInt32BE(packet, sigLen, p += algoLen);
				packet.set(signature, p += 4);
				this._authsQueue.push("publickey");
				this._debug && this._debug("Outbound: Sending USERAUTH_REQUEST (publickey)");
				sendPacket(this, this._packetRW.write.finalize(packet));
			});
		}
		authHostbased(username, pubKey, hostname, userlocal, keyAlgo, cbSign) {
			if (this._server) throw new Error("Client-only method called in server mode");
			pubKey = parseKey(pubKey);
			if (pubKey instanceof Error) throw new Error("Invalid key");
			const keyType = pubKey.type;
			pubKey = pubKey.getPublicSSH();
			if (typeof keyAlgo === "function") {
				cbSign = keyAlgo;
				keyAlgo = void 0;
			}
			if (!keyAlgo) keyAlgo = keyType;
			const userLen = Buffer.byteLength(username);
			const algoLen = Buffer.byteLength(keyAlgo);
			const pubKeyLen = pubKey.length;
			const sessionID = this._kex.sessionID;
			const sesLen = sessionID.length;
			const hostnameLen = Buffer.byteLength(hostname);
			const userlocalLen = Buffer.byteLength(userlocal);
			const data = Buffer.allocUnsafe(4 + sesLen + 1 + 4 + userLen + 4 + 14 + 4 + 9 + 4 + algoLen + 4 + pubKeyLen + 4 + hostnameLen + 4 + userlocalLen);
			let p = 0;
			writeUInt32BE(data, sesLen, p);
			data.set(sessionID, p += 4);
			data[p += sesLen] = MESSAGE.USERAUTH_REQUEST;
			writeUInt32BE(data, userLen, ++p);
			data.utf8Write(username, p += 4, userLen);
			writeUInt32BE(data, 14, p += userLen);
			data.utf8Write("ssh-connection", p += 4, 14);
			writeUInt32BE(data, 9, p += 14);
			data.utf8Write("hostbased", p += 4, 9);
			writeUInt32BE(data, algoLen, p += 9);
			data.utf8Write(keyAlgo, p += 4, algoLen);
			writeUInt32BE(data, pubKeyLen, p += algoLen);
			data.set(pubKey, p += 4);
			writeUInt32BE(data, hostnameLen, p += pubKeyLen);
			data.utf8Write(hostname, p += 4, hostnameLen);
			writeUInt32BE(data, userlocalLen, p += hostnameLen);
			data.utf8Write(userlocal, p += 4, userlocalLen);
			cbSign(data, (signature) => {
				signature = convertSignature(signature, keyType);
				if (!signature) throw new Error("Error while converting handshake signature");
				const sigLen = signature.length;
				const reqDataLen = data.length - sesLen - 4;
				p = this._packetRW.write.allocStart;
				const packet = this._packetRW.write.alloc(reqDataLen + 4 + 4 + algoLen + 4 + sigLen);
				bufferCopy(data, packet, 4 + sesLen, data.length, p);
				writeUInt32BE(packet, 4 + algoLen + 4 + sigLen, p += reqDataLen);
				writeUInt32BE(packet, algoLen, p += 4);
				packet.utf8Write(keyAlgo, p += 4, algoLen);
				writeUInt32BE(packet, sigLen, p += algoLen);
				packet.set(signature, p += 4);
				this._authsQueue.push("hostbased");
				this._debug && this._debug("Outbound: Sending USERAUTH_REQUEST (hostbased)");
				sendPacket(this, this._packetRW.write.finalize(packet));
			});
		}
		authKeyboard(username) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const userLen = Buffer.byteLength(username);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + userLen + 4 + 14 + 4 + 20 + 4 + 4);
			packet[p] = MESSAGE.USERAUTH_REQUEST;
			writeUInt32BE(packet, userLen, ++p);
			packet.utf8Write(username, p += 4, userLen);
			writeUInt32BE(packet, 14, p += userLen);
			packet.utf8Write("ssh-connection", p += 4, 14);
			writeUInt32BE(packet, 20, p += 14);
			packet.utf8Write("keyboard-interactive", p += 4, 20);
			writeUInt32BE(packet, 0, p += 20);
			writeUInt32BE(packet, 0, p += 4);
			this._authsQueue.push("keyboard-interactive");
			this._debug && this._debug("Outbound: Sending USERAUTH_REQUEST (keyboard-interactive)");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		authNone(username) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const userLen = Buffer.byteLength(username);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + userLen + 4 + 14 + 4 + 4);
			packet[p] = MESSAGE.USERAUTH_REQUEST;
			writeUInt32BE(packet, userLen, ++p);
			packet.utf8Write(username, p += 4, userLen);
			writeUInt32BE(packet, 14, p += userLen);
			packet.utf8Write("ssh-connection", p += 4, 14);
			writeUInt32BE(packet, 4, p += 14);
			packet.utf8Write("none", p += 4, 4);
			this._authsQueue.push("none");
			this._debug && this._debug("Outbound: Sending USERAUTH_REQUEST (none)");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		authInfoRes(responses) {
			if (this._server) throw new Error("Client-only method called in server mode");
			let responsesTotalLen = 0;
			let responseLens;
			if (responses) {
				responseLens = new Array(responses.length);
				for (let i = 0; i < responses.length; ++i) {
					const len = Buffer.byteLength(responses[i]);
					responseLens[i] = len;
					responsesTotalLen += 4 + len;
				}
			}
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + responsesTotalLen);
			packet[p] = MESSAGE.USERAUTH_INFO_RESPONSE;
			if (responses) {
				writeUInt32BE(packet, responses.length, ++p);
				p += 4;
				for (let i = 0; i < responses.length; ++i) {
					const len = responseLens[i];
					writeUInt32BE(packet, len, p);
					p += 4;
					if (len) {
						packet.utf8Write(responses[i], p, len);
						p += len;
					}
				}
			} else writeUInt32BE(packet, 0, ++p);
			this._debug && this._debug("Outbound: Sending USERAUTH_INFO_RESPONSE");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		tcpipForward(bindAddr, bindPort, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const addrLen = Buffer.byteLength(bindAddr);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(23 + addrLen + 4);
			packet[p] = MESSAGE.GLOBAL_REQUEST;
			writeUInt32BE(packet, 13, ++p);
			packet.utf8Write("tcpip-forward", p += 4, 13);
			packet[p += 13] = wantReply === void 0 || wantReply === true ? 1 : 0;
			writeUInt32BE(packet, addrLen, ++p);
			packet.utf8Write(bindAddr, p += 4, addrLen);
			writeUInt32BE(packet, bindPort, p += addrLen);
			this._debug && this._debug("Outbound: Sending GLOBAL_REQUEST (tcpip-forward)");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		cancelTcpipForward(bindAddr, bindPort, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const addrLen = Buffer.byteLength(bindAddr);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(30 + addrLen + 4);
			packet[p] = MESSAGE.GLOBAL_REQUEST;
			writeUInt32BE(packet, 20, ++p);
			packet.utf8Write("cancel-tcpip-forward", p += 4, 20);
			packet[p += 20] = wantReply === void 0 || wantReply === true ? 1 : 0;
			writeUInt32BE(packet, addrLen, ++p);
			packet.utf8Write(bindAddr, p += 4, addrLen);
			writeUInt32BE(packet, bindPort, p += addrLen);
			this._debug && this._debug("Outbound: Sending GLOBAL_REQUEST (cancel-tcpip-forward)");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		openssh_streamLocalForward(socketPath, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const socketPathLen = Buffer.byteLength(socketPath);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(41 + socketPathLen);
			packet[p] = MESSAGE.GLOBAL_REQUEST;
			writeUInt32BE(packet, 31, ++p);
			packet.utf8Write("streamlocal-forward@openssh.com", p += 4, 31);
			packet[p += 31] = wantReply === void 0 || wantReply === true ? 1 : 0;
			writeUInt32BE(packet, socketPathLen, ++p);
			packet.utf8Write(socketPath, p += 4, socketPathLen);
			this._debug && this._debug("Outbound: Sending GLOBAL_REQUEST (streamlocal-forward@openssh.com)");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		openssh_cancelStreamLocalForward(socketPath, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const socketPathLen = Buffer.byteLength(socketPath);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(48 + socketPathLen);
			packet[p] = MESSAGE.GLOBAL_REQUEST;
			writeUInt32BE(packet, 38, ++p);
			packet.utf8Write("cancel-streamlocal-forward@openssh.com", p += 4, 38);
			packet[p += 38] = wantReply === void 0 || wantReply === true ? 1 : 0;
			writeUInt32BE(packet, socketPathLen, ++p);
			packet.utf8Write(socketPath, p += 4, socketPathLen);
			if (this._debug) this._debug("Outbound: Sending GLOBAL_REQUEST (cancel-streamlocal-forward@openssh.com)");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		directTcpip(chan, initWindow, maxPacket, cfg) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const srcLen = Buffer.byteLength(cfg.srcIP);
			const dstLen = Buffer.byteLength(cfg.dstIP);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(33 + srcLen + 4 + 4 + dstLen + 4);
			packet[p] = MESSAGE.CHANNEL_OPEN;
			writeUInt32BE(packet, 12, ++p);
			packet.utf8Write("direct-tcpip", p += 4, 12);
			writeUInt32BE(packet, chan, p += 12);
			writeUInt32BE(packet, initWindow, p += 4);
			writeUInt32BE(packet, maxPacket, p += 4);
			writeUInt32BE(packet, dstLen, p += 4);
			packet.utf8Write(cfg.dstIP, p += 4, dstLen);
			writeUInt32BE(packet, cfg.dstPort, p += dstLen);
			writeUInt32BE(packet, srcLen, p += 4);
			packet.utf8Write(cfg.srcIP, p += 4, srcLen);
			writeUInt32BE(packet, cfg.srcPort, p += srcLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_OPEN (r:${chan}, direct-tcpip)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		openssh_directStreamLocal(chan, initWindow, maxPacket, cfg) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const pathLen = Buffer.byteLength(cfg.socketPath);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(51 + pathLen + 4 + 4);
			packet[p] = MESSAGE.CHANNEL_OPEN;
			writeUInt32BE(packet, 30, ++p);
			packet.utf8Write("direct-streamlocal@openssh.com", p += 4, 30);
			writeUInt32BE(packet, chan, p += 30);
			writeUInt32BE(packet, initWindow, p += 4);
			writeUInt32BE(packet, maxPacket, p += 4);
			writeUInt32BE(packet, pathLen, p += 4);
			packet.utf8Write(cfg.socketPath, p += 4, pathLen);
			bufferFill(packet, 0, p += pathLen, p + 8);
			if (this._debug) this._debug(`Outbound: Sending CHANNEL_OPEN (r:${chan}, direct-streamlocal@openssh.com)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		openssh_noMoreSessions(wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(34);
			packet[p] = MESSAGE.GLOBAL_REQUEST;
			writeUInt32BE(packet, 28, ++p);
			packet.utf8Write("no-more-sessions@openssh.com", p += 4, 28);
			packet[p += 28] = wantReply === void 0 || wantReply === true ? 1 : 0;
			this._debug && this._debug("Outbound: Sending GLOBAL_REQUEST (no-more-sessions@openssh.com)");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		session(chan, initWindow, maxPacket) {
			if (this._server) throw new Error("Client-only method called in server mode");
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(24);
			packet[p] = MESSAGE.CHANNEL_OPEN;
			writeUInt32BE(packet, 7, ++p);
			packet.utf8Write("session", p += 4, 7);
			writeUInt32BE(packet, chan, p += 7);
			writeUInt32BE(packet, initWindow, p += 4);
			writeUInt32BE(packet, maxPacket, p += 4);
			this._debug && this._debug(`Outbound: Sending CHANNEL_OPEN (r:${chan}, session)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		windowChange(chan, rows, cols, height, width) {
			if (this._server) throw new Error("Client-only method called in server mode");
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(39);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 13, p += 4);
			packet.utf8Write("window-change", p += 4, 13);
			packet[p += 13] = 0;
			writeUInt32BE(packet, cols, ++p);
			writeUInt32BE(packet, rows, p += 4);
			writeUInt32BE(packet, width, p += 4);
			writeUInt32BE(packet, height, p += 4);
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, window-change)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		pty(chan, rows, cols, height, width, term, modes, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			if (!term || !term.length) term = "vt100";
			if (modes && !Buffer.isBuffer(modes) && !Array.isArray(modes) && typeof modes === "object" && modes !== null) modes = modesToBytes(modes);
			if (!modes || !modes.length) modes = NO_TERMINAL_MODES_BUFFER;
			const termLen = term.length;
			const modesLen = modes.length;
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(21 + termLen + 4 + 4 + 4 + 4 + 4 + modesLen);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 7, p += 4);
			packet.utf8Write("pty-req", p += 4, 7);
			packet[p += 7] = wantReply === void 0 || wantReply === true ? 1 : 0;
			writeUInt32BE(packet, termLen, ++p);
			packet.utf8Write(term, p += 4, termLen);
			writeUInt32BE(packet, cols, p += termLen);
			writeUInt32BE(packet, rows, p += 4);
			writeUInt32BE(packet, width, p += 4);
			writeUInt32BE(packet, height, p += 4);
			writeUInt32BE(packet, modesLen, p += 4);
			p += 4;
			if (Array.isArray(modes)) for (let i = 0; i < modesLen; ++i) packet[p++] = modes[i];
			else if (Buffer.isBuffer(modes)) packet.set(modes, p);
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, pty-req)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		shell(chan, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(15);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 5, p += 4);
			packet.utf8Write("shell", p += 4, 5);
			packet[p += 5] = wantReply === void 0 || wantReply === true ? 1 : 0;
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, shell)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		exec(chan, cmd, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const isBuf = Buffer.isBuffer(cmd);
			const cmdLen = isBuf ? cmd.length : Buffer.byteLength(cmd);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(18 + cmdLen);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 4, p += 4);
			packet.utf8Write("exec", p += 4, 4);
			packet[p += 4] = wantReply === void 0 || wantReply === true ? 1 : 0;
			writeUInt32BE(packet, cmdLen, ++p);
			if (isBuf) packet.set(cmd, p += 4);
			else packet.utf8Write(cmd, p += 4, cmdLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, exec: ${cmd})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		signal(chan, signal) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const origSignal = signal;
			signal = signal.toUpperCase();
			if (signal.slice(0, 3) === "SIG") signal = signal.slice(3);
			if (SIGNALS[signal] !== 1) throw new Error(`Invalid signal: ${origSignal}`);
			const signalLen = signal.length;
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(20 + signalLen);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 6, p += 4);
			packet.utf8Write("signal", p += 4, 6);
			packet[p += 6] = 0;
			writeUInt32BE(packet, signalLen, ++p);
			packet.utf8Write(signal, p += 4, signalLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, signal: ${signal})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		env(chan, key, val, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const keyLen = Buffer.byteLength(key);
			const isBuf = Buffer.isBuffer(val);
			const valLen = isBuf ? val.length : Buffer.byteLength(val);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(17 + keyLen + 4 + valLen);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 3, p += 4);
			packet.utf8Write("env", p += 4, 3);
			packet[p += 3] = wantReply === void 0 || wantReply === true ? 1 : 0;
			writeUInt32BE(packet, keyLen, ++p);
			packet.utf8Write(key, p += 4, keyLen);
			writeUInt32BE(packet, valLen, p += keyLen);
			if (isBuf) packet.set(val, p += 4);
			else packet.utf8Write(val, p += 4, valLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, env: ${key}=${val})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		x11Forward(chan, cfg, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const protocol = cfg.protocol;
			const cookie = cfg.cookie;
			const isBufProto = Buffer.isBuffer(protocol);
			const protoLen = isBufProto ? protocol.length : Buffer.byteLength(protocol);
			const isBufCookie = Buffer.isBuffer(cookie);
			const cookieLen = isBufCookie ? cookie.length : Buffer.byteLength(cookie);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(22 + protoLen + 4 + cookieLen + 4);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 7, p += 4);
			packet.utf8Write("x11-req", p += 4, 7);
			packet[p += 7] = wantReply === void 0 || wantReply === true ? 1 : 0;
			packet[++p] = cfg.single ? 1 : 0;
			writeUInt32BE(packet, protoLen, ++p);
			if (isBufProto) packet.set(protocol, p += 4);
			else packet.utf8Write(protocol, p += 4, protoLen);
			writeUInt32BE(packet, cookieLen, p += protoLen);
			if (isBufCookie) packet.set(cookie, p += 4);
			else packet.latin1Write(cookie, p += 4, cookieLen);
			writeUInt32BE(packet, cfg.screen || 0, p += cookieLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, x11-req)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		subsystem(chan, name, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			const nameLen = Buffer.byteLength(name);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(23 + nameLen);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 9, p += 4);
			packet.utf8Write("subsystem", p += 4, 9);
			packet[p += 9] = wantReply === void 0 || wantReply === true ? 1 : 0;
			writeUInt32BE(packet, nameLen, ++p);
			packet.utf8Write(name, p += 4, nameLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, subsystem: ${name})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		openssh_agentForward(chan, wantReply) {
			if (this._server) throw new Error("Client-only method called in server mode");
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(36);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 26, p += 4);
			packet.utf8Write("auth-agent-req@openssh.com", p += 4, 26);
			packet[p += 26] = wantReply === void 0 || wantReply === true ? 1 : 0;
			if (this._debug) this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, auth-agent-req@openssh.com)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		openssh_hostKeysProve(keys) {
			if (this._server) throw new Error("Client-only method called in server mode");
			let keysTotal = 0;
			const publicKeys = [];
			for (const key of keys) {
				const publicKey = key.getPublicSSH();
				keysTotal += 4 + publicKey.length;
				publicKeys.push(publicKey);
			}
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(35 + keysTotal);
			packet[p] = MESSAGE.GLOBAL_REQUEST;
			writeUInt32BE(packet, 29, ++p);
			packet.utf8Write("hostkeys-prove-00@openssh.com", p += 4, 29);
			packet[p += 29] = 1;
			++p;
			for (const buf of publicKeys) {
				writeUInt32BE(packet, buf.length, p);
				bufferCopy(buf, packet, 0, buf.length, p += 4);
				p += buf.length;
			}
			if (this._debug) this._debug("Outbound: Sending GLOBAL_REQUEST (hostkeys-prove-00@openssh.com)");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		serviceAccept(svcName) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			const svcNameLen = Buffer.byteLength(svcName);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + svcNameLen);
			packet[p] = MESSAGE.SERVICE_ACCEPT;
			writeUInt32BE(packet, svcNameLen, ++p);
			packet.utf8Write(svcName, p += 4, svcNameLen);
			this._debug && this._debug(`Outbound: Sending SERVICE_ACCEPT (${svcName})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
			if (this._server && this._banner && svcName === "ssh-userauth") {
				const banner = this._banner;
				this._banner = void 0;
				const bannerLen = Buffer.byteLength(banner);
				p = this._packetRW.write.allocStart;
				const packet = this._packetRW.write.alloc(5 + bannerLen + 4);
				packet[p] = MESSAGE.USERAUTH_BANNER;
				writeUInt32BE(packet, bannerLen, ++p);
				packet.utf8Write(banner, p += 4, bannerLen);
				writeUInt32BE(packet, 0, p += bannerLen);
				this._debug && this._debug("Outbound: Sending USERAUTH_BANNER");
				sendPacket(this, this._packetRW.write.finalize(packet));
			}
		}
		forwardedTcpip(chan, initWindow, maxPacket, cfg) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			const boundAddrLen = Buffer.byteLength(cfg.boundAddr);
			const remoteAddrLen = Buffer.byteLength(cfg.remoteAddr);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(36 + boundAddrLen + 4 + 4 + remoteAddrLen + 4);
			packet[p] = MESSAGE.CHANNEL_OPEN;
			writeUInt32BE(packet, 15, ++p);
			packet.utf8Write("forwarded-tcpip", p += 4, 15);
			writeUInt32BE(packet, chan, p += 15);
			writeUInt32BE(packet, initWindow, p += 4);
			writeUInt32BE(packet, maxPacket, p += 4);
			writeUInt32BE(packet, boundAddrLen, p += 4);
			packet.utf8Write(cfg.boundAddr, p += 4, boundAddrLen);
			writeUInt32BE(packet, cfg.boundPort, p += boundAddrLen);
			writeUInt32BE(packet, remoteAddrLen, p += 4);
			packet.utf8Write(cfg.remoteAddr, p += 4, remoteAddrLen);
			writeUInt32BE(packet, cfg.remotePort, p += remoteAddrLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_OPEN (r:${chan}, forwarded-tcpip)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		x11(chan, initWindow, maxPacket, cfg) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			const addrLen = Buffer.byteLength(cfg.originAddr);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(24 + addrLen + 4);
			packet[p] = MESSAGE.CHANNEL_OPEN;
			writeUInt32BE(packet, 3, ++p);
			packet.utf8Write("x11", p += 4, 3);
			writeUInt32BE(packet, chan, p += 3);
			writeUInt32BE(packet, initWindow, p += 4);
			writeUInt32BE(packet, maxPacket, p += 4);
			writeUInt32BE(packet, addrLen, p += 4);
			packet.utf8Write(cfg.originAddr, p += 4, addrLen);
			writeUInt32BE(packet, cfg.originPort, p += addrLen);
			this._debug && this._debug(`Outbound: Sending CHANNEL_OPEN (r:${chan}, x11)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		openssh_authAgent(chan, initWindow, maxPacket) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(39);
			packet[p] = MESSAGE.CHANNEL_OPEN;
			writeUInt32BE(packet, 22, ++p);
			packet.utf8Write("auth-agent@openssh.com", p += 4, 22);
			writeUInt32BE(packet, chan, p += 22);
			writeUInt32BE(packet, initWindow, p += 4);
			writeUInt32BE(packet, maxPacket, p += 4);
			this._debug && this._debug(`Outbound: Sending CHANNEL_OPEN (r:${chan}, auth-agent@openssh.com)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		openssh_forwardedStreamLocal(chan, initWindow, maxPacket, cfg) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			const pathLen = Buffer.byteLength(cfg.socketPath);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(54 + pathLen + 4);
			packet[p] = MESSAGE.CHANNEL_OPEN;
			writeUInt32BE(packet, 33, ++p);
			packet.utf8Write("forwarded-streamlocal@openssh.com", p += 4, 33);
			writeUInt32BE(packet, chan, p += 33);
			writeUInt32BE(packet, initWindow, p += 4);
			writeUInt32BE(packet, maxPacket, p += 4);
			writeUInt32BE(packet, pathLen, p += 4);
			packet.utf8Write(cfg.socketPath, p += 4, pathLen);
			writeUInt32BE(packet, 0, p += pathLen);
			if (this._debug) this._debug(`Outbound: Sending CHANNEL_OPEN (r:${chan}, forwarded-streamlocal@openssh.com)`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		exitStatus(chan, status) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(25);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 11, p += 4);
			packet.utf8Write("exit-status", p += 4, 11);
			packet[p += 11] = 0;
			writeUInt32BE(packet, status, ++p);
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, exit-status: ${status})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		exitSignal(chan, name, coreDumped, msg) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			const origSignal = name;
			if (typeof origSignal !== "string" || !origSignal) throw new Error(`Invalid signal: ${origSignal}`);
			let signal = name.toUpperCase();
			if (signal.slice(0, 3) === "SIG") signal = signal.slice(3);
			if (SIGNALS[signal] !== 1) throw new Error(`Invalid signal: ${origSignal}`);
			const nameLen = Buffer.byteLength(signal);
			const msgLen = msg ? Buffer.byteLength(msg) : 0;
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(25 + nameLen + 1 + 4 + msgLen + 4);
			packet[p] = MESSAGE.CHANNEL_REQUEST;
			writeUInt32BE(packet, chan, ++p);
			writeUInt32BE(packet, 11, p += 4);
			packet.utf8Write("exit-signal", p += 4, 11);
			packet[p += 11] = 0;
			writeUInt32BE(packet, nameLen, ++p);
			packet.utf8Write(signal, p += 4, nameLen);
			packet[p += nameLen] = coreDumped ? 1 : 0;
			writeUInt32BE(packet, msgLen, ++p);
			p += 4;
			if (msgLen) {
				packet.utf8Write(msg, p, msgLen);
				p += msgLen;
			}
			writeUInt32BE(packet, 0, p);
			this._debug && this._debug(`Outbound: Sending CHANNEL_REQUEST (r:${chan}, exit-signal: ${name})`);
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		authFailure(authMethods, isPartial) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			if (this._authsQueue.length === 0) throw new Error("No auth in progress");
			let methods;
			if (typeof authMethods === "boolean") {
				isPartial = authMethods;
				authMethods = void 0;
			}
			if (authMethods) {
				methods = [];
				for (let i = 0; i < authMethods.length; ++i) {
					if (authMethods[i].toLowerCase() === "none") continue;
					methods.push(authMethods[i]);
				}
				methods = methods.join(",");
			} else methods = "";
			const methodsLen = methods.length;
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + methodsLen + 1);
			packet[p] = MESSAGE.USERAUTH_FAILURE;
			writeUInt32BE(packet, methodsLen, ++p);
			packet.utf8Write(methods, p += 4, methodsLen);
			packet[p += methodsLen] = isPartial === true ? 1 : 0;
			this._authsQueue.shift();
			this._debug && this._debug("Outbound: Sending USERAUTH_FAILURE");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		authSuccess() {
			if (!this._server) throw new Error("Server-only method called in client mode");
			if (this._authsQueue.length === 0) throw new Error("No auth in progress");
			const p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(1);
			packet[p] = MESSAGE.USERAUTH_SUCCESS;
			this._authsQueue.shift();
			this._authenticated = true;
			this._debug && this._debug("Outbound: Sending USERAUTH_SUCCESS");
			sendPacket(this, this._packetRW.write.finalize(packet));
			if (this._kex.negotiated.cs.compress === "zlib@openssh.com") this._packetRW.read = new ZlibPacketReader();
			if (this._kex.negotiated.sc.compress === "zlib@openssh.com") this._packetRW.write = new ZlibPacketWriter(this);
		}
		authPKOK(keyAlgo, key) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			if (this._authsQueue.length === 0 || this._authsQueue[0] !== "publickey") throw new Error("\"publickey\" auth not in progress");
			const keyAlgoLen = Buffer.byteLength(keyAlgo);
			const keyLen = key.length;
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + keyAlgoLen + 4 + keyLen);
			packet[p] = MESSAGE.USERAUTH_PK_OK;
			writeUInt32BE(packet, keyAlgoLen, ++p);
			packet.utf8Write(keyAlgo, p += 4, keyAlgoLen);
			writeUInt32BE(packet, keyLen, p += keyAlgoLen);
			packet.set(key, p += 4);
			this._authsQueue.shift();
			this._debug && this._debug("Outbound: Sending USERAUTH_PK_OK");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		authPasswdChg(prompt) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			const promptLen = Buffer.byteLength(prompt);
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + promptLen + 4);
			packet[p] = MESSAGE.USERAUTH_PASSWD_CHANGEREQ;
			writeUInt32BE(packet, promptLen, ++p);
			packet.utf8Write(prompt, p += 4, promptLen);
			writeUInt32BE(packet, 0, p += promptLen);
			this._debug && this._debug("Outbound: Sending USERAUTH_PASSWD_CHANGEREQ");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
		authInfoReq(name, instructions, prompts) {
			if (!this._server) throw new Error("Server-only method called in client mode");
			let promptsLen = 0;
			const nameLen = name ? Buffer.byteLength(name) : 0;
			const instrLen = instructions ? Buffer.byteLength(instructions) : 0;
			for (let i = 0; i < prompts.length; ++i) promptsLen += 4 + Buffer.byteLength(prompts[i].prompt) + 1;
			let p = this._packetRW.write.allocStart;
			const packet = this._packetRW.write.alloc(5 + nameLen + 4 + instrLen + 4 + 4 + promptsLen);
			packet[p] = MESSAGE.USERAUTH_INFO_REQUEST;
			writeUInt32BE(packet, nameLen, ++p);
			p += 4;
			if (name) {
				packet.utf8Write(name, p, nameLen);
				p += nameLen;
			}
			writeUInt32BE(packet, instrLen, p);
			p += 4;
			if (instructions) {
				packet.utf8Write(instructions, p, instrLen);
				p += instrLen;
			}
			writeUInt32BE(packet, 0, p);
			writeUInt32BE(packet, prompts.length, p += 4);
			p += 4;
			for (let i = 0; i < prompts.length; ++i) {
				const prompt = prompts[i];
				const promptLen = Buffer.byteLength(prompt.prompt);
				writeUInt32BE(packet, promptLen, p);
				p += 4;
				if (promptLen) {
					packet.utf8Write(prompt.prompt, p, promptLen);
					p += promptLen;
				}
				packet[p++] = prompt.echo ? 1 : 0;
			}
			this._debug && this._debug("Outbound: Sending USERAUTH_INFO_REQUEST");
			sendPacket(this, this._packetRW.write.finalize(packet));
		}
	};
	const RE_IDENT = /^SSH-(2\.0|1\.99)-([^ ]+)(?: (.*))?$/;
	function parseHeader(chunk, p, len) {
		let data;
		let chunkOffset;
		if (this._buffer) {
			data = Buffer.allocUnsafe(this._buffer.length + (len - p));
			data.set(this._buffer, 0);
			if (p === 0) data.set(chunk, this._buffer.length);
			else data.set(new Uint8Array(chunk.buffer, chunk.byteOffset + p, len - p), this._buffer.length);
			chunkOffset = this._buffer.length;
			p = 0;
		} else {
			data = chunk;
			chunkOffset = 0;
		}
		const op = p;
		let start = p;
		let end = p;
		let needNL = false;
		let lineLen = 0;
		let lines = 0;
		for (; p < data.length; ++p) {
			const ch = data[p];
			if (ch === 13) {
				needNL = true;
				continue;
			}
			if (ch === 10) {
				if (end > start && end - start > 4 && data[start] === 83 && data[start + 1] === 83 && data[start + 2] === 72 && data[start + 3] === 45) {
					const full = data.latin1Slice(op, end + 1);
					const identRaw = start === op ? full : full.slice(start - op);
					const m = RE_IDENT.exec(identRaw);
					if (!m) throw new Error("Invalid identification string");
					const header = {
						greeting: start === op ? "" : full.slice(0, start - op),
						identRaw,
						versions: {
							protocol: m[1],
							software: m[2]
						},
						comments: m[3]
					};
					this._remoteIdentRaw = Buffer.from(identRaw);
					this._debug && this._debug(`Remote ident: ${inspect$1(identRaw)}`);
					this._compatFlags = getCompatFlags(header);
					this._buffer = void 0;
					this._decipher = new NullDecipher(0, onKEXPayload.bind(this, { firstPacket: true }));
					this._parse = parsePacket;
					this._onHeader(header);
					if (!this._destruct) return len;
					kexinit(this);
					return p + 1 - chunkOffset;
				}
				if (this._server) throw new Error("Greetings from clients not permitted");
				if (++lines > MAX_LINES) throw new Error("Max greeting lines exceeded");
				needNL = false;
				start = p + 1;
				lineLen = 0;
			} else if (needNL) throw new Error("Invalid header: expected newline");
			else if (++lineLen >= MAX_LINE_LEN) throw new Error("Header line too long");
			end = p;
		}
		if (!this._buffer) this._buffer = bufferSlice(data, op);
		return p - chunkOffset;
	}
	function parsePacket(chunk, p, len) {
		return this._decipher.decrypt(chunk, p, len);
	}
	function onPayload(payload) {
		this._onPacket();
		if (payload.length === 0) {
			this._debug && this._debug("Inbound: Skipping empty packet payload");
			return;
		}
		payload = this._packetRW.read.read(payload);
		const type = payload[0];
		if (type === MESSAGE.USERAUTH_SUCCESS && !this._server && !this._authenticated) {
			this._authenticated = true;
			if (this._kex.negotiated.cs.compress === "zlib@openssh.com") this._packetRW.write = new ZlibPacketWriter(this);
			if (this._kex.negotiated.sc.compress === "zlib@openssh.com") this._packetRW.read = new ZlibPacketReader();
		}
		const handler = MESSAGE_HANDLERS[type];
		if (handler === void 0) {
			this._debug && this._debug(`Inbound: Unsupported message type: ${type}`);
			return;
		}
		return handler(this, payload);
	}
	function getCompatFlags(header) {
		const software = header.versions.software;
		let flags = 0;
		for (const rule of COMPAT_CHECKS) if (typeof rule[0] === "string") {
			if (software === rule[0]) flags |= rule[1];
		} else if (rule[0].test(software)) flags |= rule[1];
		return flags;
	}
	function modesToBytes(modes) {
		const keys = Object.keys(modes);
		const bytes = Buffer.allocUnsafe(5 * keys.length + 1);
		let b = 0;
		for (let i = 0; i < keys.length; ++i) {
			const key = keys[i];
			if (key === "TTY_OP_END") continue;
			const opcode = TERMINAL_MODE[key];
			if (opcode === void 0) continue;
			const val = modes[key];
			if (typeof val === "number" && isFinite(val)) {
				bytes[b++] = opcode;
				bytes[b++] = val >>> 24;
				bytes[b++] = val >>> 16;
				bytes[b++] = val >>> 8;
				bytes[b++] = val;
			}
		}
		bytes[b++] = TERMINAL_MODE.TTY_OP_END;
		if (b < bytes.length) return bufferSlice(bytes, 0, b);
		return bytes;
	}
	function sendExtInfo(proto) {
		let serverSigAlgs = "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss";
		if (eddsaSupported) serverSigAlgs = `ssh-ed25519,${serverSigAlgs}`;
		const algsLen = Buffer.byteLength(serverSigAlgs);
		let p = proto._packetRW.write.allocStart;
		const packet = proto._packetRW.write.alloc(28 + algsLen);
		packet[p] = MESSAGE.EXT_INFO;
		writeUInt32BE(packet, 1, ++p);
		writeUInt32BE(packet, 15, p += 4);
		packet.utf8Write("server-sig-algs", p += 4, 15);
		writeUInt32BE(packet, algsLen, p += 15);
		packet.utf8Write(serverSigAlgs, p += 4, algsLen);
		proto._debug && proto._debug("Outbound: Sending EXT_INFO");
		sendPacket(proto, proto._packetRW.write.finalize(packet));
	}
	module.exports = Protocol;
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/node-fs-compat.js
var require_node_fs_compat = /* @__PURE__ */ __commonJSMin(((exports) => {
	const assert = __require("assert");
	const { inspect } = __require("util");
	function addNumericalSeparator(val) {
		let res = "";
		let i = val.length;
		const start = val[0] === "-" ? 1 : 0;
		for (; i >= start + 4; i -= 3) res = `_${val.slice(i - 3, i)}${res}`;
		return `${val.slice(0, i)}${res}`;
	}
	function oneOf(expected, thing) {
		assert(typeof thing === "string", "`thing` has to be of type string");
		if (Array.isArray(expected)) {
			const len = expected.length;
			assert(len > 0, "At least one expected value needs to be specified");
			expected = expected.map((i) => String(i));
			if (len > 2) return `one of ${thing} ${expected.slice(0, len - 1).join(", ")}, or ` + expected[len - 1];
			else if (len === 2) return `one of ${thing} ${expected[0]} or ${expected[1]}`;
			return `of ${thing} ${expected[0]}`;
		}
		return `of ${thing} ${String(expected)}`;
	}
	exports.ERR_INTERNAL_ASSERTION = class ERR_INTERNAL_ASSERTION extends Error {
		constructor(message) {
			super();
			Error.captureStackTrace(this, ERR_INTERNAL_ASSERTION);
			const suffix = "This is caused by either a bug in ssh2 or incorrect usage of ssh2 internals.\nPlease open an issue with this stack trace at https://github.com/mscdex/ssh2/issues\n";
			this.message = message === void 0 ? suffix : `${message}\n${suffix}`;
		}
	};
	const MAX_32BIT_INT = 2 ** 32;
	const MAX_32BIT_BIGINT = (() => {
		try {
			return new Function("return 2n ** 32n")();
		} catch {}
	})();
	exports.ERR_OUT_OF_RANGE = class ERR_OUT_OF_RANGE extends RangeError {
		constructor(str, range, input, replaceDefaultBoolean) {
			super();
			Error.captureStackTrace(this, ERR_OUT_OF_RANGE);
			assert(range, "Missing \"range\" argument");
			let msg = replaceDefaultBoolean ? str : `The value of "${str}" is out of range.`;
			let received;
			if (Number.isInteger(input) && Math.abs(input) > MAX_32BIT_INT) received = addNumericalSeparator(String(input));
			else if (typeof input === "bigint") {
				received = String(input);
				if (input > MAX_32BIT_BIGINT || input < -MAX_32BIT_BIGINT) received = addNumericalSeparator(received);
				received += "n";
			} else received = inspect(input);
			msg += ` It must be ${range}. Received ${received}`;
			this.message = msg;
		}
	};
	var ERR_INVALID_ARG_TYPE = class ERR_INVALID_ARG_TYPE extends TypeError {
		constructor(name, expected, actual) {
			super();
			Error.captureStackTrace(this, ERR_INVALID_ARG_TYPE);
			assert(typeof name === "string", `'name' must be a string`);
			let determiner;
			if (typeof expected === "string" && expected.startsWith("not ")) {
				determiner = "must not be";
				expected = expected.replace(/^not /, "");
			} else determiner = "must be";
			let msg;
			if (name.endsWith(" argument")) msg = `The ${name} ${determiner} ${oneOf(expected, "type")}`;
			else msg = `The "${name}" ${name.includes(".") ? "property" : "argument"} ${determiner} ${oneOf(expected, "type")}`;
			msg += `. Received type ${typeof actual}`;
			this.message = msg;
		}
	};
	exports.ERR_INVALID_ARG_TYPE = ERR_INVALID_ARG_TYPE;
	exports.validateNumber = function validateNumber(value, name) {
		if (typeof value !== "number") throw new ERR_INVALID_ARG_TYPE(name, "number", value);
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/protocol/SFTP.js
var require_SFTP = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const EventEmitter$2 = __require("events");
	const fs = __require("fs");
	const { constants } = fs;
	const { Readable: ReadableStream$1, Writable: WritableStream$1 } = __require("stream");
	const { inherits, types: { isDate } } = __require("util");
	const FastBuffer = Buffer[Symbol.species];
	const { bufferCopy, bufferSlice, makeBufferParser, writeUInt32BE } = require_utils$1();
	const ATTR = {
		SIZE: 1,
		UIDGID: 2,
		PERMISSIONS: 4,
		ACMODTIME: 8,
		EXTENDED: 2147483648
	};
	const ATTRS_BUF = Buffer.alloc(28);
	const STATUS_CODE = {
		OK: 0,
		EOF: 1,
		NO_SUCH_FILE: 2,
		PERMISSION_DENIED: 3,
		FAILURE: 4,
		BAD_MESSAGE: 5,
		NO_CONNECTION: 6,
		CONNECTION_LOST: 7,
		OP_UNSUPPORTED: 8
	};
	const VALID_STATUS_CODES = new Map(Object.values(STATUS_CODE).map((n) => [n, 1]));
	const STATUS_CODE_STR = {
		[STATUS_CODE.OK]: "No error",
		[STATUS_CODE.EOF]: "End of file",
		[STATUS_CODE.NO_SUCH_FILE]: "No such file or directory",
		[STATUS_CODE.PERMISSION_DENIED]: "Permission denied",
		[STATUS_CODE.FAILURE]: "Failure",
		[STATUS_CODE.BAD_MESSAGE]: "Bad message",
		[STATUS_CODE.NO_CONNECTION]: "No connection",
		[STATUS_CODE.CONNECTION_LOST]: "Connection lost",
		[STATUS_CODE.OP_UNSUPPORTED]: "Operation unsupported"
	};
	const REQUEST = {
		INIT: 1,
		OPEN: 3,
		CLOSE: 4,
		READ: 5,
		WRITE: 6,
		LSTAT: 7,
		FSTAT: 8,
		SETSTAT: 9,
		FSETSTAT: 10,
		OPENDIR: 11,
		READDIR: 12,
		REMOVE: 13,
		MKDIR: 14,
		RMDIR: 15,
		REALPATH: 16,
		STAT: 17,
		RENAME: 18,
		READLINK: 19,
		SYMLINK: 20,
		EXTENDED: 200
	};
	const RESPONSE = {
		VERSION: 2,
		STATUS: 101,
		HANDLE: 102,
		DATA: 103,
		NAME: 104,
		ATTRS: 105,
		EXTENDED: 201
	};
	const OPEN_MODE = {
		READ: 1,
		WRITE: 2,
		APPEND: 4,
		CREAT: 8,
		TRUNC: 16,
		EXCL: 32
	};
	const PKT_RW_OVERHEAD = 2048;
	const MAX_REQID = 2 ** 32 - 1;
	const CLIENT_VERSION_BUFFER = Buffer.from([
		0,
		0,
		0,
		5,
		REQUEST.INIT,
		0,
		0,
		0,
		3
	]);
	const SERVER_VERSION_BUFFER = Buffer.from([
		0,
		0,
		0,
		5,
		RESPONSE.VERSION,
		0,
		0,
		0,
		3
	]);
	const RE_OPENSSH = /^SSH-2.0-(?:OpenSSH|dropbear)/;
	const OPENSSH_MAX_PKT_LEN = 262144;
	const bufferParser = makeBufferParser();
	const fakeStderr = {
		readable: false,
		writable: false,
		push: (data) => {},
		once: () => {},
		on: () => {},
		emit: () => {},
		end: () => {}
	};
	function noop() {}
	var SFTP = class extends EventEmitter$2 {
		constructor(client, chanInfo, cfg) {
			super();
			if (typeof cfg !== "object" || !cfg) cfg = {};
			const remoteIdentRaw = client._protocol._remoteIdentRaw;
			this.server = !!cfg.server;
			this._debug = typeof cfg.debug === "function" ? cfg.debug : void 0;
			this._isOpenSSH = remoteIdentRaw && RE_OPENSSH.test(remoteIdentRaw);
			this._version = -1;
			this._extensions = {};
			this._biOpt = cfg.biOpt;
			this._pktLenBytes = 0;
			this._pktLen = 0;
			this._pktPos = 0;
			this._pktType = 0;
			this._pktData = void 0;
			this._writeReqid = -1;
			this._requests = {};
			this._maxInPktLen = OPENSSH_MAX_PKT_LEN;
			this._maxOutPktLen = 34e3;
			this._maxReadLen = (this._isOpenSSH ? OPENSSH_MAX_PKT_LEN : 34e3) - PKT_RW_OVERHEAD;
			this._maxWriteLen = (this._isOpenSSH ? OPENSSH_MAX_PKT_LEN : 34e3) - PKT_RW_OVERHEAD;
			this.maxOpenHandles = void 0;
			this._client = client;
			this._protocol = client._protocol;
			this._callbacks = [];
			this._hasX11 = false;
			this._exit = {
				code: void 0,
				signal: void 0,
				dump: void 0,
				desc: void 0
			};
			this._waitWindow = false;
			this._chunkcb = void 0;
			this._buffer = [];
			this.type = chanInfo.type;
			this.subtype = void 0;
			this.incoming = chanInfo.incoming;
			this.outgoing = chanInfo.outgoing;
			this.stderr = fakeStderr;
			this.readable = true;
		}
		push(data) {
			if (data === null) {
				cleanupRequests(this);
				if (!this.readable) return;
				this.readable = false;
				this.emit("end");
				return;
			}
			let p = 0;
			while (p < data.length) {
				if (this._pktLenBytes < 4) {
					let nb = Math.min(4 - this._pktLenBytes, data.length - p);
					this._pktLenBytes += nb;
					while (nb--) this._pktLen = (this._pktLen << 8) + data[p++];
					if (this._pktLenBytes < 4) return;
					if (this._pktLen === 0) return doFatalSFTPError(this, "Invalid packet length");
					if (this._pktLen > this._maxInPktLen) {
						const max = this._maxInPktLen;
						return doFatalSFTPError(this, `Packet length ${this._pktLen} exceeds max length of ${max}`);
					}
					if (p >= data.length) return;
				}
				if (this._pktPos < this._pktLen) {
					const nb = Math.min(this._pktLen - this._pktPos, data.length - p);
					if (p !== 0 || nb !== data.length) {
						if (nb === this._pktLen) this._pkt = new FastBuffer(data.buffer, data.byteOffset + p, nb);
						else {
							if (!this._pkt) this._pkt = Buffer.allocUnsafe(this._pktLen);
							this._pkt.set(new Uint8Array(data.buffer, data.byteOffset + p, nb), this._pktPos);
						}
					} else if (nb === this._pktLen) this._pkt = data;
					else {
						if (!this._pkt) this._pkt = Buffer.allocUnsafe(this._pktLen);
						this._pkt.set(data, this._pktPos);
					}
					p += nb;
					this._pktPos += nb;
					if (this._pktPos < this._pktLen) return;
				}
				const type = this._pkt[0];
				const payload = this._pkt;
				this._pktLen = 0;
				this._pktLenBytes = 0;
				this._pkt = void 0;
				this._pktPos = 0;
				const handler = this.server ? SERVER_HANDLERS[type] : CLIENT_HANDLERS[type];
				if (!handler) return doFatalSFTPError(this, `Unknown packet type ${type}`);
				if (this._version === -1) {
					if (this.server) {
						if (type !== REQUEST.INIT) return doFatalSFTPError(this, `Expected INIT packet, got ${type}`);
					} else if (type !== RESPONSE.VERSION) return doFatalSFTPError(this, `Expected VERSION packet, got ${type}`);
				}
				if (handler(this, payload) === false) return;
			}
		}
		end() {
			this.destroy();
		}
		destroy() {
			if (this.outgoing.state === "open" || this.outgoing.state === "eof") {
				this.outgoing.state = "closing";
				this._protocol.channelClose(this.outgoing.id);
			}
		}
		_init() {
			this._init = noop;
			if (!this.server) sendOrBuffer(this, CLIENT_VERSION_BUFFER);
		}
		createReadStream(path, options) {
			if (this.server) throw new Error("Client-only method called in server mode");
			return new ReadStream(this, path, options);
		}
		createWriteStream(path, options) {
			if (this.server) throw new Error("Client-only method called in server mode");
			return new WriteStream(this, path, options);
		}
		open(path, flags_, attrs, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (typeof attrs === "function") {
				cb = attrs;
				attrs = void 0;
			}
			const flags = typeof flags_ === "number" ? flags_ : stringToFlags(flags_);
			if (flags === null) throw new Error(`Unknown flags string: ${flags_}`);
			let attrsFlags = 0;
			let attrsLen = 0;
			if (typeof attrs === "string" || typeof attrs === "number") attrs = { mode: attrs };
			if (typeof attrs === "object" && attrs !== null) {
				attrs = attrsToBytes(attrs);
				attrsFlags = attrs.flags;
				attrsLen = attrs.nb;
			}
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + pathLen + 4 + 4 + attrsLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.OPEN;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, pathLen, p);
			buf.utf8Write(path, p += 4, pathLen);
			writeUInt32BE(buf, flags, p += pathLen);
			writeUInt32BE(buf, attrsFlags, p += 4);
			if (attrsLen) {
				p += 4;
				if (attrsLen === ATTRS_BUF.length) buf.set(ATTRS_BUF, p);
				else bufferCopy(ATTRS_BUF, buf, 0, attrsLen, p);
				p += attrsLen;
			}
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} OPEN`);
		}
		close(handle, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (!Buffer.isBuffer(handle)) throw new Error("handle is not a Buffer");
			const handleLen = handle.length;
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + handleLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.CLOSE;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, handleLen, p);
			buf.set(handle, p += 4);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} CLOSE`);
		}
		read(handle, buf, off, len, position, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (!Buffer.isBuffer(handle)) throw new Error("handle is not a Buffer");
			if (!Buffer.isBuffer(buf)) throw new Error("buffer is not a Buffer");
			if (off >= buf.length) throw new Error("offset is out of bounds");
			if (off + len > buf.length) throw new Error("length extends beyond buffer");
			if (position === null) throw new Error("null position currently unsupported");
			read_(this, handle, buf, off, len, position, cb);
		}
		readData(handle, buf, off, len, position, cb) {
			this.read(handle, buf, off, len, position, cb);
		}
		write(handle, buf, off, len, position, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (!Buffer.isBuffer(handle)) throw new Error("handle is not a Buffer");
			if (!Buffer.isBuffer(buf)) throw new Error("buffer is not a Buffer");
			if (off > buf.length) throw new Error("offset is out of bounds");
			if (off + len > buf.length) throw new Error("length extends beyond buffer");
			if (position === null) throw new Error("null position currently unsupported");
			if (!len) {
				cb && process.nextTick(cb, void 0, 0);
				return;
			}
			const maxDataLen = this._maxWriteLen;
			const overflow = Math.max(len - maxDataLen, 0);
			const origPosition = position;
			if (overflow) len = maxDataLen;
			const handleLen = handle.length;
			let p = 9;
			const out = Buffer.allocUnsafe(13 + handleLen + 8 + 4 + len);
			writeUInt32BE(out, out.length - 4, 0);
			out[4] = REQUEST.WRITE;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(out, reqid, 5);
			writeUInt32BE(out, handleLen, p);
			out.set(handle, p += 4);
			p += handleLen;
			for (let i = 7; i >= 0; --i) {
				out[p + i] = position & 255;
				position /= 256;
			}
			writeUInt32BE(out, len, p += 8);
			bufferCopy(buf, out, off, off + len, p += 4);
			this._requests[reqid] = { cb: (err) => {
				if (err) {
					if (typeof cb === "function") cb(err);
				} else if (overflow) this.write(handle, buf, off + len, overflow, origPosition + len, cb);
				else if (typeof cb === "function") cb(void 0, off + len);
			} };
			const isSent = sendOrBuffer(this, out);
			if (this._debug) {
				const how = isSent ? "Sent" : "Buffered";
				this._debug(`SFTP: Outbound: ${how} WRITE (id:${reqid})`);
			}
		}
		writeData(handle, buf, off, len, position, cb) {
			this.write(handle, buf, off, len, position, cb);
		}
		fastGet(remotePath, localPath, opts, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			fastXfer(this, fs, remotePath, localPath, opts, cb);
		}
		fastPut(localPath, remotePath, opts, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			fastXfer(fs, this, localPath, remotePath, opts, cb);
		}
		readFile(path, options, callback_) {
			if (this.server) throw new Error("Client-only method called in server mode");
			let callback;
			if (typeof callback_ === "function") callback = callback_;
			else if (typeof options === "function") {
				callback = options;
				options = void 0;
			}
			if (typeof options === "string") options = {
				encoding: options,
				flag: "r"
			};
			else if (!options) options = {
				encoding: null,
				flag: "r"
			};
			else if (typeof options !== "object") throw new TypeError("Bad arguments");
			const encoding = options.encoding;
			if (encoding && !Buffer.isEncoding(encoding)) throw new Error(`Unknown encoding: ${encoding}`);
			let size;
			let buffer;
			let buffers;
			let pos = 0;
			let handle;
			let bytesRead = 0;
			const flag = options.flag || "r";
			const read = () => {
				if (size === 0) {
					buffer = Buffer.allocUnsafe(8192);
					this.read(handle, buffer, 0, 8192, bytesRead, afterRead);
				} else this.read(handle, buffer, pos, size - pos, bytesRead, afterRead);
			};
			const afterRead = (er, nbytes) => {
				let eof;
				if (er) {
					eof = er.code === STATUS_CODE.EOF;
					if (!eof) return this.close(handle, () => {
						return callback && callback(er);
					});
				} else eof = false;
				if (eof || size === 0 && nbytes === 0) return close();
				bytesRead += nbytes;
				pos += nbytes;
				if (size !== 0) {
					if (pos === size) close();
					else read();
				} else {
					buffers.push(bufferSlice(buffer, 0, nbytes));
					read();
				}
			};
			afterRead._wantEOFError = true;
			const close = () => {
				this.close(handle, (er) => {
					if (size === 0) buffer = Buffer.concat(buffers, pos);
					else if (pos < size) buffer = bufferSlice(buffer, 0, pos);
					if (encoding) buffer = buffer.toString(encoding);
					return callback && callback(er, buffer);
				});
			};
			this.open(path, flag, 438, (er, handle_) => {
				if (er) return callback && callback(er);
				handle = handle_;
				const tryStat = (er, st) => {
					if (er) {
						this.stat(path, (er_, st_) => {
							if (er_) return this.close(handle, () => {
								callback && callback(er);
							});
							tryStat(null, st_);
						});
						return;
					}
					size = st.size || 0;
					if (size === 0) {
						buffers = [];
						return read();
					}
					buffer = Buffer.allocUnsafe(size);
					read();
				};
				this.fstat(handle, tryStat);
			});
		}
		writeFile(path, data, options, callback_) {
			if (this.server) throw new Error("Client-only method called in server mode");
			let callback;
			if (typeof callback_ === "function") callback = callback_;
			else if (typeof options === "function") {
				callback = options;
				options = void 0;
			}
			if (typeof options === "string") options = {
				encoding: options,
				mode: 438,
				flag: "w"
			};
			else if (!options) options = {
				encoding: "utf8",
				mode: 438,
				flag: "w"
			};
			else if (typeof options !== "object") throw new TypeError("Bad arguments");
			if (options.encoding && !Buffer.isEncoding(options.encoding)) throw new Error(`Unknown encoding: ${options.encoding}`);
			const flag = options.flag || "w";
			this.open(path, flag, options.mode, (openErr, handle) => {
				if (openErr) callback && callback(openErr);
				else {
					const buffer = Buffer.isBuffer(data) ? data : Buffer.from("" + data, options.encoding || "utf8");
					const position = /a/.test(flag) ? null : 0;
					if (position === null) {
						const tryStat = (er, st) => {
							if (er) {
								this.stat(path, (er_, st_) => {
									if (er_) return this.close(handle, () => {
										callback && callback(er);
									});
									tryStat(null, st_);
								});
								return;
							}
							writeAll(this, handle, buffer, 0, buffer.length, st.size, callback);
						};
						this.fstat(handle, tryStat);
						return;
					}
					writeAll(this, handle, buffer, 0, buffer.length, position, callback);
				}
			});
		}
		appendFile(path, data, options, callback_) {
			if (this.server) throw new Error("Client-only method called in server mode");
			let callback;
			if (typeof callback_ === "function") callback = callback_;
			else if (typeof options === "function") {
				callback = options;
				options = void 0;
			}
			if (typeof options === "string") options = {
				encoding: options,
				mode: 438,
				flag: "a"
			};
			else if (!options) options = {
				encoding: "utf8",
				mode: 438,
				flag: "a"
			};
			else if (typeof options !== "object") throw new TypeError("Bad arguments");
			if (!options.flag) options = Object.assign({ flag: "a" }, options);
			this.writeFile(path, data, options, callback);
		}
		exists(path, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			this.stat(path, (err) => {
				cb && cb(err ? false : true);
			});
		}
		unlink(filename, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const fnameLen = Buffer.byteLength(filename);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + fnameLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.REMOVE;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, fnameLen, p);
			buf.utf8Write(filename, p += 4, fnameLen);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} REMOVE`);
		}
		rename(oldPath, newPath, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const oldLen = Buffer.byteLength(oldPath);
			const newLen = Buffer.byteLength(newPath);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + oldLen + 4 + newLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.RENAME;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, oldLen, p);
			buf.utf8Write(oldPath, p += 4, oldLen);
			writeUInt32BE(buf, newLen, p += oldLen);
			buf.utf8Write(newPath, p += 4, newLen);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} RENAME`);
		}
		mkdir(path, attrs, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			let flags = 0;
			let attrsLen = 0;
			if (typeof attrs === "function") {
				cb = attrs;
				attrs = void 0;
			}
			if (typeof attrs === "object" && attrs !== null) {
				attrs = attrsToBytes(attrs);
				flags = attrs.flags;
				attrsLen = attrs.nb;
			}
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + pathLen + 4 + attrsLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.MKDIR;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, pathLen, p);
			buf.utf8Write(path, p += 4, pathLen);
			writeUInt32BE(buf, flags, p += pathLen);
			if (attrsLen) {
				p += 4;
				if (attrsLen === ATTRS_BUF.length) buf.set(ATTRS_BUF, p);
				else bufferCopy(ATTRS_BUF, buf, 0, attrsLen, p);
				p += attrsLen;
			}
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} MKDIR`);
		}
		rmdir(path, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + pathLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.RMDIR;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, pathLen, p);
			buf.utf8Write(path, p += 4, pathLen);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} RMDIR`);
		}
		readdir(where, opts, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (typeof opts === "function") {
				cb = opts;
				opts = {};
			}
			if (typeof opts !== "object" || opts === null) opts = {};
			const doFilter = opts && opts.full ? false : true;
			if (!Buffer.isBuffer(where) && typeof where !== "string") throw new Error("missing directory handle or path");
			if (typeof where === "string") {
				const entries = [];
				let e = 0;
				const reread = (err, handle) => {
					if (err) return cb(err);
					this.readdir(handle, opts, (err, list) => {
						const eof = err && err.code === STATUS_CODE.EOF;
						if (err && !eof) return this.close(handle, () => cb(err));
						if (eof) return this.close(handle, (err) => {
							if (err) return cb(err);
							cb(void 0, entries);
						});
						for (let i = 0; i < list.length; ++i, ++e) entries[e] = list[i];
						reread(void 0, handle);
					});
				};
				return this.opendir(where, reread);
			}
			const handleLen = where.length;
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + handleLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.READDIR;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, handleLen, p);
			buf.set(where, p += 4);
			this._requests[reqid] = { cb: doFilter ? (err, list) => {
				if (typeof cb !== "function") return;
				if (err) return cb(err);
				for (let i = list.length - 1; i >= 0; --i) if (list[i].filename === "." || list[i].filename === "..") list.splice(i, 1);
				cb(void 0, list);
			} : cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} READDIR`);
		}
		fstat(handle, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (!Buffer.isBuffer(handle)) throw new Error("handle is not a Buffer");
			const handleLen = handle.length;
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + handleLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.FSTAT;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, handleLen, p);
			buf.set(handle, p += 4);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} FSTAT`);
		}
		stat(path, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + pathLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.STAT;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, pathLen, p);
			buf.utf8Write(path, p += 4, pathLen);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} STAT`);
		}
		lstat(path, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + pathLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.LSTAT;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, pathLen, p);
			buf.utf8Write(path, p += 4, pathLen);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} LSTAT`);
		}
		opendir(path, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + pathLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.OPENDIR;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, pathLen, p);
			buf.utf8Write(path, p += 4, pathLen);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} OPENDIR`);
		}
		setstat(path, attrs, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			let flags = 0;
			let attrsLen = 0;
			if (typeof attrs === "object" && attrs !== null) {
				attrs = attrsToBytes(attrs);
				flags = attrs.flags;
				attrsLen = attrs.nb;
			} else if (typeof attrs === "function") cb = attrs;
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + pathLen + 4 + attrsLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.SETSTAT;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, pathLen, p);
			buf.utf8Write(path, p += 4, pathLen);
			writeUInt32BE(buf, flags, p += pathLen);
			if (attrsLen) {
				p += 4;
				if (attrsLen === ATTRS_BUF.length) buf.set(ATTRS_BUF, p);
				else bufferCopy(ATTRS_BUF, buf, 0, attrsLen, p);
				p += attrsLen;
			}
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} SETSTAT`);
		}
		fsetstat(handle, attrs, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (!Buffer.isBuffer(handle)) throw new Error("handle is not a Buffer");
			let flags = 0;
			let attrsLen = 0;
			if (typeof attrs === "object" && attrs !== null) {
				attrs = attrsToBytes(attrs);
				flags = attrs.flags;
				attrsLen = attrs.nb;
			} else if (typeof attrs === "function") cb = attrs;
			const handleLen = handle.length;
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + handleLen + 4 + attrsLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.FSETSTAT;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, handleLen, p);
			buf.set(handle, p += 4);
			writeUInt32BE(buf, flags, p += handleLen);
			if (attrsLen) {
				p += 4;
				if (attrsLen === ATTRS_BUF.length) buf.set(ATTRS_BUF, p);
				else bufferCopy(ATTRS_BUF, buf, 0, attrsLen, p);
				p += attrsLen;
			}
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} FSETSTAT`);
		}
		futimes(handle, atime, mtime, cb) {
			return this.fsetstat(handle, {
				atime: toUnixTimestamp(atime),
				mtime: toUnixTimestamp(mtime)
			}, cb);
		}
		utimes(path, atime, mtime, cb) {
			return this.setstat(path, {
				atime: toUnixTimestamp(atime),
				mtime: toUnixTimestamp(mtime)
			}, cb);
		}
		fchown(handle, uid, gid, cb) {
			return this.fsetstat(handle, {
				uid,
				gid
			}, cb);
		}
		chown(path, uid, gid, cb) {
			return this.setstat(path, {
				uid,
				gid
			}, cb);
		}
		fchmod(handle, mode, cb) {
			return this.fsetstat(handle, { mode }, cb);
		}
		chmod(path, mode, cb) {
			return this.setstat(path, { mode }, cb);
		}
		readlink(path, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + pathLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.READLINK;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, pathLen, p);
			buf.utf8Write(path, p += 4, pathLen);
			this._requests[reqid] = { cb: (err, names) => {
				if (typeof cb !== "function") return;
				if (err) return cb(err);
				if (!names || !names.length) return cb(/* @__PURE__ */ new Error("Response missing link info"));
				cb(void 0, names[0].filename);
			} };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} READLINK`);
		}
		symlink(targetPath, linkPath, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const linkLen = Buffer.byteLength(linkPath);
			const targetLen = Buffer.byteLength(targetPath);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + linkLen + 4 + targetLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.SYMLINK;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			if (this._isOpenSSH) {
				writeUInt32BE(buf, targetLen, p);
				buf.utf8Write(targetPath, p += 4, targetLen);
				writeUInt32BE(buf, linkLen, p += targetLen);
				buf.utf8Write(linkPath, p += 4, linkLen);
			} else {
				writeUInt32BE(buf, linkLen, p);
				buf.utf8Write(linkPath, p += 4, linkLen);
				writeUInt32BE(buf, targetLen, p += linkLen);
				buf.utf8Write(targetPath, p += 4, targetLen);
			}
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} SYMLINK`);
		}
		realpath(path, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + pathLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.REALPATH;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, pathLen, p);
			buf.utf8Write(path, p += 4, pathLen);
			this._requests[reqid] = { cb: (err, names) => {
				if (typeof cb !== "function") return;
				if (err) return cb(err);
				if (!names || !names.length) return cb(/* @__PURE__ */ new Error("Response missing path info"));
				cb(void 0, names[0].filename);
			} };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} REALPATH`);
		}
		ext_openssh_rename(oldPath, newPath, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const ext = this._extensions["posix-rename@openssh.com"];
			if (!ext || ext !== "1") throw new Error("Server does not support this extended request");
			const oldLen = Buffer.byteLength(oldPath);
			const newLen = Buffer.byteLength(newPath);
			let p = 9;
			const buf = Buffer.allocUnsafe(41 + oldLen + 4 + newLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.EXTENDED;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, 24, p);
			buf.utf8Write("posix-rename@openssh.com", p += 4, 24);
			writeUInt32BE(buf, oldLen, p += 24);
			buf.utf8Write(oldPath, p += 4, oldLen);
			writeUInt32BE(buf, newLen, p += oldLen);
			buf.utf8Write(newPath, p += 4, newLen);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			if (this._debug) {
				const which = isBuffered ? "Buffered" : "Sending";
				this._debug(`SFTP: Outbound: ${which} posix-rename@openssh.com`);
			}
		}
		ext_openssh_statvfs(path, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const ext = this._extensions["statvfs@openssh.com"];
			if (!ext || ext !== "2") throw new Error("Server does not support this extended request");
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(36 + pathLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.EXTENDED;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, 19, p);
			buf.utf8Write("statvfs@openssh.com", p += 4, 19);
			writeUInt32BE(buf, pathLen, p += 19);
			buf.utf8Write(path, p += 4, pathLen);
			this._requests[reqid] = {
				extended: "statvfs@openssh.com",
				cb
			};
			const isBuffered = sendOrBuffer(this, buf);
			if (this._debug) {
				const which = isBuffered ? "Buffered" : "Sending";
				this._debug(`SFTP: Outbound: ${which} statvfs@openssh.com`);
			}
		}
		ext_openssh_fstatvfs(handle, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			const ext = this._extensions["fstatvfs@openssh.com"];
			if (!ext || ext !== "2") throw new Error("Server does not support this extended request");
			if (!Buffer.isBuffer(handle)) throw new Error("handle is not a Buffer");
			const handleLen = handle.length;
			let p = 9;
			const buf = Buffer.allocUnsafe(37 + handleLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.EXTENDED;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, 20, p);
			buf.utf8Write("fstatvfs@openssh.com", p += 4, 20);
			writeUInt32BE(buf, handleLen, p += 20);
			buf.set(handle, p += 4);
			this._requests[reqid] = {
				extended: "fstatvfs@openssh.com",
				cb
			};
			const isBuffered = sendOrBuffer(this, buf);
			if (this._debug) {
				const which = isBuffered ? "Buffered" : "Sending";
				this._debug(`SFTP: Outbound: ${which} fstatvfs@openssh.com`);
			}
		}
		ext_openssh_hardlink(oldPath, newPath, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (this._extensions["hardlink@openssh.com"] !== "1") throw new Error("Server does not support this extended request");
			const oldLen = Buffer.byteLength(oldPath);
			const newLen = Buffer.byteLength(newPath);
			let p = 9;
			const buf = Buffer.allocUnsafe(37 + oldLen + 4 + newLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.EXTENDED;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, 20, p);
			buf.utf8Write("hardlink@openssh.com", p += 4, 20);
			writeUInt32BE(buf, oldLen, p += 20);
			buf.utf8Write(oldPath, p += 4, oldLen);
			writeUInt32BE(buf, newLen, p += oldLen);
			buf.utf8Write(newPath, p += 4, newLen);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			if (this._debug) {
				const which = isBuffered ? "Buffered" : "Sending";
				this._debug(`SFTP: Outbound: ${which} hardlink@openssh.com`);
			}
		}
		ext_openssh_fsync(handle, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (this._extensions["fsync@openssh.com"] !== "1") throw new Error("Server does not support this extended request");
			if (!Buffer.isBuffer(handle)) throw new Error("handle is not a Buffer");
			const handleLen = handle.length;
			let p = 9;
			const buf = Buffer.allocUnsafe(34 + handleLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.EXTENDED;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, 17, p);
			buf.utf8Write("fsync@openssh.com", p += 4, 17);
			writeUInt32BE(buf, handleLen, p += 17);
			buf.set(handle, p += 4);
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} fsync@openssh.com`);
		}
		ext_openssh_lsetstat(path, attrs, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (this._extensions["lsetstat@openssh.com"] !== "1") throw new Error("Server does not support this extended request");
			let flags = 0;
			let attrsLen = 0;
			if (typeof attrs === "object" && attrs !== null) {
				attrs = attrsToBytes(attrs);
				flags = attrs.flags;
				attrsLen = attrs.nb;
			} else if (typeof attrs === "function") cb = attrs;
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(37 + pathLen + 4 + attrsLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.EXTENDED;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, 20, p);
			buf.utf8Write("lsetstat@openssh.com", p += 4, 20);
			writeUInt32BE(buf, pathLen, p += 20);
			buf.utf8Write(path, p += 4, pathLen);
			writeUInt32BE(buf, flags, p += pathLen);
			if (attrsLen) {
				p += 4;
				if (attrsLen === ATTRS_BUF.length) buf.set(ATTRS_BUF, p);
				else bufferCopy(ATTRS_BUF, buf, 0, attrsLen, p);
				p += attrsLen;
			}
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			if (this._debug) {
				const status = isBuffered ? "Buffered" : "Sending";
				this._debug(`SFTP: Outbound: ${status} lsetstat@openssh.com`);
			}
		}
		ext_openssh_expandPath(path, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (this._extensions["expand-path@openssh.com"] !== "1") throw new Error("Server does not support this extended request");
			const pathLen = Buffer.byteLength(path);
			let p = 9;
			const buf = Buffer.allocUnsafe(40 + pathLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = REQUEST.EXTENDED;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, 23, p);
			buf.utf8Write("expand-path@openssh.com", p += 4, 23);
			writeUInt32BE(buf, pathLen, p += 20);
			buf.utf8Write(path, p += 4, pathLen);
			this._requests[reqid] = { cb: (err, names) => {
				if (typeof cb !== "function") return;
				if (err) return cb(err);
				if (!names || !names.length) return cb(/* @__PURE__ */ new Error("Response missing expanded path"));
				cb(void 0, names[0].filename);
			} };
			const isBuffered = sendOrBuffer(this, buf);
			if (this._debug) {
				const status = isBuffered ? "Buffered" : "Sending";
				this._debug(`SFTP: Outbound: ${status} expand-path@openssh.com`);
			}
		}
		ext_copy_data(srcHandle, srcOffset, len, dstHandle, dstOffset, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (this._extensions["copy-data"] !== "1") throw new Error("Server does not support this extended request");
			if (!Buffer.isBuffer(srcHandle)) throw new Error("Source handle is not a Buffer");
			if (!Buffer.isBuffer(dstHandle)) throw new Error("Destination handle is not a Buffer");
			let p = 0;
			const buf = Buffer.allocUnsafe(26 + srcHandle.length + 8 + 8 + 4 + dstHandle.length + 8);
			writeUInt32BE(buf, buf.length - 4, p);
			p += 4;
			buf[p] = REQUEST.EXTENDED;
			++p;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, p);
			p += 4;
			writeUInt32BE(buf, 9, p);
			p += 4;
			buf.utf8Write("copy-data", p, 9);
			p += 9;
			writeUInt32BE(buf, srcHandle.length, p);
			p += 4;
			buf.set(srcHandle, p);
			p += srcHandle.length;
			for (let i = 7; i >= 0; --i) {
				buf[p + i] = srcOffset & 255;
				srcOffset /= 256;
			}
			p += 8;
			for (let i = 7; i >= 0; --i) {
				buf[p + i] = len & 255;
				len /= 256;
			}
			p += 8;
			writeUInt32BE(buf, dstHandle.length, p);
			p += 4;
			buf.set(dstHandle, p);
			p += dstHandle.length;
			for (let i = 7; i >= 0; --i) {
				buf[p + i] = dstOffset & 255;
				dstOffset /= 256;
			}
			this._requests[reqid] = { cb };
			const isBuffered = sendOrBuffer(this, buf);
			if (this._debug) {
				const status = isBuffered ? "Buffered" : "Sending";
				this._debug(`SFTP: Outbound: ${status} copy-data`);
			}
		}
		ext_home_dir(username, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (this._extensions["home-directory"] !== "1") throw new Error("Server does not support this extended request");
			if (typeof username !== "string") throw new TypeError("username is not a string");
			let p = 0;
			const usernameLen = Buffer.byteLength(username);
			const buf = Buffer.allocUnsafe(31 + usernameLen);
			writeUInt32BE(buf, buf.length - 4, p);
			p += 4;
			buf[p] = REQUEST.EXTENDED;
			++p;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, p);
			p += 4;
			writeUInt32BE(buf, 14, p);
			p += 4;
			buf.utf8Write("home-directory", p, 14);
			p += 14;
			writeUInt32BE(buf, usernameLen, p);
			p += 4;
			buf.utf8Write(username, p, usernameLen);
			p += usernameLen;
			this._requests[reqid] = { cb: (err, names) => {
				if (typeof cb !== "function") return;
				if (err) return cb(err);
				if (!names || !names.length) return cb(/* @__PURE__ */ new Error("Response missing home directory"));
				cb(void 0, names[0].filename);
			} };
			const isBuffered = sendOrBuffer(this, buf);
			if (this._debug) {
				const status = isBuffered ? "Buffered" : "Sending";
				this._debug(`SFTP: Outbound: ${status} home-directory`);
			}
		}
		ext_users_groups(uids, gids, cb) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (this._extensions["users-groups-by-id@openssh.com"] !== "1") throw new Error("Server does not support this extended request");
			if (!Array.isArray(uids)) throw new TypeError("uids is not an array");
			for (const val of uids) if (!Number.isInteger(val) || val < 0 || val > 2 ** 32 - 1) throw new Error("uid values must all be 32-bit unsigned integers");
			if (!Array.isArray(gids)) throw new TypeError("gids is not an array");
			for (const val of gids) if (!Number.isInteger(val) || val < 0 || val > 2 ** 32 - 1) throw new Error("gid values must all be 32-bit unsigned integers");
			let p = 0;
			const buf = Buffer.allocUnsafe(47 + 4 * uids.length + 4 + 4 * gids.length);
			writeUInt32BE(buf, buf.length - 4, p);
			p += 4;
			buf[p] = REQUEST.EXTENDED;
			++p;
			const reqid = this._writeReqid = this._writeReqid + 1 & MAX_REQID;
			writeUInt32BE(buf, reqid, p);
			p += 4;
			writeUInt32BE(buf, 30, p);
			p += 4;
			buf.utf8Write("users-groups-by-id@openssh.com", p, 30);
			p += 30;
			writeUInt32BE(buf, 4 * uids.length, p);
			p += 4;
			for (const val of uids) {
				writeUInt32BE(buf, val, p);
				p += 4;
			}
			writeUInt32BE(buf, 4 * gids.length, p);
			p += 4;
			for (const val of gids) {
				writeUInt32BE(buf, val, p);
				p += 4;
			}
			this._requests[reqid] = {
				extended: "users-groups-by-id@openssh.com",
				cb
			};
			const isBuffered = sendOrBuffer(this, buf);
			if (this._debug) {
				const status = isBuffered ? "Buffered" : "Sending";
				this._debug(`SFTP: Outbound: ${status} users-groups-by-id@openssh.com`);
			}
		}
		handle(reqid, handle) {
			if (!this.server) throw new Error("Server-only method called in client mode");
			if (!Buffer.isBuffer(handle)) throw new Error("handle is not a Buffer");
			const handleLen = handle.length;
			if (handleLen > 256) throw new Error("handle too large (> 256 bytes)");
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + handleLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = RESPONSE.HANDLE;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, handleLen, p);
			if (handleLen) buf.set(handle, p += 4);
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} HANDLE`);
		}
		status(reqid, code, message) {
			if (!this.server) throw new Error("Server-only method called in client mode");
			if (!VALID_STATUS_CODES.has(code)) throw new Error(`Bad status code: ${code}`);
			message || (message = "");
			const msgLen = Buffer.byteLength(message);
			let p = 9;
			const buf = Buffer.allocUnsafe(17 + msgLen + 4);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = RESPONSE.STATUS;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, code, p);
			writeUInt32BE(buf, msgLen, p += 4);
			p += 4;
			if (msgLen) {
				buf.utf8Write(message, p, msgLen);
				p += msgLen;
			}
			writeUInt32BE(buf, 0, p);
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} STATUS`);
		}
		data(reqid, data, encoding) {
			if (!this.server) throw new Error("Server-only method called in client mode");
			const isBuffer = Buffer.isBuffer(data);
			if (!isBuffer && typeof data !== "string") throw new Error("data is not a Buffer or string");
			let isUTF8;
			if (!isBuffer && !encoding) {
				encoding = void 0;
				isUTF8 = true;
			}
			const dataLen = isBuffer ? data.length : Buffer.byteLength(data, encoding);
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + dataLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = RESPONSE.DATA;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, dataLen, p);
			if (dataLen) {
				if (isBuffer) buf.set(data, p += 4);
				else if (isUTF8) buf.utf8Write(data, p += 4, dataLen);
				else buf.write(data, p += 4, dataLen, encoding);
			}
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} DATA`);
		}
		name(reqid, names) {
			if (!this.server) throw new Error("Server-only method called in client mode");
			if (!Array.isArray(names)) {
				if (typeof names !== "object" || names === null) throw new Error("names is not an object or array");
				names = [names];
			}
			const count = names.length;
			let namesLen = 0;
			let nameAttrs;
			const attrs = [];
			for (let i = 0; i < count; ++i) {
				const name = names[i];
				const filename = !name || !name.filename || typeof name.filename !== "string" ? "" : name.filename;
				namesLen += 4 + Buffer.byteLength(filename);
				const longname = !name || !name.longname || typeof name.longname !== "string" ? "" : name.longname;
				namesLen += 4 + Buffer.byteLength(longname);
				if (typeof name.attrs === "object" && name.attrs !== null) {
					nameAttrs = attrsToBytes(name.attrs);
					namesLen += 4 + nameAttrs.nb;
					if (nameAttrs.nb) {
						let bytes;
						if (nameAttrs.nb === ATTRS_BUF.length) bytes = new Uint8Array(ATTRS_BUF);
						else {
							bytes = new Uint8Array(nameAttrs.nb);
							bufferCopy(ATTRS_BUF, bytes, 0, nameAttrs.nb, 0);
						}
						nameAttrs.bytes = bytes;
					}
					attrs.push(nameAttrs);
				} else {
					namesLen += 4;
					attrs.push(null);
				}
			}
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + namesLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = RESPONSE.NAME;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, count, p);
			p += 4;
			for (let i = 0; i < count; ++i) {
				const name = names[i];
				{
					const filename = !name || !name.filename || typeof name.filename !== "string" ? "" : name.filename;
					const len = Buffer.byteLength(filename);
					writeUInt32BE(buf, len, p);
					p += 4;
					if (len) {
						buf.utf8Write(filename, p, len);
						p += len;
					}
				}
				{
					const longname = !name || !name.longname || typeof name.longname !== "string" ? "" : name.longname;
					const len = Buffer.byteLength(longname);
					writeUInt32BE(buf, len, p);
					p += 4;
					if (len) {
						buf.utf8Write(longname, p, len);
						p += len;
					}
				}
				const attr = attrs[i];
				if (attr) {
					writeUInt32BE(buf, attr.flags, p);
					p += 4;
					if (attr.flags && attr.bytes) {
						buf.set(attr.bytes, p);
						p += attr.nb;
					}
				} else {
					writeUInt32BE(buf, 0, p);
					p += 4;
				}
			}
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} NAME`);
		}
		attrs(reqid, attrs) {
			if (!this.server) throw new Error("Server-only method called in client mode");
			if (typeof attrs !== "object" || attrs === null) throw new Error("attrs is not an object");
			attrs = attrsToBytes(attrs);
			const flags = attrs.flags;
			const attrsLen = attrs.nb;
			let p = 9;
			const buf = Buffer.allocUnsafe(13 + attrsLen);
			writeUInt32BE(buf, buf.length - 4, 0);
			buf[4] = RESPONSE.ATTRS;
			writeUInt32BE(buf, reqid, 5);
			writeUInt32BE(buf, flags, p);
			if (attrsLen) {
				p += 4;
				if (attrsLen === ATTRS_BUF.length) buf.set(ATTRS_BUF, p);
				else bufferCopy(ATTRS_BUF, buf, 0, attrsLen, p);
				p += attrsLen;
			}
			const isBuffered = sendOrBuffer(this, buf);
			this._debug && this._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} ATTRS`);
		}
	};
	function tryCreateBuffer(size) {
		try {
			return Buffer.allocUnsafe(size);
		} catch (ex) {
			return ex;
		}
	}
	function read_(self, handle, buf, off, len, position, cb, req_) {
		const maxDataLen = self._maxReadLen;
		const overflow = Math.max(len - maxDataLen, 0);
		if (overflow) len = maxDataLen;
		const handleLen = handle.length;
		let p = 9;
		let pos = position;
		const out = Buffer.allocUnsafe(13 + handleLen + 8 + 4);
		writeUInt32BE(out, out.length - 4, 0);
		out[4] = REQUEST.READ;
		const reqid = self._writeReqid = self._writeReqid + 1 & MAX_REQID;
		writeUInt32BE(out, reqid, 5);
		writeUInt32BE(out, handleLen, p);
		out.set(handle, p += 4);
		p += handleLen;
		for (let i = 7; i >= 0; --i) {
			out[p + i] = pos & 255;
			pos /= 256;
		}
		writeUInt32BE(out, len, p += 8);
		if (typeof cb !== "function") cb = noop;
		const req = req_ || {
			nb: 0,
			position,
			off,
			origOff: off,
			len: void 0,
			overflow: void 0,
			cb: (err, data, nb) => {
				const len = req.len;
				const overflow = req.overflow;
				if (err) {
					if (cb._wantEOFError || err.code !== STATUS_CODE.EOF) return cb(err);
				} else if (nb > len) return cb(/* @__PURE__ */ new Error("Received more data than requested"));
				else if (nb === len && overflow) {
					req.nb += nb;
					req.position += nb;
					req.off += nb;
					read_(self, handle, buf, req.off, overflow, req.position, cb, req);
					return;
				}
				nb = nb || 0;
				if (req.origOff === 0 && buf.length === req.nb) data = buf;
				else data = bufferSlice(buf, req.origOff, req.origOff + req.nb + nb);
				cb(void 0, req.nb + nb, data, req.position);
			},
			buffer: void 0
		};
		req.len = len;
		req.overflow = overflow;
		req.buffer = bufferSlice(buf, off, off + len);
		self._requests[reqid] = req;
		const isBuffered = sendOrBuffer(self, out);
		self._debug && self._debug(`SFTP: Outbound: ${isBuffered ? "Buffered" : "Sending"} READ`);
	}
	function fastXfer(src, dst, srcPath, dstPath, opts, cb) {
		let concurrency = 64;
		let chunkSize = 32768;
		let onstep;
		let mode;
		let fileSize;
		if (typeof opts === "function") cb = opts;
		else if (typeof opts === "object" && opts !== null) {
			if (typeof opts.concurrency === "number" && opts.concurrency > 0 && !isNaN(opts.concurrency)) concurrency = opts.concurrency;
			if (typeof opts.chunkSize === "number" && opts.chunkSize > 0 && !isNaN(opts.chunkSize)) chunkSize = opts.chunkSize;
			if (typeof opts.fileSize === "number" && opts.fileSize > 0 && !isNaN(opts.fileSize)) fileSize = opts.fileSize;
			if (typeof opts.step === "function") onstep = opts.step;
			if (typeof opts.mode === "string" || typeof opts.mode === "number") mode = modeNum(opts.mode);
		}
		let fsize;
		let pdst = 0;
		let total = 0;
		let hadError = false;
		let srcHandle;
		let dstHandle;
		let readbuf;
		let bufsize = chunkSize * concurrency;
		function onerror(err) {
			if (hadError) return;
			hadError = true;
			let left = 0;
			let cbfinal;
			if (srcHandle || dstHandle) {
				cbfinal = () => {
					if (--left === 0) cb(err);
				};
				if (srcHandle && (src === fs || src.outgoing.state === "open")) ++left;
				if (dstHandle && (dst === fs || dst.outgoing.state === "open")) ++left;
				if (srcHandle && (src === fs || src.outgoing.state === "open")) src.close(srcHandle, cbfinal);
				if (dstHandle && (dst === fs || dst.outgoing.state === "open")) dst.close(dstHandle, cbfinal);
			} else cb(err);
		}
		src.open(srcPath, "r", (err, sourceHandle) => {
			if (err) return onerror(err);
			srcHandle = sourceHandle;
			if (fileSize === void 0) src.fstat(srcHandle, tryStat);
			else tryStat(null, { size: fileSize });
			function tryStat(err, attrs) {
				if (err) {
					if (src !== fs) {
						src.stat(srcPath, (err_, attrs_) => {
							if (err_) return onerror(err);
							tryStat(null, attrs_);
						});
						return;
					}
					return onerror(err);
				}
				fsize = attrs.size;
				dst.open(dstPath, "w", (err, destHandle) => {
					if (err) return onerror(err);
					dstHandle = destHandle;
					if (fsize <= 0) return onerror();
					while (bufsize > fsize) {
						if (concurrency === 1) {
							bufsize = fsize;
							break;
						}
						bufsize -= chunkSize;
						--concurrency;
					}
					readbuf = tryCreateBuffer(bufsize);
					if (readbuf instanceof Error) return onerror(readbuf);
					if (mode !== void 0) dst.fchmod(dstHandle, mode, function tryAgain(err) {
						if (err) {
							dst.chmod(dstPath, mode, (err_) => tryAgain());
							return;
						}
						startReads();
					});
					else startReads();
					function onread(err, nb, data, dstpos, datapos, origChunkLen) {
						if (err) return onerror(err);
						datapos = datapos || 0;
						dst.write(dstHandle, readbuf, datapos, nb, dstpos, writeCb);
						function writeCb(err) {
							if (err) return onerror(err);
							total += nb;
							onstep && onstep(total, nb, fsize);
							if (nb < origChunkLen) return singleRead(datapos, dstpos + nb, origChunkLen - nb);
							if (total === fsize) {
								dst.close(dstHandle, (err) => {
									dstHandle = void 0;
									if (err) return onerror(err);
									src.close(srcHandle, (err) => {
										srcHandle = void 0;
										if (err) return onerror(err);
										cb();
									});
								});
								return;
							}
							if (pdst >= fsize) return;
							const chunk = pdst + chunkSize > fsize ? fsize - pdst : chunkSize;
							singleRead(datapos, pdst, chunk);
							pdst += chunk;
						}
					}
					function makeCb(psrc, pdst, chunk) {
						return (err, nb, data) => {
							onread(err, nb, data, pdst, psrc, chunk);
						};
					}
					function singleRead(psrc, pdst, chunk) {
						src.read(srcHandle, readbuf, psrc, chunk, pdst, makeCb(psrc, pdst, chunk));
					}
					function startReads() {
						let reads = 0;
						let psrc = 0;
						while (pdst < fsize && reads < concurrency) {
							const chunk = pdst + chunkSize > fsize ? fsize - pdst : chunkSize;
							singleRead(psrc, pdst, chunk);
							psrc += chunk;
							pdst += chunk;
							++reads;
						}
					}
				});
			}
		});
	}
	function writeAll(sftp, handle, buffer, offset, length, position, callback_) {
		const callback = typeof callback_ === "function" ? callback_ : void 0;
		sftp.write(handle, buffer, offset, length, position, (writeErr, written) => {
			if (writeErr) return sftp.close(handle, () => {
				callback && callback(writeErr);
			});
			if (written === length) sftp.close(handle, callback);
			else {
				offset += written;
				length -= written;
				position += written;
				writeAll(sftp, handle, buffer, offset, length, position, callback);
			}
		});
	}
	var Stats = class {
		constructor(initial) {
			this.mode = initial && initial.mode;
			this.uid = initial && initial.uid;
			this.gid = initial && initial.gid;
			this.size = initial && initial.size;
			this.atime = initial && initial.atime;
			this.mtime = initial && initial.mtime;
			this.extended = initial && initial.extended;
		}
		isDirectory() {
			return (this.mode & constants.S_IFMT) === constants.S_IFDIR;
		}
		isFile() {
			return (this.mode & constants.S_IFMT) === constants.S_IFREG;
		}
		isBlockDevice() {
			return (this.mode & constants.S_IFMT) === constants.S_IFBLK;
		}
		isCharacterDevice() {
			return (this.mode & constants.S_IFMT) === constants.S_IFCHR;
		}
		isSymbolicLink() {
			return (this.mode & constants.S_IFMT) === constants.S_IFLNK;
		}
		isFIFO() {
			return (this.mode & constants.S_IFMT) === constants.S_IFIFO;
		}
		isSocket() {
			return (this.mode & constants.S_IFMT) === constants.S_IFSOCK;
		}
	};
	function attrsToBytes(attrs) {
		let flags = 0;
		let nb = 0;
		if (typeof attrs === "object" && attrs !== null) {
			if (typeof attrs.size === "number") {
				flags |= ATTR.SIZE;
				const val = attrs.size;
				ATTRS_BUF[nb++] = val / 72057594037927940;
				ATTRS_BUF[nb++] = val / 281474976710656;
				ATTRS_BUF[nb++] = val / 1099511627776;
				ATTRS_BUF[nb++] = val / 4294967296;
				ATTRS_BUF[nb++] = val / 16777216;
				ATTRS_BUF[nb++] = val / 65536;
				ATTRS_BUF[nb++] = val / 256;
				ATTRS_BUF[nb++] = val;
			}
			if (typeof attrs.uid === "number" && typeof attrs.gid === "number") {
				flags |= ATTR.UIDGID;
				const uid = attrs.uid;
				const gid = attrs.gid;
				ATTRS_BUF[nb++] = uid >>> 24;
				ATTRS_BUF[nb++] = uid >>> 16;
				ATTRS_BUF[nb++] = uid >>> 8;
				ATTRS_BUF[nb++] = uid;
				ATTRS_BUF[nb++] = gid >>> 24;
				ATTRS_BUF[nb++] = gid >>> 16;
				ATTRS_BUF[nb++] = gid >>> 8;
				ATTRS_BUF[nb++] = gid;
			}
			if (typeof attrs.mode === "number" || typeof attrs.mode === "string") {
				const mode = modeNum(attrs.mode);
				flags |= ATTR.PERMISSIONS;
				ATTRS_BUF[nb++] = mode >>> 24;
				ATTRS_BUF[nb++] = mode >>> 16;
				ATTRS_BUF[nb++] = mode >>> 8;
				ATTRS_BUF[nb++] = mode;
			}
			if ((typeof attrs.atime === "number" || isDate(attrs.atime)) && (typeof attrs.mtime === "number" || isDate(attrs.mtime))) {
				const atime = toUnixTimestamp(attrs.atime);
				const mtime = toUnixTimestamp(attrs.mtime);
				flags |= ATTR.ACMODTIME;
				ATTRS_BUF[nb++] = atime >>> 24;
				ATTRS_BUF[nb++] = atime >>> 16;
				ATTRS_BUF[nb++] = atime >>> 8;
				ATTRS_BUF[nb++] = atime;
				ATTRS_BUF[nb++] = mtime >>> 24;
				ATTRS_BUF[nb++] = mtime >>> 16;
				ATTRS_BUF[nb++] = mtime >>> 8;
				ATTRS_BUF[nb++] = mtime;
			}
		}
		return {
			flags,
			nb
		};
	}
	function toUnixTimestamp(time) {
		if (typeof time === "number" && time === time) return time;
		if (isDate(time)) return parseInt(time.getTime() / 1e3, 10);
		throw new Error(`Cannot parse time: ${time}`);
	}
	function modeNum(mode) {
		if (typeof mode === "number" && mode === mode) return mode;
		if (typeof mode === "string") return modeNum(parseInt(mode, 8));
		throw new Error(`Cannot parse mode: ${mode}`);
	}
	const stringFlagMap = {
		"r": OPEN_MODE.READ,
		"r+": OPEN_MODE.READ | OPEN_MODE.WRITE,
		"w": OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.WRITE,
		"wx": OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.WRITE | OPEN_MODE.EXCL,
		"xw": OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.WRITE | OPEN_MODE.EXCL,
		"w+": OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE,
		"wx+": OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE | OPEN_MODE.EXCL,
		"xw+": OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE | OPEN_MODE.EXCL,
		"a": OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.WRITE,
		"ax": OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.WRITE | OPEN_MODE.EXCL,
		"xa": OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.WRITE | OPEN_MODE.EXCL,
		"a+": OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE,
		"ax+": OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE | OPEN_MODE.EXCL,
		"xa+": OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE | OPEN_MODE.EXCL
	};
	function stringToFlags(str) {
		const flags = stringFlagMap[str];
		return flags !== void 0 ? flags : null;
	}
	const flagsToString = (() => {
		const stringFlagMapKeys = Object.keys(stringFlagMap);
		return (flags) => {
			for (let i = 0; i < stringFlagMapKeys.length; ++i) {
				const key = stringFlagMapKeys[i];
				if (stringFlagMap[key] === flags) return key;
			}
			return null;
		};
	})();
	function readAttrs(biOpt) {
		const flags = bufferParser.readUInt32BE();
		if (flags === void 0) return;
		const attrs = new Stats();
		if (flags & ATTR.SIZE) {
			const size = bufferParser.readUInt64BE(biOpt);
			if (size === void 0) return;
			attrs.size = size;
		}
		if (flags & ATTR.UIDGID) {
			const uid = bufferParser.readUInt32BE();
			const gid = bufferParser.readUInt32BE();
			if (gid === void 0) return;
			attrs.uid = uid;
			attrs.gid = gid;
		}
		if (flags & ATTR.PERMISSIONS) {
			const mode = bufferParser.readUInt32BE();
			if (mode === void 0) return;
			attrs.mode = mode;
		}
		if (flags & ATTR.ACMODTIME) {
			const atime = bufferParser.readUInt32BE();
			const mtime = bufferParser.readUInt32BE();
			if (mtime === void 0) return;
			attrs.atime = atime;
			attrs.mtime = mtime;
		}
		if (flags & ATTR.EXTENDED) {
			const count = bufferParser.readUInt32BE();
			if (count === void 0) return;
			const extended = {};
			for (let i = 0; i < count; ++i) {
				const type = bufferParser.readString(true);
				const data = bufferParser.readString();
				if (data === void 0) return;
				extended[type] = data;
			}
			attrs.extended = extended;
		}
		return attrs;
	}
	function sendOrBuffer(sftp, payload) {
		const ret = tryWritePayload(sftp, payload);
		if (ret !== void 0) {
			sftp._buffer.push(ret);
			return false;
		}
		return true;
	}
	function tryWritePayload(sftp, payload) {
		const outgoing = sftp.outgoing;
		if (outgoing.state !== "open") return;
		if (outgoing.window === 0) {
			sftp._waitWindow = true;
			sftp._chunkcb = drainBuffer;
			return payload;
		}
		let ret;
		const len = payload.length;
		let p = 0;
		while (len - p > 0 && outgoing.window > 0) {
			const actualLen = Math.min(len - p, outgoing.window, outgoing.packetSize);
			outgoing.window -= actualLen;
			if (outgoing.window === 0) {
				sftp._waitWindow = true;
				sftp._chunkcb = drainBuffer;
			}
			if (p === 0 && actualLen === len) sftp._protocol.channelData(sftp.outgoing.id, payload);
			else sftp._protocol.channelData(sftp.outgoing.id, bufferSlice(payload, p, p + actualLen));
			p += actualLen;
		}
		if (len - p > 0) {
			if (p > 0) ret = bufferSlice(payload, p, len);
			else ret = payload;
		}
		return ret;
	}
	function drainBuffer() {
		this._chunkcb = void 0;
		const buffer = this._buffer;
		let i = 0;
		while (i < buffer.length) {
			const payload = buffer[i];
			const ret = tryWritePayload(this, payload);
			if (ret !== void 0) {
				if (ret !== payload) buffer[i] = ret;
				if (i > 0) this._buffer = buffer.slice(i);
				return;
			}
			++i;
		}
		if (i > 0) this._buffer = [];
	}
	function doFatalSFTPError(sftp, msg, noDebug) {
		const err = new Error(msg);
		err.level = "sftp-protocol";
		if (!noDebug && sftp._debug) sftp._debug(`SFTP: Inbound: ${msg}`);
		sftp.emit("error", err);
		sftp.destroy();
		cleanupRequests(sftp);
		return false;
	}
	function cleanupRequests(sftp) {
		const keys = Object.keys(sftp._requests);
		if (keys.length === 0) return;
		const reqs = sftp._requests;
		sftp._requests = {};
		const err = /* @__PURE__ */ new Error("No response from server");
		for (let i = 0; i < keys.length; ++i) {
			const req = reqs[keys[i]];
			if (typeof req.cb === "function") req.cb(err);
		}
	}
	function requestLimits(sftp, cb) {
		let p = 9;
		const buf = Buffer.allocUnsafe(31);
		writeUInt32BE(buf, buf.length - 4, 0);
		buf[4] = REQUEST.EXTENDED;
		const reqid = sftp._writeReqid = sftp._writeReqid + 1 & MAX_REQID;
		writeUInt32BE(buf, reqid, 5);
		writeUInt32BE(buf, 18, p);
		buf.utf8Write("limits@openssh.com", p += 4, 18);
		sftp._requests[reqid] = {
			extended: "limits@openssh.com",
			cb
		};
		const isBuffered = sendOrBuffer(sftp, buf);
		if (sftp._debug) {
			const which = isBuffered ? "Buffered" : "Sending";
			sftp._debug(`SFTP: Outbound: ${which} limits@openssh.com`);
		}
	}
	const CLIENT_HANDLERS = {
		[RESPONSE.VERSION]: (sftp, payload) => {
			if (sftp._version !== -1) return doFatalSFTPError(sftp, "Duplicate VERSION packet");
			const extensions = {};
			bufferParser.init(payload, 1);
			let version = bufferParser.readUInt32BE();
			while (bufferParser.avail()) {
				const extName = bufferParser.readString(true);
				const extData = bufferParser.readString(true);
				if (extData === void 0) {
					version = void 0;
					break;
				}
				extensions[extName] = extData;
			}
			bufferParser.clear();
			if (version === void 0) return doFatalSFTPError(sftp, "Malformed VERSION packet");
			if (sftp._debug) {
				const names = Object.keys(extensions);
				if (names.length) sftp._debug(`SFTP: Inbound: Received VERSION (v${version}, exts:${names})`);
				else sftp._debug(`SFTP: Inbound: Received VERSION (v${version})`);
			}
			sftp._version = version;
			sftp._extensions = extensions;
			if (extensions["limits@openssh.com"] === "1") return requestLimits(sftp, (err, limits) => {
				if (!err) {
					if (limits.maxPktLen > 0) sftp._maxOutPktLen = limits.maxPktLen;
					if (limits.maxReadLen > 0) sftp._maxReadLen = limits.maxReadLen;
					if (limits.maxWriteLen > 0) sftp._maxWriteLen = limits.maxWriteLen;
					sftp.maxOpenHandles = limits.maxOpenHandles > 0 ? limits.maxOpenHandles : Infinity;
				}
				sftp.emit("ready");
			});
			sftp.emit("ready");
		},
		[RESPONSE.STATUS]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const errorCode = bufferParser.readUInt32BE();
			const errorMsg = bufferParser.readString(true);
			bufferParser.clear();
			if (sftp._debug) {
				const jsonMsg = JSON.stringify(errorMsg);
				sftp._debug(`SFTP: Inbound: Received STATUS (id:${reqID}, ${errorCode}, ${jsonMsg})`);
			}
			const req = sftp._requests[reqID];
			delete sftp._requests[reqID];
			if (req && typeof req.cb === "function") {
				if (errorCode === STATUS_CODE.OK) {
					req.cb();
					return;
				}
				const err = new Error(errorMsg || STATUS_CODE_STR[errorCode] || "Unknown status");
				err.code = errorCode;
				req.cb(err);
			}
		},
		[RESPONSE.HANDLE]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const handle = bufferParser.readString();
			bufferParser.clear();
			if (handle === void 0) {
				if (reqID !== void 0) delete sftp._requests[reqID];
				return doFatalSFTPError(sftp, "Malformed HANDLE packet");
			}
			sftp._debug && sftp._debug(`SFTP: Inbound: Received HANDLE (id:${reqID})`);
			const req = sftp._requests[reqID];
			delete sftp._requests[reqID];
			if (req && typeof req.cb === "function") req.cb(void 0, handle);
		},
		[RESPONSE.DATA]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			let req;
			if (reqID !== void 0) {
				req = sftp._requests[reqID];
				delete sftp._requests[reqID];
			}
			if (req && typeof req.cb === "function") {
				if (req.buffer) {
					const nb = bufferParser.readString(req.buffer);
					bufferParser.clear();
					if (nb !== void 0) {
						sftp._debug && sftp._debug(`SFTP: Inbound: Received DATA (id:${reqID}, ${nb})`);
						req.cb(void 0, req.buffer, nb);
						return;
					}
				} else {
					const data = bufferParser.readString();
					bufferParser.clear();
					if (data !== void 0) {
						sftp._debug && sftp._debug(`SFTP: Inbound: Received DATA (id:${reqID}, ${data.length})`);
						req.cb(void 0, data);
						return;
					}
				}
			} else {
				const nb = bufferParser.skipString();
				bufferParser.clear();
				if (nb !== void 0) {
					sftp._debug && sftp._debug(`SFTP: Inbound: Received DATA (id:${reqID}, ${nb})`);
					return;
				}
			}
			return doFatalSFTPError(sftp, "Malformed DATA packet");
		},
		[RESPONSE.NAME]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			let req;
			if (reqID !== void 0) {
				req = sftp._requests[reqID];
				delete sftp._requests[reqID];
			}
			const count = bufferParser.readUInt32BE();
			if (count !== void 0) {
				let names = [];
				for (let i = 0; i < count; ++i) {
					const filename = bufferParser.readString(true);
					const longname = bufferParser.readString(true);
					const attrs = readAttrs(sftp._biOpt);
					if (attrs === void 0) {
						names = void 0;
						break;
					}
					names.push({
						filename,
						longname,
						attrs
					});
				}
				if (names !== void 0) {
					sftp._debug && sftp._debug(`SFTP: Inbound: Received NAME (id:${reqID}, ${names.length})`);
					bufferParser.clear();
					if (req && typeof req.cb === "function") req.cb(void 0, names);
					return;
				}
			}
			bufferParser.clear();
			return doFatalSFTPError(sftp, "Malformed NAME packet");
		},
		[RESPONSE.ATTRS]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			let req;
			if (reqID !== void 0) {
				req = sftp._requests[reqID];
				delete sftp._requests[reqID];
			}
			const attrs = readAttrs(sftp._biOpt);
			bufferParser.clear();
			if (attrs !== void 0) {
				sftp._debug && sftp._debug(`SFTP: Inbound: Received ATTRS (id:${reqID})`);
				if (req && typeof req.cb === "function") req.cb(void 0, attrs);
				return;
			}
			return doFatalSFTPError(sftp, "Malformed ATTRS packet");
		},
		[RESPONSE.EXTENDED]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			if (reqID !== void 0) {
				const req = sftp._requests[reqID];
				if (req) {
					delete sftp._requests[reqID];
					switch (req.extended) {
						case "statvfs@openssh.com":
						case "fstatvfs@openssh.com": {
							const biOpt = sftp._biOpt;
							const stats = {
								f_bsize: bufferParser.readUInt64BE(biOpt),
								f_frsize: bufferParser.readUInt64BE(biOpt),
								f_blocks: bufferParser.readUInt64BE(biOpt),
								f_bfree: bufferParser.readUInt64BE(biOpt),
								f_bavail: bufferParser.readUInt64BE(biOpt),
								f_files: bufferParser.readUInt64BE(biOpt),
								f_ffree: bufferParser.readUInt64BE(biOpt),
								f_favail: bufferParser.readUInt64BE(biOpt),
								f_sid: bufferParser.readUInt64BE(biOpt),
								f_flag: bufferParser.readUInt64BE(biOpt),
								f_namemax: bufferParser.readUInt64BE(biOpt)
							};
							if (stats.f_namemax === void 0) break;
							if (sftp._debug) sftp._debug(`SFTP: Inbound: Received EXTENDED_REPLY (id:${reqID}, ${req.extended})`);
							bufferParser.clear();
							if (typeof req.cb === "function") req.cb(void 0, stats);
							return;
						}
						case "limits@openssh.com": {
							const limits = {
								maxPktLen: bufferParser.readUInt64BE(),
								maxReadLen: bufferParser.readUInt64BE(),
								maxWriteLen: bufferParser.readUInt64BE(),
								maxOpenHandles: bufferParser.readUInt64BE()
							};
							if (limits.maxOpenHandles === void 0) break;
							if (sftp._debug) sftp._debug(`SFTP: Inbound: Received EXTENDED_REPLY (id:${reqID}, ${req.extended})`);
							bufferParser.clear();
							if (typeof req.cb === "function") req.cb(void 0, limits);
							return;
						}
						case "users-groups-by-id@openssh.com": {
							const usernameCount = bufferParser.readUInt32BE();
							if (usernameCount === void 0) break;
							const usernames = new Array(usernameCount);
							for (let i = 0; i < usernames.length; ++i) usernames[i] = bufferParser.readString(true);
							const groupnameCount = bufferParser.readUInt32BE();
							if (groupnameCount === void 0) break;
							const groupnames = new Array(groupnameCount);
							for (let i = 0; i < groupnames.length; ++i) groupnames[i] = bufferParser.readString(true);
							if (groupnames.length > 0 && groupnames[groupnames.length - 1] === void 0) break;
							if (sftp._debug) sftp._debug(`SFTP: Inbound: Received EXTENDED_REPLY (id:${reqID}, ${req.extended})`);
							bufferParser.clear();
							if (typeof req.cb === "function") req.cb(void 0, usernames, groupnames);
							return;
						}
						default:
							sftp._debug && sftp._debug(`SFTP: Inbound: Received EXTENDED_REPLY (id:${reqID}, ???)`);
							bufferParser.clear();
							if (typeof req.cb === "function") req.cb();
							return;
					}
				} else {
					sftp._debug && sftp._debug(`SFTP: Inbound: Received EXTENDED_REPLY (id:${reqID}, ???)`);
					bufferParser.clear();
					return;
				}
			}
			bufferParser.clear();
			return doFatalSFTPError(sftp, "Malformed EXTENDED_REPLY packet");
		}
	};
	const SERVER_HANDLERS = {
		[REQUEST.INIT]: (sftp, payload) => {
			if (sftp._version !== -1) return doFatalSFTPError(sftp, "Duplicate INIT packet");
			const extensions = {};
			bufferParser.init(payload, 1);
			let version = bufferParser.readUInt32BE();
			while (bufferParser.avail()) {
				const extName = bufferParser.readString(true);
				const extData = bufferParser.readString(true);
				if (extData === void 0) {
					version = void 0;
					break;
				}
				extensions[extName] = extData;
			}
			bufferParser.clear();
			if (version === void 0) return doFatalSFTPError(sftp, "Malformed INIT packet");
			if (sftp._debug) {
				const names = Object.keys(extensions);
				if (names.length) sftp._debug(`SFTP: Inbound: Received INIT (v${version}, exts:${names})`);
				else sftp._debug(`SFTP: Inbound: Received INIT (v${version})`);
			}
			sendOrBuffer(sftp, SERVER_VERSION_BUFFER);
			sftp._version = version;
			sftp._extensions = extensions;
			sftp.emit("ready");
		},
		[REQUEST.OPEN]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const filename = bufferParser.readString(true);
			const pflags = bufferParser.readUInt32BE();
			const attrs = readAttrs(sftp._biOpt);
			bufferParser.clear();
			if (attrs === void 0) return doFatalSFTPError(sftp, "Malformed OPEN packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received OPEN (id:${reqID})`);
			if (!sftp.emit("OPEN", reqID, filename, pflags, attrs)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.CLOSE]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const handle = bufferParser.readString();
			bufferParser.clear();
			if (handle === void 0 || handle.length > 256) return doFatalSFTPError(sftp, "Malformed CLOSE packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received CLOSE (id:${reqID})`);
			if (!sftp.emit("CLOSE", reqID, handle)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.READ]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const handle = bufferParser.readString();
			const offset = bufferParser.readUInt64BE(sftp._biOpt);
			const len = bufferParser.readUInt32BE();
			bufferParser.clear();
			if (len === void 0 || handle.length > 256) return doFatalSFTPError(sftp, "Malformed READ packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received READ (id:${reqID})`);
			if (!sftp.emit("READ", reqID, handle, offset, len)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.WRITE]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const handle = bufferParser.readString();
			const offset = bufferParser.readUInt64BE(sftp._biOpt);
			const data = bufferParser.readString();
			bufferParser.clear();
			if (data === void 0 || handle.length > 256) return doFatalSFTPError(sftp, "Malformed WRITE packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received WRITE (id:${reqID})`);
			if (!sftp.emit("WRITE", reqID, handle, offset, data)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.LSTAT]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const path = bufferParser.readString(true);
			bufferParser.clear();
			if (path === void 0) return doFatalSFTPError(sftp, "Malformed LSTAT packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received LSTAT (id:${reqID})`);
			if (!sftp.emit("LSTAT", reqID, path)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.FSTAT]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const handle = bufferParser.readString();
			bufferParser.clear();
			if (handle === void 0 || handle.length > 256) return doFatalSFTPError(sftp, "Malformed FSTAT packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received FSTAT (id:${reqID})`);
			if (!sftp.emit("FSTAT", reqID, handle)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.SETSTAT]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const path = bufferParser.readString(true);
			const attrs = readAttrs(sftp._biOpt);
			bufferParser.clear();
			if (attrs === void 0) return doFatalSFTPError(sftp, "Malformed SETSTAT packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received SETSTAT (id:${reqID})`);
			if (!sftp.emit("SETSTAT", reqID, path, attrs)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.FSETSTAT]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const handle = bufferParser.readString();
			const attrs = readAttrs(sftp._biOpt);
			bufferParser.clear();
			if (attrs === void 0 || handle.length > 256) return doFatalSFTPError(sftp, "Malformed FSETSTAT packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received FSETSTAT (id:${reqID})`);
			if (!sftp.emit("FSETSTAT", reqID, handle, attrs)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.OPENDIR]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const path = bufferParser.readString(true);
			bufferParser.clear();
			if (path === void 0) return doFatalSFTPError(sftp, "Malformed OPENDIR packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received OPENDIR (id:${reqID})`);
			if (!sftp.emit("OPENDIR", reqID, path)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.READDIR]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const handle = bufferParser.readString();
			bufferParser.clear();
			if (handle === void 0 || handle.length > 256) return doFatalSFTPError(sftp, "Malformed READDIR packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received READDIR (id:${reqID})`);
			if (!sftp.emit("READDIR", reqID, handle)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.REMOVE]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const path = bufferParser.readString(true);
			bufferParser.clear();
			if (path === void 0) return doFatalSFTPError(sftp, "Malformed REMOVE packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received REMOVE (id:${reqID})`);
			if (!sftp.emit("REMOVE", reqID, path)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.MKDIR]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const path = bufferParser.readString(true);
			const attrs = readAttrs(sftp._biOpt);
			bufferParser.clear();
			if (attrs === void 0) return doFatalSFTPError(sftp, "Malformed MKDIR packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received MKDIR (id:${reqID})`);
			if (!sftp.emit("MKDIR", reqID, path, attrs)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.RMDIR]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const path = bufferParser.readString(true);
			bufferParser.clear();
			if (path === void 0) return doFatalSFTPError(sftp, "Malformed RMDIR packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received RMDIR (id:${reqID})`);
			if (!sftp.emit("RMDIR", reqID, path)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.REALPATH]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const path = bufferParser.readString(true);
			bufferParser.clear();
			if (path === void 0) return doFatalSFTPError(sftp, "Malformed REALPATH packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received REALPATH (id:${reqID})`);
			if (!sftp.emit("REALPATH", reqID, path)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.STAT]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const path = bufferParser.readString(true);
			bufferParser.clear();
			if (path === void 0) return doFatalSFTPError(sftp, "Malformed STAT packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received STAT (id:${reqID})`);
			if (!sftp.emit("STAT", reqID, path)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.RENAME]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const oldPath = bufferParser.readString(true);
			const newPath = bufferParser.readString(true);
			bufferParser.clear();
			if (newPath === void 0) return doFatalSFTPError(sftp, "Malformed RENAME packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received RENAME (id:${reqID})`);
			if (!sftp.emit("RENAME", reqID, oldPath, newPath)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.READLINK]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const path = bufferParser.readString(true);
			bufferParser.clear();
			if (path === void 0) return doFatalSFTPError(sftp, "Malformed READLINK packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received READLINK (id:${reqID})`);
			if (!sftp.emit("READLINK", reqID, path)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.SYMLINK]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const linkPath = bufferParser.readString(true);
			const targetPath = bufferParser.readString(true);
			bufferParser.clear();
			if (targetPath === void 0) return doFatalSFTPError(sftp, "Malformed SYMLINK packet");
			sftp._debug && sftp._debug(`SFTP: Inbound: Received SYMLINK (id:${reqID})`);
			let handled;
			if (sftp._isOpenSSH) handled = sftp.emit("SYMLINK", reqID, targetPath, linkPath);
			else handled = sftp.emit("SYMLINK", reqID, linkPath, targetPath);
			if (!handled) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		},
		[REQUEST.EXTENDED]: (sftp, payload) => {
			bufferParser.init(payload, 1);
			const reqID = bufferParser.readUInt32BE();
			const extName = bufferParser.readString(true);
			if (extName === void 0) {
				bufferParser.clear();
				return doFatalSFTPError(sftp, "Malformed EXTENDED packet");
			}
			let extData;
			if (bufferParser.avail()) extData = bufferParser.readRaw();
			bufferParser.clear();
			sftp._debug && sftp._debug(`SFTP: Inbound: Received EXTENDED (id:${reqID})`);
			if (!sftp.emit("EXTENDED", reqID, extName, extData)) sftp.status(reqID, STATUS_CODE.OP_UNSUPPORTED);
		}
	};
	const { ERR_INVALID_ARG_TYPE, ERR_OUT_OF_RANGE, validateNumber } = require_node_fs_compat();
	const kMinPoolSpace = 128;
	let pool;
	const poolFragments = [];
	function allocNewPool(poolSize) {
		if (poolFragments.length > 0) pool = poolFragments.pop();
		else pool = Buffer.allocUnsafe(poolSize);
		pool.used = 0;
	}
	function checkPosition(pos, name) {
		if (!Number.isSafeInteger(pos)) {
			validateNumber(pos, name);
			if (!Number.isInteger(pos)) throw new ERR_OUT_OF_RANGE(name, "an integer", pos);
			throw new ERR_OUT_OF_RANGE(name, ">= 0 and <= 2 ** 53 - 1", pos);
		}
		if (pos < 0) throw new ERR_OUT_OF_RANGE(name, ">= 0 and <= 2 ** 53 - 1", pos);
	}
	function roundUpToMultipleOf8(n) {
		return n + 7 & -8;
	}
	function ReadStream(sftp, path, options) {
		if (options === void 0) options = {};
		else if (typeof options === "string") options = { encoding: options };
		else if (options === null || typeof options !== "object") throw new TypeError("\"options\" argument must be a string or an object");
		else options = Object.create(options);
		if (options.highWaterMark === void 0) options.highWaterMark = 65536;
		options.emitClose = false;
		options.autoDestroy = false;
		ReadableStream$1.call(this, options);
		this.path = path;
		this.flags = options.flags === void 0 ? "r" : options.flags;
		this.mode = options.mode === void 0 ? 438 : options.mode;
		this.start = options.start;
		this.end = options.end;
		this.autoClose = options.autoClose === void 0 ? true : options.autoClose;
		this.pos = 0;
		this.bytesRead = 0;
		this.isClosed = false;
		this.handle = options.handle === void 0 ? null : options.handle;
		this.sftp = sftp;
		this._opening = false;
		if (this.start !== void 0) {
			checkPosition(this.start, "start");
			this.pos = this.start;
		}
		if (this.end === void 0) this.end = Infinity;
		else if (this.end !== Infinity) {
			checkPosition(this.end, "end");
			if (this.start !== void 0 && this.start > this.end) throw new ERR_OUT_OF_RANGE("start", `<= "end" (here: ${this.end})`, this.start);
		}
		this.on("end", function() {
			if (this.autoClose) this.destroy();
		});
		if (!Buffer.isBuffer(this.handle)) this.open();
	}
	inherits(ReadStream, ReadableStream$1);
	ReadStream.prototype.open = function() {
		if (this._opening) return;
		this._opening = true;
		this.sftp.open(this.path, this.flags, this.mode, (er, handle) => {
			this._opening = false;
			if (er) {
				this.emit("error", er);
				if (this.autoClose) this.destroy();
				return;
			}
			this.handle = handle;
			this.emit("open", handle);
			this.emit("ready");
			this.read();
		});
	};
	ReadStream.prototype._read = function(n) {
		if (!Buffer.isBuffer(this.handle)) return this.once("open", () => this._read(n));
		if (this.destroyed) return;
		if (!pool || pool.length - pool.used < kMinPoolSpace) allocNewPool(this.readableHighWaterMark || this._readableState.highWaterMark);
		const thisPool = pool;
		let toRead = Math.min(pool.length - pool.used, n);
		const start = pool.used;
		if (this.end !== void 0) toRead = Math.min(this.end - this.pos + 1, toRead);
		if (toRead <= 0) return this.push(null);
		this.sftp.read(this.handle, pool, pool.used, toRead, this.pos, (er, bytesRead) => {
			if (er) {
				this.emit("error", er);
				if (this.autoClose) this.destroy();
				return;
			}
			let b = null;
			if (start + toRead === thisPool.used && thisPool === pool) thisPool.used = roundUpToMultipleOf8(thisPool.used + bytesRead - toRead);
			else {
				const alignedEnd = start + toRead & -8;
				const alignedStart = roundUpToMultipleOf8(start + bytesRead);
				if (alignedEnd - alignedStart >= kMinPoolSpace) poolFragments.push(thisPool.slice(alignedStart, alignedEnd));
			}
			if (bytesRead > 0) {
				this.bytesRead += bytesRead;
				b = thisPool.slice(start, start + bytesRead);
			}
			this.pos += bytesRead;
			this.push(b);
		});
		pool.used = roundUpToMultipleOf8(pool.used + toRead);
	};
	ReadStream.prototype._destroy = function(err, cb) {
		if (this._opening && !Buffer.isBuffer(this.handle)) {
			this.once("open", closeStream.bind(null, this, cb, err));
			return;
		}
		closeStream(this, cb, err);
		this.handle = null;
		this._opening = false;
	};
	function closeStream(stream, cb, err) {
		if (!stream.handle) return onclose();
		stream.sftp.close(stream.handle, onclose);
		function onclose(er) {
			er = er || err;
			cb(er);
			stream.isClosed = true;
			if (!er) stream.emit("close");
		}
	}
	ReadStream.prototype.close = function(cb) {
		this.destroy(null, cb);
	};
	Object.defineProperty(ReadStream.prototype, "pending", {
		get() {
			return this.handle === null;
		},
		configurable: true
	});
	function WriteStream(sftp, path, options) {
		if (options === void 0) options = {};
		else if (typeof options === "string") options = { encoding: options };
		else if (options === null || typeof options !== "object") throw new TypeError("\"options\" argument must be a string or an object");
		else options = Object.create(options);
		options.emitClose = false;
		options.autoDestroy = false;
		WritableStream$1.call(this, options);
		this.path = path;
		this.flags = options.flags === void 0 ? "w" : options.flags;
		this.mode = options.mode === void 0 ? 438 : options.mode;
		this.start = options.start;
		this.autoClose = options.autoClose === void 0 ? true : options.autoClose;
		this.pos = 0;
		this.bytesWritten = 0;
		this.isClosed = false;
		this.handle = options.handle === void 0 ? null : options.handle;
		this.sftp = sftp;
		this._opening = false;
		if (this.start !== void 0) {
			checkPosition(this.start, "start");
			this.pos = this.start;
		}
		if (options.encoding) this.setDefaultEncoding(options.encoding);
		this.on("finish", function() {
			if (this._writableState.finalCalled) return;
			if (this.autoClose) this.destroy();
		});
		if (!Buffer.isBuffer(this.handle)) this.open();
	}
	inherits(WriteStream, WritableStream$1);
	WriteStream.prototype._final = function(cb) {
		if (this.autoClose) this.destroy();
		cb();
	};
	WriteStream.prototype.open = function() {
		if (this._opening) return;
		this._opening = true;
		this.sftp.open(this.path, this.flags, this.mode, (er, handle) => {
			this._opening = false;
			if (er) {
				this.emit("error", er);
				if (this.autoClose) this.destroy();
				return;
			}
			this.handle = handle;
			const tryAgain = (err) => {
				if (err) {
					this.sftp.chmod(this.path, this.mode, (err_) => tryAgain());
					return;
				}
				if (this.flags[0] === "a") {
					const tryStat = (err, st) => {
						if (err) {
							this.sftp.stat(this.path, (err_, st_) => {
								if (err_) {
									this.destroy();
									this.emit("error", err);
									return;
								}
								tryStat(null, st_);
							});
							return;
						}
						this.pos = st.size;
						this.emit("open", handle);
						this.emit("ready");
					};
					this.sftp.fstat(handle, tryStat);
					return;
				}
				this.emit("open", handle);
				this.emit("ready");
			};
			this.sftp.fchmod(handle, this.mode, tryAgain);
		});
	};
	WriteStream.prototype._write = function(data, encoding, cb) {
		if (!Buffer.isBuffer(data)) {
			const err = new ERR_INVALID_ARG_TYPE("data", "Buffer", data);
			return this.emit("error", err);
		}
		if (!Buffer.isBuffer(this.handle)) return this.once("open", function() {
			this._write(data, encoding, cb);
		});
		this.sftp.write(this.handle, data, 0, data.length, this.pos, (er, bytes) => {
			if (er) {
				if (this.autoClose) this.destroy();
				return cb(er);
			}
			this.bytesWritten += bytes;
			cb();
		});
		this.pos += data.length;
	};
	WriteStream.prototype._writev = function(data, cb) {
		if (!Buffer.isBuffer(this.handle)) return this.once("open", function() {
			this._writev(data, cb);
		});
		const sftp = this.sftp;
		const handle = this.handle;
		let writesLeft = data.length;
		const onwrite = (er, bytes) => {
			if (er) {
				this.destroy();
				return cb(er);
			}
			this.bytesWritten += bytes;
			if (--writesLeft === 0) cb();
		};
		for (let i = 0; i < data.length; ++i) {
			const chunk = data[i].chunk;
			sftp.write(handle, chunk, 0, chunk.length, this.pos, onwrite);
			this.pos += chunk.length;
		}
	};
	if (typeof WritableStream$1.prototype.destroy !== "function") WriteStream.prototype.destroy = ReadStream.prototype.destroy;
	WriteStream.prototype._destroy = ReadStream.prototype._destroy;
	WriteStream.prototype.close = function(cb) {
		if (cb) {
			if (this.isClosed) {
				process.nextTick(cb);
				return;
			}
			this.on("close", cb);
		}
		if (!this.autoClose) this.on("finish", this.destroy.bind(this));
		this.end();
	};
	WriteStream.prototype.destroySoon = WriteStream.prototype.end;
	Object.defineProperty(WriteStream.prototype, "pending", {
		get() {
			return this.handle === null;
		},
		configurable: true
	});
	module.exports = {
		flagsToString,
		OPEN_MODE,
		SFTP,
		Stats,
		STATUS_CODE,
		stringToFlags
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/Channel.js
var require_Channel = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { Duplex: DuplexStream, Readable: ReadableStream, Writable: WritableStream } = __require("stream");
	const { CHANNEL_EXTENDED_DATATYPE: { STDERR } } = require_constants();
	const { bufferSlice } = require_utils$1();
	const PACKET_SIZE = 32768;
	const MAX_WINDOW = 2097152;
	const WINDOW_THRESHOLD = MAX_WINDOW / 2;
	var ClientStderr = class extends ReadableStream {
		constructor(channel, streamOpts) {
			super(streamOpts);
			this._channel = channel;
		}
		_read(n) {
			if (this._channel._waitChanDrain) {
				this._channel._waitChanDrain = false;
				if (this._channel.incoming.window <= WINDOW_THRESHOLD) windowAdjust(this._channel);
			}
		}
	};
	var ServerStderr = class extends WritableStream {
		constructor(channel) {
			super({ highWaterMark: MAX_WINDOW });
			this._channel = channel;
		}
		_write(data, encoding, cb) {
			const channel = this._channel;
			const protocol = channel._client._protocol;
			const outgoing = channel.outgoing;
			const packetSize = outgoing.packetSize;
			const id = outgoing.id;
			let window = outgoing.window;
			const len = data.length;
			let p = 0;
			if (outgoing.state !== "open") return;
			while (len - p > 0 && window > 0) {
				let sliceLen = len - p;
				if (sliceLen > window) sliceLen = window;
				if (sliceLen > packetSize) sliceLen = packetSize;
				if (p === 0 && sliceLen === len) protocol.channelExtData(id, data, STDERR);
				else protocol.channelExtData(id, bufferSlice(data, p, p + sliceLen), STDERR);
				p += sliceLen;
				window -= sliceLen;
			}
			outgoing.window = window;
			if (len - p > 0) {
				if (window === 0) channel._waitWindow = true;
				if (p > 0) channel._chunkErr = bufferSlice(data, p, len);
				else channel._chunkErr = data;
				channel._chunkcbErr = cb;
				return;
			}
			cb();
		}
	};
	var Channel = class extends DuplexStream {
		constructor(client, info, opts) {
			const streamOpts = {
				highWaterMark: MAX_WINDOW,
				allowHalfOpen: !opts || opts && opts.allowHalfOpen !== false,
				emitClose: false
			};
			super(streamOpts);
			this.allowHalfOpen = streamOpts.allowHalfOpen;
			const server = !!(opts && opts.server);
			this.server = server;
			this.type = info.type;
			this.subtype = void 0;
			this.incoming = info.incoming;
			this.outgoing = info.outgoing;
			this._callbacks = [];
			this._client = client;
			this._hasX11 = false;
			this._exit = {
				code: void 0,
				signal: void 0,
				dump: void 0,
				desc: void 0
			};
			this.stdin = this.stdout = this;
			if (server) this.stderr = new ServerStderr(this);
			else this.stderr = new ClientStderr(this, streamOpts);
			this._waitWindow = false;
			this._waitChanDrain = false;
			this._chunk = void 0;
			this._chunkcb = void 0;
			this._chunkErr = void 0;
			this._chunkcbErr = void 0;
			this.on("finish", onFinish).on("prefinish", onFinish);
			this.on("end", onEnd).on("close", onEnd);
		}
		_read(n) {
			if (this._waitChanDrain) {
				this._waitChanDrain = false;
				if (this.incoming.window <= WINDOW_THRESHOLD) windowAdjust(this);
			}
		}
		_write(data, encoding, cb) {
			const protocol = this._client._protocol;
			const outgoing = this.outgoing;
			const packetSize = outgoing.packetSize;
			const id = outgoing.id;
			let window = outgoing.window;
			const len = data.length;
			let p = 0;
			if (outgoing.state !== "open") return;
			while (len - p > 0 && window > 0) {
				let sliceLen = len - p;
				if (sliceLen > window) sliceLen = window;
				if (sliceLen > packetSize) sliceLen = packetSize;
				if (p === 0 && sliceLen === len) protocol.channelData(id, data);
				else protocol.channelData(id, bufferSlice(data, p, p + sliceLen));
				p += sliceLen;
				window -= sliceLen;
			}
			outgoing.window = window;
			if (len - p > 0) {
				if (window === 0) this._waitWindow = true;
				if (p > 0) this._chunk = bufferSlice(data, p, len);
				else this._chunk = data;
				this._chunkcb = cb;
				return;
			}
			cb();
		}
		eof() {
			if (this.outgoing.state === "open") {
				this.outgoing.state = "eof";
				this._client._protocol.channelEOF(this.outgoing.id);
			}
		}
		close() {
			if (this.outgoing.state === "open" || this.outgoing.state === "eof") {
				this.outgoing.state = "closing";
				this._client._protocol.channelClose(this.outgoing.id);
			}
		}
		destroy() {
			this.end();
			this.close();
			return this;
		}
		setWindow(rows, cols, height, width) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (this.type === "session" && (this.subtype === "shell" || this.subtype === "exec") && this.writable && this.outgoing.state === "open") this._client._protocol.windowChange(this.outgoing.id, rows, cols, height, width);
		}
		signal(signalName) {
			if (this.server) throw new Error("Client-only method called in server mode");
			if (this.type === "session" && this.writable && this.outgoing.state === "open") this._client._protocol.signal(this.outgoing.id, signalName);
		}
		exit(statusOrSignal, coreDumped, msg) {
			if (!this.server) throw new Error("Server-only method called in client mode");
			if (this.type === "session" && this.writable && this.outgoing.state === "open") {
				if (typeof statusOrSignal === "number") this._client._protocol.exitStatus(this.outgoing.id, statusOrSignal);
				else this._client._protocol.exitSignal(this.outgoing.id, statusOrSignal, coreDumped, msg);
			}
		}
	};
	function onFinish() {
		this.eof();
		if (this.server || !this.allowHalfOpen) this.close();
		this.writable = false;
	}
	function onEnd() {
		this.readable = false;
	}
	function windowAdjust(self) {
		if (self.outgoing.state === "closed") return;
		const amt = MAX_WINDOW - self.incoming.window;
		if (amt <= 0) return;
		self.incoming.window += amt;
		self._client._protocol.channelWindowAdjust(self.outgoing.id, amt);
	}
	module.exports = {
		Channel,
		MAX_WINDOW,
		PACKET_SIZE,
		windowAdjust,
		WINDOW_THRESHOLD
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/utils.js
var require_utils = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { SFTP } = require_SFTP();
	const MAX_CHANNEL = 2 ** 32 - 1;
	function onChannelOpenFailure(self, recipient, info, cb) {
		self._chanMgr.remove(recipient);
		if (typeof cb !== "function") return;
		let err;
		if (info instanceof Error) err = info;
		else if (typeof info === "object" && info !== null) {
			err = /* @__PURE__ */ new Error(`(SSH) Channel open failure: ${info.description}`);
			err.reason = info.reason;
		} else {
			err = /* @__PURE__ */ new Error("(SSH) Channel open failure: server closed channel unexpectedly");
			err.reason = "";
		}
		cb(err);
	}
	function onCHANNEL_CLOSE(self, recipient, channel, err, dead) {
		if (typeof channel === "function") {
			onChannelOpenFailure(self, recipient, err, channel);
			return;
		}
		if (typeof channel !== "object" || channel === null) return;
		if (channel.incoming && channel.incoming.state === "closed") return;
		self._chanMgr.remove(recipient);
		if (channel.server && channel.constructor.name === "Session") return;
		channel.incoming.state = "closed";
		if (channel.readable) channel.push(null);
		if (channel.server) {
			if (channel.stderr.writable) channel.stderr.end();
		} else if (channel.stderr.readable) channel.stderr.push(null);
		if (channel.constructor !== SFTP && (channel.outgoing.state === "open" || channel.outgoing.state === "eof") && !dead) channel.close();
		if (channel.outgoing.state === "closing") channel.outgoing.state = "closed";
		const readState = channel._readableState;
		const writeState = channel._writableState;
		if (writeState && !writeState.ending && !writeState.finished && !dead) channel.end();
		const chanCallbacks = channel._callbacks;
		channel._callbacks = [];
		for (let i = 0; i < chanCallbacks.length; ++i) chanCallbacks[i](true);
		if (channel.server) {
			if (!channel.readable || channel.destroyed || readState && readState.endEmitted) channel.emit("close");
			else channel.once("end", () => channel.emit("close"));
		} else {
			let doClose;
			switch (channel.type) {
				case "direct-streamlocal@openssh.com":
				case "direct-tcpip":
					doClose = () => channel.emit("close");
					break;
				default: {
					const exit = channel._exit;
					doClose = () => {
						if (exit.code === null) channel.emit("close", exit.code, exit.signal, exit.dump, exit.desc);
						else channel.emit("close", exit.code);
					};
				}
			}
			if (!channel.readable || channel.destroyed || readState && readState.endEmitted) doClose();
			else channel.once("end", doClose);
			const errReadState = channel.stderr._readableState;
			if (!channel.stderr.readable || channel.stderr.destroyed || errReadState && errReadState.endEmitted) channel.stderr.emit("close");
			else channel.stderr.once("end", () => channel.stderr.emit("close"));
		}
	}
	var ChannelManager = class {
		constructor(client) {
			this._client = client;
			this._channels = {};
			this._cur = -1;
			this._count = 0;
		}
		add(val) {
			let id;
			if (this._cur < MAX_CHANNEL) id = ++this._cur;
			else if (this._count === 0) {
				this._cur = 0;
				id = 0;
			} else {
				const channels = this._channels;
				for (let i = 0; i < MAX_CHANNEL; ++i) if (channels[i] === void 0) {
					id = i;
					break;
				}
			}
			if (id === void 0) return -1;
			this._channels[id] = val || true;
			++this._count;
			return id;
		}
		update(id, val) {
			if (typeof id !== "number" || id < 0 || id >= MAX_CHANNEL || !isFinite(id)) throw new Error(`Invalid channel id: ${id}`);
			if (val && this._channels[id]) this._channels[id] = val;
		}
		get(id) {
			if (typeof id !== "number" || id < 0 || id >= MAX_CHANNEL || !isFinite(id)) throw new Error(`Invalid channel id: ${id}`);
			return this._channels[id];
		}
		remove(id) {
			if (typeof id !== "number" || id < 0 || id >= MAX_CHANNEL || !isFinite(id)) throw new Error(`Invalid channel id: ${id}`);
			if (this._channels[id]) {
				delete this._channels[id];
				if (this._count) --this._count;
			}
		}
		cleanup(err) {
			const channels = this._channels;
			this._channels = {};
			this._cur = -1;
			this._count = 0;
			const chanIDs = Object.keys(channels);
			const client = this._client;
			for (let i = 0; i < chanIDs.length; ++i) {
				const id = +chanIDs[i];
				const channel = channels[id];
				onCHANNEL_CLOSE(client, id, channel._channel || channel, err, true);
			}
		}
	};
	const isRegExp = (() => {
		const toString = Object.prototype.toString;
		return (val) => toString.call(val) === "[object RegExp]";
	})();
	function generateAlgorithmList(algoList, defaultList, supportedList) {
		if (Array.isArray(algoList) && algoList.length > 0) {
			for (let i = 0; i < algoList.length; ++i) if (supportedList.indexOf(algoList[i]) === -1) throw new Error(`Unsupported algorithm: ${algoList[i]}`);
			return algoList;
		}
		if (typeof algoList === "object" && algoList !== null) {
			const keys = Object.keys(algoList);
			let list = defaultList;
			for (let i = 0; i < keys.length; ++i) {
				const key = keys[i];
				let val = algoList[key];
				switch (key) {
					case "append":
						if (!Array.isArray(val)) val = [val];
						if (Array.isArray(val)) for (let j = 0; j < val.length; ++j) {
							const append = val[j];
							if (typeof append === "string") {
								if (!append || list.indexOf(append) !== -1) continue;
								if (supportedList.indexOf(append) === -1) throw new Error(`Unsupported algorithm: ${append}`);
								if (list === defaultList) list = list.slice();
								list.push(append);
							} else if (isRegExp(append)) for (let k = 0; k < supportedList.length; ++k) {
								const algo = supportedList[k];
								if (append.test(algo)) {
									if (list.indexOf(algo) !== -1) continue;
									if (list === defaultList) list = list.slice();
									list.push(algo);
								}
							}
						}
						break;
					case "prepend":
						if (!Array.isArray(val)) val = [val];
						if (Array.isArray(val)) for (let j = val.length; j >= 0; --j) {
							const prepend = val[j];
							if (typeof prepend === "string") {
								if (!prepend || list.indexOf(prepend) !== -1) continue;
								if (supportedList.indexOf(prepend) === -1) throw new Error(`Unsupported algorithm: ${prepend}`);
								if (list === defaultList) list = list.slice();
								list.unshift(prepend);
							} else if (isRegExp(prepend)) for (let k = supportedList.length; k >= 0; --k) {
								const algo = supportedList[k];
								if (prepend.test(algo)) {
									if (list.indexOf(algo) !== -1) continue;
									if (list === defaultList) list = list.slice();
									list.unshift(algo);
								}
							}
						}
						break;
					case "remove":
						if (!Array.isArray(val)) val = [val];
						if (Array.isArray(val)) for (let j = 0; j < val.length; ++j) {
							const search = val[j];
							if (typeof search === "string") {
								if (!search) continue;
								const idx = list.indexOf(search);
								if (idx === -1) continue;
								if (list === defaultList) list = list.slice();
								list.splice(idx, 1);
							} else if (isRegExp(search)) {
								for (let k = 0; k < list.length; ++k) if (search.test(list[k])) {
									if (list === defaultList) list = list.slice();
									list.splice(k, 1);
									--k;
								}
							}
						}
				}
			}
			return list;
		}
		return defaultList;
	}
	module.exports = {
		ChannelManager,
		generateAlgorithmList,
		onChannelOpenFailure,
		onCHANNEL_CLOSE,
		isWritable: (stream) => {
			return stream && stream.writable && stream._readableState && stream._readableState.ended === false;
		}
	};
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/client.js
var require_client = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { createHash: createHash$1, getHashes, randomFillSync } = __require("crypto");
	const { Socket } = __require("net");
	const { lookup: dnsLookup } = __require("dns");
	const EventEmitter$1 = __require("events");
	const HASHES = getHashes();
	const { COMPAT, CHANNEL_EXTENDED_DATATYPE: { STDERR }, CHANNEL_OPEN_FAILURE, DEFAULT_CIPHER, DEFAULT_COMPRESSION, DEFAULT_KEX, DEFAULT_MAC, DEFAULT_SERVER_HOST_KEY, DISCONNECT_REASON, DISCONNECT_REASON_BY_VALUE, SUPPORTED_CIPHER, SUPPORTED_COMPRESSION, SUPPORTED_KEX, SUPPORTED_MAC, SUPPORTED_SERVER_HOST_KEY } = require_constants();
	const { init: cryptoInit } = require_crypto();
	const Protocol = require_Protocol();
	const { parseKey } = require_keyParser();
	const { SFTP } = require_SFTP();
	const { bufferCopy, makeBufferParser, makeError, readUInt32BE, sigSSHToASN1, writeUInt32BE } = require_utils$1();
	const { AgentContext, createAgent, isAgent } = require_agent();
	const { Channel, MAX_WINDOW, PACKET_SIZE, windowAdjust, WINDOW_THRESHOLD } = require_Channel();
	const { ChannelManager, generateAlgorithmList, isWritable, onChannelOpenFailure, onCHANNEL_CLOSE } = require_utils();
	const bufferParser = makeBufferParser();
	const sigParser = makeBufferParser();
	const RE_OPENSSH = /^OpenSSH_(?:(?![0-4])\d)|(?:\d{2,})/;
	const noop = (err) => {};
	var Client = class extends EventEmitter$1 {
		constructor() {
			super();
			this.config = {
				host: void 0,
				port: void 0,
				localAddress: void 0,
				localPort: void 0,
				forceIPv4: void 0,
				forceIPv6: void 0,
				keepaliveCountMax: void 0,
				keepaliveInterval: void 0,
				readyTimeout: void 0,
				ident: void 0,
				username: void 0,
				password: void 0,
				privateKey: void 0,
				tryKeyboard: void 0,
				agent: void 0,
				allowAgentFwd: void 0,
				authHandler: void 0,
				hostHashAlgo: void 0,
				hostHashCb: void 0,
				strictVendor: void 0,
				debug: void 0
			};
			this._agent = void 0;
			this._readyTimeout = void 0;
			this._chanMgr = void 0;
			this._callbacks = void 0;
			this._forwarding = void 0;
			this._forwardingUnix = void 0;
			this._acceptX11 = void 0;
			this._agentFwdEnabled = void 0;
			this._remoteVer = void 0;
			this._protocol = void 0;
			this._sock = void 0;
			this._resetKA = void 0;
		}
		connect(cfg) {
			if (this._sock && isWritable(this._sock)) {
				this.once("close", () => {
					this.connect(cfg);
				});
				this.end();
				return this;
			}
			this.config.host = cfg.hostname || cfg.host || "localhost";
			this.config.port = cfg.port || 22;
			this.config.localAddress = typeof cfg.localAddress === "string" ? cfg.localAddress : void 0;
			this.config.localPort = typeof cfg.localPort === "string" || typeof cfg.localPort === "number" ? cfg.localPort : void 0;
			this.config.forceIPv4 = cfg.forceIPv4 || false;
			this.config.forceIPv6 = cfg.forceIPv6 || false;
			this.config.keepaliveCountMax = typeof cfg.keepaliveCountMax === "number" && cfg.keepaliveCountMax >= 0 ? cfg.keepaliveCountMax : 3;
			this.config.keepaliveInterval = typeof cfg.keepaliveInterval === "number" && cfg.keepaliveInterval > 0 ? cfg.keepaliveInterval : 0;
			this.config.readyTimeout = typeof cfg.readyTimeout === "number" && cfg.readyTimeout >= 0 ? cfg.readyTimeout : 2e4;
			this.config.ident = typeof cfg.ident === "string" || Buffer.isBuffer(cfg.ident) ? cfg.ident : void 0;
			const algorithms = {
				kex: void 0,
				serverHostKey: void 0,
				cs: {
					cipher: void 0,
					mac: void 0,
					compress: void 0,
					lang: []
				},
				sc: void 0
			};
			let allOfferDefaults = true;
			if (typeof cfg.algorithms === "object" && cfg.algorithms !== null) {
				algorithms.kex = generateAlgorithmList(cfg.algorithms.kex, DEFAULT_KEX, SUPPORTED_KEX);
				if (algorithms.kex !== DEFAULT_KEX) allOfferDefaults = false;
				algorithms.serverHostKey = generateAlgorithmList(cfg.algorithms.serverHostKey, DEFAULT_SERVER_HOST_KEY, SUPPORTED_SERVER_HOST_KEY);
				if (algorithms.serverHostKey !== DEFAULT_SERVER_HOST_KEY) allOfferDefaults = false;
				algorithms.cs.cipher = generateAlgorithmList(cfg.algorithms.cipher, DEFAULT_CIPHER, SUPPORTED_CIPHER);
				if (algorithms.cs.cipher !== DEFAULT_CIPHER) allOfferDefaults = false;
				algorithms.cs.mac = generateAlgorithmList(cfg.algorithms.hmac, DEFAULT_MAC, SUPPORTED_MAC);
				if (algorithms.cs.mac !== DEFAULT_MAC) allOfferDefaults = false;
				algorithms.cs.compress = generateAlgorithmList(cfg.algorithms.compress, DEFAULT_COMPRESSION, SUPPORTED_COMPRESSION);
				if (algorithms.cs.compress !== DEFAULT_COMPRESSION) allOfferDefaults = false;
				if (!allOfferDefaults) algorithms.sc = algorithms.cs;
			}
			if (typeof cfg.username === "string") this.config.username = cfg.username;
			else if (typeof cfg.user === "string") this.config.username = cfg.user;
			else throw new Error("Invalid username");
			this.config.password = typeof cfg.password === "string" ? cfg.password : void 0;
			this.config.privateKey = typeof cfg.privateKey === "string" || Buffer.isBuffer(cfg.privateKey) ? cfg.privateKey : void 0;
			this.config.localHostname = typeof cfg.localHostname === "string" ? cfg.localHostname : void 0;
			this.config.localUsername = typeof cfg.localUsername === "string" ? cfg.localUsername : void 0;
			this.config.tryKeyboard = cfg.tryKeyboard === true;
			if (typeof cfg.agent === "string" && cfg.agent.length) this.config.agent = createAgent(cfg.agent);
			else if (isAgent(cfg.agent)) this.config.agent = cfg.agent;
			else this.config.agent = void 0;
			this.config.allowAgentFwd = cfg.agentForward === true && this.config.agent !== void 0;
			let authHandler = this.config.authHandler = typeof cfg.authHandler === "function" || Array.isArray(cfg.authHandler) ? cfg.authHandler : void 0;
			this.config.strictVendor = typeof cfg.strictVendor === "boolean" ? cfg.strictVendor : true;
			const debug = this.config.debug = typeof cfg.debug === "function" ? cfg.debug : void 0;
			if (cfg.agentForward === true && !this.config.allowAgentFwd) throw new Error("You must set a valid agent path to allow agent forwarding");
			let callbacks = this._callbacks = [];
			this._chanMgr = new ChannelManager(this);
			this._forwarding = {};
			this._forwardingUnix = {};
			this._acceptX11 = 0;
			this._agentFwdEnabled = false;
			this._agent = this.config.agent ? this.config.agent : void 0;
			this._remoteVer = void 0;
			let privateKey;
			if (this.config.privateKey) {
				privateKey = parseKey(this.config.privateKey, cfg.passphrase);
				if (privateKey instanceof Error) throw new Error(`Cannot parse privateKey: ${privateKey.message}`);
				if (Array.isArray(privateKey)) privateKey = privateKey[0];
				if (privateKey.getPrivatePEM() === null) throw new Error("privateKey value does not contain a (valid) private key");
			}
			let hostVerifier;
			if (typeof cfg.hostVerifier === "function") {
				const hashCb = cfg.hostVerifier;
				let hashAlgo;
				if (HASHES.indexOf(cfg.hostHash) !== -1) hashAlgo = cfg.hostHash;
				hostVerifier = (key, verify) => {
					if (hashAlgo) key = createHash$1(hashAlgo).update(key).digest("hex");
					const ret = hashCb(key, verify);
					if (ret !== void 0) verify(ret);
				};
			}
			const sock = this._sock = cfg.sock || new Socket();
			let ready = false;
			let sawHeader = false;
			if (this._protocol) this._protocol.cleanup();
			const DEBUG_HANDLER = !debug ? void 0 : (p, display, msg) => {
				debug(`Debug output from server: ${JSON.stringify(msg)}`);
			};
			let serverSigAlgs;
			const proto = this._protocol = new Protocol({
				ident: this.config.ident,
				offer: allOfferDefaults ? void 0 : algorithms,
				onWrite: (data) => {
					if (isWritable(sock)) sock.write(data);
				},
				onError: (err) => {
					if (err.level === "handshake") clearTimeout(this._readyTimeout);
					if (!proto._destruct) sock.removeAllListeners("data");
					this.emit("error", err);
					try {
						sock.end();
					} catch {}
				},
				onHeader: (header) => {
					sawHeader = true;
					this._remoteVer = header.versions.software;
					if (header.greeting) this.emit("greeting", header.greeting);
				},
				onHandshakeComplete: (negotiated) => {
					this.emit("handshake", negotiated);
					if (!ready) {
						ready = true;
						proto.service("ssh-userauth");
					}
				},
				debug,
				hostVerifier,
				messageHandlers: {
					DEBUG: DEBUG_HANDLER,
					DISCONNECT: (p, reason, desc) => {
						if (reason !== DISCONNECT_REASON.BY_APPLICATION) {
							if (!desc) {
								desc = DISCONNECT_REASON_BY_VALUE[reason];
								if (desc === void 0) desc = `Unexpected disconnection reason: ${reason}`;
							}
							const err = new Error(desc);
							err.code = reason;
							this.emit("error", err);
						}
						sock.end();
					},
					SERVICE_ACCEPT: (p, name) => {
						if (name === "ssh-userauth") tryNextAuth();
					},
					EXT_INFO: (p, exts) => {
						if (serverSigAlgs === void 0) {
							for (const ext of exts) if (ext.name === "server-sig-algs") {
								serverSigAlgs = ext.algs;
								return;
							}
							serverSigAlgs = null;
						}
					},
					USERAUTH_BANNER: (p, msg) => {
						this.emit("banner", msg);
					},
					USERAUTH_SUCCESS: (p) => {
						resetKA();
						clearTimeout(this._readyTimeout);
						this.emit("ready");
					},
					USERAUTH_FAILURE: (p, authMethods, partialSuccess) => {
						if (curAuth.keyAlgos) {
							const oldKeyAlgo = curAuth.keyAlgos[0][0];
							if (debug) debug(`Client: ${curAuth.type} (${oldKeyAlgo}) auth failed`);
							curAuth.keyAlgos.shift();
							if (curAuth.keyAlgos.length) {
								const [keyAlgo, hashAlgo] = curAuth.keyAlgos[0];
								switch (curAuth.type) {
									case "agent":
										proto.authPK(curAuth.username, curAuth.agentCtx.currentKey(), keyAlgo);
										return;
									case "publickey":
										proto.authPK(curAuth.username, curAuth.key, keyAlgo);
										return;
									case "hostbased":
										proto.authHostbased(curAuth.username, curAuth.key, curAuth.localHostname, curAuth.localUsername, keyAlgo, (buf, cb) => {
											const signature = curAuth.key.sign(buf, hashAlgo);
											if (signature instanceof Error) {
												signature.message = `Error while signing with key: ${signature.message}`;
												signature.level = "client-authentication";
												this.emit("error", signature);
												return tryNextAuth();
											}
											cb(signature);
										});
										return;
								}
							} else curAuth.keyAlgos = void 0;
						}
						if (curAuth.type === "agent") {
							const pos = curAuth.agentCtx.pos();
							debug && debug(`Client: Agent key #${pos + 1} failed`);
							return tryNextAgentKey();
						}
						debug && debug(`Client: ${curAuth.type} auth failed`);
						curPartial = partialSuccess;
						curAuthsLeft = authMethods;
						tryNextAuth();
					},
					USERAUTH_PASSWD_CHANGEREQ: (p, prompt) => {
						if (curAuth.type === "password") this.emit("change password", prompt, (newPassword) => {
							proto.authPassword(this.config.username, this.config.password, newPassword);
						});
					},
					USERAUTH_PK_OK: (p) => {
						let keyAlgo;
						let hashAlgo;
						if (curAuth.keyAlgos) [keyAlgo, hashAlgo] = curAuth.keyAlgos[0];
						if (curAuth.type === "agent") {
							const key = curAuth.agentCtx.currentKey();
							proto.authPK(curAuth.username, key, keyAlgo, (buf, cb) => {
								const opts = { hash: hashAlgo };
								curAuth.agentCtx.sign(key, buf, opts, (err, signed) => {
									if (err) {
										err.level = "agent";
										this.emit("error", err);
									} else return cb(signed);
									tryNextAgentKey();
								});
							});
						} else if (curAuth.type === "publickey") proto.authPK(curAuth.username, curAuth.key, keyAlgo, (buf, cb) => {
							const signature = curAuth.key.sign(buf, hashAlgo);
							if (signature instanceof Error) {
								signature.message = `Error signing data with key: ${signature.message}`;
								signature.level = "client-authentication";
								this.emit("error", signature);
								return tryNextAuth();
							}
							cb(signature);
						});
					},
					USERAUTH_INFO_REQUEST: (p, name, instructions, prompts) => {
						if (curAuth.type === "keyboard-interactive") {
							if ((Array.isArray(prompts) ? prompts.length : 0) === 0) {
								debug && debug("Client: Sending automatic USERAUTH_INFO_RESPONSE");
								proto.authInfoRes();
								return;
							}
							curAuth.prompt(name, instructions, "", prompts, (answers) => {
								proto.authInfoRes(answers);
							});
						}
					},
					REQUEST_SUCCESS: (p, data) => {
						if (callbacks.length) callbacks.shift()(false, data);
					},
					REQUEST_FAILURE: (p) => {
						if (callbacks.length) callbacks.shift()(true);
					},
					GLOBAL_REQUEST: (p, name, wantReply, data) => {
						switch (name) {
							case "hostkeys-00@openssh.com":
								hostKeysProve(this, data, (err, keys) => {
									if (err) return;
									this.emit("hostkeys", keys);
								});
								if (wantReply) proto.requestSuccess();
								break;
							default: if (wantReply) proto.requestFailure();
						}
					},
					CHANNEL_OPEN: (p, info) => {
						onCHANNEL_OPEN(this, info);
					},
					CHANNEL_OPEN_CONFIRMATION: (p, info) => {
						const channel = this._chanMgr.get(info.recipient);
						if (typeof channel !== "function") return;
						const isSFTP = channel.type === "sftp";
						const chanInfo = {
							type: isSFTP ? "session" : channel.type,
							incoming: {
								id: info.recipient,
								window: MAX_WINDOW,
								packetSize: PACKET_SIZE,
								state: "open"
							},
							outgoing: {
								id: info.sender,
								window: info.window,
								packetSize: info.packetSize,
								state: "open"
							}
						};
						const instance = isSFTP ? new SFTP(this, chanInfo, { debug }) : new Channel(this, chanInfo);
						this._chanMgr.update(info.recipient, instance);
						channel(void 0, instance);
					},
					CHANNEL_OPEN_FAILURE: (p, recipient, reason, description) => {
						const channel = this._chanMgr.get(recipient);
						if (typeof channel !== "function") return;
						const info = {
							reason,
							description
						};
						onChannelOpenFailure(this, recipient, info, channel);
					},
					CHANNEL_DATA: (p, recipient, data) => {
						const channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						if (channel.incoming.window === 0) return;
						channel.incoming.window -= data.length;
						if (channel.push(data) === false) {
							channel._waitChanDrain = true;
							return;
						}
						if (channel.incoming.window <= WINDOW_THRESHOLD) windowAdjust(channel);
					},
					CHANNEL_EXTENDED_DATA: (p, recipient, data, type) => {
						if (type !== STDERR) return;
						const channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						if (channel.incoming.window === 0) return;
						channel.incoming.window -= data.length;
						if (!channel.stderr.push(data)) {
							channel._waitChanDrain = true;
							return;
						}
						if (channel.incoming.window <= WINDOW_THRESHOLD) windowAdjust(channel);
					},
					CHANNEL_WINDOW_ADJUST: (p, recipient, amount) => {
						const channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						channel.outgoing.window += amount;
						if (channel._waitWindow) {
							channel._waitWindow = false;
							if (channel._chunk) channel._write(channel._chunk, null, channel._chunkcb);
							else if (channel._chunkcb) channel._chunkcb();
							else if (channel._chunkErr) channel.stderr._write(channel._chunkErr, null, channel._chunkcbErr);
							else if (channel._chunkcbErr) channel._chunkcbErr();
						}
					},
					CHANNEL_SUCCESS: (p, recipient) => {
						const channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						this._resetKA();
						if (channel._callbacks.length) channel._callbacks.shift()(false);
					},
					CHANNEL_FAILURE: (p, recipient) => {
						const channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						this._resetKA();
						if (channel._callbacks.length) channel._callbacks.shift()(true);
					},
					CHANNEL_REQUEST: (p, recipient, type, wantReply, data) => {
						const channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						const exit = channel._exit;
						if (exit.code !== void 0) return;
						switch (type) {
							case "exit-status":
								channel.emit("exit", exit.code = data);
								return;
							case "exit-signal":
								channel.emit("exit", exit.code = null, exit.signal = `SIG${data.signal}`, exit.dump = data.coreDumped, exit.desc = data.errorMessage);
								return;
						}
						if (wantReply) p.channelFailure(channel.outgoing.id);
					},
					CHANNEL_EOF: (p, recipient) => {
						const channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						if (channel.incoming.state !== "open") return;
						channel.incoming.state = "eof";
						if (channel.readable) channel.push(null);
						if (channel.stderr.readable) channel.stderr.push(null);
					},
					CHANNEL_CLOSE: (p, recipient) => {
						onCHANNEL_CLOSE(this, recipient, this._chanMgr.get(recipient));
					}
				}
			});
			sock.pause();
			const kainterval = this.config.keepaliveInterval;
			const kacountmax = this.config.keepaliveCountMax;
			let kacount = 0;
			let katimer;
			const sendKA = () => {
				if (++kacount > kacountmax) {
					clearInterval(katimer);
					if (sock.readable) {
						const err = /* @__PURE__ */ new Error("Keepalive timeout");
						err.level = "client-timeout";
						this.emit("error", err);
						sock.destroy();
					}
					return;
				}
				if (isWritable(sock)) {
					callbacks.push(resetKA);
					proto.ping();
				} else clearInterval(katimer);
			};
			function resetKA() {
				if (kainterval > 0) {
					kacount = 0;
					clearInterval(katimer);
					if (isWritable(sock)) katimer = setInterval(sendKA, kainterval);
				}
			}
			this._resetKA = resetKA;
			const onDone = (() => {
				let called = false;
				return () => {
					if (called) return;
					called = true;
					if (wasConnected && !sawHeader) {
						const err = makeError("Connection lost before handshake", "protocol", true);
						this.emit("error", err);
					}
				};
			})();
			const onConnect = (() => {
				let called = false;
				return () => {
					if (called) return;
					called = true;
					wasConnected = true;
					debug && debug("Socket connected");
					this.emit("connect");
					cryptoInit.then(() => {
						proto.start();
						sock.on("data", (data) => {
							try {
								proto.parse(data, 0, data.length);
							} catch (ex) {
								this.emit("error", ex);
								try {
									if (isWritable(sock)) sock.end();
								} catch {}
							}
						});
						if (sock.stderr && typeof sock.stderr.resume === "function") sock.stderr.resume();
						sock.resume();
					}).catch((err) => {
						this.emit("error", err);
						try {
							if (isWritable(sock)) sock.end();
						} catch {}
					});
				};
			})();
			let wasConnected = false;
			sock.on("connect", onConnect).on("timeout", () => {
				this.emit("timeout");
			}).on("error", (err) => {
				debug && debug(`Socket error: ${err.message}`);
				clearTimeout(this._readyTimeout);
				err.level = "client-socket";
				this.emit("error", err);
			}).on("end", () => {
				debug && debug("Socket ended");
				onDone();
				proto.cleanup();
				clearTimeout(this._readyTimeout);
				clearInterval(katimer);
				this.emit("end");
			}).on("close", () => {
				debug && debug("Socket closed");
				onDone();
				proto.cleanup();
				clearTimeout(this._readyTimeout);
				clearInterval(katimer);
				this.emit("close");
				const callbacks_ = callbacks;
				callbacks = this._callbacks = [];
				const err = /* @__PURE__ */ new Error("No response from server");
				for (let i = 0; i < callbacks_.length; ++i) callbacks_[i](err);
				this._chanMgr.cleanup(err);
			});
			let curAuth;
			let curPartial = null;
			let curAuthsLeft = null;
			const authsAllowed = ["none"];
			if (this.config.password !== void 0) authsAllowed.push("password");
			if (privateKey !== void 0) authsAllowed.push("publickey");
			if (this._agent !== void 0) authsAllowed.push("agent");
			if (this.config.tryKeyboard) authsAllowed.push("keyboard-interactive");
			if (privateKey !== void 0 && this.config.localHostname !== void 0 && this.config.localUsername !== void 0) authsAllowed.push("hostbased");
			if (Array.isArray(authHandler)) authHandler = makeSimpleAuthHandler(authHandler);
			else if (typeof authHandler !== "function") authHandler = makeSimpleAuthHandler(authsAllowed);
			let hasSentAuth = false;
			const doNextAuth = (nextAuth) => {
				if (hasSentAuth) return;
				hasSentAuth = true;
				if (nextAuth === false) {
					const err = /* @__PURE__ */ new Error("All configured authentication methods failed");
					err.level = "client-authentication";
					this.emit("error", err);
					this.end();
					return;
				}
				if (typeof nextAuth === "string") {
					const type = nextAuth;
					if (authsAllowed.indexOf(type) === -1) return skipAuth(`Authentication method not allowed: ${type}`);
					const username = this.config.username;
					switch (type) {
						case "password":
							nextAuth = {
								type,
								username,
								password: this.config.password
							};
							break;
						case "publickey":
							nextAuth = {
								type,
								username,
								key: privateKey
							};
							break;
						case "hostbased":
							nextAuth = {
								type,
								username,
								key: privateKey,
								localHostname: this.config.localHostname,
								localUsername: this.config.localUsername
							};
							break;
						case "agent":
							nextAuth = {
								type,
								username,
								agentCtx: new AgentContext(this._agent)
							};
							break;
						case "keyboard-interactive":
							nextAuth = {
								type,
								username,
								prompt: (...args) => this.emit("keyboard-interactive", ...args)
							};
							break;
						case "none":
							nextAuth = {
								type,
								username
							};
							break;
						default: return skipAuth(`Skipping unsupported authentication method: ${nextAuth}`);
					}
				} else if (typeof nextAuth !== "object" || nextAuth === null) return skipAuth(`Skipping invalid authentication attempt: ${nextAuth}`);
				else {
					const username = nextAuth.username;
					if (typeof username !== "string") return skipAuth(`Skipping invalid authentication attempt: ${nextAuth}`);
					const type = nextAuth.type;
					switch (type) {
						case "password": {
							const { password } = nextAuth;
							if (typeof password !== "string" && !Buffer.isBuffer(password)) return skipAuth("Skipping invalid password auth attempt");
							nextAuth = {
								type,
								username,
								password
							};
							break;
						}
						case "publickey": {
							const key = parseKey(nextAuth.key, nextAuth.passphrase);
							if (key instanceof Error) return skipAuth("Skipping invalid key auth attempt");
							if (!key.isPrivateKey()) return skipAuth("Skipping non-private key");
							nextAuth = {
								type,
								username,
								key
							};
							break;
						}
						case "hostbased": {
							const { localHostname, localUsername } = nextAuth;
							const key = parseKey(nextAuth.key, nextAuth.passphrase);
							if (key instanceof Error || typeof localHostname !== "string" || typeof localUsername !== "string") return skipAuth("Skipping invalid hostbased auth attempt");
							if (!key.isPrivateKey()) return skipAuth("Skipping non-private key");
							nextAuth = {
								type,
								username,
								key,
								localHostname,
								localUsername
							};
							break;
						}
						case "agent": {
							let agent = nextAuth.agent;
							if (typeof agent === "string" && agent.length) agent = createAgent(agent);
							else if (!isAgent(agent)) return skipAuth(`Skipping invalid agent: ${nextAuth.agent}`);
							nextAuth = {
								type,
								username,
								agentCtx: new AgentContext(agent)
							};
							break;
						}
						case "keyboard-interactive": {
							const { prompt } = nextAuth;
							if (typeof prompt !== "function") return skipAuth("Skipping invalid keyboard-interactive auth attempt");
							nextAuth = {
								type,
								username,
								prompt
							};
							break;
						}
						case "none":
							nextAuth = {
								type,
								username
							};
							break;
						default: return skipAuth(`Skipping unsupported authentication method: ${nextAuth}`);
					}
				}
				curAuth = nextAuth;
				try {
					const username = curAuth.username;
					switch (curAuth.type) {
						case "password":
							proto.authPassword(username, curAuth.password);
							break;
						case "publickey": {
							let keyAlgo;
							curAuth.keyAlgos = getKeyAlgos(this, curAuth.key, serverSigAlgs);
							if (curAuth.keyAlgos) {
								if (curAuth.keyAlgos.length) keyAlgo = curAuth.keyAlgos[0][0];
								else return skipAuth("Skipping key authentication (no mutual hash algorithm)");
							}
							proto.authPK(username, curAuth.key, keyAlgo);
							break;
						}
						case "hostbased": {
							let keyAlgo;
							let hashAlgo;
							curAuth.keyAlgos = getKeyAlgos(this, curAuth.key, serverSigAlgs);
							if (curAuth.keyAlgos) {
								if (curAuth.keyAlgos.length) [keyAlgo, hashAlgo] = curAuth.keyAlgos[0];
								else return skipAuth("Skipping hostbased authentication (no mutual hash algorithm)");
							}
							proto.authHostbased(username, curAuth.key, curAuth.localHostname, curAuth.localUsername, keyAlgo, (buf, cb) => {
								const signature = curAuth.key.sign(buf, hashAlgo);
								if (signature instanceof Error) {
									signature.message = `Error while signing with key: ${signature.message}`;
									signature.level = "client-authentication";
									this.emit("error", signature);
									return tryNextAuth();
								}
								cb(signature);
							});
							break;
						}
						case "agent":
							curAuth.agentCtx.init((err) => {
								if (err) {
									err.level = "agent";
									this.emit("error", err);
									return tryNextAuth();
								}
								tryNextAgentKey();
							});
							break;
						case "keyboard-interactive":
							proto.authKeyboard(username);
							break;
						case "none": proto.authNone(username);
					}
				} finally {
					hasSentAuth = false;
				}
			};
			function skipAuth(msg) {
				debug && debug(msg);
				process.nextTick(tryNextAuth);
			}
			function tryNextAuth() {
				hasSentAuth = false;
				const auth = authHandler(curAuthsLeft, curPartial, doNextAuth);
				if (hasSentAuth || auth === void 0) return;
				doNextAuth(auth);
			}
			const tryNextAgentKey = () => {
				if (curAuth.type === "agent") {
					const key = curAuth.agentCtx.nextKey();
					if (key === false) {
						debug && debug("Agent: No more keys left to try");
						debug && debug("Client: agent auth failed");
						tryNextAuth();
					} else {
						const pos = curAuth.agentCtx.pos();
						let keyAlgo;
						curAuth.keyAlgos = getKeyAlgos(this, key, serverSigAlgs);
						if (curAuth.keyAlgos) {
							if (curAuth.keyAlgos.length) keyAlgo = curAuth.keyAlgos[0][0];
							else {
								debug && debug(`Agent: Skipping key #${pos + 1} (no mutual hash algorithm)`);
								tryNextAgentKey();
								return;
							}
						}
						debug && debug(`Agent: Trying key #${pos + 1}`);
						proto.authPK(curAuth.username, key, keyAlgo);
					}
				}
			};
			const startTimeout = () => {
				if (this.config.readyTimeout > 0) this._readyTimeout = setTimeout(() => {
					const err = /* @__PURE__ */ new Error("Timed out while waiting for handshake");
					err.level = "client-timeout";
					this.emit("error", err);
					sock.destroy();
				}, this.config.readyTimeout);
			};
			if (!cfg.sock) {
				let host = this.config.host;
				const forceIPv4 = this.config.forceIPv4;
				const forceIPv6 = this.config.forceIPv6;
				debug && debug(`Client: Trying ${host} on port ${this.config.port} ...`);
				const doConnect = () => {
					startTimeout();
					sock.connect({
						host,
						port: this.config.port,
						localAddress: this.config.localAddress,
						localPort: this.config.localPort
					});
					sock.setMaxListeners(0);
					sock.setTimeout(typeof cfg.timeout === "number" ? cfg.timeout : 0);
				};
				if (!forceIPv4 && !forceIPv6 || forceIPv4 && forceIPv6) doConnect();
				else dnsLookup(host, forceIPv4 ? 4 : 6, (err, address, family) => {
					if (err) {
						const error = /* @__PURE__ */ new Error(`Error while looking up ${forceIPv4 ? "IPv4" : "IPv6"} address for '${host}': ${err}`);
						clearTimeout(this._readyTimeout);
						error.level = "client-dns";
						this.emit("error", error);
						this.emit("close");
						return;
					}
					host = address;
					doConnect();
				});
			} else {
				startTimeout();
				if (typeof sock.connecting === "boolean") {
					if (!sock.connecting) onConnect();
				} else onConnect();
			}
			return this;
		}
		end() {
			if (this._sock && isWritable(this._sock)) {
				this._protocol.disconnect(DISCONNECT_REASON.BY_APPLICATION);
				this._sock.end();
			}
			return this;
		}
		destroy() {
			this._sock && isWritable(this._sock) && this._sock.destroy();
			return this;
		}
		exec(cmd, opts, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			if (typeof opts === "function") {
				cb = opts;
				opts = {};
			}
			const extraOpts = { allowHalfOpen: opts.allowHalfOpen !== false };
			openChannel(this, "session", extraOpts, (err, chan) => {
				if (err) {
					cb(err);
					return;
				}
				const todo = [];
				function reqCb(err) {
					if (err) {
						chan.close();
						cb(err);
						return;
					}
					if (todo.length) todo.shift()();
				}
				if (this.config.allowAgentFwd === true || opts && opts.agentForward === true && this._agent !== void 0) todo.push(() => reqAgentFwd(chan, reqCb));
				if (typeof opts === "object" && opts !== null) {
					if (typeof opts.env === "object" && opts.env !== null) reqEnv(chan, opts.env);
					if (typeof opts.pty === "object" && opts.pty !== null || opts.pty === true) todo.push(() => reqPty(chan, opts.pty, reqCb));
					if (typeof opts.x11 === "object" && opts.x11 !== null || opts.x11 === "number" || opts.x11 === true) todo.push(() => reqX11(chan, opts.x11, reqCb));
				}
				todo.push(() => reqExec(chan, cmd, opts, cb));
				todo.shift()();
			});
			return this;
		}
		shell(wndopts, opts, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			if (typeof wndopts === "function") {
				cb = wndopts;
				wndopts = opts = void 0;
			} else if (typeof opts === "function") {
				cb = opts;
				opts = void 0;
			}
			if (wndopts && (wndopts.x11 !== void 0 || wndopts.env !== void 0)) {
				opts = wndopts;
				wndopts = void 0;
			}
			openChannel(this, "session", (err, chan) => {
				if (err) {
					cb(err);
					return;
				}
				const todo = [];
				function reqCb(err) {
					if (err) {
						chan.close();
						cb(err);
						return;
					}
					if (todo.length) todo.shift()();
				}
				if (this.config.allowAgentFwd === true || opts && opts.agentForward === true && this._agent !== void 0) todo.push(() => reqAgentFwd(chan, reqCb));
				if (wndopts !== false) todo.push(() => reqPty(chan, wndopts, reqCb));
				if (typeof opts === "object" && opts !== null) {
					if (typeof opts.env === "object" && opts.env !== null) reqEnv(chan, opts.env);
					if (typeof opts.x11 === "object" && opts.x11 !== null || opts.x11 === "number" || opts.x11 === true) todo.push(() => reqX11(chan, opts.x11, reqCb));
				}
				todo.push(() => reqShell(chan, cb));
				todo.shift()();
			});
			return this;
		}
		subsys(name, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			openChannel(this, "session", (err, chan) => {
				if (err) {
					cb(err);
					return;
				}
				reqSubsystem(chan, name, (err, stream) => {
					if (err) {
						cb(err);
						return;
					}
					cb(void 0, stream);
				});
			});
			return this;
		}
		forwardIn(bindAddr, bindPort, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			const wantReply = typeof cb === "function";
			if (wantReply) this._callbacks.push((had_err, data) => {
				if (had_err) {
					cb(had_err !== true ? had_err : /* @__PURE__ */ new Error(`Unable to bind to ${bindAddr}:${bindPort}`));
					return;
				}
				let realPort = bindPort;
				if (bindPort === 0 && data && data.length >= 4) {
					realPort = readUInt32BE(data, 0);
					if (!(this._protocol._compatFlags & COMPAT.DYN_RPORT_BUG)) bindPort = realPort;
				}
				this._forwarding[`${bindAddr}:${bindPort}`] = realPort;
				cb(void 0, realPort);
			});
			this._protocol.tcpipForward(bindAddr, bindPort, wantReply);
			return this;
		}
		unforwardIn(bindAddr, bindPort, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			const wantReply = typeof cb === "function";
			if (wantReply) this._callbacks.push((had_err) => {
				if (had_err) {
					cb(had_err !== true ? had_err : /* @__PURE__ */ new Error(`Unable to unbind from ${bindAddr}:${bindPort}`));
					return;
				}
				delete this._forwarding[`${bindAddr}:${bindPort}`];
				cb();
			});
			this._protocol.cancelTcpipForward(bindAddr, bindPort, wantReply);
			return this;
		}
		forwardOut(srcIP, srcPort, dstIP, dstPort, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			const cfg = {
				srcIP,
				srcPort,
				dstIP,
				dstPort
			};
			if (typeof cb !== "function") cb = noop;
			openChannel(this, "direct-tcpip", cfg, cb);
			return this;
		}
		openssh_noMoreSessions(cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			const wantReply = typeof cb === "function";
			if (!this.config.strictVendor || this.config.strictVendor && RE_OPENSSH.test(this._remoteVer)) {
				if (wantReply) this._callbacks.push((had_err) => {
					if (had_err) {
						cb(had_err !== true ? had_err : /* @__PURE__ */ new Error("Unable to disable future sessions"));
						return;
					}
					cb();
				});
				this._protocol.openssh_noMoreSessions(wantReply);
				return this;
			}
			if (!wantReply) return this;
			process.nextTick(cb, /* @__PURE__ */ new Error("strictVendor enabled and server is not OpenSSH or compatible version"));
			return this;
		}
		openssh_forwardInStreamLocal(socketPath, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			const wantReply = typeof cb === "function";
			if (!this.config.strictVendor || this.config.strictVendor && RE_OPENSSH.test(this._remoteVer)) {
				if (wantReply) this._callbacks.push((had_err) => {
					if (had_err) {
						cb(had_err !== true ? had_err : /* @__PURE__ */ new Error(`Unable to bind to ${socketPath}`));
						return;
					}
					this._forwardingUnix[socketPath] = true;
					cb();
				});
				this._protocol.openssh_streamLocalForward(socketPath, wantReply);
				return this;
			}
			if (!wantReply) return this;
			process.nextTick(cb, /* @__PURE__ */ new Error("strictVendor enabled and server is not OpenSSH or compatible version"));
			return this;
		}
		openssh_unforwardInStreamLocal(socketPath, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			const wantReply = typeof cb === "function";
			if (!this.config.strictVendor || this.config.strictVendor && RE_OPENSSH.test(this._remoteVer)) {
				if (wantReply) this._callbacks.push((had_err) => {
					if (had_err) {
						cb(had_err !== true ? had_err : /* @__PURE__ */ new Error(`Unable to unbind from ${socketPath}`));
						return;
					}
					delete this._forwardingUnix[socketPath];
					cb();
				});
				this._protocol.openssh_cancelStreamLocalForward(socketPath, wantReply);
				return this;
			}
			if (!wantReply) return this;
			process.nextTick(cb, /* @__PURE__ */ new Error("strictVendor enabled and server is not OpenSSH or compatible version"));
			return this;
		}
		openssh_forwardOutStreamLocal(socketPath, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			if (typeof cb !== "function") cb = noop;
			if (!this.config.strictVendor || this.config.strictVendor && RE_OPENSSH.test(this._remoteVer)) {
				openChannel(this, "direct-streamlocal@openssh.com", { socketPath }, cb);
				return this;
			}
			process.nextTick(cb, /* @__PURE__ */ new Error("strictVendor enabled and server is not OpenSSH or compatible version"));
			return this;
		}
		sftp(env, cb) {
			if (!this._sock || !isWritable(this._sock)) throw new Error("Not connected");
			if (typeof env === "function") {
				cb = env;
				env = void 0;
			}
			openChannel(this, "sftp", (err, sftp) => {
				if (err) {
					cb(err);
					return;
				}
				const reqSubsystemCb = (err, sftp_) => {
					if (err) {
						cb(err);
						return;
					}
					function removeListeners() {
						sftp.removeListener("ready", onReady);
						sftp.removeListener("error", onError);
						sftp.removeListener("exit", onExit);
						sftp.removeListener("close", onExit);
					}
					function onReady() {
						removeListeners();
						cb(void 0, sftp);
					}
					function onError(err) {
						removeListeners();
						cb(err);
					}
					function onExit(code, signal) {
						removeListeners();
						let msg;
						if (typeof code === "number") msg = `Received exit code ${code} while establishing SFTP session`;
						else if (signal !== void 0) msg = `Received signal ${signal} while establishing SFTP session`;
						else msg = "Received unexpected SFTP session termination";
						const err = new Error(msg);
						err.code = code;
						err.signal = signal;
						cb(err);
					}
					sftp.on("ready", onReady).on("error", onError).on("exit", onExit).on("close", onExit);
					sftp._init();
				};
				if (typeof env === "object" && env !== null) reqEnv(sftp, env, (err) => {
					if (err) {
						cb(err);
						return;
					}
					reqSubsystem(sftp, "sftp", reqSubsystemCb);
				});
				else reqSubsystem(sftp, "sftp", reqSubsystemCb);
			});
			return this;
		}
		setNoDelay(noDelay) {
			if (this._sock && typeof this._sock.setNoDelay === "function") this._sock.setNoDelay(noDelay);
			return this;
		}
	};
	function openChannel(self, type, opts, cb) {
		const initWindow = MAX_WINDOW;
		const maxPacket = PACKET_SIZE;
		if (typeof opts === "function") {
			cb = opts;
			opts = {};
		}
		const wrapper = (err, stream) => {
			cb(err, stream);
		};
		wrapper.type = type;
		const localChan = self._chanMgr.add(wrapper);
		if (localChan === -1) {
			cb(/* @__PURE__ */ new Error("No free channels available"));
			return;
		}
		switch (type) {
			case "session":
			case "sftp":
				self._protocol.session(localChan, initWindow, maxPacket);
				break;
			case "direct-tcpip":
				self._protocol.directTcpip(localChan, initWindow, maxPacket, opts);
				break;
			case "direct-streamlocal@openssh.com":
				self._protocol.openssh_directStreamLocal(localChan, initWindow, maxPacket, opts);
				break;
			default: throw new Error(`Unsupported channel type: ${type}`);
		}
	}
	function reqX11(chan, screen, cb) {
		const cfg = {
			single: false,
			protocol: "MIT-MAGIC-COOKIE-1",
			cookie: void 0,
			screen: 0
		};
		if (typeof screen === "function") cb = screen;
		else if (typeof screen === "object" && screen !== null) {
			if (typeof screen.single === "boolean") cfg.single = screen.single;
			if (typeof screen.screen === "number") cfg.screen = screen.screen;
			if (typeof screen.protocol === "string") cfg.protocol = screen.protocol;
			if (typeof screen.cookie === "string") cfg.cookie = screen.cookie;
			else if (Buffer.isBuffer(screen.cookie)) cfg.cookie = screen.cookie.hexSlice(0, screen.cookie.length);
		}
		if (cfg.cookie === void 0) cfg.cookie = randomCookie();
		const wantReply = typeof cb === "function";
		if (chan.outgoing.state !== "open") {
			if (wantReply) cb(/* @__PURE__ */ new Error("Channel is not open"));
			return;
		}
		if (wantReply) chan._callbacks.push((had_err) => {
			if (had_err) {
				cb(had_err !== true ? had_err : /* @__PURE__ */ new Error("Unable to request X11"));
				return;
			}
			chan._hasX11 = true;
			++chan._client._acceptX11;
			chan.once("close", () => {
				if (chan._client._acceptX11) --chan._client._acceptX11;
			});
			cb();
		});
		chan._client._protocol.x11Forward(chan.outgoing.id, cfg, wantReply);
	}
	function reqPty(chan, opts, cb) {
		let rows = 24;
		let cols = 80;
		let width = 640;
		let height = 480;
		let term = "vt100";
		let modes = null;
		if (typeof opts === "function") cb = opts;
		else if (typeof opts === "object" && opts !== null) {
			if (typeof opts.rows === "number") rows = opts.rows;
			if (typeof opts.cols === "number") cols = opts.cols;
			if (typeof opts.width === "number") width = opts.width;
			if (typeof opts.height === "number") height = opts.height;
			if (typeof opts.term === "string") term = opts.term;
			if (typeof opts.modes === "object") modes = opts.modes;
		}
		const wantReply = typeof cb === "function";
		if (chan.outgoing.state !== "open") {
			if (wantReply) cb(/* @__PURE__ */ new Error("Channel is not open"));
			return;
		}
		if (wantReply) chan._callbacks.push((had_err) => {
			if (had_err) {
				cb(had_err !== true ? had_err : /* @__PURE__ */ new Error("Unable to request a pseudo-terminal"));
				return;
			}
			cb();
		});
		chan._client._protocol.pty(chan.outgoing.id, rows, cols, height, width, term, modes, wantReply);
	}
	function reqAgentFwd(chan, cb) {
		const wantReply = typeof cb === "function";
		if (chan.outgoing.state !== "open") {
			wantReply && cb(/* @__PURE__ */ new Error("Channel is not open"));
			return;
		}
		if (chan._client._agentFwdEnabled) {
			wantReply && cb(false);
			return;
		}
		chan._client._agentFwdEnabled = true;
		chan._callbacks.push((had_err) => {
			if (had_err) {
				chan._client._agentFwdEnabled = false;
				if (wantReply) cb(had_err !== true ? had_err : /* @__PURE__ */ new Error("Unable to request agent forwarding"));
				return;
			}
			if (wantReply) cb();
		});
		chan._client._protocol.openssh_agentForward(chan.outgoing.id, true);
	}
	function reqShell(chan, cb) {
		if (chan.outgoing.state !== "open") {
			cb(/* @__PURE__ */ new Error("Channel is not open"));
			return;
		}
		chan._callbacks.push((had_err) => {
			if (had_err) {
				cb(had_err !== true ? had_err : /* @__PURE__ */ new Error("Unable to open shell"));
				return;
			}
			chan.subtype = "shell";
			cb(void 0, chan);
		});
		chan._client._protocol.shell(chan.outgoing.id, true);
	}
	function reqExec(chan, cmd, opts, cb) {
		if (chan.outgoing.state !== "open") {
			cb(/* @__PURE__ */ new Error("Channel is not open"));
			return;
		}
		chan._callbacks.push((had_err) => {
			if (had_err) {
				cb(had_err !== true ? had_err : /* @__PURE__ */ new Error("Unable to exec"));
				return;
			}
			chan.subtype = "exec";
			chan.allowHalfOpen = opts.allowHalfOpen !== false;
			cb(void 0, chan);
		});
		chan._client._protocol.exec(chan.outgoing.id, cmd, true);
	}
	function reqEnv(chan, env, cb) {
		const wantReply = typeof cb === "function";
		if (chan.outgoing.state !== "open") {
			if (wantReply) cb(/* @__PURE__ */ new Error("Channel is not open"));
			return;
		}
		if (wantReply) chan._callbacks.push((had_err) => {
			if (had_err) {
				cb(had_err !== true ? had_err : /* @__PURE__ */ new Error("Unable to set environment"));
				return;
			}
			cb();
		});
		const keys = Object.keys(env || {});
		for (let i = 0; i < keys.length; ++i) {
			const key = keys[i];
			const val = env[key];
			chan._client._protocol.env(chan.outgoing.id, key, val, wantReply);
		}
	}
	function reqSubsystem(chan, name, cb) {
		if (chan.outgoing.state !== "open") {
			cb(/* @__PURE__ */ new Error("Channel is not open"));
			return;
		}
		chan._callbacks.push((had_err) => {
			if (had_err) {
				cb(had_err !== true ? had_err : /* @__PURE__ */ new Error(`Unable to start subsystem: ${name}`));
				return;
			}
			chan.subtype = "subsystem";
			cb(void 0, chan);
		});
		chan._client._protocol.subsystem(chan.outgoing.id, name, true);
	}
	function onCHANNEL_OPEN(self, info) {
		let localChan = -1;
		let reason;
		const accept = () => {
			const chanInfo = {
				type: info.type,
				incoming: {
					id: localChan,
					window: MAX_WINDOW,
					packetSize: PACKET_SIZE,
					state: "open"
				},
				outgoing: {
					id: info.sender,
					window: info.window,
					packetSize: info.packetSize,
					state: "open"
				}
			};
			const stream = new Channel(self, chanInfo);
			self._chanMgr.update(localChan, stream);
			self._protocol.channelOpenConfirm(info.sender, localChan, MAX_WINDOW, PACKET_SIZE);
			return stream;
		};
		const reject = () => {
			if (reason === void 0) {
				if (localChan === -1) reason = CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE;
				else reason = CHANNEL_OPEN_FAILURE.CONNECT_FAILED;
			}
			if (localChan !== -1) self._chanMgr.remove(localChan);
			self._protocol.channelOpenFail(info.sender, reason, "");
		};
		const reserveChannel = () => {
			localChan = self._chanMgr.add();
			if (localChan === -1) {
				reason = CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE;
				if (self.config.debug) self.config.debug("Client: Automatic rejection of incoming channel open: no channels available");
			}
			return localChan !== -1;
		};
		const data = info.data;
		switch (info.type) {
			case "forwarded-tcpip": {
				const val = self._forwarding[`${data.destIP}:${data.destPort}`];
				if (val !== void 0 && reserveChannel()) {
					if (data.destPort === 0) data.destPort = val;
					self.emit("tcp connection", data, accept, reject);
					return;
				}
				break;
			}
			case "forwarded-streamlocal@openssh.com":
				if (self._forwardingUnix[data.socketPath] !== void 0 && reserveChannel()) {
					self.emit("unix connection", data, accept, reject);
					return;
				}
				break;
			case "auth-agent@openssh.com":
				if (self._agentFwdEnabled && typeof self._agent.getStream === "function" && reserveChannel()) {
					self._agent.getStream((err, stream) => {
						if (err) return reject();
						const upstream = accept();
						upstream.pipe(stream).pipe(upstream);
					});
					return;
				}
				break;
			case "x11":
				if (self._acceptX11 !== 0 && reserveChannel()) {
					self.emit("x11", data, accept, reject);
					return;
				}
				break;
			default:
				reason = CHANNEL_OPEN_FAILURE.UNKNOWN_CHANNEL_TYPE;
				if (self.config.debug) self.config.debug(`Client: Automatic rejection of unsupported incoming channel open type: ${info.type}`);
		}
		if (reason === void 0) {
			reason = CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED;
			if (self.config.debug) self.config.debug("Client: Automatic rejection of unexpected incoming channel open for: " + info.type);
		}
		reject();
	}
	const randomCookie = (() => {
		const buffer = Buffer.allocUnsafe(16);
		return () => {
			randomFillSync(buffer, 0, 16);
			return buffer.hexSlice(0, 16);
		};
	})();
	function makeSimpleAuthHandler(authList) {
		if (!Array.isArray(authList)) throw new Error("authList must be an array");
		let a = 0;
		return (authsLeft, partialSuccess, cb) => {
			if (a === authList.length) return false;
			return authList[a++];
		};
	}
	function hostKeysProve(client, keys_, cb) {
		if (!client._sock || !isWritable(client._sock)) return;
		if (typeof cb !== "function") cb = noop;
		if (!Array.isArray(keys_)) throw new TypeError("Invalid keys argument type");
		const keys = [];
		for (const key of keys_) {
			const parsed = parseKey(key);
			if (parsed instanceof Error) throw parsed;
			keys.push(parsed);
		}
		if (!client.config.strictVendor || client.config.strictVendor && RE_OPENSSH.test(client._remoteVer)) {
			client._callbacks.push((had_err, data) => {
				if (had_err) {
					cb(had_err !== true ? had_err : /* @__PURE__ */ new Error("Server failed to prove supplied keys"));
					return;
				}
				const ret = [];
				let keyIdx = 0;
				bufferParser.init(data, 0);
				while (bufferParser.avail()) {
					if (keyIdx === keys.length) break;
					const key = keys[keyIdx++];
					const keyPublic = key.getPublicSSH();
					const sigEntry = bufferParser.readString();
					sigParser.init(sigEntry, 0);
					const type = sigParser.readString(true);
					let value = sigParser.readString();
					let algo;
					if (type !== key.type) {
						if (key.type === "ssh-rsa") switch (type) {
							case "rsa-sha2-256":
								algo = "sha256";
								break;
							case "rsa-sha2-512":
								algo = "sha512";
								break;
							default: continue;
						}
						else continue;
					}
					const sessionID = client._protocol._kex.sessionID;
					const verifyData = Buffer.allocUnsafe(37 + sessionID.length + 4 + keyPublic.length);
					let p = 0;
					writeUInt32BE(verifyData, 29, p);
					verifyData.utf8Write("hostkeys-prove-00@openssh.com", p += 4, 29);
					writeUInt32BE(verifyData, sessionID.length, p += 29);
					bufferCopy(sessionID, verifyData, 0, sessionID.length, p += 4);
					writeUInt32BE(verifyData, keyPublic.length, p += sessionID.length);
					bufferCopy(keyPublic, verifyData, 0, keyPublic.length, p += 4);
					if (!(value = sigSSHToASN1(value, type))) continue;
					if (key.verify(verifyData, value, algo) === true) ret.push(key);
				}
				sigParser.clear();
				bufferParser.clear();
				cb(null, ret);
			});
			client._protocol.openssh_hostKeysProve(keys);
			return;
		}
		process.nextTick(cb, /* @__PURE__ */ new Error("strictVendor enabled and server is not OpenSSH or compatible version"));
	}
	function getKeyAlgos(client, key, serverSigAlgs) {
		switch (key.type) {
			case "ssh-rsa":
				if (client._protocol._compatFlags & COMPAT.IMPLY_RSA_SHA2_SIGALGS) {
					if (!Array.isArray(serverSigAlgs)) serverSigAlgs = ["rsa-sha2-256", "rsa-sha2-512"];
					else serverSigAlgs = [
						"rsa-sha2-256",
						"rsa-sha2-512",
						...serverSigAlgs
					];
				}
				if (Array.isArray(serverSigAlgs)) {
					if (serverSigAlgs.indexOf("rsa-sha2-256") !== -1) return [["rsa-sha2-256", "sha256"]];
					if (serverSigAlgs.indexOf("rsa-sha2-512") !== -1) return [["rsa-sha2-512", "sha512"]];
					if (serverSigAlgs.indexOf("ssh-rsa") === -1) return [];
				}
				return [["ssh-rsa", "sha1"]];
		}
	}
	module.exports = Client;
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/http-agents.js
var require_http_agents = /* @__PURE__ */ __commonJSMin(((exports) => {
	const { Agent: HttpAgent } = __require("http");
	const { Agent: HttpsAgent } = __require("https");
	const { connect: tlsConnect } = __require("tls");
	let Client;
	for (const ctor of [HttpAgent, HttpsAgent]) {
		class SSHAgent extends ctor {
			constructor(connectCfg, agentOptions) {
				super(agentOptions);
				this._connectCfg = connectCfg;
				this._defaultSrcIP = agentOptions && agentOptions.srcIP || "localhost";
			}
			createConnection(options, cb) {
				const srcIP = options && options.localAddress || this._defaultSrcIP;
				const srcPort = options && options.localPort || 0;
				const dstIP = options.host;
				const dstPort = options.port;
				if (Client === void 0) Client = require_client();
				const client = new Client();
				let triedForward = false;
				client.on("ready", () => {
					client.forwardOut(srcIP, srcPort, dstIP, dstPort, (err, stream) => {
						triedForward = true;
						if (err) {
							client.end();
							return cb(err);
						}
						stream.once("close", () => client.end());
						cb(null, decorateStream(stream, ctor, options));
					});
				}).on("error", cb).on("close", () => {
					if (!triedForward) cb(/* @__PURE__ */ new Error("Unexpected connection close"));
				}).connect(this._connectCfg);
			}
		}
		exports[ctor === HttpAgent ? "SSHTTPAgent" : "SSHTTPSAgent"] = SSHAgent;
	}
	function noop() {}
	function decorateStream(stream, ctor, options) {
		if (ctor === HttpAgent) {
			stream.setKeepAlive = noop;
			stream.setNoDelay = noop;
			stream.setTimeout = noop;
			stream.ref = noop;
			stream.unref = noop;
			stream.destroySoon = stream.destroy;
			return stream;
		}
		options.socket = stream;
		const wrapped = tlsConnect(options);
		const onClose = (() => {
			let called = false;
			return () => {
				if (called) return;
				called = true;
				if (stream.isPaused()) stream.resume();
			};
		})();
		wrapped.on("end", onClose).on("close", onClose);
		return wrapped;
	}
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/server.js
var require_server = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { Server: netServer } = __require("net");
	const EventEmitter = __require("events");
	const { listenerCount } = EventEmitter;
	const { CHANNEL_OPEN_FAILURE, DEFAULT_CIPHER, DEFAULT_COMPRESSION, DEFAULT_KEX, DEFAULT_MAC, DEFAULT_SERVER_HOST_KEY, DISCONNECT_REASON, DISCONNECT_REASON_BY_VALUE, SUPPORTED_CIPHER, SUPPORTED_COMPRESSION, SUPPORTED_KEX, SUPPORTED_MAC, SUPPORTED_SERVER_HOST_KEY } = require_constants();
	const { init: cryptoInit } = require_crypto();
	const { KexInit } = require_kex();
	const { parseKey } = require_keyParser();
	const Protocol = require_Protocol();
	const { SFTP } = require_SFTP();
	const { writeUInt32BE } = require_utils$1();
	const { Channel, MAX_WINDOW, PACKET_SIZE, windowAdjust, WINDOW_THRESHOLD } = require_Channel();
	const { ChannelManager, generateAlgorithmList, isWritable, onChannelOpenFailure, onCHANNEL_CLOSE } = require_utils();
	const MAX_PENDING_AUTHS = 10;
	var AuthContext = class extends EventEmitter {
		constructor(protocol, username, service, method, cb) {
			super();
			this.username = this.user = username;
			this.service = service;
			this.method = method;
			this._initialResponse = false;
			this._finalResponse = false;
			this._multistep = false;
			this._cbfinal = (allowed, methodsLeft, isPartial) => {
				if (!this._finalResponse) {
					this._finalResponse = true;
					cb(this, allowed, methodsLeft, isPartial);
				}
			};
			this._protocol = protocol;
		}
		accept() {
			this._cleanup && this._cleanup();
			this._initialResponse = true;
			this._cbfinal(true);
		}
		reject(methodsLeft, isPartial) {
			this._cleanup && this._cleanup();
			this._initialResponse = true;
			this._cbfinal(false, methodsLeft, isPartial);
		}
	};
	var KeyboardAuthContext = class extends AuthContext {
		constructor(protocol, username, service, method, submethods, cb) {
			super(protocol, username, service, method, cb);
			this._multistep = true;
			this._cb = void 0;
			this._onInfoResponse = (responses) => {
				const callback = this._cb;
				if (callback) {
					this._cb = void 0;
					callback(responses);
				}
			};
			this.submethods = submethods;
			this.on("abort", () => {
				this._cb && this._cb(/* @__PURE__ */ new Error("Authentication request aborted"));
			});
		}
		prompt(prompts, title, instructions, cb) {
			if (!Array.isArray(prompts)) prompts = [prompts];
			if (typeof title === "function") {
				cb = title;
				title = instructions = void 0;
			} else if (typeof instructions === "function") {
				cb = instructions;
				instructions = void 0;
			} else if (typeof cb !== "function") cb = void 0;
			for (let i = 0; i < prompts.length; ++i) if (typeof prompts[i] === "string") prompts[i] = {
				prompt: prompts[i],
				echo: true
			};
			this._cb = cb;
			this._initialResponse = true;
			this._protocol.authInfoReq(title, instructions, prompts);
		}
	};
	var PKAuthContext = class extends AuthContext {
		constructor(protocol, username, service, method, pkInfo, cb) {
			super(protocol, username, service, method, cb);
			this.key = {
				algo: pkInfo.keyAlgo,
				data: pkInfo.key
			};
			this.hashAlgo = pkInfo.hashAlgo;
			this.signature = pkInfo.signature;
			this.blob = pkInfo.blob;
		}
		accept() {
			if (!this.signature) {
				this._initialResponse = true;
				this._protocol.authPKOK(this.key.algo, this.key.data);
			} else AuthContext.prototype.accept.call(this);
		}
	};
	var HostbasedAuthContext = class extends AuthContext {
		constructor(protocol, username, service, method, pkInfo, cb) {
			super(protocol, username, service, method, cb);
			this.key = {
				algo: pkInfo.keyAlgo,
				data: pkInfo.key
			};
			this.hashAlgo = pkInfo.hashAlgo;
			this.signature = pkInfo.signature;
			this.blob = pkInfo.blob;
			this.localHostname = pkInfo.localHostname;
			this.localUsername = pkInfo.localUsername;
		}
	};
	var PwdAuthContext = class extends AuthContext {
		constructor(protocol, username, service, method, password, cb) {
			super(protocol, username, service, method, cb);
			this.password = password;
			this._changeCb = void 0;
		}
		requestChange(prompt, cb) {
			if (this._changeCb) throw new Error("Change request already in progress");
			if (typeof prompt !== "string") throw new Error("prompt argument must be a string");
			if (typeof cb !== "function") throw new Error("Callback argument must be a function");
			this._changeCb = cb;
			this._protocol.authPasswdChg(prompt);
		}
	};
	var Session = class extends EventEmitter {
		constructor(client, info, localChan) {
			super();
			this.type = "session";
			this.subtype = void 0;
			this.server = true;
			this._ending = false;
			this._channel = void 0;
			this._chanInfo = {
				type: "session",
				incoming: {
					id: localChan,
					window: MAX_WINDOW,
					packetSize: PACKET_SIZE,
					state: "open"
				},
				outgoing: {
					id: info.sender,
					window: info.window,
					packetSize: info.packetSize,
					state: "open"
				}
			};
		}
	};
	var Server = class extends EventEmitter {
		constructor(cfg, listener) {
			super();
			if (typeof cfg !== "object" || cfg === null) throw new Error("Missing configuration object");
			const hostKeys = Object.create(null);
			const hostKeyAlgoOrder = [];
			const hostKeys_ = cfg.hostKeys;
			if (!Array.isArray(hostKeys_)) throw new Error("hostKeys must be an array");
			const cfgAlgos = typeof cfg.algorithms === "object" && cfg.algorithms !== null ? cfg.algorithms : {};
			const hostKeyAlgos = generateAlgorithmList(cfgAlgos.serverHostKey, DEFAULT_SERVER_HOST_KEY, SUPPORTED_SERVER_HOST_KEY);
			for (let i = 0; i < hostKeys_.length; ++i) {
				let privateKey;
				if (Buffer.isBuffer(hostKeys_[i]) || typeof hostKeys_[i] === "string") privateKey = parseKey(hostKeys_[i]);
				else privateKey = parseKey(hostKeys_[i].key, hostKeys_[i].passphrase);
				if (privateKey instanceof Error) throw new Error(`Cannot parse privateKey: ${privateKey.message}`);
				if (Array.isArray(privateKey)) privateKey = privateKey[0];
				if (privateKey.getPrivatePEM() === null) throw new Error("privateKey value contains an invalid private key");
				if (hostKeyAlgoOrder.includes(privateKey.type)) continue;
				if (privateKey.type === "ssh-rsa") {
					let sha1Pos = hostKeyAlgos.indexOf("ssh-rsa");
					const sha256Pos = hostKeyAlgos.indexOf("rsa-sha2-256");
					const sha512Pos = hostKeyAlgos.indexOf("rsa-sha2-512");
					if (sha1Pos === -1) sha1Pos = Infinity;
					[
						sha1Pos,
						sha256Pos,
						sha512Pos
					].sort(compareNumbers).forEach((pos) => {
						if (pos === -1) return;
						let type;
						switch (pos) {
							case sha1Pos:
								type = "ssh-rsa";
								break;
							case sha256Pos:
								type = "rsa-sha2-256";
								break;
							case sha512Pos:
								type = "rsa-sha2-512";
								break;
							default: return;
						}
						hostKeys[type] = privateKey;
						hostKeyAlgoOrder.push(type);
					});
				} else {
					hostKeys[privateKey.type] = privateKey;
					hostKeyAlgoOrder.push(privateKey.type);
				}
			}
			const algorithms = {
				kex: generateAlgorithmList(cfgAlgos.kex, DEFAULT_KEX, SUPPORTED_KEX).concat(["kex-strict-s-v00@openssh.com"]),
				serverHostKey: hostKeyAlgoOrder,
				cs: {
					cipher: generateAlgorithmList(cfgAlgos.cipher, DEFAULT_CIPHER, SUPPORTED_CIPHER),
					mac: generateAlgorithmList(cfgAlgos.hmac, DEFAULT_MAC, SUPPORTED_MAC),
					compress: generateAlgorithmList(cfgAlgos.compress, DEFAULT_COMPRESSION, SUPPORTED_COMPRESSION),
					lang: []
				},
				sc: void 0
			};
			algorithms.sc = algorithms.cs;
			if (typeof listener === "function") this.on("connection", listener);
			const origDebug = typeof cfg.debug === "function" ? cfg.debug : void 0;
			const ident = cfg.ident ? Buffer.from(cfg.ident) : void 0;
			const offer = new KexInit(algorithms);
			this._srv = new netServer((socket) => {
				if (this._connections >= this.maxConnections) {
					socket.destroy();
					return;
				}
				++this._connections;
				socket.once("close", () => {
					--this._connections;
				});
				let debug;
				if (origDebug) {
					const debugPrefix = `[${process.hrtime().join(".")}] `;
					debug = (msg) => {
						origDebug(`${debugPrefix}${msg}`);
					};
				}
				new Client(socket, hostKeys, ident, offer, debug, this, cfg);
			}).on("error", (err) => {
				this.emit("error", err);
			}).on("listening", () => {
				this.emit("listening");
			}).on("close", () => {
				this.emit("close");
			});
			this._connections = 0;
			this.maxConnections = Infinity;
		}
		injectSocket(socket) {
			this._srv.emit("connection", socket);
		}
		listen(...args) {
			this._srv.listen(...args);
			return this;
		}
		address() {
			return this._srv.address();
		}
		getConnections(cb) {
			this._srv.getConnections(cb);
			return this;
		}
		close(cb) {
			this._srv.close(cb);
			return this;
		}
		ref() {
			this._srv.ref();
			return this;
		}
		unref() {
			this._srv.unref();
			return this;
		}
	};
	Server.KEEPALIVE_CLIENT_INTERVAL = 15e3;
	Server.KEEPALIVE_CLIENT_COUNT_MAX = 3;
	var Client = class extends EventEmitter {
		constructor(socket, hostKeys, ident, offer, debug, server, srvCfg) {
			super();
			let exchanges = 0;
			let acceptedAuthSvc = false;
			let pendingAuths = [];
			let authCtx;
			let kaTimer;
			let onPacket;
			const unsentGlobalRequestsReplies = [];
			this._sock = socket;
			this._chanMgr = new ChannelManager(this);
			this._debug = debug;
			this.noMoreSessions = false;
			this.authenticated = false;
			function onClientPreHeaderError(err) {}
			this.on("error", onClientPreHeaderError);
			const DEBUG_HANDLER = !debug ? void 0 : (p, display, msg) => {
				debug(`Debug output from client: ${JSON.stringify(msg)}`);
			};
			const kaIntvl = typeof srvCfg.keepaliveInterval === "number" && isFinite(srvCfg.keepaliveInterval) && srvCfg.keepaliveInterval > 0 ? srvCfg.keepaliveInterval : typeof Server.KEEPALIVE_CLIENT_INTERVAL === "number" && isFinite(Server.KEEPALIVE_CLIENT_INTERVAL) && Server.KEEPALIVE_CLIENT_INTERVAL > 0 ? Server.KEEPALIVE_CLIENT_INTERVAL : -1;
			const kaCountMax = typeof srvCfg.keepaliveCountMax === "number" && isFinite(srvCfg.keepaliveCountMax) && srvCfg.keepaliveCountMax >= 0 ? srvCfg.keepaliveCountMax : typeof Server.KEEPALIVE_CLIENT_COUNT_MAX === "number" && isFinite(Server.KEEPALIVE_CLIENT_COUNT_MAX) && Server.KEEPALIVE_CLIENT_COUNT_MAX >= 0 ? Server.KEEPALIVE_CLIENT_COUNT_MAX : -1;
			let kaCurCount = 0;
			if (kaIntvl !== -1 && kaCountMax !== -1) {
				this.once("ready", () => {
					const onClose = () => {
						clearInterval(kaTimer);
					};
					this.on("close", onClose).on("end", onClose);
					kaTimer = setInterval(() => {
						if (++kaCurCount > kaCountMax) {
							clearInterval(kaTimer);
							const err = /* @__PURE__ */ new Error("Keepalive timeout");
							err.level = "client-timeout";
							this.emit("error", err);
							this.end();
						} else proto.ping();
					}, kaIntvl);
				});
				onPacket = () => {
					kaTimer && kaTimer.refresh();
					kaCurCount = 0;
				};
			}
			const proto = this._protocol = new Protocol({
				server: true,
				hostKeys,
				ident,
				offer,
				onPacket,
				greeting: srvCfg.greeting,
				banner: srvCfg.banner,
				onWrite: (data) => {
					if (isWritable(socket)) socket.write(data);
				},
				onError: (err) => {
					if (!proto._destruct) socket.removeAllListeners("data");
					this.emit("error", err);
					try {
						socket.end();
					} catch {}
				},
				onHeader: (header) => {
					this.removeListener("error", onClientPreHeaderError);
					const info = {
						ip: socket.remoteAddress,
						family: socket.remoteFamily,
						port: socket.remotePort,
						header
					};
					if (!server.emit("connection", this, info)) {
						proto.disconnect(DISCONNECT_REASON.BY_APPLICATION);
						socket.end();
						return;
					}
					if (header.greeting) this.emit("greeting", header.greeting);
				},
				onHandshakeComplete: (negotiated) => {
					if (++exchanges > 1) this.emit("rekey");
					this.emit("handshake", negotiated);
				},
				debug,
				messageHandlers: {
					DEBUG: DEBUG_HANDLER,
					DISCONNECT: (p, reason, desc) => {
						if (reason !== DISCONNECT_REASON.BY_APPLICATION) {
							if (!desc) {
								desc = DISCONNECT_REASON_BY_VALUE[reason];
								if (desc === void 0) desc = `Unexpected disconnection reason: ${reason}`;
							}
							const err = new Error(desc);
							err.code = reason;
							this.emit("error", err);
						}
						socket.end();
					},
					CHANNEL_OPEN: (p, info) => {
						if (info.type === "session" && this.noMoreSessions || !this.authenticated) {
							const reasonCode = CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED;
							return proto.channelOpenFail(info.sender, reasonCode);
						}
						let localChan = -1;
						let reason;
						let replied = false;
						let accept;
						const reject = () => {
							if (replied) return;
							replied = true;
							if (reason === void 0) {
								if (localChan === -1) reason = CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE;
								else reason = CHANNEL_OPEN_FAILURE.CONNECT_FAILED;
							}
							if (localChan !== -1) this._chanMgr.remove(localChan);
							proto.channelOpenFail(info.sender, reason, "");
						};
						const reserveChannel = () => {
							localChan = this._chanMgr.add();
							if (localChan === -1) {
								reason = CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE;
								if (debug) debug("Automatic rejection of incoming channel open: no channels available");
							}
							return localChan !== -1;
						};
						const data = info.data;
						switch (info.type) {
							case "session":
								if (listenerCount(this, "session") && reserveChannel()) {
									accept = () => {
										if (replied) return;
										replied = true;
										const instance = new Session(this, info, localChan);
										this._chanMgr.update(localChan, instance);
										proto.channelOpenConfirm(info.sender, localChan, MAX_WINDOW, PACKET_SIZE);
										return instance;
									};
									this.emit("session", accept, reject);
									return;
								}
								break;
							case "direct-tcpip":
								if (listenerCount(this, "tcpip") && reserveChannel()) {
									accept = () => {
										if (replied) return;
										replied = true;
										const chanInfo = {
											type: void 0,
											incoming: {
												id: localChan,
												window: MAX_WINDOW,
												packetSize: PACKET_SIZE,
												state: "open"
											},
											outgoing: {
												id: info.sender,
												window: info.window,
												packetSize: info.packetSize,
												state: "open"
											}
										};
										const stream = new Channel(this, chanInfo, { server: true });
										this._chanMgr.update(localChan, stream);
										proto.channelOpenConfirm(info.sender, localChan, MAX_WINDOW, PACKET_SIZE);
										return stream;
									};
									this.emit("tcpip", accept, reject, data);
									return;
								}
								break;
							case "direct-streamlocal@openssh.com":
								if (listenerCount(this, "openssh.streamlocal") && reserveChannel()) {
									accept = () => {
										if (replied) return;
										replied = true;
										const chanInfo = {
											type: void 0,
											incoming: {
												id: localChan,
												window: MAX_WINDOW,
												packetSize: PACKET_SIZE,
												state: "open"
											},
											outgoing: {
												id: info.sender,
												window: info.window,
												packetSize: info.packetSize,
												state: "open"
											}
										};
										const stream = new Channel(this, chanInfo, { server: true });
										this._chanMgr.update(localChan, stream);
										proto.channelOpenConfirm(info.sender, localChan, MAX_WINDOW, PACKET_SIZE);
										return stream;
									};
									this.emit("openssh.streamlocal", accept, reject, data);
									return;
								}
								break;
							default:
								reason = CHANNEL_OPEN_FAILURE.UNKNOWN_CHANNEL_TYPE;
								if (debug) debug(`Automatic rejection of unsupported incoming channel open type: ${info.type}`);
						}
						if (reason === void 0) {
							reason = CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED;
							if (debug) debug(`Automatic rejection of unexpected incoming channel open for: ${info.type}`);
						}
						reject();
					},
					CHANNEL_OPEN_CONFIRMATION: (p, info) => {
						const channel = this._chanMgr.get(info.recipient);
						if (typeof channel !== "function") return;
						const chanInfo = {
							type: channel.type,
							incoming: {
								id: info.recipient,
								window: MAX_WINDOW,
								packetSize: PACKET_SIZE,
								state: "open"
							},
							outgoing: {
								id: info.sender,
								window: info.window,
								packetSize: info.packetSize,
								state: "open"
							}
						};
						const instance = new Channel(this, chanInfo, { server: true });
						this._chanMgr.update(info.recipient, instance);
						channel(void 0, instance);
					},
					CHANNEL_OPEN_FAILURE: (p, recipient, reason, description) => {
						const channel = this._chanMgr.get(recipient);
						if (typeof channel !== "function") return;
						const info = {
							reason,
							description
						};
						onChannelOpenFailure(this, recipient, info, channel);
					},
					CHANNEL_DATA: (p, recipient, data) => {
						let channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						if (channel.constructor === Session) {
							channel = channel._channel;
							if (!channel) return;
						}
						if (channel.incoming.window === 0) return;
						channel.incoming.window -= data.length;
						if (channel.push(data) === false) {
							channel._waitChanDrain = true;
							return;
						}
						if (channel.incoming.window <= WINDOW_THRESHOLD) windowAdjust(channel);
					},
					CHANNEL_EXTENDED_DATA: (p, recipient, data, type) => {},
					CHANNEL_WINDOW_ADJUST: (p, recipient, amount) => {
						let channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						if (channel.constructor === Session) {
							channel = channel._channel;
							if (!channel) return;
						}
						channel.outgoing.window += amount;
						if (channel._waitWindow) {
							channel._waitWindow = false;
							if (channel._chunk) channel._write(channel._chunk, null, channel._chunkcb);
							else if (channel._chunkcb) channel._chunkcb();
							else if (channel._chunkErr) channel.stderr._write(channel._chunkErr, null, channel._chunkcbErr);
							else if (channel._chunkcbErr) channel._chunkcbErr();
						}
					},
					CHANNEL_SUCCESS: (p, recipient) => {
						let channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						if (channel.constructor === Session) {
							channel = channel._channel;
							if (!channel) return;
						}
						if (channel._callbacks.length) channel._callbacks.shift()(false);
					},
					CHANNEL_FAILURE: (p, recipient) => {
						let channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						if (channel.constructor === Session) {
							channel = channel._channel;
							if (!channel) return;
						}
						if (channel._callbacks.length) channel._callbacks.shift()(true);
					},
					CHANNEL_REQUEST: (p, recipient, type, wantReply, data) => {
						const session = this._chanMgr.get(recipient);
						if (typeof session !== "object" || session === null) return;
						let replied = false;
						let accept;
						let reject;
						if (session.constructor !== Session) {
							if (wantReply) proto.channelFailure(session.outgoing.id);
							return;
						}
						if (wantReply) {
							if (type !== "shell" && type !== "exec" && type !== "subsystem") accept = () => {
								if (replied || session._ending || session._channel) return;
								replied = true;
								proto.channelSuccess(session._chanInfo.outgoing.id);
							};
							reject = () => {
								if (replied || session._ending || session._channel) return;
								replied = true;
								proto.channelFailure(session._chanInfo.outgoing.id);
							};
						}
						if (session._ending) {
							reject && reject();
							return;
						}
						switch (type) {
							case "env":
								if (listenerCount(session, "env")) {
									session.emit("env", accept, reject, {
										key: data.name,
										val: data.value
									});
									return;
								}
								break;
							case "pty-req":
								if (listenerCount(session, "pty")) {
									session.emit("pty", accept, reject, data);
									return;
								}
								break;
							case "window-change":
								if (listenerCount(session, "window-change")) session.emit("window-change", accept, reject, data);
								else reject && reject();
								break;
							case "x11-req":
								if (listenerCount(session, "x11")) {
									session.emit("x11", accept, reject, data);
									return;
								}
								break;
							case "signal":
								if (listenerCount(session, "signal")) {
									session.emit("signal", accept, reject, { name: data });
									return;
								}
								break;
							case "auth-agent-req@openssh.com":
								if (listenerCount(session, "auth-agent")) {
									session.emit("auth-agent", accept, reject);
									return;
								}
								break;
							case "shell":
								if (listenerCount(session, "shell")) {
									accept = () => {
										if (replied || session._ending || session._channel) return;
										replied = true;
										if (wantReply) proto.channelSuccess(session._chanInfo.outgoing.id);
										const channel = new Channel(this, session._chanInfo, { server: true });
										channel.subtype = session.subtype = type;
										session._channel = channel;
										return channel;
									};
									session.emit("shell", accept, reject);
									return;
								}
								break;
							case "exec":
								if (listenerCount(session, "exec")) {
									accept = () => {
										if (replied || session._ending || session._channel) return;
										replied = true;
										if (wantReply) proto.channelSuccess(session._chanInfo.outgoing.id);
										const channel = new Channel(this, session._chanInfo, { server: true });
										channel.subtype = session.subtype = type;
										session._channel = channel;
										return channel;
									};
									session.emit("exec", accept, reject, { command: data });
									return;
								}
								break;
							case "subsystem": {
								let useSFTP = data === "sftp";
								accept = () => {
									if (replied || session._ending || session._channel) return;
									replied = true;
									if (wantReply) proto.channelSuccess(session._chanInfo.outgoing.id);
									let instance;
									if (useSFTP) instance = new SFTP(this, session._chanInfo, {
										server: true,
										debug
									});
									else {
										instance = new Channel(this, session._chanInfo, { server: true });
										instance.subtype = session.subtype = `${type}:${data}`;
									}
									session._channel = instance;
									return instance;
								};
								if (data === "sftp") {
									if (listenerCount(session, "sftp")) {
										session.emit("sftp", accept, reject);
										return;
									}
									useSFTP = false;
								}
								if (listenerCount(session, "subsystem")) {
									session.emit("subsystem", accept, reject, { name: data });
									return;
								}
								break;
							}
						}
						debug && debug(`Automatic rejection of incoming channel request: ${type}`);
						reject && reject();
					},
					CHANNEL_EOF: (p, recipient) => {
						let channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						if (channel.constructor === Session) {
							if (!channel._ending) {
								channel._ending = true;
								channel.emit("eof");
								channel.emit("end");
							}
							channel = channel._channel;
							if (!channel) return;
						}
						if (channel.incoming.state !== "open") return;
						channel.incoming.state = "eof";
						if (channel.readable) channel.push(null);
					},
					CHANNEL_CLOSE: (p, recipient) => {
						let channel = this._chanMgr.get(recipient);
						if (typeof channel !== "object" || channel === null) return;
						if (channel.constructor === Session) {
							channel._ending = true;
							channel.emit("close");
							channel = channel._channel;
							if (!channel) return;
						}
						onCHANNEL_CLOSE(this, recipient, channel);
					},
					SERVICE_REQUEST: (p, service) => {
						if (exchanges === 0 || acceptedAuthSvc || this.authenticated || service !== "ssh-userauth") {
							proto.disconnect(DISCONNECT_REASON.SERVICE_NOT_AVAILABLE);
							socket.end();
							return;
						}
						acceptedAuthSvc = true;
						proto.serviceAccept(service);
					},
					USERAUTH_REQUEST: (p, username, service, method, methodData) => {
						if (exchanges === 0 || this.authenticated || authCtx && (authCtx.username !== username || authCtx.service !== service) || method !== "password" && method !== "publickey" && method !== "hostbased" && method !== "keyboard-interactive" && method !== "none" || pendingAuths.length === MAX_PENDING_AUTHS) {
							proto.disconnect(DISCONNECT_REASON.PROTOCOL_ERROR);
							socket.end();
							return;
						} else if (service !== "ssh-connection") {
							proto.disconnect(DISCONNECT_REASON.SERVICE_NOT_AVAILABLE);
							socket.end();
							return;
						}
						let ctx;
						switch (method) {
							case "keyboard-interactive":
								ctx = new KeyboardAuthContext(proto, username, service, method, methodData, onAuthDecide);
								break;
							case "publickey":
								ctx = new PKAuthContext(proto, username, service, method, methodData, onAuthDecide);
								break;
							case "hostbased":
								ctx = new HostbasedAuthContext(proto, username, service, method, methodData, onAuthDecide);
								break;
							case "password":
								if (authCtx && authCtx instanceof PwdAuthContext && authCtx._changeCb) {
									const cb = authCtx._changeCb;
									authCtx._changeCb = void 0;
									cb(methodData.newPassword);
									return;
								}
								ctx = new PwdAuthContext(proto, username, service, method, methodData, onAuthDecide);
								break;
							case "none": ctx = new AuthContext(proto, username, service, method, onAuthDecide);
						}
						if (authCtx) {
							if (!authCtx._initialResponse) return pendingAuths.push(ctx);
							else if (authCtx._multistep && !authCtx._finalResponse) {
								authCtx._cleanup && authCtx._cleanup();
								authCtx.emit("abort");
							}
						}
						authCtx = ctx;
						if (listenerCount(this, "authentication")) this.emit("authentication", authCtx);
						else authCtx.reject();
					},
					USERAUTH_INFO_RESPONSE: (p, responses) => {
						if (authCtx && authCtx instanceof KeyboardAuthContext) authCtx._onInfoResponse(responses);
					},
					GLOBAL_REQUEST: (p, name, wantReply, data) => {
						const reply = {
							type: null,
							buf: null
						};
						function setReply(type, buf) {
							reply.type = type;
							reply.buf = buf;
							sendReplies();
						}
						if (wantReply) unsentGlobalRequestsReplies.push(reply);
						if ((name === "tcpip-forward" || name === "cancel-tcpip-forward" || name === "no-more-sessions@openssh.com" || name === "streamlocal-forward@openssh.com" || name === "cancel-streamlocal-forward@openssh.com") && listenerCount(this, "request") && this.authenticated) {
							let accept;
							let reject;
							if (wantReply) {
								let replied = false;
								accept = (chosenPort) => {
									if (replied) return;
									replied = true;
									let bufPort;
									if (name === "tcpip-forward" && data.bindPort === 0 && typeof chosenPort === "number") {
										bufPort = Buffer.allocUnsafe(4);
										writeUInt32BE(bufPort, chosenPort, 0);
									}
									setReply("SUCCESS", bufPort);
								};
								reject = () => {
									if (replied) return;
									replied = true;
									setReply("FAILURE");
								};
							}
							if (name === "no-more-sessions@openssh.com") {
								this.noMoreSessions = true;
								accept && accept();
								return;
							}
							this.emit("request", accept, reject, name, data);
						} else if (wantReply) setReply("FAILURE");
					}
				}
			});
			socket.pause();
			cryptoInit.then(() => {
				proto.start();
				socket.on("data", (data) => {
					try {
						proto.parse(data, 0, data.length);
					} catch (ex) {
						this.emit("error", ex);
						try {
							if (isWritable(socket)) socket.end();
						} catch {}
					}
				});
				socket.resume();
			}).catch((err) => {
				this.emit("error", err);
				try {
					if (isWritable(socket)) socket.end();
				} catch {}
			});
			socket.on("error", (err) => {
				err.level = "socket";
				this.emit("error", err);
			}).once("end", () => {
				debug && debug("Socket ended");
				proto.cleanup();
				this.emit("end");
			}).once("close", () => {
				debug && debug("Socket closed");
				proto.cleanup();
				this.emit("close");
				const err = /* @__PURE__ */ new Error("No response from server");
				this._chanMgr.cleanup(err);
			});
			const onAuthDecide = (ctx, allowed, methodsLeft, isPartial) => {
				if (authCtx === ctx && !this.authenticated) {
					if (allowed) {
						authCtx = void 0;
						this.authenticated = true;
						proto.authSuccess();
						pendingAuths = [];
						this.emit("ready");
					} else {
						proto.authFailure(methodsLeft, isPartial);
						if (pendingAuths.length) {
							authCtx = pendingAuths.pop();
							if (listenerCount(this, "authentication")) this.emit("authentication", authCtx);
							else authCtx.reject();
						}
					}
				}
			};
			function sendReplies() {
				while (unsentGlobalRequestsReplies.length > 0 && unsentGlobalRequestsReplies[0].type) {
					const reply = unsentGlobalRequestsReplies.shift();
					if (reply.type === "SUCCESS") proto.requestSuccess(reply.buf);
					if (reply.type === "FAILURE") proto.requestFailure();
				}
			}
		}
		end() {
			if (this._sock && isWritable(this._sock)) {
				this._protocol.disconnect(DISCONNECT_REASON.BY_APPLICATION);
				this._sock.end();
			}
			return this;
		}
		x11(originAddr, originPort, cb) {
			const opts = {
				originAddr,
				originPort
			};
			openChannel(this, "x11", opts, cb);
			return this;
		}
		forwardOut(boundAddr, boundPort, remoteAddr, remotePort, cb) {
			const opts = {
				boundAddr,
				boundPort,
				remoteAddr,
				remotePort
			};
			openChannel(this, "forwarded-tcpip", opts, cb);
			return this;
		}
		openssh_forwardOutStreamLocal(socketPath, cb) {
			const opts = { socketPath };
			openChannel(this, "forwarded-streamlocal@openssh.com", opts, cb);
			return this;
		}
		rekey(cb) {
			let error;
			try {
				this._protocol.rekey();
			} catch (ex) {
				error = ex;
			}
			if (typeof cb === "function") {
				if (error) process.nextTick(cb, error);
				else this.once("rekey", cb);
			}
		}
		setNoDelay(noDelay) {
			if (this._sock && typeof this._sock.setNoDelay === "function") this._sock.setNoDelay(noDelay);
			return this;
		}
	};
	function openChannel(self, type, opts, cb) {
		const initWindow = MAX_WINDOW;
		const maxPacket = PACKET_SIZE;
		if (typeof opts === "function") {
			cb = opts;
			opts = {};
		}
		const wrapper = (err, stream) => {
			cb(err, stream);
		};
		wrapper.type = type;
		const localChan = self._chanMgr.add(wrapper);
		if (localChan === -1) {
			cb(/* @__PURE__ */ new Error("No free channels available"));
			return;
		}
		switch (type) {
			case "forwarded-tcpip":
				self._protocol.forwardedTcpip(localChan, initWindow, maxPacket, opts);
				break;
			case "x11":
				self._protocol.x11(localChan, initWindow, maxPacket, opts);
				break;
			case "forwarded-streamlocal@openssh.com":
				self._protocol.openssh_forwardedStreamLocal(localChan, initWindow, maxPacket, opts);
				break;
			default: throw new Error(`Unsupported channel type: ${type}`);
		}
	}
	function compareNumbers(a, b) {
		return a - b;
	}
	module.exports = Server;
	module.exports.IncomingClient = Client;
}));
//#endregion
//#region node_modules/.pnpm/ssh2@1.17.0/node_modules/ssh2/lib/keygen.js
var require_keygen = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { createCipheriv, generateKeyPair: generateKeyPair_, generateKeyPairSync: generateKeyPairSync_, getCurves, randomBytes } = __require("crypto");
	const { Ber } = require_lib$1();
	const bcrypt_pbkdf = require_bcrypt_pbkdf().pbkdf;
	const { CIPHER_INFO } = require_crypto();
	const SALT_LEN = 16;
	const DEFAULT_ROUNDS = 16;
	const curves = getCurves();
	const ciphers = new Map(Object.entries(CIPHER_INFO));
	function makeArgs(type, opts) {
		if (typeof type !== "string") throw new TypeError("Key type must be a string");
		const publicKeyEncoding = {
			type: "spki",
			format: "der"
		};
		const privateKeyEncoding = {
			type: "pkcs8",
			format: "der"
		};
		switch (type.toLowerCase()) {
			case "rsa": {
				if (typeof opts !== "object" || opts === null) throw new TypeError("Missing options object for RSA key");
				const modulusLength = opts.bits;
				if (!Number.isInteger(modulusLength)) throw new TypeError("RSA bits must be an integer");
				if (modulusLength <= 0 || modulusLength > 16384) throw new RangeError("RSA bits must be non-zero and <= 16384");
				return ["rsa", {
					modulusLength,
					publicKeyEncoding,
					privateKeyEncoding
				}];
			}
			case "ecdsa": {
				if (typeof opts !== "object" || opts === null) throw new TypeError("Missing options object for ECDSA key");
				if (!Number.isInteger(opts.bits)) throw new TypeError("ECDSA bits must be an integer");
				let namedCurve;
				switch (opts.bits) {
					case 256:
						namedCurve = "prime256v1";
						break;
					case 384:
						namedCurve = "secp384r1";
						break;
					case 521:
						namedCurve = "secp521r1";
						break;
					default: throw new Error("ECDSA bits must be 256, 384, or 521");
				}
				if (!curves.includes(namedCurve)) throw new Error("Unsupported ECDSA bits value");
				return ["ec", {
					namedCurve,
					publicKeyEncoding,
					privateKeyEncoding
				}];
			}
			case "ed25519": return ["ed25519", {
				publicKeyEncoding,
				privateKeyEncoding
			}];
			default: throw new Error(`Unsupported key type: ${type}`);
		}
	}
	function parseDERs(keyType, pub, priv) {
		switch (keyType) {
			case "rsa": {
				let reader = new Ber.Reader(priv);
				reader.readSequence();
				if (reader.readInt() !== 0) throw new Error("Unsupported version in RSA private key");
				reader.readSequence();
				if (reader.readOID() !== "1.2.840.113549.1.1.1") throw new Error("Bad RSA private OID");
				if (reader.readByte() !== Ber.Null) throw new Error("Malformed RSA private key (expected null)");
				if (reader.readByte() !== 0) throw new Error("Malformed RSA private key (expected zero-length null)");
				reader = new Ber.Reader(reader.readString(Ber.OctetString, true));
				reader.readSequence();
				if (reader.readInt() !== 0) throw new Error("Unsupported version in RSA private key");
				const n = reader.readString(Ber.Integer, true);
				const e = reader.readString(Ber.Integer, true);
				const d = reader.readString(Ber.Integer, true);
				const p = reader.readString(Ber.Integer, true);
				const q = reader.readString(Ber.Integer, true);
				reader.readString(Ber.Integer, true);
				reader.readString(Ber.Integer, true);
				const iqmp = reader.readString(Ber.Integer, true);
				const keyName = Buffer.from("ssh-rsa");
				const privBuf = Buffer.allocUnsafe(4 + keyName.length + 4 + n.length + 4 + e.length + 4 + d.length + 4 + iqmp.length + 4 + p.length + 4 + q.length);
				let pos = 0;
				privBuf.writeUInt32BE(keyName.length, pos += 0);
				privBuf.set(keyName, pos += 4);
				privBuf.writeUInt32BE(n.length, pos += keyName.length);
				privBuf.set(n, pos += 4);
				privBuf.writeUInt32BE(e.length, pos += n.length);
				privBuf.set(e, pos += 4);
				privBuf.writeUInt32BE(d.length, pos += e.length);
				privBuf.set(d, pos += 4);
				privBuf.writeUInt32BE(iqmp.length, pos += d.length);
				privBuf.set(iqmp, pos += 4);
				privBuf.writeUInt32BE(p.length, pos += iqmp.length);
				privBuf.set(p, pos += 4);
				privBuf.writeUInt32BE(q.length, pos += p.length);
				privBuf.set(q, pos += 4);
				const pubBuf = Buffer.allocUnsafe(4 + keyName.length + 4 + e.length + 4 + n.length);
				pos = 0;
				pubBuf.writeUInt32BE(keyName.length, pos += 0);
				pubBuf.set(keyName, pos += 4);
				pubBuf.writeUInt32BE(e.length, pos += keyName.length);
				pubBuf.set(e, pos += 4);
				pubBuf.writeUInt32BE(n.length, pos += e.length);
				pubBuf.set(n, pos += 4);
				return {
					sshName: keyName.toString(),
					priv: privBuf,
					pub: pubBuf
				};
			}
			case "ec": {
				let reader = new Ber.Reader(pub);
				reader.readSequence();
				reader.readSequence();
				if (reader.readOID() !== "1.2.840.10045.2.1") throw new Error("Bad ECDSA public OID");
				reader.readOID();
				let pubBin = reader.readString(Ber.BitString, true);
				{
					let i = 0;
					for (; i < pubBin.length && pubBin[i] === 0; ++i);
					if (i > 0) pubBin = pubBin.slice(i);
				}
				reader = new Ber.Reader(priv);
				reader.readSequence();
				if (reader.readInt() !== 0) throw new Error("Unsupported version in ECDSA private key");
				reader.readSequence();
				if (reader.readOID() !== "1.2.840.10045.2.1") throw new Error("Bad ECDSA private OID");
				const curveOID = reader.readOID();
				let sshCurveName;
				switch (curveOID) {
					case "1.2.840.10045.3.1.7":
						sshCurveName = "nistp256";
						break;
					case "1.3.132.0.34":
						sshCurveName = "nistp384";
						break;
					case "1.3.132.0.35":
						sshCurveName = "nistp521";
						break;
					default: throw new Error("Unsupported curve in ECDSA private key");
				}
				reader = new Ber.Reader(reader.readString(Ber.OctetString, true));
				reader.readSequence();
				if (reader.readInt() !== 1) throw new Error("Unsupported version in ECDSA private key");
				const privBin = Buffer.concat([Buffer.from([0]), reader.readString(Ber.OctetString, true)]);
				const keyName = Buffer.from(`ecdsa-sha2-${sshCurveName}`);
				sshCurveName = Buffer.from(sshCurveName);
				const privBuf = Buffer.allocUnsafe(4 + keyName.length + 4 + sshCurveName.length + 4 + pubBin.length + 4 + privBin.length);
				let pos = 0;
				privBuf.writeUInt32BE(keyName.length, pos += 0);
				privBuf.set(keyName, pos += 4);
				privBuf.writeUInt32BE(sshCurveName.length, pos += keyName.length);
				privBuf.set(sshCurveName, pos += 4);
				privBuf.writeUInt32BE(pubBin.length, pos += sshCurveName.length);
				privBuf.set(pubBin, pos += 4);
				privBuf.writeUInt32BE(privBin.length, pos += pubBin.length);
				privBuf.set(privBin, pos += 4);
				const pubBuf = Buffer.allocUnsafe(4 + keyName.length + 4 + sshCurveName.length + 4 + pubBin.length);
				pos = 0;
				pubBuf.writeUInt32BE(keyName.length, pos += 0);
				pubBuf.set(keyName, pos += 4);
				pubBuf.writeUInt32BE(sshCurveName.length, pos += keyName.length);
				pubBuf.set(sshCurveName, pos += 4);
				pubBuf.writeUInt32BE(pubBin.length, pos += sshCurveName.length);
				pubBuf.set(pubBin, pos += 4);
				return {
					sshName: keyName.toString(),
					priv: privBuf,
					pub: pubBuf
				};
			}
			case "ed25519": {
				let reader = new Ber.Reader(pub);
				reader.readSequence();
				reader.readSequence();
				if (reader.readOID() !== "1.3.101.112") throw new Error("Bad ED25519 public OID");
				let pubBin = reader.readString(Ber.BitString, true);
				{
					let i = 0;
					for (; i < pubBin.length && pubBin[i] === 0; ++i);
					if (i > 0) pubBin = pubBin.slice(i);
				}
				reader = new Ber.Reader(priv);
				reader.readSequence();
				if (reader.readInt() !== 0) throw new Error("Unsupported version in ED25519 private key");
				reader.readSequence();
				if (reader.readOID() !== "1.3.101.112") throw new Error("Bad ED25519 private OID");
				reader = new Ber.Reader(reader.readString(Ber.OctetString, true));
				const privBin = reader.readString(Ber.OctetString, true);
				const keyName = Buffer.from("ssh-ed25519");
				const privBuf = Buffer.allocUnsafe(4 + keyName.length + 4 + pubBin.length + 4 + (privBin.length + pubBin.length));
				let pos = 0;
				privBuf.writeUInt32BE(keyName.length, pos += 0);
				privBuf.set(keyName, pos += 4);
				privBuf.writeUInt32BE(pubBin.length, pos += keyName.length);
				privBuf.set(pubBin, pos += 4);
				privBuf.writeUInt32BE(privBin.length + pubBin.length, pos += pubBin.length);
				privBuf.set(privBin, pos += 4);
				privBuf.set(pubBin, pos += privBin.length);
				const pubBuf = Buffer.allocUnsafe(4 + keyName.length + 4 + pubBin.length);
				pos = 0;
				pubBuf.writeUInt32BE(keyName.length, pos += 0);
				pubBuf.set(keyName, pos += 4);
				pubBuf.writeUInt32BE(pubBin.length, pos += keyName.length);
				pubBuf.set(pubBin, pos += 4);
				return {
					sshName: keyName.toString(),
					priv: privBuf,
					pub: pubBuf
				};
			}
		}
	}
	function convertKeys(keyType, pub, priv, opts) {
		let format = "new";
		let encrypted;
		let comment = "";
		if (typeof opts === "object" && opts !== null) {
			if (typeof opts.comment === "string" && opts.comment) comment = opts.comment;
			if (typeof opts.format === "string" && opts.format) format = opts.format;
			if (opts.passphrase) {
				let passphrase;
				if (typeof opts.passphrase === "string") passphrase = Buffer.from(opts.passphrase);
				else if (Buffer.isBuffer(opts.passphrase)) passphrase = opts.passphrase;
				else throw new Error("Invalid passphrase");
				if (opts.cipher === void 0) throw new Error("Missing cipher name");
				const cipher = ciphers.get(opts.cipher);
				if (cipher === void 0) throw new Error("Invalid cipher name");
				if (format === "new") {
					let rounds = DEFAULT_ROUNDS;
					if (opts.rounds !== void 0) {
						if (!Number.isInteger(opts.rounds)) throw new TypeError("rounds must be an integer");
						if (opts.rounds > 0) rounds = opts.rounds;
					}
					const gen = Buffer.allocUnsafe(cipher.keyLen + cipher.ivLen);
					const salt = randomBytes(SALT_LEN);
					if (bcrypt_pbkdf(passphrase, passphrase.length, salt, salt.length, gen, gen.length, rounds) !== 0) return /* @__PURE__ */ new Error("Failed to generate information to encrypt key");
					const kdfOptions = Buffer.allocUnsafe(4 + salt.length + 4);
					{
						let pos = 0;
						kdfOptions.writeUInt32BE(salt.length, pos += 0);
						kdfOptions.set(salt, pos += 4);
						kdfOptions.writeUInt32BE(rounds, pos += salt.length);
					}
					encrypted = {
						cipher,
						cipherName: opts.cipher,
						kdfName: "bcrypt",
						kdfOptions,
						key: gen.slice(0, cipher.keyLen),
						iv: gen.slice(cipher.keyLen)
					};
				}
			}
		}
		switch (format) {
			case "new": {
				let privateB64 = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
				let publicB64;
				const cipherName = Buffer.from(encrypted ? encrypted.cipherName : "none");
				const kdfName = Buffer.from(encrypted ? encrypted.kdfName : "none");
				const kdfOptions = encrypted ? encrypted.kdfOptions : Buffer.alloc(0);
				const blockLen = encrypted ? encrypted.cipher.blockLen : 8;
				const parsed = parseDERs(keyType, pub, priv);
				const checkInt = randomBytes(4);
				const commentBin = Buffer.from(comment);
				const privBlobLen = 8 + parsed.priv.length + 4 + commentBin.length;
				let padding = [];
				for (let i = 1; (privBlobLen + padding.length) % blockLen; ++i) padding.push(i & 255);
				padding = Buffer.from(padding);
				let privBlob = Buffer.allocUnsafe(privBlobLen + padding.length);
				let extra;
				{
					let pos = 0;
					privBlob.set(checkInt, pos += 0);
					privBlob.set(checkInt, pos += 4);
					privBlob.set(parsed.priv, pos += 4);
					privBlob.writeUInt32BE(commentBin.length, pos += parsed.priv.length);
					privBlob.set(commentBin, pos += 4);
					privBlob.set(padding, pos += commentBin.length);
				}
				if (encrypted) {
					const options = { authTagLength: encrypted.cipher.authLen };
					const cipher = createCipheriv(encrypted.cipher.sslName, encrypted.key, encrypted.iv, options);
					cipher.setAutoPadding(false);
					privBlob = Buffer.concat([cipher.update(privBlob), cipher.final()]);
					if (encrypted.cipher.authLen > 0) extra = cipher.getAuthTag();
					else extra = Buffer.alloc(0);
					encrypted.key.fill(0);
					encrypted.iv.fill(0);
				} else extra = Buffer.alloc(0);
				const magicBytes = Buffer.from("openssh-key-v1\0");
				const privBin = Buffer.allocUnsafe(magicBytes.length + 4 + cipherName.length + 4 + kdfName.length + 4 + kdfOptions.length + 4 + 4 + parsed.pub.length + 4 + privBlob.length + extra.length);
				{
					let pos = 0;
					privBin.set(magicBytes, pos += 0);
					privBin.writeUInt32BE(cipherName.length, pos += magicBytes.length);
					privBin.set(cipherName, pos += 4);
					privBin.writeUInt32BE(kdfName.length, pos += cipherName.length);
					privBin.set(kdfName, pos += 4);
					privBin.writeUInt32BE(kdfOptions.length, pos += kdfName.length);
					privBin.set(kdfOptions, pos += 4);
					privBin.writeUInt32BE(1, pos += kdfOptions.length);
					privBin.writeUInt32BE(parsed.pub.length, pos += 4);
					privBin.set(parsed.pub, pos += 4);
					privBin.writeUInt32BE(privBlob.length, pos += parsed.pub.length);
					privBin.set(privBlob, pos += 4);
					privBin.set(extra, pos += privBlob.length);
				}
				{
					const b64 = privBin.base64Slice(0, privBin.length);
					let formatted = b64.replace(/.{64}/g, "$&\n");
					if (b64.length & 63) formatted += "\n";
					privateB64 += formatted;
				}
				{
					const b64 = parsed.pub.base64Slice(0, parsed.pub.length);
					publicB64 = `${parsed.sshName} ${b64}${comment ? ` ${comment}` : ""}`;
				}
				privateB64 += "-----END OPENSSH PRIVATE KEY-----\n";
				return {
					private: privateB64,
					public: publicB64
				};
			}
			default: throw new Error("Invalid output key format");
		}
	}
	function noop() {}
	module.exports = {
		generateKeyPair: (keyType, opts, cb) => {
			if (typeof opts === "function") {
				cb = opts;
				opts = void 0;
			}
			if (typeof cb !== "function") cb = noop;
			const args = makeArgs(keyType, opts);
			generateKeyPair_(...args, (err, pub, priv) => {
				if (err) return cb(err);
				let ret;
				try {
					ret = convertKeys(args[0], pub, priv, opts);
				} catch (ex) {
					return cb(ex);
				}
				cb(null, ret);
			});
		},
		generateKeyPairSync: (keyType, opts) => {
			const args = makeArgs(keyType, opts);
			const { publicKey: pub, privateKey: priv } = generateKeyPairSync_(...args);
			return convertKeys(args[0], pub, priv, opts);
		}
	};
}));
//#endregion
//#region src/paths.ts
var import_lib = /* @__PURE__ */ __toESM((/* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { AgentProtocol, BaseAgent, createAgent, CygwinAgent, OpenSSHAgent, PageantAgent } = require_agent();
	const { SSHTTPAgent: HTTPAgent, SSHTTPSAgent: HTTPSAgent } = require_http_agents();
	const { parseKey } = require_keyParser();
	const { flagsToString, OPEN_MODE, STATUS_CODE, stringToFlags } = require_SFTP();
	module.exports = {
		AgentProtocol,
		BaseAgent,
		createAgent,
		Client: require_client(),
		CygwinAgent,
		HTTPAgent,
		HTTPSAgent,
		OpenSSHAgent,
		PageantAgent,
		Server: require_server(),
		utils: {
			parseKey,
			...require_keygen(),
			sftp: {
				flagsToString,
				OPEN_MODE,
				STATUS_CODE,
				stringToFlags
			}
		}
	};
})))(), 1);
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
const { Client } = import_lib.default;
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
* Machine registry: the durable list of saved SSH machines. Pure functions
* over a file path so tests drive real files. Saved machines are STANDBY
* connections; which machine serves a workspace is decided by that
* workspace's anchor alone — the registry holds no "current" pointer.
* @module dsh-remote-development/registry
*/
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
			machines: []
		};
		const machines = raw.machines.map((m) => sanitizeMachine(m));
		return {
			version: REGISTRY_VERSION,
			machines
		};
	} catch {
		return {
			version: REGISTRY_VERSION,
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
* Whether the registry file exists at all.
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
		saveRegistry(this.registryFile, this.registry);
		const key = [...this.pools.keys()].find((k) => k.startsWith(id + "\0"));
		if (key) {
			this.pools.get(key)?.close();
			this.pools.delete(key);
		}
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
/**
* The refusal message for an anchor whose machine is no longer configured.
* Anchors survive machine deletion (their metadata is durable), but without
* a matching registry/config identity nothing may act on them — callers
* surface this instead of silently falling back to another machine or the
* local host.
* @param anchor - the orphaned anchor.
* @returns the user-facing error message.
*/
function unconfiguredMachineMessage(anchor) {
	return `the machine ${`${anchor.meta.username || "user"}@${anchor.meta.host}:${anchor.meta.port}`} behind remote workspace "${anchor.dir}" is no longer configured — re-add it in the remote development settings, or delete the workspace directory`;
}
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
	* command output), then the local backend. An anchor whose machine is no
	* longer configured refuses instead of falling back — serving the anchor
	* directory locally would silently act on the wrong host.
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
			throw new FsError(unconfiguredMachineMessage(local.route.anchor), "FS_IO_ERROR");
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
				throw new FsError(unconfiguredMachineMessage(remote.anchor), "FS_IO_ERROR");
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
	/**
	* The refusal for a target whose machine record is gone. The identity is
	* parsed from the machine id (`host|port|user`) so the message names the
	* machine even though the registry entry no longer exists.
	* @param displayPath - the model-facing path.
	* @param machineId - the machine id from the target key.
	* @returns the typed filesystem error.
	*/
	static unconfiguredTarget(displayPath, machineId) {
		const [host = "?", port = "?", username = "?"] = machineId.split("|");
		return new FsError(`the machine ${username}@${host}:${port} behind "${displayPath}" is no longer configured — re-add it in the remote development settings, or delete the workspace directory`, "FS_IO_ERROR");
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
		if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId);
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
		if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId);
		return readRemoteText(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs, this.maxFileBytes);
	}
	async streamText(target, signal) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.streamText(target, signal);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId);
		return streamRemoteText(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs, this.maxFileBytes);
	}
	async readBytes(target, signal, maxBytes) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.readBytes(target, signal, maxBytes);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId);
		return readRemoteBytes(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs, maxBytes);
	}
	async listDir(target, signal) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.listDir(target, signal);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId);
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
		if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId);
		this.checkRemoteMutation(remote.remotePath, target.displayPath, sandboxPolicy);
		return this.lockRemote(target.targetKey, async () => writeRemoteText(await this.sftpFor(machine), remote.remotePath, content, expected, signal, this.opTimeoutMs));
	}
	async editText(target, edit, expected, signal, sandboxPolicy) {
		const remote = RoutingFileSystem.parseKey(target);
		if (remote === null) return super.editText(target, edit, expected, signal, sandboxPolicy);
		const machine = this.world.machineById(remote.machineId);
		if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId);
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
* The routing subprocess runtime. Construction registers `ctx.subprocess`;
* the workdir classification alone decides between the remote branch and the
* inherited local runtime, so routing behavior is identical on every host
* platform.
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
		const route = this.world.classifyHostPath(spec.cwd);
		if (route.kind !== "remote") return super.spawn(spec);
		const machine = this.world.machineForAnchor(route.route.anchor);
		if (!machine) throw new Error(unconfiguredMachineMessage(route.route.anchor));
		return new RemoteSpawnHandle(this.world, machine, spec);
	}
	async spawnTerminal(spec) {
		if (this.world.classifyHostPath(spec.cwd).kind === "remote") throw new Error("remote terminal sessions are not supported by dsh-remote-development yet. Use the bash tool to run commands on the remote host instead.");
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
/**
* The remote branch shared by both routing executors: workdir classification,
* remote script composition, and foreground/background execution over the SSH
* exec channel. Each host-platform executor owns its local fallback and
* delegates every anchor-routed command here.
*/
var RemoteShellBranch = class {
	world;
	/**
	* @param world - the remote world coordinator.
	*/
	constructor(world) {
		this.world = world;
	}
	/**
	* Resolve the remote path for a workdir, accepting both coordinates: the
	* anchor-local spelling (session cwd) and a remote path the model saw in
	* command output. An anchor whose machine is no longer configured refuses
	* instead of falling back — running the command locally would silently act
	* on the wrong host.
	* @param workdir - the resolved local workdir.
	* @returns the machine and remote cwd, or null for the local backend.
	*/
	routeOf(workdir) {
		const local = this.world.classifyHostPath(workdir);
		if (local.kind === "remote") {
			const machine = this.world.machineForAnchor(local.route.anchor);
			if (machine) return {
				machine,
				remotePath: local.route.remotePath
			};
			throw new Error(unconfiguredMachineMessage(local.route.anchor));
		}
		const remote = this.world.classifyRemotePath(workdir);
		if (remote) {
			const machine = this.world.machineForAnchor(remote.anchor);
			if (machine) return {
				machine,
				remotePath: remote.remotePath
			};
			throw new Error(unconfiguredMachineMessage(remote.anchor));
		}
		return null;
	}
	/**
	* Run one command on its remote machine.
	* @param spec - the resolved shell spec.
	* @param route - the machine and remote cwd for the workdir.
	* @param sandboxMode - the executor's default sandbox mode, reported as the
	*   remote run's mode when the spec carries no per-call policy.
	* @returns the remote outcome with non-enforcing sandbox facts.
	*/
	async run(spec, route, sandboxMode) {
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
				mode: spec.sandboxPolicy?.mode ?? sandboxMode ?? "danger-full-access",
				denied: false
			}
		};
	}
	/**
	* Start one remote background process.
	* @param spec - the resolved shell spec.
	* @param route - the machine and remote cwd for the workdir.
	* @returns the live remote process handle.
	*/
	start(spec, route) {
		const pool = this.world.poolFor(route.machine);
		const command = `bash -c ${shq(this.script(route, spec, [`printf '${PID_MARKER}%s\\n' "$$"`]))}`;
		return new RemoteBackgroundProcess(this.world, route.machine, command, spec, pool.tunables.maxOutputChars);
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
};
/** The POSIX-host routing executor: local workdirs stay with local bash. */
var RoutingBashExecutor = class extends SandboxBashExecutor {
	branch;
	/**
	* @param ctx - plugin context.
	* @param config - the inherited executor config (defaults).
	* @param world - the remote world coordinator.
	*/
	constructor(ctx, config, world) {
		super(ctx, config);
		this.branch = new RemoteShellBranch(world);
	}
	async run(spec) {
		const route = this.branch.routeOf(spec.workdir);
		if (!route) return super.run(spec);
		return this.branch.run(spec, route, this.sandboxMode);
	}
	start(spec) {
		const route = this.branch.routeOf(spec.workdir);
		if (!route) return super.start(spec);
		return this.branch.start(spec, route);
	}
};
/**
* The win32-host routing executor: local workdirs keep the inherited pwsh
* executor (confinement, encoding, and settings included); anchor workdirs
* cross to the remote host's bash.
*/
var RoutingPwshExecutor = class extends SandboxPwshExecutor {
	branch;
	/**
	* @param ctx - plugin context.
	* @param config - the inherited executor config (defaults).
	* @param world - the remote world coordinator.
	*/
	constructor(ctx, config, world) {
		super(ctx, config);
		this.branch = new RemoteShellBranch(world);
	}
	async run(spec) {
		const route = this.branch.routeOf(spec.workdir);
		if (!route) return super.run(spec);
		return this.branch.run(spec, route, this.sandboxMode);
	}
	start(spec) {
		const route = this.branch.routeOf(spec.workdir);
		if (!route) return super.start(spec);
		return this.branch.start(spec, route);
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
			if (!machine) return [
				"## Remote workspace (unavailable)",
				`This session's workspace directory is a handle for a remote workspace on ${`${anchor.meta.username || "user"}@${anchor.meta.host}:${anchor.meta.port}`}, but that machine is no longer configured.`,
				"File and shell tools refuse to act on it until the machine is re-added in the remote development settings, or the workspace directory is deleted.",
				"Tell the operator why operations fail instead of retrying them."
			].join("\n");
			const who = `${machine.machine.username || "user"}@${machine.machine.host}`;
			const name = remoteBasename(local.route.remotePath) || local.route.remotePath;
			return [
				"## Remote workspace",
				`This session's workspace is a remote directory: ${who}:${local.route.remotePath} ("${name}").`,
				"All file tools (read/write/edit/ls/grep/glob) and shell commands operate on that remote host directly.",
				"Shell commands run through bash on the remote host; the pwsh tool does not apply to this workspace.",
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
				if (local.kind !== "remote") return cwd;
				return world.machineForAnchor(local.route.anchor) ? local.route.remotePath : cwd;
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
//#region src/tool-visibility.ts
/**
* The global shell tools one session must not see.
* @param world - the remote world coordinator (path classification).
* @param cwd - the session's durable working directory, when attached.
* @param registered - whether a global tool name is registered at all; a
*   name the composition never mounted must not enter the deny list (the
*   restriction API rejects unknown names).
* @param localPlatform - the host platform: the local-session deny applies
*   only where the local dialect is pwsh and the plugin's patch added bash.
* @returns the tool names to deny, empty when no restriction applies.
*/
function denyListFor(world, cwd, registered, localPlatform) {
	if (!cwd) return [];
	if (world.classifyHostPath(cwd).kind === "remote") return ["pwsh"].filter(registered);
	if (localPlatform === "win32") return ["bash"].filter(registered);
	return [];
}
/**
* Install the per-agent visibility restriction for every agent, present and
* future. The fiber lives in the agent's context, so agent disposal
* unregisters it (the same discipline as the prompt module's cwd override).
* @param ctx - plugin context.
* @param world - the remote world coordinator.
*/
function registerToolVisibility(ctx, world) {
	const fibers = /* @__PURE__ */ new Map();
	const install = (agent) => {
		if (fibers.has(agent)) return;
		fibers.set(agent, agent.ctx.inject(["tools"], (scope) => {
			const deny = denyListFor(world, agent.session?.header?.cwd, (name) => scope.tools.get(name) !== void 0, process.platform);
			if (deny.length === 0) return;
			scope.tools.restrict({ deny });
		}));
	};
	const dispose = (agent) => {
		const fiber = fibers.get(agent);
		if (fiber === void 0) return;
		fibers.delete(agent);
		fiber.dispose().catch((error) => {
			ctx.logger.warn(`dsh-remote-development: tool visibility cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
		});
	};
	for (const agent of ctx.agents.list()) install(agent);
	ctx.on("agent/session-start", ({ agent }) => {
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
	const machineIdOf = (body) => String(body.machineId ?? body.id ?? "");
	const resolveRef = (body) => {
		const id = machineIdOf(body);
		return id ? world.machineById(id) : null;
	};
	const refError = (body) => {
		const id = machineIdOf(body);
		return id ? `no saved machine matches machineId "${id}"` : "machineId is required";
	};
	const disposers = [
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/machines`,
			handler: async (req, res) => {
				if (req.method === "GET") return sendJson(res, 200, { machines: world.listMachines().map(publicMachine) });
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
				const id = machineIdOf(body);
				let ref;
				if (id) {
					const saved = world.machineById(id);
					if (!saved) return sendJson(res, 400, {
						ok: false,
						error: `no saved machine matches machineId "${id}"`
					});
					ref = saved;
				} else if (String(body.host ?? "").trim()) ref = world.ephemeralRef(machineFromBody(body));
				else return sendJson(res, 400, {
					ok: false,
					error: "machineId is required"
				});
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
					error: refError(body)
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
					error: refError(body)
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
					error: refError(body)
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
			path: `${ROUTE_PREFIX}/picker`,
			handler: async (_req, res) => {
				const picker = ctx.get("directoryPicker");
				let kind = "unknown";
				try {
					const probed = picker?.capability?.().kind;
					if (probed === "native" || probed === "browse") kind = probed;
				} catch {}
				return sendJson(res, 200, { kind });
			}
		},
		{
			kind: "exact",
			path: `${ROUTE_PREFIX}/status`,
			handler: async (_req, res) => {
				return sendJson(res, 200, { anchors: world.anchors().map((a) => ({
					dir: a.dir,
					remotePath: a.remoteRoot
				})) });
			}
		}
	].map((route) => webServer.register(route));
	ctx.effect(() => () => disposers.forEach((dispose) => dispose()), "dsh-remote-development.routes");
}
//#endregion
//#region src/index.ts
const name = "dsh-remote-development";
/**
* Service dependencies, declared at module level because this is a namespace
* plugin: the Loader builds the fiber's inject from this list, and the
* `static inject` of the manually constructed provider classes is ignored.
* Every service those classes read directly must appear here or the
* ancestor-only fiber walk throws "cannot get property … without inject":
*   • systemPrompt — the prompt section registers on it.
*   • sandboxPolicy — both routing executors and SandboxedFileSystem read it.
*   • sandbox — the routing executors wrap every local command through
*     `ctx.sandbox.confine`; without the declaration the walk from this
*     plugin's fiber reaches root and every shell call crashes (the incident
*     behind the 2025-07 bash-tool outage).
*   • agents — the per-agent cwd override and tool visibility enumerate live
*     agents.
* (`subprocess` is read by the local executor halves too, but this plugin
* provides `ctx.subprocess` itself, so its own store satisfies the walk.)
*/
const inject = [
	"systemPrompt",
	"sandboxPolicy",
	"sandbox",
	"agents"
];
/** Local-backend defaults used when constructing the routing providers by hand. */
const LOCAL_FS_DIFF_BASIS_MAX_BYTES = 10485760;
const SHELL_TIMEOUT_MS = 12e4;
const SHELL_MAX_TIMEOUT_MS = 6e5;
const SHELL_MAX_OUTPUT_BYTES = 64e3;
const SHELL_MAX_SPILL_BYTES = 67108864;
const SHELL_GRACE_MS = 3e3;
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
	const shellBudgets = {
		cwd: process.cwd(),
		timeoutMs: SHELL_TIMEOUT_MS,
		maxTimeoutMs: SHELL_MAX_TIMEOUT_MS,
		maxOutputBytes: SHELL_MAX_OUTPUT_BYTES,
		maxSpillBytes: SHELL_MAX_SPILL_BYTES,
		graceMs: SHELL_GRACE_MS
	};
	if (process.platform === "win32") new RoutingPwshExecutor(ctx, shellBudgets, world);
	else new RoutingBashExecutor(ctx, shellBudgets, world);
	registerPrompt(ctx, world);
	registerToolVisibility(ctx, world);
	ctx.inject(["webServer"], (serviceCtx) => {
		registerRoutes(serviceCtx, serviceCtx.webServer, world);
	});
}
//#endregion
export { Config, apply, inject, name };

//# sourceMappingURL=index.js.map