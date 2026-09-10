/**
 * Remote file operations over one SFTP channel, mirroring the `ctx.fs`
 * contract the local backend implements: text reads with binary rejection,
 * LF-normalized edit bases with CRLF write-back, atomic publication via
 * temp-file + rename, and version guards derived from stat identity.
 *
 * Every function takes an `SFTPWrapper` so tests run against fakes; none of
 * them resolves paths (the router maps coordinates before calling in).
 * @module dsh-remote-development/remote-io
 */

import type { FileEntryWithStats, SFTPWrapper, Stats } from 'ssh2'
import { FsError, FsVersion } from '@deepseek-ai/dsh-fs'
import type { FsEditRequest, FsInfo, FsPathInfo, FsWriteIntent } from '@deepseek-ai/dsh-fs'
import { remoteDirname } from './paths.ts'

/** Thrown by sftp calls that exceed their deadline. */
class SftpTimeoutError extends Error {
  constructor(op: string) {
    super(`sftp ${op} timed out`)
    this.name = 'SftpTimeoutError'
  }
}

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
export function sftpCall<T>(
  op: string,
  signal: AbortSignal | undefined,
  timeoutMs: number,
  run: (cb: (err: Error | null, value: T) => void) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false
    let timer: NodeJS.Timeout | undefined
    const finish = (err: Error | null, value: T | undefined): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      offAbort()
      if (err) reject(mapSftpError(err, op))
      else resolve(value as T)
    }
    const onAbort = (): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(new FsError('remote file operation aborted', 'FS_ABORTED'))
    }
    const offAbort = attachAbort(signal, onAbort)
    timer = setTimeout(() => finish(new SftpTimeoutError(op), undefined), timeoutMs)
    try {
      run((err, value) => finish(err, value))
    } catch (err) {
      finish(err as Error, undefined)
    }
  })
}

function attachAbort(signal: AbortSignal | undefined, fn: () => void): () => void {
  if (!signal) return () => {}
  if (signal.aborted) {
    fn()
    return () => {}
  }
  const listener = (): void => fn()
  signal.addEventListener('abort', listener, { once: true })
  return () => signal.removeEventListener('abort', listener)
}

/** SFTP wire status codes (SSH_FX_*) the mapping recognizes. */
const SFTP_NO_SUCH = new Set([2, 10])
const SFTP_PERMISSION = new Set([3])

/** Map a raw SFTP error onto the fs error taxonomy where the code is known.
 * ssh2 surfaces numeric SSH_FX_* codes; errno-style string codes appear on
 * fakes and some servers. */
function mapSftpError(err: Error, op: string): Error {
  const code = (err as NodeJS.ErrnoException).code
  const numeric = typeof code === 'number' ? code : undefined
  if (typeof code === 'string' && (code === 'ENOENT' || code === 'ENOTDIR')) {
    return new FsError(err.message, code === 'ENOTDIR' ? 'FS_NOT_DIRECTORY' : 'FS_NOT_FOUND')
  }
  if (numeric !== undefined && SFTP_NO_SUCH.has(numeric)) {
    return new FsError(err.message, 'FS_NOT_FOUND')
  }
  if ((typeof code === 'string' && (code === 'EACCES' || code === 'EPERM')) || (numeric !== undefined && SFTP_PERMISSION.has(numeric))) {
    return new FsError(err.message, 'FS_PERMISSION_DENIED')
  }
  return new FsError(`${op} failed: ${err.message}`, 'FS_IO_ERROR', { cause: err })
}

/**
 * The freshness token for a remote file: stat identity, stable across aliases.
 * @param stats - the SFTP stat result.
 * @returns the branded version string.
 */
export function versionOf(stats: Stats): FsVersion {
  return FsVersion(`${Math.floor(Number(stats.mtime) * 1000)}-${stats.size}`)
}

/** The fs metadata type for one stat result. */
function typeOf(stats: Stats, symlink: boolean): FsInfo['type'] | FsPathInfo['type'] {
  if (symlink) return 'symlink'
  if (stats.isDirectory()) return 'directory'
  if (stats.isFile()) return 'file'
  return 'other'
}

/**
 * Stat a remote path (follows symlinks).
 * @param sftp - the SFTP channel.
 * @param p - remote path.
 * @param signal - abort hook.
 * @param timeoutMs - operation deadline.
 * @returns metadata, or undefined when absent.
 */
export async function statPath(sftp: SFTPWrapper, p: string, signal: AbortSignal | undefined, timeoutMs: number): Promise<FsInfo | undefined> {
  try {
    const stats = await sftpCall<Stats>('stat', signal, timeoutMs, (cb) => sftp.stat(p, cb as never))
    return { version: versionOf(stats), type: typeOf(stats, false) as FsInfo['type'], size: stats.size }
  } catch (err) {
    if ((err as FsError).code === 'FS_NOT_FOUND') return undefined
    throw err
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
export async function lstatPath(sftp: SFTPWrapper, p: string, signal: AbortSignal | undefined, timeoutMs: number): Promise<FsPathInfo | undefined> {
  try {
    const stats = await sftpCall<Stats>('lstat', signal, timeoutMs, (cb) => sftp.lstat(p, cb as never))
    return { version: versionOf(stats), type: typeOf(stats, stats.isSymbolicLink()) as FsPathInfo['type'], size: stats.size }
  } catch (err) {
    if ((err as FsError).code === 'FS_NOT_FOUND') return undefined
    throw err
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
export async function listRemoteDir(
  sftp: SFTPWrapper,
  dir: string,
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<{ name: string; type: FsInfo['type']; size?: number; version?: FsVersion }[]> {
  const entries = await sftpCall<FileEntryWithStats[]>(
    'readdir',
    signal,
    timeoutMs,
    (cb) => sftp.readdir(dir, cb as never),
  )
  return entries.map((e) => ({
    name: e.filename,
    type: typeOf(e.attrs, e.attrs.isSymbolicLink()) as FsInfo['type'],
    ...(e.attrs.isFile() ? { size: e.attrs.size } : {}),
    version: versionOf(e.attrs),
  }))
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
export async function readRemoteBytes(sftp: SFTPWrapper, p: string, signal: AbortSignal | undefined, timeoutMs: number, maxBytes: number): Promise<Uint8Array> {
  const stats = await sftpCall<Stats>('stat', signal, timeoutMs, (cb) => sftp.stat(p, cb as never))
  if (!stats.isFile()) throw new FsError(`"${p}" is not a regular file`, 'FS_NOT_REGULAR_FILE')
  if (maxBytes > 0 && stats.size > maxBytes) {
    throw new FsError(`"${p}" is ${stats.size} bytes, above the ${maxBytes}-byte read cap`, 'FS_TOO_LARGE')
  }
  return sftpCall<Buffer>('readFile', signal, timeoutMs, (cb) => sftp.readFile(p, cb as never))
}

/**
 * Read one byte window of a remote file. The window is the bound, not the
 * file: only the requested range transfers, the result truncates at the
 * file's end, and an offset past the end yields nothing. No whole-file cap
 * applies — the Host sizes the window before calling.
 * @param sftp - the SFTP channel.
 * @param p - remote path.
 * @param range - `offset`, the 0-based first byte, and `length`, the largest byte count.
 * @param signal - abort hook.
 * @param timeoutMs - deadline for the whole window read.
 * @returns the window's bytes, at most `length` long.
 */
export async function readRemoteByteWindow(
  sftp: SFTPWrapper,
  p: string,
  range: { offset: number; length: number },
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<Uint8Array> {
  if (range.length === 0) return new Uint8Array(0)
  if (signal?.aborted) throw new FsError('remote file read aborted', 'FS_ABORTED')
  const stream = sftp.createReadStream(p, { start: range.offset, end: range.offset + range.length - 1, autoClose: true })
  const chunks: Buffer[] = []
  const timer = setTimeout(() => stream.destroy(new SftpTimeoutError('read window')), timeoutMs)
  const offAbort = attachAbort(signal, () => stream.destroy(new FsError('remote file read aborted', 'FS_ABORTED')))
  try {
    for await (const chunk of stream as AsyncIterable<Buffer>) {
      chunks.push(chunk)
    }
  } catch (err) {
    // Our own refusals keep their codes; server errors map onto the taxonomy.
    if (err instanceof FsError || err instanceof SftpTimeoutError) throw err
    throw mapSftpError(err as Error, 'read window')
  } finally {
    clearTimeout(timer)
    offAbort()
    stream.destroy()
  }
  return new Uint8Array(Buffer.concat(chunks))
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
export async function readRemoteText(sftp: SFTPWrapper, p: string, signal: AbortSignal | undefined, timeoutMs: number, maxBytes: number): Promise<string> {
  const bytes = await readRemoteBytes(sftp, p, signal, timeoutMs, maxBytes)
  return decodeStrict(bytes, p)
}

/** Decode UTF-8 strictly; a NUL byte or invalid sequence is a text refusal. */
function decodeStrict(bytes: Uint8Array, p: string): string {
  if (bytes.includes(0)) throw new FsError(`cannot read "${p}": binary file`, 'FS_NOT_TEXT')
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new FsError(`cannot read "${p}": not valid UTF-8 text`, 'FS_NOT_TEXT')
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
export function streamRemoteText(sftp: SFTPWrapper, p: string, signal: AbortSignal | undefined, timeoutMs: number, maxBytes: number): AsyncIterable<string> {
  async function* generate(): AsyncGenerator<string> {
    const stats = await sftpCall<Stats>('stat', signal, timeoutMs, (cb) => sftp.stat(p, cb as never))
    if (!stats.isFile()) throw new FsError(`"${p}" is not a regular file`, 'FS_NOT_REGULAR_FILE')
    if (maxBytes > 0 && stats.size > maxBytes) {
      throw new FsError(`"${p}" is ${stats.size} bytes, above the ${maxBytes}-byte read cap`, 'FS_TOO_LARGE')
    }
    const stream = sftp.createReadStream(p)
    const decoder = new TextDecoder('utf-8', { fatal: false })
    let pending = new Uint8Array(0)
    let sawBinary = false
    try {
      for await (const chunk of stream as AsyncIterable<Buffer>) {
        if (signal?.aborted) throw new FsError('remote file read aborted', 'FS_ABORTED')
        const bytes = new Uint8Array(chunk)
        if (bytes.includes(0)) {
          sawBinary = true
          break
        }
        const merged = mergeBytes(pending, bytes)
        // Keep the trailing bytes that may continue a multibyte sequence.
        const safe = merged.length >= 4 ? merged.length - 3 : 0
        pending = merged.slice(safe)
        const text = decoder.decode(merged.slice(0, safe))
        if (text) yield text
      }
    } finally {
      stream.destroy()
    }
    if (sawBinary) throw new FsError(`cannot read "${p}": binary file`, 'FS_NOT_TEXT')
    try {
      const tail = decoder.decode()
      if (tail) yield tail
    } catch {
      throw new FsError(`cannot read "${p}": not valid UTF-8 text`, 'FS_NOT_TEXT')
    }
  }
  return generate()
}

function mergeBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

/**
 * Create parent directories for a remote path (mkdir -p semantics).
 * @param sftp - the SFTP channel.
 * @param dir - deepest directory to ensure.
 * @param signal - abort hook.
 * @param timeoutMs - per-mkdir deadline.
 */
export async function ensureRemoteDirs(sftp: SFTPWrapper, dir: string, signal: AbortSignal | undefined, timeoutMs: number): Promise<void> {
  const parts = dir.split('/').filter(Boolean)
  let cur = dir.startsWith('/') ? '' : '.'
  for (const part of parts) {
    cur = cur === '' ? '/' + part : (cur === '.' ? part : cur + '/' + part)
    try {
      await sftpCall('mkdir', signal, timeoutMs, (cb) => sftp.mkdir(cur, cb as never))
    } catch (err) {
      const code = (err as FsError).code
      if (code === 'FS_IO_ERROR' || code === 'FS_NOT_DIRECTORY') {
        // An existing directory also surfaces as a mkdir failure on some servers.
        const st = await statPath(sftp, cur, signal, timeoutMs)
        if (st?.type === 'directory') continue
      }
      throw err
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
export async function publishRemoteFile(sftp: SFTPWrapper, p: string, bytes: Uint8Array, signal: AbortSignal | undefined, timeoutMs: number): Promise<void> {
  const dir = remoteDirname(p)
  if (dir && dir !== '.') await ensureRemoteDirs(sftp, dir, signal, timeoutMs)
  const tmp = `${p}.dsh-rdv-tmp-${Math.random().toString(36).slice(2, 10)}`
  await sftpCall('writeFile', signal, timeoutMs, (cb) => sftp.writeFile(tmp, Buffer.from(bytes), cb as never))
  try {
    await sftpCall('rename', signal, timeoutMs, (cb) => sftp.rename(tmp, p, cb as never))
  } catch (err) {
    // Some servers refuse rename onto an existing file: replace explicitly.
    try {
      await sftpCall('unlink', signal, timeoutMs, (cb) => sftp.unlink(p, cb as never))
      await sftpCall('rename', signal, timeoutMs, (cb) => sftp.rename(tmp, p, cb as never))
    } catch (retryErr) {
      try {
        await sftpCall('unlink', signal, timeoutMs, (cb) => sftp.unlink(tmp, cb as never))
      } catch { /* best-effort temp cleanup */ }
      throw retryErr
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
export async function writeRemoteText(
  sftp: SFTPWrapper,
  p: string,
  content: string,
  intent: FsWriteIntent | undefined,
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<{ operation: 'create' | 'update'; version: FsVersion; before: string | null; after: string }> {
  const existing = await statPath(sftp, p, signal, timeoutMs)
  if (intent?.kind === 'createIfAbsent' && existing) {
    throw new FsError(`"${p}" already exists (createIfAbsent)`, 'FS_NOT_OBSERVED')
  }
  if (intent?.kind === 'replaceIfVersion' && existing?.version !== intent.version) {
    throw new FsError(`"${p}" changed since it was observed (stale version)`, 'FS_STALE_VERSION')
  }
  let before: string | null = null
  if (existing?.type === 'file') {
    try {
      before = await readRemoteText(sftp, p, signal, timeoutMs, 0)
    } catch {
      before = null
    }
  } else if (existing) {
    throw new FsError(`cannot write "${p}": not a regular file`, 'FS_NOT_REGULAR_FILE')
  }
  await publishRemoteFile(sftp, p, Buffer.from(content, 'utf8'), signal, timeoutMs)
  const stats = await sftpCall<Stats>('stat', signal, timeoutMs, (cb) => sftp.stat(p, cb as never))
  return { operation: existing ? 'update' : 'create', version: versionOf(stats), before, after: content }
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
export async function editRemoteText(
  sftp: SFTPWrapper,
  p: string,
  edit: FsEditRequest,
  expected: { version: FsVersion } | undefined,
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<{ version: FsVersion; before: string; after: string }> {
  const stats = await statPath(sftp, p, signal, timeoutMs)
  if (!stats) throw new FsError(`"${p}" was not found`, 'FS_NOT_FOUND')
  if (stats.type !== 'file') throw new FsError(`cannot edit "${p}": not a regular file`, 'FS_NOT_REGULAR_FILE')
  if (expected && stats.version !== expected.version) {
    throw new FsError(`"${p}" changed since it was observed (stale version)`, 'FS_STALE_VERSION')
  }
  const raw = await readRemoteText(sftp, p, signal, timeoutMs, 0)
  const crlf = detectCrlf(raw)
  const content = crlf ? raw.replaceAll('\r\n', '\n') : raw
  const oldNorm = edit.oldString.replaceAll('\r\n', '\n')
  const newNorm = edit.newString.replaceAll('\r\n', '\n')
  if (oldNorm.length === 0) throw new FsError('old_string must be a non-empty string', 'FS_EDIT_NOT_FOUND')
  const occurrences = countOccurrences(content, oldNorm)
  if (occurrences === 0) throw new FsError(`old_string was not found in "${p}"`, 'FS_EDIT_NOT_FOUND')
  if (!edit.replaceAll && occurrences > 1) {
    throw new FsError(`old_string matched ${occurrences} times in "${p}"; provide a more specific old_string or set replace_all to true`, 'FS_AMBIGUOUS_EDIT')
  }
  const edited = content.split(oldNorm).join(newNorm)
  const restored = crlf ? edited.split('\n').join('\r\n') : edited
  await publishRemoteFile(sftp, p, Buffer.from(restored, 'utf8'), signal, timeoutMs)
  const after = await statPath(sftp, p, signal, timeoutMs)
  return { version: after?.version ?? FsVersion('unknown'), before: content, after: edited }
}

function detectCrlf(raw: string): boolean {
  const sample = raw.slice(0, 4096)
  const crlf = sample.split('\r\n').length - 1
  const lf = sample.split('\n').length - 1 - crlf
  return crlf > lf
}

function countOccurrences(content: string, needle: string): number {
  let count = 0
  let index = 0
  for (;;) {
    const found = content.indexOf(needle, index)
    if (found === -1) return count
    count += 1
    index = found + needle.length
  }
}
