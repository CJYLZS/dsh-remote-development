/**
 * Remote path helpers for POSIX remote hosts. Windows remote machines are a
 * reserved follow-up: every helper takes the platform only to fail loud until
 * the Git Bash adapter lands, so a Windows remote surfaces one clear message
 * instead of subtly wrong paths.
 * @module dsh-remote-development/paths
 */

/** Remote platforms this package can drive in its current version. */
export type RemotePlatform = 'posix' | 'windows' | 'unknown'

/**
 * Collapse `//`, strip a trailing slash (except the root), and resolve `.`/`..`
 * lexically. No I/O: remote realpath is a separate round trip callers opt into.
 * @param p - remote path to normalize.
 * @returns the normalized absolute-or-relative remote path.
 */
export function normalizeRemotePath(p: string): string {
  let s = String(p ?? '').replace(/\\/g, '/')
  if (!s) return ''
  const absolute = s.startsWith('/')
  const out: string[] = []
  for (const seg of s.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      if (out.length > 0 && out[out.length - 1] !== '..') out.pop()
      else if (!absolute) out.push('..')
      continue
    }
    out.push(seg)
  }
  const joined = out.join('/')
  if (absolute) return '/' + joined
  return joined || '.'
}

/**
 * Join two remote paths and normalize the result.
 * @param base - left-hand path.
 * @param rest - right-hand path (may be absolute, which then wins).
 * @returns the joined normalized path.
 */
export function joinRemotePath(base: string, rest: string): string {
  const r = String(rest ?? '')
  if (r.startsWith('/')) return normalizeRemotePath(r)
  const b = normalizeRemotePath(base)
  if (!b || b === '.') return normalizeRemotePath(r)
  if (!r) return b
  return normalizeRemotePath(`${b}/${r}`)
}

/**
 * The parent directory of a remote path.
 * @param p - remote path.
 * @returns the parent path ('/' for root children, '.' for a bare name).
 */
export function remoteDirname(p: string): string {
  const norm = normalizeRemotePath(p)
  const i = norm.lastIndexOf('/')
  if (i < 0) return '.'
  if (i === 0) return '/'
  return norm.slice(0, i)
}

/**
 * The final segment of a remote path.
 * @param p - remote path.
 * @returns the basename ('' for the root).
 */
export function remoteBasename(p: string): string {
  const norm = normalizeRemotePath(p)
  if (norm === '/') return ''
  const i = norm.lastIndexOf('/')
  return i < 0 ? norm : norm.slice(i + 1)
}

/**
 * The path relative to `root`, or `null` when `p` is not under it. Both inputs
 * are normalized first, so either spelling works.
 * @param root - candidate ancestor directory.
 * @param p - candidate descendant path.
 * @returns the relative path ('' when equal), or null when not under the root.
 */
export function relUnder(root: string, p: string): string | null {
  const r = normalizeRemotePath(root)
  const norm = normalizeRemotePath(p)
  if (r === norm) return ''
  const prefix = r === '/' ? '/' : r + '/'
  if (!norm.startsWith(prefix)) return null
  return norm.slice(prefix.length)
}

/**
 * Quote one string as a single POSIX shell word (single-quote escaping).
 * @param s - raw string to quote.
 * @returns the safely quoted word.
 */
export function shq(s: string): string {
  return `'${String(s ?? '').replaceAll("'", `'\\''`)}'`
}

/**
 * Compose one remote command line from an argv vector. Every element is
 * quoted, so the join is safe under the login shell that runs SSH exec.
 * @param argv - exact program and arguments.
 * @returns the quoted command line.
 */
export function argvToRemoteCommand(argv: readonly string[]): string {
  return argv.map(shq).join(' ')
}

/** Deterministic 8-hex suffix for disambiguating same-named anchors. */
export function shortHash(s: string): string {
  let h = 5381
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0
  return (h >>> 0).toString(16).padStart(8, '0')
}

/**
 * Truncate collected text to a character ceiling, keeping the HEAD (command
 * output reads best from the top) and marking nothing — the caller decides
 * how to surface truncation.
 * @param s - collected text.
 * @param maxChars - inclusive ceiling.
 * @returns the possibly shortened text.
 */
export function truncateHead(s: string, maxChars: number): string {
  if (s.length <= maxChars) return s
  return s.slice(0, Math.max(0, maxChars))
}
