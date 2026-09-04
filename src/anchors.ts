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

import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import type { Machine } from './registry.ts'
import { normalizeRemotePath, relUnder, remoteBasename, shortHash } from './paths.ts'

/** Metadata file stored inside every anchor directory. */
export const ANCHOR_META_FILE = '.dsh-remote-development.json'

/** Durable anchor metadata (also the anchor↔machine join key). */
export interface AnchorMeta {
  host: string
  port: number
  username: string
  remotePath: string
  createdAt: string
}

/** One resolved anchor: the local dir plus its remote origin. */
export interface AnchorInfo {
  dir: string
  meta: AnchorMeta
  /** Normalized remote root this anchor stands for. */
  remoteRoot: string
}

/** Route decision for a path under an anchor. */
export interface AnchorRoute {
  anchor: AnchorInfo
  /** The remote path the local path maps onto. */
  remotePath: string
}

/**
 * The anchor directory for one remote origin under a machine tag directory.
 * Pure so tests can assert naming without touching the filesystem.
 * @param root - anchor root directory.
 * @param machine - target machine.
 * @param remotePath - remote workspace path.
 * @returns the anchor directory path (not created).
 */
export function anchorDirFor(root: string, machine: Pick<Machine, 'host' | 'username' | 'port'>, remotePath: string): string {
  const tag = [machine.host, machine.username, machine.port]
    .filter((part) => part !== undefined && part !== null && String(part).length > 0)
    .join('-')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
  const base = remoteBasename(remotePath) || 'workspace'
  return path.join(root, tag, base)
}

/**
 * Read one anchor's metadata; null when absent or unreadable.
 * @param dir - candidate anchor directory.
 * @returns the parsed metadata, or null.
 */
export function readAnchorMeta(dir: string): AnchorMeta | null {
  try {
    const raw = JSON.parse(readFileSync(path.join(dir, ANCHOR_META_FILE), 'utf8')) as Partial<AnchorMeta>
    if (typeof raw.host !== 'string' || typeof raw.remotePath !== 'string') return null
    return {
      host: raw.host,
      port: Number(raw.port) || 22,
      username: String(raw.username ?? ''),
      remotePath: normalizeRemotePath(raw.remotePath),
      createdAt: String(raw.createdAt ?? ''),
    }
  } catch {
    return null
  }
}

/** List immediate child directories of `dir`, ignoring unreadable entries. */
function childDirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => {
        try {
          return statSync(path.join(dir, e.name)).isDirectory()
        } catch {
          return false
        }
      })
      .map((e) => e.name)
  } catch {
    return []
  }
}

/**
 * Scan an anchor root and collect every anchor directory.
 * @param root - anchor root directory.
 * @returns all anchors found.
 */
export function scanAnchors(root: string): AnchorInfo[] {
  const out: AnchorInfo[] = []
  if (!existsSync(root)) return out
  for (const tag of childDirs(root)) {
    for (const name of childDirs(path.join(root, tag))) {
      const dir = path.join(root, tag, name)
      const meta = readAnchorMeta(dir)
      if (!meta) continue
      out.push({ dir, meta, remoteRoot: meta.remotePath })
    }
  }
  return out
}

/**
 * Create (or reuse) the anchor directory for one remote origin.
 * @param root - anchor root directory.
 * @param machine - target machine.
 * @param remotePath - remote workspace path.
 * @returns the anchor directory path.
 */
export function createAnchorDir(root: string, machine: Pick<Machine, 'host' | 'username' | 'port'>, remotePath: string): string {
  const norm = normalizeRemotePath(remotePath)
  const plain = anchorDirFor(root, machine, norm)
  const existing = readAnchorMeta(plain)
  if (existing && existing.remotePath === norm && existing.host === machine.host
    && Number(existing.port) === Number(machine.port) && existing.username === machine.username) {
    return plain
  }
  const dir = existsSync(plain) ? plain + '-' + shortHash(norm) : plain
  mkdirSync(dir, { recursive: true })
  writeFileSync(
    path.join(dir, ANCHOR_META_FILE),
    JSON.stringify(
      { host: machine.host, port: machine.port, username: machine.username, remotePath: norm, createdAt: new Date().toISOString() },
      null,
      2,
    ) + '\n',
    { mode: 0o600 },
  )
  return dir
}

/**
 * Resolve the remote path for a local path under an anchor.
 * @param anchor - the resolved anchor.
 * @param localPath - absolute local path under the anchor.
 * @returns the mapped remote path.
 */
export function remotePathFor(anchor: AnchorInfo, localPath: string): string {
  const rel = relUnder(anchor.dir, localPath)
  if (rel === null || rel === '') return anchor.remoteRoot
  return normalizeRemotePath(`${anchor.remoteRoot}/${rel}`)
}

/**
 * Match a remote-coordinate path against the known anchors (longest root wins).
 * @param remotePath - candidate remote path.
 * @param anchors - known anchors.
 * @returns the matched route, or null when no anchor claims the path.
 */
export function matchRemotePath(remotePath: string, anchors: AnchorInfo[]): AnchorRoute | null {
  const norm = normalizeRemotePath(remotePath)
  let best: AnchorRoute | null = null
  for (const anchor of anchors) {
    const rel = relUnder(anchor.remoteRoot, norm)
    if (rel === null) continue
    const mapped = rel === '' ? anchor.remoteRoot : normalizeRemotePath(`${anchor.remoteRoot}/${rel}`)
    if (best === null || anchor.remoteRoot.length > best.anchor.remoteRoot.length) {
      best = { anchor, remotePath: mapped }
    }
  }
  return best
}
