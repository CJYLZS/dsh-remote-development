/**
 * The remote world: one coordinator owning the machine registry, the anchor
 * index, per-machine SSH pools, and the audit log. Both the routing providers
 * and the web routes go through it, so a settings change, an added machine,
 * or a new anchor is visible to every consumer the same way.
 * @module dsh-remote-development/world
 */

import { appendFileSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'
import { HostKeyGuard } from './hostkey.ts'
import type { KnownHostEntry } from './hostkey.ts'
import { SshPool, UnsupportedRemoteError } from './pool.ts'
import type { PoolTarget, PoolTunables } from './pool.ts'
import { ANCHOR_META_FILE, createAnchorDir, matchRemotePath, scanAnchors } from './anchors.ts'
import type { AnchorInfo, AnchorMeta } from './anchors.ts'
import { loadRegistry, machineId, registryExists, saveRegistry, sanitizeMachine } from './registry.ts'
import type { MachineInput } from './registry.ts'
import type { Machine, RegistryData } from './registry.ts'
import type { Config } from './config.ts'
import { normalizeRemotePath } from './paths.ts'

/** Harness home: `DSH_HOME` when set, else `~/.dsh`. */
export function dshHome(): string {
  const env = process.env.DSH_HOME
  if (env && env.trim()) return path.resolve(env.trim())
  return path.join(homedir(), '.dsh')
}

/** The machine a tool call acts on, resolved per call. */
export type MachineRef =
  | { source: 'registry'; machine: Machine }
  | { source: 'config'; machine: Machine }

/** One audit entry's machine coordinates. */
export interface AuditTarget {
  host: string
  username: string
  port: number
}

/**
 * Coordinator for the remote execution world. Constructed once by the plugin's
 * `apply`; its `dispose()` closes every pool (registered as a ctx effect).
 */
export class RemoteWorld {
  readonly config: Config
  private readonly registryFile: string
  private readonly knownHostsFile: string
  private readonly anchorRoot: string
  private registry: RegistryData
  private anchorCache: AnchorInfo[] | null = null
  private readonly pools = new Map<string, SshPool>()

  /**
   * @param config - validated plugin config.
   */
  constructor(config: Config) {
    this.config = config
    const base = config.anchorRoot.trim() || path.join(dshHome(), 'remote-workspaces')
    this.anchorRoot = base
    this.registryFile = path.join(base, 'machines.json')
    this.knownHostsFile = path.join(base, 'known_hosts.json')
    this.registry = loadRegistry(this.registryFile)
    // A fresh registry adopts the configured host as its first saved machine
    // (standby only — nothing routes to it until a workspace's anchor names
    // it); an existing registry is left untouched.
    if (!registryExists(this.registryFile) && config.host) {
      const machine = sanitizeMachine({
        host: config.host,
        port: config.port,
        username: config.username,
        password: config.password,
        privateKeyPath: config.privateKeyPath,
        passphrase: config.passphrase,
        hostKeyMode: config.hostKeyMode,
        workspace: config.workspace,
      })
      this.registry.machines.push(machine)
      saveRegistry(this.registryFile, this.registry)
    }
  }

  /** Close every pool (composition teardown). */
  dispose(): void {
    for (const pool of this.pools.values()) {
      try { pool.close() } catch { /* pool already torn down */ }
    }
    this.pools.clear()
  }

  // ── machines ──────────────────────────────────────────────────────────────

  /** All saved machines, plus the config default when no registry exists. */
  listMachines(): Machine[] {
    return [...this.registry.machines]
  }

  /**
   * Add or update a machine by identity; returns the stored record. On an
   * update, absent secrets (`undefined` password, passphrase, or proxy
   * password) keep the stored values: the public machine wire withholds
   * secrets, so an edit that leaves them out is a keep, not a clear. An
   * explicit string sets or clears.
   * @param raw - machine fields from the UI or config; secrets may be absent.
   * @returns the sanitized stored machine.
   */
  upsertMachine(raw: MachineInput): Machine {
    const machine = sanitizeMachine(raw)
    const stored = this.registry.machines.find((m) => m.id === machine.id)
    if (stored === undefined) {
      this.registry.machines.push(machine)
      saveRegistry(this.registryFile, this.registry)
      return machine
    }
    const merged: Machine = {
      ...machine,
      password: raw.password ?? stored.password,
      passphrase: raw.passphrase ?? stored.passphrase,
    }
    if (machine.proxy) {
      merged.proxy = { ...machine.proxy, password: raw.proxy?.password ?? stored.proxy?.password ?? '' }
    }
    this.registry.machines[this.registry.machines.indexOf(stored)] = merged
    saveRegistry(this.registryFile, this.registry)
    return merged
  }

  /**
   * Remove one machine; anchors stay (their metadata is durable) but lose
   * their credential source until the machine is re-added.
   * @param id - machine id.
   * @returns true when a machine was removed.
   */
  removeMachine(id: string): boolean {
    const index = this.registry.machines.findIndex((m) => m.id === id)
    if (index < 0) return false
    this.registry.machines.splice(index, 1)
    saveRegistry(this.registryFile, this.registry)
    const key = [...this.pools.keys()].find((k) => k.startsWith(id + '\u0000'))
    if (key) {
      this.pools.get(key)?.close()
      this.pools.delete(key)
    }
    return true
  }

  /**
   * Resolve the machine record for an anchor origin. Anchors record only
   * host/port/user; the registry supplies credentials. The config default
   * covers an anchor created before its machine was saved under a matching
   * identity.
   * @param meta - anchor metadata.
   * @returns the machine reference, or null when unresolvable.
   */
  machineForMeta(meta: AnchorMeta): MachineRef | null {
    const id = machineId(meta.host, meta.port, meta.username)
    const stored = this.registry.machines.find((m) => m.id === id)
    if (stored) return { source: 'registry', machine: stored }
    if (this.config.host && this.config.host === meta.host
      && Number(this.config.port) === Number(meta.port)
      && this.config.username === meta.username) {
      return {
        source: 'config',
        machine: sanitizeMachine({
          host: this.config.host,
          port: this.config.port,
          username: this.config.username,
          password: this.config.password,
          privateKeyPath: this.config.privateKeyPath,
          passphrase: this.config.passphrase,
          hostKeyMode: this.config.hostKeyMode,
        }),
      }
    }
    return null
  }

  /**
   * Resolve the machine for one anchor (by its metadata).
   * @param anchor - the anchor.
   * @returns the machine reference, or null when unresolvable.
   */
  machineForAnchor(anchor: AnchorInfo): MachineRef | null {
    return this.machineForMeta(anchor.meta)
  }

  /**
   * Look a machine up by id. The config default is registered into the
   * registry at construction, so the registry list is exhaustive here.
   * @param id - machine id.
   * @returns the machine reference, or null.
   */
  machineById(id: string): MachineRef | null {
    const stored = this.registry.machines.find((m) => m.id === id)
    return stored ? { source: 'registry', machine: stored } : null
  }

  /**
   * A non-persisted machine reference for one-shot flows (test-connection
   * with unsaved fields).
   * @param raw - partial machine fields.
   * @returns the ephemeral machine reference.
   */
  ephemeralRef(raw: MachineInput): MachineRef {
    return { source: 'config', machine: sanitizeMachine(raw) }
  }

  // ── anchors ───────────────────────────────────────────────────────────────

  /** All anchors, rescanned when the cache is dirty. */
  anchors(): AnchorInfo[] {
    if (this.anchorCache === null) this.anchorCache = scanAnchors(this.anchorRoot)
    return this.anchorCache
  }

  /**
   * Create (or reuse) the anchor for one remote origin and refresh the cache.
   * @param machine - target machine.
   * @param remotePath - remote workspace path.
   * @returns the anchor directory.
   */
  createAnchor(machine: Machine, remotePath: string): string {
    const dir = createAnchorDir(this.anchorRoot, machine, remotePath)
    this.anchorCache = null
    return dir
  }

  /**
   * Classify a host-absolute path: under an anchor → remote (with its remote
   * path); an anchor's own metadata file → stays local.
   * @param absPath - absolute local path.
   * @returns the routing decision.
   */
  classifyHostPath(absPath: string): { kind: 'meta'; dir: string } | { kind: 'remote'; route: AnchorRouteInfo } | { kind: 'local' } {
    const norm = path.normalize(absPath)
    for (const anchor of this.anchors()) {
      if (norm === path.join(anchor.dir, ANCHOR_META_FILE)) return { kind: 'meta', dir: anchor.dir }
    }
    for (const anchor of this.anchors()) {
      const rel = relUnderLocal(anchor.dir, norm)
      if (rel !== null) {
        return {
          kind: 'remote',
          route: { anchor, remotePath: rel === '' ? anchor.remoteRoot : normalizeRemotePath(`${anchor.remoteRoot}/${rel}`) },
        }
      }
    }
    return { kind: 'local' }
  }

  /**
   * Classify a remote-coordinate path (the model may name remote paths
   * directly after seeing them in command output).
   * @param remotePath - candidate remote path.
   * @returns the matched route, or null.
   */
  classifyRemotePath(remotePath: string): AnchorRouteInfo | null {
    return matchRemotePath(remotePath, this.anchors())
  }

  // ── pools ─────────────────────────────────────────────────────────────────

  /**
   * The pool for one machine identity (created lazily, shared across calls).
   * @param ref - the machine reference.
   * @returns the pool.
   */
  poolFor(ref: MachineRef): SshPool {
    const m = ref.machine
    const key = m.id + '\u0000' + m.host + '\u0000' + m.port + '\u0000' + m.username
    const existing = this.pools.get(key)
    if (existing) {
      existing.retune(this.tunables())
      return existing
    }
    const pool = new SshPool(
      this.poolTarget(m),
      this.tunables(),
      {
        read: () => this.readKnownHosts(),
        write: (entries) => this.writeKnownHosts(entries),
      },
    )
    this.pools.set(key, pool)
    return pool
  }

  private tunables(): PoolTunables {
    return {
      connectTimeoutMs: this.config.connectTimeoutMs,
      commandTimeoutMs: this.config.commandTimeoutMs,
      maxOutputChars: this.config.maxOutputChars,
      maxFileBytes: this.config.maxFileBytes,
    }
  }

  private poolTarget(m: Machine): PoolTarget {
    return {
      host: m.host,
      port: m.port,
      username: m.username || 'root',
      password: m.password,
      privateKeyPath: m.privateKeyPath,
      passphrase: m.passphrase,
      useAgent: m.useAgent,
      keyboardInteractive: m.keyboardInteractive,
      ...(m.proxy ? { proxy: m.proxy } : {}),
      hostKeyMode: m.hostKeyMode || this.config.hostKeyMode,
    }
  }

  /**
   * Run one command on a machine with the audit hook and the Windows-remote
   * refusal surfaced as a typed error.
   * @param ref - machine reference.
   * @param command - remote command line.
   * @param opts - timeout/stdin/abort.
   * @returns the exec result.
   */
  async execOn(ref: MachineRef, command: string, opts: { timeoutMs?: number; stdin?: string; signal?: AbortSignal } = {}): Promise<Awaited<ReturnType<SshPool['exec']>>> {
    const pool = this.poolFor(ref)
    try {
      const result = await pool.exec(command, opts)
      this.audit(ref, command, result.code)
      return result
    } catch (err) {
      if (err instanceof UnsupportedRemoteError) {
        this.audit(ref, command, null)
        throw err
      }
      this.audit(ref, command, null)
      throw err
    }
  }

  // ── audit + known hosts ───────────────────────────────────────────────────

  private auditFile(): string {
    return path.join(this.anchorRoot, 'audit.log')
  }

  /**
   * Append one audit line; failures are swallowed (the audit log must never
   * break a tool call).
   * @param ref - machine acted on.
   * @param command - command text or operation detail.
   * @param code - exit code, or null when not applicable.
   */
  audit(ref: MachineRef, command: string, code: number | null): void {
    if (!this.config.auditLog) return
    try {
      mkdirSync(this.anchorRoot, { recursive: true })
      const line = [
        new Date().toISOString(),
        `${ref.machine.username || '?'}@${ref.machine.host}:${ref.machine.port}`,
        String(command).replace(/\s+/g, ' ').slice(0, 400),
        code == null ? '-' : String(code),
      ].join(' | ') + '\n'
      appendFileSync(this.auditFile(), line, 'utf8')
    } catch {
      // Swallowed: the audit log is best-effort and nothing else can reach it.
    }
  }

  private readKnownHosts(): Record<string, KnownHostEntry> {
    try {
      const raw = JSON.parse(readFileSync(this.knownHostsFile, 'utf8')) as Record<string, KnownHostEntry>
      if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw
    } catch { /* fresh store */ }
    return {}
  }

  private writeKnownHosts(entries: Record<string, KnownHostEntry>): void {
    try {
      mkdirSync(path.dirname(this.knownHostsFile), { recursive: true })
      const tmp = this.knownHostsFile + '.tmp'
      writeFileSync(tmp, JSON.stringify(entries, null, 2) + '\n', { mode: 0o600 })
      renameSync(tmp, this.knownHostsFile)
    } catch (err) {
      throw new Error(`cannot persist known hosts: ${(err as Error).message}`)
    }
  }

  /** Drop one host's trusted key (re-trust flow). */
  forgetHostKey(host: string, port: number): void {
    const guard = new HostKeyGuard('accept-new', {
      read: () => this.readKnownHosts(),
      write: (entries) => this.writeKnownHosts(entries),
    })
    guard.forget(`${host}:${port}`)
  }

  /** Build a plain guard for ad-hoc verification (test-connection flow). */
  hostKeyGuard(): HostKeyGuard {
    return new HostKeyGuard(this.config.hostKeyMode, {
      read: () => this.readKnownHosts(),
      write: (entries) => this.writeKnownHosts(entries),
    })
  }
}

/** Alias so route shapes read uniformly across the two classify methods. */
export interface AnchorRouteInfo {
  anchor: AnchorInfo
  remotePath: string
}

/**
 * The refusal message for an anchor whose machine is no longer configured.
 * Anchors survive machine deletion (their metadata is durable), but without
 * a matching registry/config identity nothing may act on them — callers
 * surface this instead of silently falling back to another machine or the
 * local host.
 * @param anchor - the orphaned anchor.
 * @returns the user-facing error message.
 */
export function unconfiguredMachineMessage(anchor: AnchorInfo): string {
  const who = `${anchor.meta.username || 'user'}@${anchor.meta.host}:${anchor.meta.port}`
  return `the machine ${who} behind remote workspace "${anchor.dir}" is no longer configured`
    + ` — re-add it in the remote development settings, or delete the workspace directory`
}

/** Local prefix containment for anchor dirs (lexical, no I/O). */
function relUnderLocal(dir: string, p: string): string | null {
  const d = dir.endsWith(path.sep) ? dir : dir + path.sep
  if (p === dir) return ''
  if (!p.startsWith(d)) return null
  return p.slice(d.length)
}
