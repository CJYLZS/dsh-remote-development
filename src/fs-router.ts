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

import path from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { FsError, FsTargetKey } from '@deepseek-ai/dsh-fs'
import type { FsDirEntry, FsEditOutcome, FsEditRequest, FsInfo, FsPathInfo, FsTarget, FsVersion, FsWriteIntent, FsWriteOutcome } from '@deepseek-ai/dsh-fs'
import { SandboxedFileSystem } from '@deepseek-ai/dsh-fs-sandbox'
import type { Config as LocalFsConfig } from '@deepseek-ai/dsh-fs-local'
import type { SandboxExecutionPolicy } from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import type { SFTPWrapper } from 'ssh2'
import { RemoteWorld } from './world.ts'
import type { MachineRef } from './world.ts'
import { unconfiguredMachineMessage } from './world.ts'
import { listRemoteDir, lstatPath, readRemoteBytes, readRemoteByteWindow, readRemoteText, statPath, streamRemoteText, editRemoteText, writeRemoteText } from './remote-io.ts'
import { relUnder } from './paths.ts'

/** targetKey namespace marker for remote targets (opaque to consumers). */
const KEY_PREFIX = 'rdv:'

/** The machine + path pair a remote target key decodes to. */
interface RemoteKey {
  machineId: string
  remotePath: string
}

/** The remote branch of the routing filesystem. */
export class RoutingFileSystem extends SandboxedFileSystem {
  private readonly world: RemoteWorld
  private readonly opTimeoutMs: number
  private readonly maxFileBytes: number
  private readonly remoteLocks = new Map<string, Promise<unknown>>()

  /**
   * @param ctx - plugin context (constructing registers this instance as `ctx.fs`).
   * @param world - the remote world coordinator.
   * @param opTimeoutMs - per-SFTP-operation deadline.
   * @param maxFileBytes - remote read byte cap (0 = unbounded).
   * @param baseConfig - the inherited local backend's config (defaults).
   */
  constructor(
    ctx: Context,
    world: RemoteWorld,
    opTimeoutMs: number,
    maxFileBytes: number,
    baseConfig: LocalFsConfig = { cwd: process.cwd() },
  ) {
    super(ctx, baseConfig)
    this.world = world
    this.opTimeoutMs = opTimeoutMs
    this.maxFileBytes = maxFileBytes
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
  private routeOf(p: string, cwd?: string): { machine: MachineRef; remotePath: string } | null {
    const absolute = path.isAbsolute(p) ? path.normalize(p) : path.normalize(path.resolve(cwd ?? this.config.cwd, p))
    const local = this.world.classifyHostPath(absolute)
    if (local.kind === 'remote') {
      const machine = this.world.machineForAnchor(local.route.anchor)
      if (machine) return { machine, remotePath: local.route.remotePath }
      throw new FsError(unconfiguredMachineMessage(local.route.anchor), 'FS_IO_ERROR')
    }
    if (local.kind === 'meta') return null
    if (path.isAbsolute(p)) {
      const remote = this.world.classifyRemotePath(p)
      if (remote) {
        const machine = this.world.machineForAnchor(remote.anchor)
        if (machine) return { machine, remotePath: remote.remotePath }
        throw new FsError(unconfiguredMachineMessage(remote.anchor), 'FS_IO_ERROR')
      }
    }
    return null
  }

  /** Encode a remote identity into the opaque target key. */
  private static keyOf(machineId: string, remotePath: string): FsTarget['targetKey'] {
    return FsTargetKey(KEY_PREFIX + JSON.stringify([machineId, remotePath]))
  }

  /** Decode a remote target key; null for local (inherited) keys. */
  private static parseKey(target: FsTarget): RemoteKey | null {
    const key = target.targetKey as unknown as string
    if (!key.startsWith(KEY_PREFIX)) return null
    try {
      const [machineId, remotePath] = JSON.parse(key.slice(KEY_PREFIX.length)) as [string, string]
      if (typeof machineId !== 'string' || typeof remotePath !== 'string') return null
      return { machineId, remotePath }
    } catch {
      return null
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
  private static unconfiguredTarget(displayPath: string, machineId: string): FsError {
    const [host = '?', port = '?', username = '?'] = machineId.split('|')
    return new FsError(
      `the machine ${username}@${host}:${port} behind "${displayPath}" is no longer configured`
        + ' — re-add it in the remote development settings, or delete the workspace directory',
      'FS_IO_ERROR',
    )
  }

  private async sftpFor(machine: MachineRef): Promise<SFTPWrapper> {
    return this.world.poolFor(machine).sftp()
  }

  override async resolve(p: string, opts?: { cwd?: string; signal?: AbortSignal }): Promise<FsTarget> {
    const route = this.routeOf(p, opts?.cwd)
    if (!route) return super.resolve(p, opts)
    return {
      targetKey: RoutingFileSystem.keyOf(route.machine.machine.id, route.remotePath),
      displayPath: route.remotePath,
    }
  }

  override processPath(target: FsTarget): string {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.processPath(target)
    return remote.remotePath
  }

  override fileUrl(target: FsTarget): string {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.fileUrl(target)
    return 'file://' + (remote.remotePath.startsWith('/') ? remote.remotePath : '/' + remote.remotePath)
  }

  override contains(parent: FsTarget, child: FsTarget): boolean {
    const parentRemote = RoutingFileSystem.parseKey(parent)
    const childRemote = RoutingFileSystem.parseKey(child)
    if (parentRemote === null && childRemote === null) return super.contains(parent, child)
    if (parentRemote === null || childRemote === null) return false
    if (parentRemote.machineId !== childRemote.machineId) return false
    return relUnder(parentRemote.remotePath, childRemote.remotePath) !== null
  }

  override async stat(target: FsTarget, signal?: AbortSignal): Promise<FsInfo | undefined> {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.stat(target, signal)
    const machine = this.world.machineById(remote.machineId)
    if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId)
    return statPath(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs)
  }

  override async lstat(p: string, opts?: { cwd?: string }, signal?: AbortSignal): Promise<FsPathInfo | undefined> {
    const route = this.routeOf(p, opts?.cwd)
    if (!route) return super.lstat(p, opts, signal)
    return lstatPath(await this.sftpFor(route.machine), route.remotePath, signal, this.opTimeoutMs)
  }

  override async readText(target: FsTarget, signal?: AbortSignal): Promise<string> {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.readText(target, signal)
    const machine = this.world.machineById(remote.machineId)
    if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId)
    return readRemoteText(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs, this.maxFileBytes)
  }

  override async streamText(target: FsTarget, signal?: AbortSignal): Promise<AsyncIterable<string>> {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.streamText(target, signal)
    const machine = this.world.machineById(remote.machineId)
    if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId)
    return streamRemoteText(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs, this.maxFileBytes)
  }

  override async readBytes(target: FsTarget, signal: AbortSignal | undefined, maxBytes: number): Promise<Uint8Array> {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.readBytes(target, signal, maxBytes)
    const machine = this.world.machineById(remote.machineId)
    if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId)
    return readRemoteBytes(await this.sftpFor(machine), remote.remotePath, signal, this.opTimeoutMs, maxBytes)
  }

  override async readByteRange(target: FsTarget, range: { offset: number; length: number }, signal?: AbortSignal): Promise<Uint8Array> {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.readByteRange(target, range, signal)
    const machine = this.world.machineById(remote.machineId)
    if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId)
    return readRemoteByteWindow(await this.sftpFor(machine), remote.remotePath, range, signal, this.opTimeoutMs)
  }

  override async listDir(target: FsTarget, signal?: AbortSignal): Promise<FsDirEntry[]> {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.listDir(target, signal)
    const machine = this.world.machineById(remote.machineId)
    if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId)
    const sftp = await this.sftpFor(machine)
    const entries = await listRemoteDir(sftp, remote.remotePath, signal, this.opTimeoutMs)
    return entries.map((e) => {
      const child = remote.remotePath.endsWith('/') ? remote.remotePath + e.name : remote.remotePath + '/' + e.name
      return {
        name: e.name,
        type: e.type,
        target: { targetKey: RoutingFileSystem.keyOf(remote.machineId, child), displayPath: child },
        ...e.version !== undefined ? { version: e.version } : {},
        ...e.size !== undefined ? { size: e.size } : {},
      }
    })
  }

  override async writeText(
    target: FsTarget,
    content: string,
    expected?: FsWriteIntent,
    signal?: AbortSignal,
    sandboxPolicy?: SandboxExecutionPolicy,
  ): Promise<FsWriteOutcome> {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.writeText(target, content, expected, signal, sandboxPolicy)
    const machine = this.world.machineById(remote.machineId)
    if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId)
    this.checkRemoteMutation(remote.remotePath, target.displayPath, sandboxPolicy)
    return this.lockRemote(target.targetKey as unknown as string, async () =>
      writeRemoteText(await this.sftpFor(machine), remote.remotePath, content, expected, signal, this.opTimeoutMs))
  }

  override async editText(
    target: FsTarget,
    edit: FsEditRequest,
    expected?: { version: FsVersion },
    signal?: AbortSignal,
    sandboxPolicy?: SandboxExecutionPolicy,
  ): Promise<FsEditOutcome> {
    const remote = RoutingFileSystem.parseKey(target)
    if (remote === null) return super.editText(target, edit, expected, signal, sandboxPolicy)
    const machine = this.world.machineById(remote.machineId)
    if (!machine) throw RoutingFileSystem.unconfiguredTarget(target.displayPath, remote.machineId)
    this.checkRemoteMutation(remote.remotePath, target.displayPath, sandboxPolicy)
    return this.lockRemote(target.targetKey as unknown as string, async () =>
      editRemoteText(await this.sftpFor(machine), remote.remotePath, edit, expected, signal, this.opTimeoutMs))
  }

  /**
   * Fence a remote mutation by the per-call policy: `read-only` denies;
   * `workspace-write` allows only under the remote root mapped from the
   * policy's workspace root (an anchor) or the remote `/tmp`.
   * @param remotePath - the remote target path.
   * @param displayPath - the model-facing path for the denial message.
   * @param sandboxPolicy - the per-call policy; omit to use deployment policy.
   */
  private checkRemoteMutation(remotePath: string, displayPath: string, sandboxPolicy?: SandboxExecutionPolicy): void {
    const policy = sandboxPolicy ?? this.ctx.sandboxPolicy.resolve()
    if (policy.mode === 'danger-full-access') return
    if (policy.mode === 'read-only') {
      throw new FsError(`cannot write "${displayPath}": file access denied under read-only mode`, 'FS_SANDBOX_DENIED')
    }
    const roots: string[] = ['/tmp']
    const mapped = this.world.classifyHostPath(path.normalize(policy.workspaceRoot))
    if (mapped.kind === 'remote') roots.push(mapped.route.remotePath)
    for (const root of roots) {
      if (relUnder(root, remotePath) !== null) return
    }
    throw new FsError(`cannot write "${displayPath}": file access denied under workspace-write mode`, 'FS_SANDBOX_DENIED')
  }

  /** Serialize remote mutations per target (mirrors the local backend's lock). */
  private lockRemote<T>(key: string, op: () => Promise<T>): Promise<T> {
    const prior = this.remoteLocks.get(key) ?? Promise.resolve()
    const run = prior.then(op, op)
    const tail = run.then(() => undefined, () => undefined)
    this.remoteLocks.set(key, tail)
    return run
  }
}
