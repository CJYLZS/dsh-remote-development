/**
 * The routing `ctx.shell` executor: extends the sandboxed bash executor with a
 * remote branch for commands whose working directory sits under an anchor.
 * Remote commands bypass the local sandbox wrapper entirely — the remote host
 * is a different execution world — and run through `bash -c` over the SSH
 * exec channel with the anchor path mapped onto the remote root. Approval and
 * exit-status semantics stay with the unchanged bash tool.
 *
 * The sandbox facts reported for remote runs carry the requested mode with
 * `denied: false` and no enforcement claim: the local sandbox runner never
 * wraps a remote command.
 * @module dsh-remote-development/shell-router
 */

import { Context } from '@deepseek-ai/cordis'
import { homedir } from 'node:os'
import { SandboxBashExecutor } from '@deepseek-ai/dsh-bash-sandbox'
import type { ShellExecSpec, ShellProcess, ShellProcessRead, ShellRunResult } from '@deepseek-ai/dsh-shell'
import type { CollectedOutput } from '@deepseek-ai/dsh-subprocess'
import { RemoteWorld } from './world.ts'
import type { MachineRef } from './world.ts'
import { unconfiguredMachineMessage } from './world.ts'
import { shq } from './paths.ts'

/** Marker written by the cd guard so a failed cd is an infrastructure error. */
const CD_FAIL_MARKER = '@@RDV_CD_FAIL@@'

/** Marker line that reports the background script's root PID. */
const PID_MARKER = '@@RDV_PID:'

/** Why a background remote process settled. */
type RemoteBgStatus = 'running' | 'completed' | 'killed'

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
export function rewriteAnchorSpellings(
  text: string,
  anchors: ReadonlyArray<{ dir: string; remoteRoot: string }>,
  home: string,
): string {
  let out = text
  const ordered = [...anchors].sort((left, right) => right.dir.length - left.dir.length)
  for (const anchor of ordered) {
    out = out.split(anchor.dir).join(anchor.remoteRoot)
    if (anchor.dir.startsWith(`${home}/`)) {
      const rel = anchor.dir.slice(home.length)
      out = out.split(`~${rel}`).join(anchor.remoteRoot)
      out = out.split(`$HOME${rel}`).join(anchor.remoteRoot)
      out = out.split(`\${HOME}${rel}`).join(anchor.remoteRoot)
    }
  }
  return out
}

/** The remote branch of the bash executor. */
export class RoutingBashExecutor extends SandboxBashExecutor {
  private readonly world: RemoteWorld

  /**
   * @param ctx - plugin context.
   * @param config - the inherited executor config (defaults).
   * @param world - the remote world coordinator.
   */
  constructor(ctx: Context, config: ConstructorParameters<typeof SandboxBashExecutor>[1], world: RemoteWorld) {
    super(ctx, config)
    this.world = world
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
  private remoteCwdOf(workdir: string): { machine: MachineRef; remotePath: string } | null {
    const local = this.world.classifyHostPath(workdir)
    if (local.kind === 'remote') {
      const machine = this.world.machineForAnchor(local.route.anchor)
      if (machine) return { machine, remotePath: local.route.remotePath }
      throw new Error(unconfiguredMachineMessage(local.route.anchor))
    }
    const remote = this.world.classifyRemotePath(workdir)
    if (remote) {
      const machine = this.world.machineForAnchor(remote.anchor)
      if (machine) return { machine, remotePath: remote.remotePath }
      throw new Error(unconfiguredMachineMessage(remote.anchor))
    }
    return null
  }

  override async run(spec: ShellExecSpec): Promise<ShellRunResult> {
    const route = this.remoteCwdOf(spec.workdir)
    if (!route) return super.run(spec)
    return this.runRemote(spec, route)
  }

  override start(spec: ShellExecSpec): ShellProcess {
    const route = this.remoteCwdOf(spec.workdir)
    if (!route) return super.start(spec)
    return this.startRemote(spec, route)
  }

  /** Compose the remote script: cd guard, env exports, then the command. */
  private script(route: { machine: MachineRef; remotePath: string }, spec: ShellExecSpec, prefixLines: readonly string[]): string {
    const lines = [
      `cd ${shq(route.remotePath)} || { echo ${shq(CD_FAIL_MARKER)} >&2; exit 125; }`,
      ...prefixLines,
    ]
    if (spec.env) {
      for (const [key, value] of Object.entries(spec.env)) {
        if (value === undefined) continue
        lines.push(`export ${key}=${shq(this.rewriteAnchorPaths(value, route.machine))}`)
      }
    }
    lines.push(this.rewriteAnchorPaths(spec.command, route.machine))
    return lines.join('\n') + '\n'
  }

  /**
   * Replace anchor-directory spellings in command text with their remote
   * paths. Only anchors of the machine the command runs on are rewritten —
   * another machine's handle must not be silently redirected.
   * @param text - command text or an env value.
   * @param machine - the machine the command will run on.
   * @returns the text with same-machine anchor paths mapped to remote paths.
   */
  private rewriteAnchorPaths(text: string, machine: MachineRef): string {
    const anchors = this.world.anchors()
      .filter((anchor) => {
        const ref = this.world.machineForAnchor(anchor)
        return ref !== null && ref.machine.id === machine.machine.id
      })
      .map(anchor => ({ dir: anchor.dir, remoteRoot: anchor.remoteRoot }))
    return rewriteAnchorSpellings(text, anchors, homedir())
  }

  private async runRemote(spec: ShellExecSpec, route: { machine: MachineRef; remotePath: string }): Promise<ShellRunResult> {
    const pool = this.world.poolFor(route.machine)
    const script = this.script(route, spec, [])
    const command = `bash -c ${shq(script)}`
    const result = await pool.exec(command, {
      timeoutMs: spec.timeoutMs,
      ...(spec.stdin !== undefined ? { stdin: spec.stdin } : {}),
      ...(spec.signal !== undefined ? { signal: spec.signal } : {}),
    })
    if (result.stderr.includes(CD_FAIL_MARKER) && result.code === 125) {
      throw new Error(`cannot use remote working directory ${route.remotePath}: ${result.stderr.replace(CD_FAIL_MARKER, '').trim()}`)
    }
    const stdout: CollectedOutput = {
      text: result.stdout,
      truncated: false,
    }
    const stderr: CollectedOutput = {
      text: result.stderr,
      truncated: false,
    }
    return {
      exitCode: result.code,
      signal: result.signal,
      timedOut: result.timedOut,
      aborted: !result.timedOut && spec.signal?.aborted === true,
      timeoutMs: spec.timeoutMs,
      stdout,
      stderr,
      sandbox: { mode: spec.sandboxPolicy?.mode ?? this.sandboxMode ?? 'danger-full-access', denied: false },
    }
  }

  private startRemote(spec: ShellExecSpec, route: { machine: MachineRef; remotePath: string }): ShellProcess {
    const pool = this.world.poolFor(route.machine)
    const script = this.script(route, spec, [`printf '${PID_MARKER}%s\\n' "$$"`])
    const command = `bash -c ${shq(script)}`
    return new RemoteBackgroundProcess(this.world, route.machine, command, spec, pool.tunables.maxOutputChars)
  }
}

/**
 * One remote background process. The first stdout line carries the root PID
 * marker (filtered out of job output); kill() signals the remote process
 * group best-effort, then closes the channel.
 */
class RemoteBackgroundProcess implements ShellProcess {
  status: RemoteBgStatus = 'running'
  exitCode: number | null = null
  signal: NodeJS.Signals | null = null
  readonly done: Promise<void>
  private chunks: string[] = []
  private readCursor = 0
  private retained = 0
  private dropped = 0
  private readonly maxBytes: number
  private pending = ''
  private markerDone = false
  private remotePid: number | null = null
  private killed = false

  /**
   * @param world - remote world (pool + audit).
   * @param machine - target machine.
   * @param command - the composed remote command line.
   * @param spec - the resolved shell spec.
   * @param maxBytes - output cap.
   */
  constructor(
    private readonly world: RemoteWorld,
    private readonly machine: MachineRef,
    private readonly command: string,
    private readonly spec: ShellExecSpec,
    maxBytes: number,
  ) {
    this.maxBytes = maxBytes
    let resolveDone: () => void
    this.done = new Promise<void>((resolve) => {
      resolveDone = resolve
    })
    void this.run(resolveDone!)
  }

  private async run(resolveDone: () => void): Promise<void> {
    try {
      const pool = this.world.poolFor(this.machine)
      const client = await pool.connect()
      await new Promise<void>((resolve, reject) => {
        client.exec(this.command, {}, (err, channel) => {
          if (err) {
            reject(new Error(`remote background command failed to start: ${err.message}`))
            return
          }
          channel.on('data', (d: Buffer) => this.ingest(d.toString('utf8')))
          channel.stderr?.on('data', (d: Buffer) => this.ingest(d.toString('utf8')))
          channel.on('close', (code: number | undefined, sig: string | undefined) => {
            this.status = this.killed ? 'killed' : 'completed'
            this.exitCode = typeof code === 'number' ? code : null
            this.signal = (sig as NodeJS.Signals) ?? null
            this.world.audit(this.machine, this.spec.command, this.exitCode)
            resolveDone()
          })
          if (this.spec.stdin !== undefined) channel.write(this.spec.stdin, 'utf8')
          try { channel.end() } catch { /* stdin already closed */ }
          if (this.spec.signal) {
            if (this.spec.signal.aborted) this.kill()
            else this.spec.signal.addEventListener('abort', () => this.kill(), { once: true })
          }
          resolve()
        })
      })
    } catch (err) {
      // A spawn failure settles as killed with the error on stderr (the seam
      // contract), never as a rejected done.
      this.status = 'killed'
      this.exitCode = null
      this.ingest(`\n[remote background spawn failed] ${(err as Error).message}\n`)
      this.world.audit(this.machine, this.spec.command, null)
      resolveDone()
    }
  }

  private ingest(text: string): void {
    this.pending += text
    if (!this.markerDone) {
      const nl = this.pending.indexOf('\n')
      if (nl >= 0) {
        const first = this.pending.slice(0, nl)
        this.pending = this.pending.slice(nl + 1)
        const at = first.indexOf(PID_MARKER)
        if (at >= 0) {
          const pid = Number.parseInt(first.slice(at + PID_MARKER.length), 10)
          if (Number.isFinite(pid)) this.remotePid = pid
        }
        this.markerDone = true
      }
    }
    if (!this.pending) return
    this.chunks.push(this.pending)
    this.retained += this.pending.length
    this.pending = ''
    if (this.maxBytes > 0 && this.retained > this.maxBytes) {
      const cut = this.retained - this.maxBytes
      this.dropped = cut
      let remaining = cut
      while (remaining > 0 && this.chunks.length > 0) {
        const head = this.chunks[0]
        if (head === undefined) break
        if (head.length <= remaining) {
          remaining -= head.length
          this.chunks.shift()
        } else {
          this.chunks[0] = head.slice(remaining)
          remaining = 0
        }
      }
      this.retained = this.maxBytes
    }
  }

  readOutput(): ShellProcessRead {
    const lossy = this.dropped > 0
    this.dropped = 0
    let delta = ''
    while (this.readCursor < this.chunks.length) {
      const chunk = this.chunks[this.readCursor]
      if (chunk !== undefined) delta += chunk
      this.readCursor += 1
    }
    return { delta, lossy }
  }

  kill(): boolean {
    if (this.status !== 'running') return false
    this.killed = true
    void this.signalRemote('TERM')
    setTimeout(() => {
      if (this.status === 'running') void this.signalRemote('KILL')
    }, 3000).unref()
    return true
  }

  private async signalRemote(scope: 'TERM' | 'KILL'): Promise<void> {
    if (this.remotePid === null) return
    const flag = scope === 'TERM' ? '-TERM' : '-KILL'
    // sshd makes each exec session a session leader, so the negative PID
    // targets the whole process group; fall back to the plain PID.
    const command = `kill ${flag} -- -${this.remotePid} 2>/dev/null || kill ${flag} ${this.remotePid} 2>/dev/null || true`
    try {
      await this.world.execOn(this.machine, command, { timeoutMs: 5000 })
    } catch {
      // Best-effort: the channel close still tears the session down.
    }
  }
}
