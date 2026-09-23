/**
 * The routing `ctx.shell` executors: extend the host platform's sandboxed
 * executor with a remote branch for commands whose working directory sits
 * under an anchor. Remote commands bypass the local sandbox wrapper entirely —
 * the remote host is a different execution world — and run through `bash -c`
 * over the SSH exec channel with the anchor path mapped onto the remote root.
 * Approval and exit-status semantics stay with the unchanged shell tools.
 *
 * One executor mounts per host platform, and the split is about the LOCAL
 * fallback only: a Windows host has no local bash, so it mounts
 * {@link RoutingPwshExecutor} (local workdirs keep the inherited pwsh
 * executor, sandbox and settings intact) while POSIX hosts mount
 * {@link RoutingBashExecutor}. Both route anchor workdirs to the remote
 * host's POSIX shell — the remote platform decides the remote dialect, never
 * the host platform.
 *
 * Both remote and local workdirs go through the seam's one execution verb:
 * `execute()` returns the live handle, remote ones built by
 * {@link RemoteShellBranch} and local ones by the inherited executor. A remote
 * handle owns its own deadline (`spec.onExpiry`), its output cap, and the
 * remote process-group kill, so a timed-out or backgrounded remote command
 * behaves like a local one.
 *
 * The sandbox facts reported for remote runs carry the requested mode with
 * `denied: false` and no enforcement claim: the local sandbox runner never
 * wraps a remote command.
 * @module dsh-remote-development/shell-router
 */

import { Context } from '@deepseek-ai/cordis'
import { homedir } from 'node:os'
import { SandboxBashExecutor } from '@deepseek-ai/dsh-bash-sandbox'
import { SandboxPwshExecutor } from '@deepseek-ai/dsh-pwsh-sandbox'
import type {
  CollectedOutput, ShellExecution, ShellExecSpec, ShellProcessRead, ShellProcessStatus, ShellRunResult, ShellSandboxInfo,
} from '@deepseek-ai/dsh-shell'
import type { SubprocessOutputReader } from '@deepseek-ai/dsh-subprocess'
import type { SandboxMode } from '@deepseek-ai/dsh-sandbox'
import { deadline, timeoutOf } from '@deepseek-ai/dsh-timeout'
import { UnsupportedRemoteError } from './pool.ts'
import { RemoteWorld } from './world.ts'
import type { MachineRef } from './world.ts'
import { unconfiguredMachineMessage } from './world.ts'
import { shq } from './paths.ts'

/** Marker written by the cd guard so a failed cd is an infrastructure error. */
const CD_FAIL_MARKER = '@@RDV_CD_FAIL@@'

/** Marker line that reports the background script's root PID. */
const PID_MARKER = '@@RDV_PID:'

/** Timeout reason stamping the fused deadline; classification reads it back. */
const TIMEOUT_CODE = 'BASH_TIMEOUT'

/** Grace between the remote SIGTERM and the SIGKILL escalation, mirroring the local executor. */
const KILL_ESCALATION_MS = 3_000

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

/**
 * The remote branch shared by both routing executors: workdir classification,
 * remote script composition, and execution over the SSH exec channel. Each
 * host-platform executor owns its local fallback and delegates every
 * anchor-routed command here.
 */
export class RemoteShellBranch {
  private readonly world: RemoteWorld

  /**
   * @param world - the remote world coordinator.
   */
  constructor(world: RemoteWorld) {
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
  routeOf(workdir: string): { machine: MachineRef; remotePath: string } | null {
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

  /**
   * Start one command on its remote machine and return the live handle. The
   * composed script reports its root PID first, so both the foreground
   * deadline and a caller's kill reach the whole remote process group.
   * @param spec - the resolved shell spec.
   * @param route - the machine and remote cwd for the workdir.
   * @param sandboxMode - the executor's default sandbox mode, reported as the
   *   remote run's mode when the spec carries no per-call policy.
   * @returns the live remote execution handle.
   */
  async execute(
    spec: ShellExecSpec,
    route: { machine: MachineRef; remotePath: string },
    sandboxMode: SandboxMode | undefined,
  ): Promise<ShellExecution> {
    const pool = this.world.poolFor(route.machine)
    if (await pool.detectPlatform() === 'windows') throw new UnsupportedRemoteError()
    const script = this.script(route, spec, [`printf '${PID_MARKER}%s\\n' "$$"`])
    return new RemoteExecution({
      world: this.world,
      machine: route.machine,
      remotePath: route.remotePath,
      command: `bash -c ${shq(script)}`,
      spec,
      maxChars: pool.tunables.maxOutputChars,
      mode: spec.sandboxPolicy?.mode ?? sandboxMode ?? 'danger-full-access',
    })
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
}

/** The POSIX-host routing executor: local workdirs stay with local bash. */
export class RoutingBashExecutor extends SandboxBashExecutor {
  private readonly branch: RemoteShellBranch

  /**
   * @param ctx - plugin context.
   * @param config - the inherited executor config.
   * @param world - the remote world coordinator.
   */
  constructor(ctx: Context, config: ConstructorParameters<typeof SandboxBashExecutor>[1], world: RemoteWorld) {
    super(ctx, config)
    this.branch = new RemoteShellBranch(world)
  }

  override async execute(spec: ShellExecSpec): Promise<ShellExecution> {
    const route = this.branch.routeOf(spec.workdir)
    if (!route) return super.execute(spec)
    return this.branch.execute(spec, route, this.sandboxMode)
  }
}

/**
 * The win32-host routing executor: local workdirs keep the inherited pwsh
 * executor (confinement, encoding, and settings included); anchor workdirs
 * cross to the remote host's bash.
 */
export class RoutingPwshExecutor extends SandboxPwshExecutor {
  private readonly branch: RemoteShellBranch

  /**
   * @param ctx - plugin context.
   * @param config - the inherited executor config.
   * @param world - the remote world coordinator.
   */
  constructor(ctx: Context, config: ConstructorParameters<typeof SandboxPwshExecutor>[1], world: RemoteWorld) {
    super(ctx, config)
    this.branch = new RemoteShellBranch(world)
  }

  override async execute(spec: ShellExecSpec): Promise<ShellExecution> {
    const route = this.branch.routeOf(spec.workdir)
    if (!route) return super.execute(spec)
    return this.branch.execute(spec, route, this.sandboxMode)
  }
}

/**
 * Bounded text retention for one remote stream. Appends decoded chunks, drops
 * the head once the cap is exceeded, and serves both the consuming read cursor
 * and the non-consuming offset readers from the same window, so a read that
 * lost text reports `lossy` instead of silently skipping it.
 */
class RetainedText {
  private readonly chunks: string[] = []
  /** Absolute offset of the retained window's first character. */
  private base = 0
  private length = 0
  private dropped = 0

  /** @param maxChars - retained characters; `<= 0` retains everything. */
  constructor(private readonly maxChars: number) {}

  /** Absolute offset just past the last character appended. */
  get end(): number {
    return this.base + this.length
  }

  /** Whether truncation ever dropped text from this stream. */
  get truncated(): boolean {
    return this.dropped > 0
  }

  /**
   * Append one decoded chunk, trimming the head to the cap.
   * @param text - the decoded chunk.
   */
  append(text: string): void {
    if (text.length === 0) return
    this.chunks.push(text)
    this.length += text.length
    if (this.maxChars > 0 && this.length > this.maxChars) {
      const cut = this.length - this.maxChars
      let remaining = cut
      while (remaining > 0 && this.chunks.length > 0) {
        const head = this.chunks[0]
        /* v8 ignore next -- the loop condition already proved a chunk exists. */
        if (head === undefined) break
        if (head.length <= remaining) {
          remaining -= head.length
          this.chunks.shift()
        } else {
          this.chunks[0] = head.slice(remaining)
          remaining = 0
        }
      }
      this.base += cut
      this.length = this.maxChars
      this.dropped += cut
    }
  }

  /**
   * Read from an absolute offset, clamped to the retained window.
   * @param from - absolute offset, as returned by a previous read.
   * @returns the text, whether truncation dropped text this read cannot
   *   include, and the offset to continue from.
   */
  readFrom(from: number): { text: string; lossy: boolean; nextOffset: number } {
    if (from >= this.end) return { text: '', lossy: false, nextOffset: this.end }
    const start = Math.max(from, this.base)
    let skip = start - this.base
    let text = ''
    for (const chunk of this.chunks) {
      if (skip >= chunk.length) {
        skip -= chunk.length
        continue
      }
      text += skip > 0 ? chunk.slice(skip) : chunk
      skip = 0
    }
    return { text, lossy: start > from, nextOffset: this.end }
  }

  /** The retained window as a collected stream output. */
  collected(): CollectedOutput {
    return { text: this.readFrom(this.base).text, truncated: this.truncated }
  }
}

/** Everything one remote execution needs to start and report itself. */
interface RemoteExecutionOptions {
  /** The remote world coordinator (pool + audit). */
  world: RemoteWorld
  /** Target machine. */
  machine: MachineRef
  /** The remote working directory, named in cd-guard failures. */
  remotePath: string
  /** The composed remote command line. */
  command: string
  /** The resolved shell spec (deadline policy, stdin, environment, signal). */
  spec: ShellExecSpec
  /** Retained characters per stream, from the pool's tunables. */
  maxChars: number
  /** Sandbox mode reported as this run's fact. */
  mode: SandboxMode
}

/**
 * One remote execution over an SSH exec channel. Opening the channel is part of
 * construction; stdout and stderr are captured into bounded buffers and served
 * to both faces the seam defines — the consuming {@link readOutput} cursor with
 * the non-consuming {@link observed} readers, and the foreground
 * {@link result} projection with first-cause `timedOut`/`aborted`
 * classification.
 *
 * A spawn that never produced a channel settles the handle as killed with the
 * note on stderr and rejects `result()` with the original error, which is the
 * seam's uniform containment for spawn failures.
 */
class RemoteExecution implements ShellExecution {
  status: ShellProcessStatus = 'running'
  exitCode: number | null = null
  signal: NodeJS.Signals | null = null
  readonly done: Promise<void>
  readonly observed: { stdout: SubprocessOutputReader; stderr: SubprocessOutputReader }
  readonly sandbox: ShellSandboxInfo

  private readonly world: RemoteWorld
  private readonly machine: MachineRef
  private readonly remotePath: string
  private readonly command: string
  private readonly spec: ShellExecSpec
  private readonly stdout: RetainedText
  private readonly stderr: RetainedText
  private readonly deadlineSignal: AbortSignal
  private readonly disarmDeadline: () => void
  private readonly onAbort: () => void
  private stdoutCursor = 0
  private stderrCursor = 0
  private remotePid: number | null = null
  private pendingMarker = ''
  private markerParsed = false
  private killed = false
  private settled = false
  private spawnFailure: unknown
  private cdFailure: string | undefined
  private resultPromise: Promise<ShellRunResult> | undefined
  private resolveDone!: () => void

  /** @param options - target, composed command, spec, and budget. */
  constructor(options: RemoteExecutionOptions) {
    this.world = options.world
    this.machine = options.machine
    this.remotePath = options.remotePath
    this.command = options.command
    this.spec = options.spec
    this.stdout = new RetainedText(options.maxChars)
    this.stderr = new RetainedText(options.maxChars)
    this.sandbox = { mode: options.mode, denied: false }
    this.observed = {
      stdout: { readFrom: from => this.stdout.readFrom(from) },
      stderr: { readFrom: from => this.stderr.readFrom(from) },
    }
    this.done = new Promise<void>((resolve) => {
      this.resolveDone = resolve
    })
    // `'kill'` fuses the caller's cancellation with the executor's own timeout
    // into one first-cause signal; `'none'` forwards cancellation only, leaving
    // the command running past its nominal timeout for the caller to bound.
    const armed = options.spec.onExpiry === 'kill'
      ? deadline(options.spec.signal, options.spec.timeoutMs, TIMEOUT_CODE)
      : undefined
    this.deadlineSignal = armed?.signal ?? options.spec.signal ?? new AbortController().signal
    this.disarmDeadline = armed === undefined ? () => {} : () => { armed[Symbol.dispose]() }
    this.onAbort = (): void => { this.kill() }
    this.deadlineSignal.addEventListener('abort', this.onAbort, { once: true })
    void this.open()
  }

  private async open(): Promise<void> {
    if (this.deadlineSignal.aborted) {
      // A signal that is already aborted counts as fired: nothing is spawned.
      this.settle(null, undefined, true)
      return
    }
    try {
      await this.openChannel()
    } catch (error) {
      this.spawnFailure = error
      this.stderr.append(`\n[remote spawn failed] ${error instanceof Error ? error.message : String(error)}\n`)
      this.settle(null, undefined, true)
    }
  }

  /**
   * Open the channel and wire it before yielding. Every listener is registered
   * inside the exec callback: a channel that closes on the first turn would
   * otherwise deliver `close` before an awaited continuation could attach, and
   * the handle would never settle.
   * @returns when the channel is open and wired.
   */
  private async openChannel(): Promise<void> {
    const client = await this.world.poolFor(this.machine).connect()
    await new Promise<void>((resolve, reject) => {
      client.exec(this.command, {}, (error, stream) => {
        if (error) {
          reject(new Error(`remote command failed to start: ${error.message}`))
          return
        }
        stream.on('data', (chunk: Buffer) => { this.ingestStdout(chunk.toString('utf8')) })
        stream.stderr?.on('data', (chunk: Buffer) => { this.stderr.append(chunk.toString('utf8')) })
        stream.on('close', (code: number | undefined, signal: string | undefined) => {
          this.settle(typeof code === 'number' ? code : null, signal)
        })
        if (this.spec.stdin !== undefined) stream.write(this.spec.stdin, 'utf8')
        try {
          stream.end()
        } catch {
          // stdin was already closed by the remote side; the command still runs.
        }
        if (this.killed) this.killChannel()
        resolve()
      })
    })
  }

  /**
   * Ingest stdout, parsing the leading PID marker once so kill() can target the
   * remote process group. The marker is the script's first line, so that line
   * is consumed rather than shown.
   */
  private ingestStdout(text: string): void {
    this.pendingMarker += text
    if (!this.markerParsed) {
      const newline = this.pendingMarker.indexOf('\n')
      if (newline >= 0) {
        const first = this.pendingMarker.slice(0, newline)
        this.pendingMarker = this.pendingMarker.slice(newline + 1)
        const at = first.indexOf(PID_MARKER)
        if (at >= 0) {
          const pid = Number.parseInt(first.slice(at + PID_MARKER.length), 10)
          if (Number.isFinite(pid)) this.remotePid = pid
        }
        this.markerParsed = true
      }
    }
    if (this.pendingMarker.length === 0) return
    this.stdout.append(this.pendingMarker)
    this.pendingMarker = ''
  }

  private settle(code: number | null, signal: string | undefined, killed = false): void {
    if (this.settled) return
    this.settled = true
    this.disarmDeadline()
    this.deadlineSignal.removeEventListener('abort', this.onAbort)
    this.exitCode = code
    this.signal = signal === undefined || signal === null ? null : signal as NodeJS.Signals
    this.status = killed || this.killed || this.signal !== null ? 'killed' : 'completed'
    if (this.exitCode === 125 && this.stderr.collected().text.includes(CD_FAIL_MARKER)) {
      this.cdFailure = `cannot use remote working directory ${this.remotePath}: `
        + this.stderr.collected().text.replace(CD_FAIL_MARKER, '').trim()
    }
    this.world.audit(this.machine, this.spec.command, this.exitCode)
    this.resolveDone()
  }

  readOutput(): ShellProcessRead {
    const out = this.stdout.readFrom(this.stdoutCursor)
    const err = this.stderr.readFrom(this.stderrCursor)
    this.stdoutCursor = out.nextOffset
    this.stderrCursor = err.nextOffset
    const separator = out.text.length > 0 && !out.text.endsWith('\n') ? '\n' : ''
    return {
      delta: out.text + (err.text.length > 0 ? `${separator}[stderr]\n${err.text}` : ''),
      lossy: out.lossy || err.lossy,
    }
  }

  kill(): boolean {
    if (this.status !== 'running') return false
    this.killed = true
    this.killChannel()
    return true
  }

  /** Signal the remote process group, escalating to SIGKILL after the grace. */
  private killChannel(): void {
    void this.signalRemote('TERM')
    const escalate = setTimeout(() => {
      if (this.status === 'running') void this.signalRemote('KILL')
    }, KILL_ESCALATION_MS)
    escalate.unref()
  }

  result(): Promise<ShellRunResult> {
    this.resultPromise ??= this.done.then(() => {
      if (this.spawnFailure !== undefined) throw this.spawnFailure
      if (this.cdFailure !== undefined) throw new Error(this.cdFailure)
      const timedOut = timeoutOf(this.deadlineSignal, TIMEOUT_CODE) !== undefined
      return {
        exitCode: this.exitCode,
        signal: this.signal,
        timedOut,
        aborted: !timedOut && this.deadlineSignal.aborted,
        timeoutMs: this.spec.timeoutMs,
        stdout: this.stdout.collected(),
        stderr: this.stderr.collected(),
        sandbox: this.sandbox,
      }
    })
    return this.resultPromise
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
      // Best-effort: closing the channel still tears the session down.
    }
  }
}
