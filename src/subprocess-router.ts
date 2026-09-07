/**
 * The routing `ctx.subprocess` provider: extends the local runtime with a
 * remote branch for spawn requests whose cwd sits under an anchor directory.
 * Remote argv runs over the SSH exec channel as a quoted command line (the
 * seam's "argv is never shell-interpreted" is preserved by quoting every
 * element); the packaged ripgrep is re-pointed at the remote `rg` so the grep
 * and glob tools keep parsing identical output.
 *
 * Remote terminal sessions are refused with a clear model-facing error in v1:
 * SSH cannot provide the foreground-process-group facts the terminal contract
 * requires, and a silently degraded terminal would be worse than an honest
 * refusal.
 * @module dsh-remote-development/subprocess-router
 */

import { Context } from '@deepseek-ai/cordis'
import { LocalSubprocessRuntime } from '@deepseek-ai/dsh-subprocess-local'
import type {
  SubprocessHandle,
  SubprocessOutcome,
  SubprocessOutputRead,
  SubprocessOutputReader,
  SubprocessSpawnSpec,
  SubprocessTerminalHandle,
  SubprocessTerminalSpawnSpec,
} from '@deepseek-ai/dsh-subprocess'
import type { ClientChannel } from 'ssh2'
import { RemoteWorld } from './world.ts'
import type { MachineRef } from './world.ts'
import { unconfiguredMachineMessage } from './world.ts'
import { argvToRemoteCommand, shq } from './paths.ts'

/** Tail-keeping byte buffer with whole-stream offset reads. */
class CollectBuffer {
  private bytes: Uint8Array = new Uint8Array(0)
  private dropped = 0
  private received = 0

  /**
   * @param maxBytes - in-memory cap; overflow keeps the tail.
   */
  constructor(readonly maxBytes: number) {}

  /** Append bytes, discarding the head beyond the cap. */
  push(chunk: Uint8Array): void {
    this.received += chunk.length
    const merged = new Uint8Array(this.bytes.length + chunk.length)
    merged.set(this.bytes, 0)
    merged.set(chunk, this.bytes.length)
    if (this.maxBytes > 0 && merged.length > this.maxBytes) {
      const cut = merged.length - this.maxBytes
      this.dropped += cut
      this.bytes = merged.slice(cut)
      return
    }
    this.bytes = merged
  }

  /** Total bytes ever received. */
  get total(): number {
    return this.received
  }

  /**
   * Offset-based, non-consuming read.
   * @param fromByte - whole-stream offset to resume from.
   * @returns the delta read.
   */
  readFrom(fromByte: number): SubprocessOutputRead {
    if (fromByte < this.dropped) {
      return { text: new TextDecoder().decode(this.bytes), nextOffset: this.received, lossy: true }
    }
    const start = Math.min(Math.max(fromByte, 0), this.received) - this.dropped
    return {
      text: new TextDecoder().decode(this.bytes.slice(Math.max(start, 0))),
      nextOffset: Math.max(fromByte, this.received),
      lossy: false,
    }
  }
}

/** Build an offset-based reader view over one buffer. */
function readerOf(buffer: CollectBuffer): SubprocessOutputReader {
  return { readFrom: (fromByte: number) => buffer.readFrom(fromByte) }
}

/** Opened-channel state (absent until the SSH exec channel exists). */
interface ChannelState {
  channel: ClientChannel
  stdoutBuffer: CollectBuffer | undefined
  stderrBuffer: CollectBuffer | undefined
  stdinPipe: boolean
  stdoutPipe: boolean
}

/**
 * One remote managed process over an SSH exec channel. The channel IS the
 * process lifetime: `done` settles at channel close with the remote exit
 * facts and rejects only when the channel cannot be opened (a spawn-level
 * failure). Remote PIDs are not observable over SSH, so `pid` is -1.
 */
class RemoteSpawnHandle implements SubprocessHandle {
  readonly pid = -1
  readonly done: Promise<SubprocessOutcome>
  private state: ChannelState | null = null
  private terminated = false
  private readonly spec: SubprocessSpawnSpec

  /**
   * Start the remote process for one spec. The SSH round trip begins
   * immediately; `spawn()` returns this handle synchronously.
   * @param world - remote world (pool access).
   * @param machine - target machine.
   * @param spec - fully-specified spawn request.
   */
  constructor(world: RemoteWorld, machine: MachineRef, spec: SubprocessSpawnSpec) {
    this.spec = spec
    let resolveDone: (outcome: SubprocessOutcome) => void
    let rejectDone: (err: Error) => void
    this.done = new Promise<SubprocessOutcome>((resolve, reject) => {
      resolveDone = resolve
      rejectDone = reject
    })
    if (spec.signal) {
      if (spec.signal.aborted) this.terminate()
      else spec.signal.addEventListener('abort', () => this.terminate(), { once: true })
    }
    void this.open(world, machine, resolveDone!, rejectDone!)
  }

  private async open(
    world: RemoteWorld,
    machine: MachineRef,
    resolveDone: (outcome: SubprocessOutcome) => void,
    rejectDone: (err: Error) => void,
  ): Promise<void> {
    try {
      const pool = world.poolFor(machine)
      const client = await pool.connect()
      const remoteArgv = rewriteRipgrep(this.spec.argv, world.config.remoteRipgrep)
      const command = buildRemoteCommand(remoteArgv, this.spec.env)
      await new Promise<void>((resolve, reject) => {
        client.exec(command, {}, (err, channel) => {
          if (err) {
            reject(new Error(`remote spawn failed: ${err.message}`))
            return
          }
          this.attach(channel, resolveDone)
          resolve()
        })
      })
    } catch (err) {
      rejectDone(err as Error)
    }
  }

  private attach(channel: ClientChannel, resolveDone: (outcome: SubprocessOutcome) => void): void {
    const spec = this.spec
    const state: ChannelState = {
      channel,
      stdoutBuffer: spec.stdio.stdout !== 'pipe' && spec.stdio.stdout !== 'inherit'
        ? new CollectBuffer(spec.stdio.stdout.maxBytes)
        : undefined,
      stderrBuffer: spec.stdio.stderr !== 'pipe' && spec.stdio.stderr !== 'inherit'
        ? new CollectBuffer(spec.stdio.stderr.maxBytes)
        : undefined,
      stdinPipe: spec.stdio.stdin === 'pipe',
      stdoutPipe: spec.stdio.stdout === 'pipe',
    }
    this.state = state
    if (state.stdoutBuffer) {
      channel.on('data', (d: Buffer) => state.stdoutBuffer?.push(new Uint8Array(d)))
    }
    if (state.stderrBuffer) {
      channel.stderr?.on('data', (d: Buffer) => state.stderrBuffer?.push(new Uint8Array(d)))
    }
    if (spec.stdio.stderr === 'inherit') {
      channel.stderr?.on('data', (d: Buffer) => process.stderr.write(d))
    }
    if (spec.stdio.stdin === 'ignore') {
      try { channel.end() } catch { /* stdin already closed */ }
    } else if (spec.stdio.stdin !== 'pipe') {
      channel.write(spec.stdio.stdin.data, 'utf8')
      try { channel.end() } catch { /* stdin already closed */ }
    }
    channel.on('close', (code: number | undefined, sig: string | undefined) => {
      resolveDone({
        exitCode: typeof code === 'number' ? code : null,
        signal: (sig as SubprocessOutcome['signal']) ?? null,
      })
    })
    channel.on('error', () => {
      // A transport error after open settles as a signal death, not a spawn
      // failure — the command ran.
      resolveDone({ exitCode: null, signal: null })
    })
    if (this.terminated) this.terminate()
  }

  get stdin(): ClientChannel | undefined {
    return this.state?.stdinPipe ? this.state.channel : undefined
  }

  get stdout(): ClientChannel | undefined {
    return this.state?.stdoutPipe ? this.state.channel : undefined
  }

  get stderr(): undefined {
    // Remote stderr pipes are not exposed: the collect mode covers every
    // remote consumer (search tools), and protocol framing stays local-only.
    return undefined
  }

  get collected(): { stdout?: SubprocessOutputReader; stderr?: SubprocessOutputReader } {
    const state = this.state
    if (!state) return {}
    return {
      ...state.stdoutBuffer ? { stdout: readerOf(state.stdoutBuffer) } : {},
      ...state.stderrBuffer ? { stderr: readerOf(state.stderrBuffer) } : {},
    }
  }

  terminate(): void {
    this.terminated = true
    const state = this.state
    if (!state) return
    try {
      state.channel.signal('SIGTERM')
    } catch { /* server without signal support */ }
    setTimeout(() => {
      try { state.channel.close() } catch { /* already closed */ }
    }, 500).unref()
  }

  async waitForExit(signal?: AbortSignal): Promise<boolean> {
    if (signal?.aborted) return false
    return Promise.race([
      this.done.then(() => true),
      ...signal
        ? [new Promise<false>((resolve) => {
            const onAbort = (): void => resolve(false)
            signal.addEventListener('abort', onAbort, { once: true })
          })]
        : [],
    ])
  }
}

/**
 * Re-point the packaged ripgrep binary at the remote `rg` command.
 * @param argv - the local argv vector.
 * @param remoteRipgrep - the remote ripgrep command name.
 * @returns the argv with argv[0] rewritten when it is the packaged rg.
 */
function rewriteRipgrep(argv: readonly string[], remoteRipgrep: string): string[] {
  const first = argv[0] ?? ''
  const rest = argv.slice(1)
  const base = first.replace(/\\/g, '/').split('/').pop() ?? ''
  if (base === 'rg' || base === 'rg.exe') return [remoteRipgrep, ...rest]
  return [first, ...rest]
}

/** Compose the remote command line: optional env prefix, then the quoted argv. */
function buildRemoteCommand(argv: readonly string[], env: NodeJS.ProcessEnv | undefined): string {
  if (env) {
    const parts: string[] = []
    for (const [key, value] of Object.entries(env)) {
      if (value === undefined) continue
      parts.push(`${key}=${shq(value)}`)
    }
    if (parts.length > 0) return `env ${parts.join(' ')} ${argvToRemoteCommand(argv)}`
  }
  return argvToRemoteCommand(argv)
}

/**
 * The routing subprocess runtime. Construction registers `ctx.subprocess`; on
 * win32 hosts every call delegates (remote command routing is a POSIX-host
 * capability in v1), so the disabled base row never leaves the seam empty.
 */
export class RoutingSubprocessRuntime extends LocalSubprocessRuntime {
  private readonly world: RemoteWorld

  /**
   * @param ctx - plugin context.
   * @param world - the remote world coordinator.
   */
  constructor(ctx: Context, world: RemoteWorld) {
    super(ctx)
    this.world = world
  }

  override spawn(spec: SubprocessSpawnSpec): SubprocessHandle {
    if (process.platform === 'win32') return super.spawn(spec)
    const route = this.world.classifyHostPath(spec.cwd)
    if (route.kind !== 'remote') return super.spawn(spec)
    const machine = this.world.machineForAnchor(route.route.anchor)
    // Refuse instead of falling back: a local spawn would silently run the
    // command on the wrong host.
    if (!machine) throw new Error(unconfiguredMachineMessage(route.route.anchor))
    return new RemoteSpawnHandle(this.world, machine, spec)
  }

  override async spawnTerminal(spec: SubprocessTerminalSpawnSpec): Promise<SubprocessTerminalHandle> {
    if (process.platform !== 'win32') {
      const route = this.world.classifyHostPath(spec.cwd)
      if (route.kind === 'remote') {
        throw new Error(
          'remote terminal sessions are not supported by dsh-remote-development yet. '
          + 'Use the bash tool to run commands on the remote host instead.',
        )
      }
    }
    return super.spawnTerminal(spec)
  }
}
