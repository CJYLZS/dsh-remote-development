import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { Context } from '@deepseek-ai/cordis'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { SandboxBashExecutor } from '@deepseek-ai/dsh-bash-sandbox'
import { SandboxPwshExecutor } from '@deepseek-ai/dsh-pwsh-sandbox'
import { RoutingBashExecutor, RoutingPwshExecutor } from '../src/shell-router.ts'
import type { RemoteWorld, MachineRef } from '../src/world.ts'
import type { AnchorInfo, AnchorRoute } from '../src/anchors.ts'
import type { ClientChannel, SshClientLike } from '../src/pool.ts'
import type { ShellExecSpec } from '@deepseek-ai/dsh-shell'

const ANCHOR: AnchorInfo = {
  dir: path.join(tmpdir(), 'rdv-fake-anchor'),
  meta: { host: 'dev.example.com', port: 22, username: 'dev', remotePath: '/home/dev/myapp', createdAt: '2026-01-01T00:00:00.000Z' },
  remoteRoot: '/home/dev/myapp',
}

const MACHINE: MachineRef = {
  source: 'registry',
  machine: {
    id: 'm1', name: 'dev', host: 'dev.example.com', port: 22, username: 'dev',
    password: '', privateKeyPath: '', passphrase: '', useAgent: false, keyboardInteractive: false, hostKeyMode: 'accept-new', workspace: '', color: '',
  },
}

/** Full-access policy: the local sandbox branch skips confinement entirely. */
const DANGER_POLICY = { mode: 'danger-full-access', workspaceRoot: '/' } as ShellExecSpec['sandboxPolicy']

/** A fake exec channel plus the two emitters the test drives it with. */
type FakeChannel = ClientChannel & {
  emitLine(event: string, ...args: unknown[]): void
  emitStderrLine(...args: unknown[]): void
}

function fakeStream(): FakeChannel {
  const listeners = new Map<string, (v?: unknown, s?: unknown) => void>()
  const stderrListeners = new Map<string, (v?: unknown) => void>()
  return {
    on(event: string, fn: (v?: unknown, s?: unknown) => void): void { listeners.set(event, fn) },
    stderr: { on(event: string, fn: (v?: unknown) => void): void { stderrListeners.set(event, fn) } },
    signal(): void {},
    close(): void {},
    end(): void {},
    write(): void {},
    emitLine(event: string, ...args: unknown[]): void { listeners.get(event)?.(...args) },
    emitStderrLine(...args: unknown[]): void { stderrListeners.get('data')?.(...args) },
  } as unknown as FakeChannel
}

/**
 * A world double exposing only the surface the remote branch reads: path
 * classification, the machine for an anchor, and one fake pool whose channel
 * the test scripts (stdout/stderr lines, when it closes).
 */
function fakeWorld(options: {
  classifyHost?: (cwd: string) => { kind: 'remote'; route: AnchorRoute } | { kind: 'local' }
  classifyRemote?: (cwd: string) => AnchorRoute | null
  machine?: MachineRef | null
  onCommand?: (command: string) => void
  exitCode?: number
  /** What the fake channel emits once it is open, and how long it stays open. */
  channel?: { stdout?: readonly string[]; stderr?: readonly string[]; closeAfterMs?: number }
}): RemoteWorld {
  const client = (): SshClientLike => ({
    exec(command: string, _opts: unknown, cb: (err: Error | undefined, stream: ClientChannel) => void): void {
      options.onCommand?.(command)
      const stream = fakeStream()
      queueMicrotask(() => {
        cb(undefined, stream)
        // One microtask later the execution's listeners are attached, so the
        // scripted lines below are delivered to it rather than dropped.
        queueMicrotask(() => {
          const script = options.channel
          for (const line of script?.stdout ?? []) stream.emitLine('data', Buffer.from(line))
          for (const line of script?.stderr ?? []) stream.emitStderrLine(Buffer.from(line))
          const close = (): void => { stream.emitLine('close', options.exitCode ?? 0, undefined) }
          if (script?.closeAfterMs === undefined) close()
          else setTimeout(close, script.closeAfterMs).unref()
        })
      })
    },
    sftp(): void {},
    forwardOut(): void {},
    end(): void {},
  }) as unknown as SshClientLike
  return {
    config: { remoteRipgrep: 'rg' },
    classifyHostPath: (cwd: string) => options.classifyHost?.(cwd) ?? { kind: 'local' },
    classifyRemotePath: (cwd: string) => options.classifyRemote?.(cwd) ?? null,
    machineForAnchor: () => options.machine === undefined ? MACHINE : options.machine,
    poolFor: () => ({
      connect: async () => client(),
      detectPlatform: async () => 'posix' as const,
      tunables: { maxOutputChars: 1000 },
    }),
    execOn: async () => ({ code: 0, signal: null, stdout: '', stderr: '', timedOut: false }),
    audit: () => {},
    anchors: () => [ANCHOR],
  } as unknown as RemoteWorld
}

/** Plain local budgets, resolved through each executor's own Config schema. */
const BUDGETS = {
  cwd: process.cwd(),
  timeoutMs: 120_000,
  maxTimeoutMs: 600_000,
  maxOutputBytes: 64_000,
  maxSpillBytes: 64 * 1024 * 1024,
  graceMs: 3_000,
}

const bashConfig = (): ConstructorParameters<typeof SandboxBashExecutor>[1] =>
  SandboxBashExecutor.Config(BUDGETS) as unknown as ConstructorParameters<typeof SandboxBashExecutor>[1]
const pwshConfig = (): ConstructorParameters<typeof SandboxPwshExecutor>[1] =>
  SandboxPwshExecutor.Config(BUDGETS) as unknown as ConstructorParameters<typeof SandboxPwshExecutor>[1]

function spec(workdir: string, command: string, timeoutMs = 120_000): ShellExecSpec {
  return {
    command,
    workdir,
    timeoutMs,
    onExpiry: 'kill',
    stdoutMaxBytes: 64_000,
    sandboxPolicy: DANGER_POLICY,
  }
}

/** Bare-root harness: the sandbox policy fake satisfies both constructors. */
function harness(): Context {

  const ctx = new Context()
  ctx.provide('sandboxPolicy', { defaultMode: 'workspace-write', resolve: () => ({ mode: 'workspace-write', workspaceRoot: '/' }) })
  return ctx
}

test('bash executor runs anchor commands as remote bash with rewritten paths', async () => {
  const commands: string[] = []
  const world = fakeWorld({
    classifyHost: (cwd) => cwd.startsWith(ANCHOR.dir)
      ? { kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp/src' } }
      : { kind: 'local' },
    onCommand: (command) => commands.push(command),
  })
  const executor = new RoutingBashExecutor(harness(), bashConfig(), world)
  const result = await (await executor.execute(spec(path.join(ANCHOR.dir, 'src'), `cat ${ANCHOR.dir}/src/app.ts`))).result()
  assert.equal(result.exitCode, 0)
  assert.equal(commands.length, 1)
  assert.ok(commands[0]!.startsWith('bash -c '), `remote commands must run through bash -c, got: ${commands[0]}`)
  assert.ok(commands[0]!.includes('/home/dev/myapp/src/app.ts'), 'anchor spellings must be rewritten to the remote path')
  assert.ok(!commands[0]!.includes(ANCHOR.dir), 'the local anchor handle must never leak into remote commands')
  assert.equal(result.sandbox?.denied, false, 'remote runs bypass the local sandbox wrapper')
})

test('pwsh executor routes anchor commands to remote bash too', async () => {
  const commands: string[] = []
  const world = fakeWorld({
    classifyHost: (cwd) => cwd.startsWith(ANCHOR.dir)
      ? { kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp' } }
      : { kind: 'local' },
    onCommand: (command) => commands.push(command),
  })
  const executor = new RoutingPwshExecutor(harness(), pwshConfig(), world)
  const result = await (await executor.execute(spec(ANCHOR.dir, 'Get-ChildItem'))).result()
  assert.equal(result.exitCode, 0)
  assert.equal(commands.length, 1)
  assert.ok(commands[0]!.startsWith('bash -c '), 'the remote host is POSIX: the command must cross as bash, not pwsh')
  assert.equal(result.sandbox?.denied, false)
})

test('both executors keep local workdirs on their local dialect', async () => {
  const spawns: string[][] = []
  const world = fakeWorld({ classifyHost: () => ({ kind: 'local' }) })
  // One ctx.shell provider per context: each executor registers the service,
  // so the two dialect checks run on separate roots sharing one spy.
  const spawnSpy = {
    spawn: (spawnSpec: { argv: string[] }) => {
      spawns.push([...spawnSpec.argv])
      return {
        done: Promise.resolve({ exitCode: 0, signal: null }),
        collected: {
          stdout: { readFrom: () => ({ text: '', nextOffset: 0, lossy: false }) },
          stderr: { readFrom: () => ({ text: '', nextOffset: 0, lossy: false }) },
        },
        terminate: () => {},
      }
    },
  }
  const bashCtx = harness()
  bashCtx.provide('subprocess', spawnSpy)
  const bashExecutor = new RoutingBashExecutor(bashCtx, bashConfig(), world)
  await (await bashExecutor.execute(spec(tmpdir(), 'echo hi'))).result()
  const pwshCtx = harness()
  pwshCtx.provide('subprocess', spawnSpy)
  const pwshExecutor = new RoutingPwshExecutor(pwshCtx, pwshConfig(), world)
  await (await pwshExecutor.execute(spec(tmpdir(), 'echo hi'))).result()
  assert.equal(spawns.length, 2)
  assert.deepEqual(spawns[0]!.slice(0, 2), ['bash', '-c'], 'the bash executor keeps local workdirs local')
  assert.ok(spawns[1]!.includes('-Command') && spawns[1]!.includes('-NoLogo'), 'the local pwsh branch runs through a pwsh -Command invocation')
})

test('a remote path the model saw classifies back onto its anchor', async () => {
  const commands: string[] = []
  const world = fakeWorld({
    classifyHost: () => ({ kind: 'local' }),
    classifyRemote: (cwd) => cwd.startsWith('/home/dev/myapp')
      ? { anchor: ANCHOR, remotePath: cwd }
      : null,
    onCommand: (command) => commands.push(command),
  })
  const executor = new RoutingBashExecutor(harness(), bashConfig(), world)
  await (await executor.execute(spec('/home/dev/myapp/build.log', 'tail -n 5 build.log'))).result()
  assert.equal(commands.length, 1, 'a remote-coordinate workdir must route to the machine it belongs to')
})

test('an anchor whose machine is gone refuses on both executors', async () => {
  const world = fakeWorld({
    classifyHost: () => ({ kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp' } }),
    machine: null,
  })
  // One ctx.shell provider per context: each executor registers the service.
  await assert.rejects(new RoutingBashExecutor(harness(), bashConfig(), world).execute(spec(ANCHOR.dir, 'ls')), /no longer configured/)
  await assert.rejects(new RoutingPwshExecutor(harness(), pwshConfig(), world).execute(spec(ANCHOR.dir, 'ls')), /no longer configured/)
})

test('a remote execution splits its streams and marks stderr on the read cursor', async () => {
  const world = fakeWorld({
    classifyHost: () => ({ kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp' } }),
    channel: { stdout: ['@@RDV_PID:4242\n', 'build ok\n'], stderr: ['warn: slow\n'] },
  })
  const executor = new RoutingBashExecutor(harness(), bashConfig(), world)
  const execution = await executor.execute(spec(ANCHOR.dir, 'make'))

  const result = await execution.result()
  assert.equal(result.stdout.text, 'build ok\n', 'the PID marker line is consumed, not shown')
  assert.equal(result.stderr.text, 'warn: slow\n')
  assert.equal(execution.observed.stdout.readFrom(0).text, 'build ok\n', 'observed readers keep the streams apart')
  assert.equal(execution.observed.stderr.readFrom(0).text, 'warn: slow\n')

  const read = execution.readOutput()
  assert.equal(read.delta, 'build ok\n[stderr]\nwarn: slow\n', 'the consuming cursor marks the stderr section')
  assert.equal(read.lossy, false)
  assert.equal(execution.readOutput().delta, '', 'the consuming cursor never re-delivers')
  assert.equal(execution.status, 'completed')
})

test('a remote command outliving its deadline is killed and classified timedOut', async () => {
  const world = fakeWorld({
    classifyHost: () => ({ kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp' } }),
    channel: { stdout: ['@@RDV_PID:4242\n'], closeAfterMs: 40 },
  })
  const executor = new RoutingBashExecutor(harness(), bashConfig(), world)
  const execution = await executor.execute(spec(ANCHOR.dir, 'sleep 30', 5))

  const result = await execution.result()
  assert.equal(result.timedOut, true, 'the executor deadline is the first cause')
  assert.equal(result.aborted, false)
  assert.equal(result.timeoutMs, 5)
  assert.equal(execution.status, 'killed')
  assert.equal(execution.kill(), false, 'killing a settled execution is a no-op')
})
