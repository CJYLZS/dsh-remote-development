import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { Context } from '@deepseek-ai/cordis'
import { tmpdir } from 'node:os'
import path from 'node:path'
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

function fakeStream(): ClientChannel {
  const listeners = new Map<string, (v?: unknown) => void>()
  return {
    on(event: string, fn: (v?: unknown) => void): void { listeners.set(event, fn) },
    stderr: { on(): void {} },
    signal(): void {},
    close(): void {},
    end(): void {},
    write(): void {},
    emit(event: string, v?: unknown): void { listeners.get(event)?.(v) },
  } as unknown as ClientChannel
}

/**
 * A world double exposing only the surface the remote branch reads: path
 * classification, the machine for an anchor, and one fake pool whose exec
 * captures the composed remote command line.
 */
function fakeWorld(options: {
  classifyHost?: (cwd: string) => { kind: 'remote'; route: AnchorRoute } | { kind: 'local' }
  classifyRemote?: (cwd: string) => AnchorRoute | null
  machine?: MachineRef | null
  onCommand?: (command: string) => void
  exitCode?: number
}): RemoteWorld {
  const client = (): SshClientLike => ({
    exec(command: string, _opts: unknown, cb: (err: Error | undefined, stream: ClientChannel) => void): void {
      options.onCommand?.(command)
      const stream = fakeStream()
      queueMicrotask(() => {
        cb(undefined, stream)
        queueMicrotask(() => stream.emit('close', options.exitCode ?? 0, undefined))
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
      exec: async (command: string) => {
        options.onCommand?.(command)
        return { code: options.exitCode ?? 0, signal: undefined, timedOut: false, stdout: '', stderr: '' }
      },
      tunables: { maxOutputChars: 1000 },
    }),
    audit: () => {},
    anchors: () => [ANCHOR],
  } as unknown as RemoteWorld
}

const BUDGETS = {
  cwd: process.cwd(),
  timeoutMs: 120_000,
  maxTimeoutMs: 600_000,
  maxOutputBytes: 64_000,
  maxSpillBytes: 64 * 1024 * 1024,
  graceMs: 3_000,
}

function spec(workdir: string, command: string): ShellExecSpec {
  return {
    command,
    workdir,
    timeoutMs: 120_000,
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
  const executor = new RoutingBashExecutor(harness(), BUDGETS, world)
  const result = await executor.run(spec(path.join(ANCHOR.dir, 'src'), `cat ${ANCHOR.dir}/src/app.ts`))
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
  const executor = new RoutingPwshExecutor(harness(), BUDGETS, world)
  const result = await executor.run(spec(ANCHOR.dir, 'Get-ChildItem'))
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
  const bashExecutor = new RoutingBashExecutor(bashCtx, BUDGETS, world)
  await bashExecutor.run(spec(tmpdir(), 'echo hi'))
  const pwshCtx = harness()
  pwshCtx.provide('subprocess', spawnSpy)
  const pwshExecutor = new RoutingPwshExecutor(pwshCtx, BUDGETS, world)
  await pwshExecutor.run(spec(tmpdir(), 'echo hi'))
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
  const executor = new RoutingBashExecutor(harness(), BUDGETS, world)
  await executor.run(spec('/home/dev/myapp/build.log', 'tail -n 5 build.log'))
  assert.equal(commands.length, 1, 'a remote-coordinate workdir must route to the machine it belongs to')
})

test('an anchor whose machine is gone refuses on both executors', async () => {
  const world = fakeWorld({
    classifyHost: () => ({ kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp' } }),
    machine: null,
  })
  // One ctx.shell provider per context: each executor registers the service.
  await assert.rejects(new RoutingBashExecutor(harness(), BUDGETS, world).run(spec(ANCHOR.dir, 'ls')), /no longer configured/)
  await assert.rejects(new RoutingPwshExecutor(harness(), BUDGETS, world).run(spec(ANCHOR.dir, 'ls')), /no longer configured/)
})

