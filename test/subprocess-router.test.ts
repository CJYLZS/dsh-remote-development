import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { Context } from '@deepseek-ai/cordis'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { RoutingSubprocessRuntime } from '../src/subprocess-router.ts'
import type { RemoteWorld, MachineRef } from '../src/world.ts'
import type { AnchorInfo, AnchorRoute } from '../src/anchors.ts'
import type { ClientChannel, SshClientLike } from '../src/pool.ts'
import type { SubprocessSpawnSpec, SubprocessTerminalSpawnSpec } from '@deepseek-ai/dsh-subprocess'

const ANCHOR: AnchorInfo = {
  dir: path.join(tmpdir(), 'rdv-fake-anchor'),
  meta: { host: 'dev.example.com', port: 22, username: 'dev', remotePath: '/home/dev/myapp', createdAt: '2026-01-01T00:00:00.000Z' },
  remoteRoot: '/home/dev/myapp',
}

const MACHINE: MachineRef = {
  source: 'registry',
  machine: {
    id: 'm1', name: 'dev', host: 'dev.example.com', port: 22, username: 'dev',
    password: '', privateKeyPath: '', passphrase: '', useAgent: false, keyboardInteractive: false, hostKeyMode: 'accept-new', workspace: '',
  },
}

/** Fake channel emitting an immediate close. */
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
 * A world double exposing only the surface the routing subprocess runtime
 * reads. `classify` decides remote vs local for every cwd; remote routes hand
 * commands to `onCommand` and settle with `exitCode`.
 */
function fakeWorld(options: {
  classify: (cwd: string) => { kind: 'remote'; route: AnchorRoute } | { kind: 'local' }
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
    classifyHostPath: (cwd: string) => options.classify(cwd),
    machineForAnchor: () => options.machine === undefined ? MACHINE : options.machine,
    poolFor: () => ({
      connect: async () => client(),
      exec: async () => ({ code: 0, signal: undefined, timedOut: false, stdout: '', stderr: '' }),
      tunables: { maxOutputChars: 1000 },
    }),
    audit: () => {},
    anchors: () => [ANCHOR],
  } as unknown as RemoteWorld
}

function spawnSpec(cwd: string, argv: readonly string[]): SubprocessSpawnSpec {
  return {
    argv: [...argv],
    cwd,
    stdio: { stdin: 'ignore', stdout: { maxBytes: 1000, spill: { maxBytes: 1000 } }, stderr: { maxBytes: 1000, spill: { maxBytes: 1000 } } },
    graceMs: 100,
  }
}

test('anchor spawns route to the remote machine on every host platform', async () => {
  const commands: string[] = []
  const world = fakeWorld({
    classify: (cwd) => cwd.startsWith(ANCHOR.dir)
      ? { kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp/src' } }
      : { kind: 'local' },
    onCommand: (command) => commands.push(command),
  })
  const router = new RoutingSubprocessRuntime(new Context(), world)
  const handle = router.spawn(spawnSpec(path.join(ANCHOR.dir, 'src'), ['rg', 'pattern', 'src']))
  const outcome = await handle.done
  assert.equal(outcome.exitCode, 0)
  assert.equal(commands.length, 1, 'the spawn must cross the SSH exec channel exactly once')
  assert.match(commands[0]!, /'rg' 'pattern'/, 'the argv must travel as a quoted remote command line')
  assert.match(
    commands[0]!,
    new RegExp(`^cd '/home/dev/myapp/src'`),
    'the remote command must start in the mapped workspace path, not the SSH default cwd',
  )
  assert.match(
    commands[0]!,
    /< \/dev\/null$/,
    "stdin 'ignore' must translate to /dev/null, not a closed pipe: programs that branch on pipe-ness (ripgrep) change behavior at EOF",
  )
})

test('stdin data travels verbatim without a /dev/null redirect', async () => {
  const commands: string[] = []
  const world = fakeWorld({
    classify: () => ({ kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp' } }),
    onCommand: (command) => commands.push(command),
  })
  const router = new RoutingSubprocessRuntime(new Context(), world)
  const handle = router.spawn({
    ...spawnSpec(ANCHOR.dir, ['cat']),
    stdio: { stdin: { data: 'payload' }, stdout: { maxBytes: 1000, spill: { maxBytes: 1000 } }, stderr: { maxBytes: 1000, spill: { maxBytes: 1000 } } },
  })
  await handle.done
  assert.equal(commands.length, 1)
  assert.ok(!commands[0]!.includes('/dev/null'), 'genuine stdin data must not be redirected away')
})

test('local spawns delegate to the inherited runtime and never touch the pool', async () => {
  let pooled = false
  const world = fakeWorld({
    classify: () => ({ kind: 'local' }),
    onCommand: () => { pooled = true },
  })
  const router = new RoutingSubprocessRuntime(new Context(), world)
  const handle = router.spawn(spawnSpec(tmpdir(), [process.execPath, '-e', 'process.exit(0)']))
  const outcome = await handle.done
  assert.equal(outcome.exitCode, 0)
  assert.equal(pooled, false, 'a local cwd must not open an SSH channel')
})

test('remote terminal sessions refuse with the model-facing error on every host platform', async () => {
  const world = fakeWorld({
    classify: (cwd) => cwd.startsWith(ANCHOR.dir)
      ? { kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp' } }
      : { kind: 'local' },
  })
  const router = new RoutingSubprocessRuntime(new Context(), world)
  const spec = { cwd: ANCHOR.dir } as SubprocessTerminalSpawnSpec
  await assert.rejects(router.spawnTerminal(spec), /remote terminal sessions are not supported/)
})

test('an anchor whose machine is gone refuses instead of running locally', () => {
  const world = fakeWorld({
    classify: () => ({ kind: 'remote', route: { anchor: ANCHOR, remotePath: '/home/dev/myapp' } }),
    machine: null,
  })
  const router = new RoutingSubprocessRuntime(new Context(), world)
  assert.throws(() => router.spawn(spawnSpec(ANCHOR.dir, ['rg', 'x'])), /no longer configured/)
})
