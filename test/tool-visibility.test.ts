import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { RemoteWorld } from '../src/world.ts'
import { sanitizeMachine } from '../src/registry.ts'
import {
  REMOTE_CODE_EXECUTION_DENIED,
  denyListFor,
  keepRemoteSessionCallable,
  type SessionToolSurface,
} from '../src/tool-visibility.ts'
import type { Config } from '../src/config.ts'

function baseConfig(anchorRoot: string): Config {
  return {
    host: '',
    port: 22,
    username: '',
    password: '',
    privateKeyPath: '',
    passphrase: '',
    workspace: '',
    commandTimeoutMs: 20000,
    connectTimeoutMs: 15000,
    maxOutputChars: 200000,
    maxFileBytes: 52428800,
    hostKeyMode: 'accept-new',
    useAgent: false,
    keyboardInteractive: false,
    proxy: { host: '', port: 22, username: '', password: '', privateKeyPath: '', passphrase: '' },
    auditLog: false,
    anchorRoot,
    remoteRipgrep: 'rg',
  }
}

const MACHINE = sanitizeMachine({ host: 'dev.example.com', username: 'dev', port: 22 })

function remoteWorld(): { world: RemoteWorld; anchorDir: string; cleanup: () => void } {
  const root = mkdtempSync(path.join(tmpdir(), 'rdv-visibility-'))
  const world = new RemoteWorld(baseConfig(root))
  world.upsertMachine(MACHINE)
  world.createAnchor(MACHINE, '/home/dev/myapp')
  const anchorDir = world.anchors()[0]!.dir
  return { world, anchorDir, cleanup: () => rmSync(root, { recursive: true, force: true }) }
}

test('a remote session denies the local-dialect shell tools that are registered', () => {
  const { world, anchorDir, cleanup } = remoteWorld()
  try {
    const deny = denyListFor(world, anchorDir, (name) => ['pwsh', 'persistent-pwsh'].includes(name), 'win32')
    assert.deepEqual(deny, ['pwsh'])
  } finally {
    cleanup()
  }
})

test('a remote session on a POSIX-only composition denies nothing (no restrict)', () => {
  const { world, anchorDir, cleanup } = remoteWorld()
  try {
    const deny = denyListFor(world, anchorDir, () => false, 'linux')
    assert.deepEqual(deny, [])
  } finally {
    cleanup()
  }
})

test('a local session on win32 denies the plugin-added bash tool', () => {
  const { world, cleanup } = remoteWorld()
  try {
    const deny = denyListFor(world, tmpdir(), (name) => ['bash', 'persistent-bash'].includes(name), 'win32')
    assert.deepEqual(deny, ['bash'])
  } finally {
    cleanup()
  }
})

test('a local session on POSIX denies nothing — bash is the native tool there', () => {
  const { world, cleanup } = remoteWorld()
  try {
    const deny = denyListFor(world, tmpdir(), () => true, 'linux')
    assert.deepEqual(deny, [])
  } finally {
    cleanup()
  }
})

test('a session without a cwd denies nothing', () => {
  const { world, cleanup } = remoteWorld()
  try {
    const deny = denyListFor(world, undefined, () => true, 'win32')
    assert.deepEqual(deny, [])
  } finally {
    cleanup()
  }
})

test('a remote session whose machine is gone still counts as remote', () => {
  // The workspace outlives its machine: tools refuse with the explicit error,
  // so visibility must keep pointing the model at the remote dialect.
  const { world, anchorDir, cleanup } = remoteWorld()
  try {
    world.removeMachine(MACHINE.id)
    const deny = denyListFor(world, anchorDir, () => true, 'win32')
    assert.deepEqual(deny, ['pwsh'])
  } finally {
    cleanup()
  }
})

/** What one keepRemoteSessionCallable() call observed on its tool surface. */
interface Observed {
  calls: string[]
  warnings: string[]
  guard: ((execution: { readonly name: string }) => string | undefined) | undefined
  result: 'presented' | 'guarded' | 'unsettled'
}

/**
 * Run the remote-session presentation switch against a recording surface.
 * @param options - which mechanisms the fake host exposes, and how presentAs replies.
 * @returns the recorded calls, warnings, captured guard and settled result.
 */
function observe(options: { presentAs?: 'ok' | 'conflict' | 'missing'; guard?: boolean } = {}): Observed {
  const calls: string[] = []
  const warnings: string[] = []
  const observed: Observed = { calls, warnings, guard: undefined, result: 'unsettled' }
  const surface: SessionToolSurface = {}
  if (options.presentAs !== 'missing') {
    surface.presentAs = (mode) => {
      calls.push(`presentAs:${mode}`)
      if (options.presentAs === 'conflict') throw new Error('tools.presentAs("native") conflicts with "ptc" already declared for this scope')
    }
  }
  if (options.guard !== false) {
    surface.guard = (guard) => { calls.push('guard'); observed.guard = guard }
  }
  observed.result = keepRemoteSessionCallable(surface, (message) => warnings.push(message))
  return observed
}

test('a remote session declares itself native, so run_code leaves the wire', () => {
  const seen = observe({ presentAs: 'ok' })
  assert.equal(seen.result, 'presented')
  assert.deepEqual(seen.calls, ['presentAs:native'])
  assert.equal(seen.guard, undefined)
  assert.deepEqual(seen.warnings, [])
})

test('a preset-owned presentation falls back to a monotonic denial with a reason', () => {
  const seen = observe({ presentAs: 'conflict' })
  assert.equal(seen.result, 'guarded')
  assert.deepEqual(seen.calls, ['presentAs:native', 'guard'])
  assert.equal(seen.warnings.length, 1)
  assert.match(seen.warnings[0]!, /already declared/)
  assert.equal(seen.guard!({ name: 'run_code' }), REMOTE_CODE_EXECUTION_DENIED)
  assert.equal(seen.guard!({ name: 'bash' }), undefined)
})

test('a host without presentAs denies run_code without warning', () => {
  const seen = observe({ presentAs: 'missing' })
  assert.equal(seen.result, 'guarded')
  assert.deepEqual(seen.calls, ['guard'])
  assert.deepEqual(seen.warnings, [])
})

test('a host exposing neither mechanism reports the gap instead of pretending', () => {
  const seen = observe({ presentAs: 'missing', guard: false })
  assert.equal(seen.result, 'unsettled')
  assert.deepEqual(seen.calls, [])
  assert.equal(seen.warnings.length, 1)
  assert.match(seen.warnings[0]!, /neither tools\.presentAs\(\) nor tools\.guard\(\)/)
})
