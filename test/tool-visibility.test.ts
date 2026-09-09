import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { RemoteWorld } from '../src/world.ts'
import { sanitizeMachine } from '../src/registry.ts'
import { denyListFor } from '../src/tool-visibility.ts'
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
