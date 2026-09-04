import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { RemoteWorld } from '../src/world.ts'
import { sanitizeMachine } from '../src/registry.ts'
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

function tempDir(): string {
  return mkdtempSync(path.join(tmpdir(), 'rdv-world-'))
}

const MACHINE = sanitizeMachine({ host: 'dev.example.com', username: 'dev', port: 22 })

function worldWithAnchor(root: string, remotePath: string): RemoteWorld {
  const world = new RemoteWorld(baseConfig(root))
  world.upsertMachine(MACHINE)
  world.createAnchor(MACHINE, remotePath)
  return world
}

test('classifyHostPath routes anchor paths remote and keeps metadata local', () => {
  const root = tempDir()
  try {
    const world = worldWithAnchor(root, '/home/dev/myapp')
    const anchor = world.anchors()[0]!
    const inside = world.classifyHostPath(path.join(anchor.dir, 'src', 'index.ts'))
    assert.equal(inside.kind, 'remote')
    if (inside.kind === 'remote') assert.equal(inside.route.remotePath, '/home/dev/myapp/src/index.ts')
    const meta = world.classifyHostPath(path.join(anchor.dir, '.dsh-remote-development.json'))
    assert.equal(meta.kind, 'meta')
    const outside = world.classifyHostPath('/etc/hosts')
    assert.equal(outside.kind, 'local')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('classifyRemotePath claims remote-coordinate paths', () => {
  const root = tempDir()
  try {
    const world = worldWithAnchor(root, '/home/dev/myapp')
    const hit = world.classifyRemotePath('/home/dev/myapp/src/index.ts')
    assert.equal(hit?.remotePath, '/home/dev/myapp/src/index.ts')
    assert.equal(world.classifyRemotePath('/var/log'), null)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('machineForMeta resolves the registry record and rejects strangers', () => {
  const root = tempDir()
  try {
    const world = worldWithAnchor(root, '/home/dev/myapp')
    const anchor = world.anchors()[0]!
    const ref = world.machineForAnchor(anchor)
    assert.equal(ref?.machine.host, 'dev.example.com')
    const stranger = new RemoteWorld(baseConfig(tempDir()))
    const none = stranger.machineForAnchor(anchor)
    assert.equal(none, null)
    void stranger.dispose()
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('a fresh registry adopts the config default; an explicit none stays inert', () => {
  const root = tempDir()
  try {
    const config = baseConfig(root)
    config.host = 'cfg.example.com'
    config.username = 'dev'
    const world = new RemoteWorld(config)
    assert.equal(world.currentMachine()?.host, 'cfg.example.com')
    const second = new RemoteWorld(config)
    second.setCurrent(null)
    const third = new RemoteWorld(config)
    assert.equal(third.currentMachine(), null)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
