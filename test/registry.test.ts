import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { loadRegistry, saveRegistry, sanitizeMachine, machineId, registryExists } from '../src/registry.ts'

function tempDir(): string {
  return mkdtempSync(path.join(tmpdir(), 'rdv-registry-'))
}

test('sanitizeMachine fills defaults and derives the id', () => {
  const m = sanitizeMachine({ host: ' 203.0.113.10 ', port: 2222, username: 'dev' })
  assert.equal(m.host, '203.0.113.10')
  assert.equal(m.port, 2222)
  assert.equal(m.id, machineId('203.0.113.10', 2222, 'dev'))
  assert.equal(m.hostKeyMode, 'accept-new')
  assert.equal(m.name, '203.0.113.10')
})

test('sanitizeMachine rejects an unknown host-key mode', () => {
  const m = sanitizeMachine({ host: 'h', hostKeyMode: 'bogus' })
  assert.equal(m.hostKeyMode, 'accept-new')
})

test('sanitizeMachine keeps a safe marker color and drops everything else', () => {
  assert.equal(sanitizeMachine({ host: 'h', color: ' #22C55E ' }).color, '#22C55E')
  assert.equal(sanitizeMachine({ host: 'h', color: 'emerald' }).color, 'emerald')
  assert.equal(sanitizeMachine({ host: 'h', color: 'red; } body {' }).color, '')
  assert.equal(sanitizeMachine({ host: 'h' }).color, '')
})

test('loadRegistry returns a fresh registry for a missing file', () => {
  const dir = tempDir()
  try {
    const data = loadRegistry(path.join(dir, 'machines.json'))
    assert.deepEqual(data, { version: 1, machines: [] })
    assert.equal(registryExists(path.join(dir, 'machines.json')), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('save + load round-trips machines', () => {
  const dir = tempDir()
  try {
    const file = path.join(dir, 'machines.json')
    const a = sanitizeMachine({ host: 'a', username: 'dev' })
    const b = sanitizeMachine({ host: 'b', username: 'dev' })
    saveRegistry(file, { version: 1, machines: [a, b] })
    assert.equal(registryExists(file), true)
    const loaded = loadRegistry(file)
    assert.equal(loaded.machines.length, 2)
    assert.equal(loaded.machines[1]?.host, 'b')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('loadRegistry drops the obsolete currentId field from older files', () => {
  const dir = tempDir()
  try {
    const file = path.join(dir, 'machines.json')
    saveRegistry(file, { version: 1, currentId: 'ghost', machines: [] } as never)
    assert.deepEqual(loadRegistry(file), { version: 1, machines: [] })
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
