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

test('loadRegistry returns a fresh registry for a missing file', () => {
  const dir = tempDir()
  try {
    const data = loadRegistry(path.join(dir, 'machines.json'))
    assert.deepEqual(data, { version: 1, currentId: null, machines: [] })
    assert.equal(registryExists(path.join(dir, 'machines.json')), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('save + load round-trips machines and the current id', () => {
  const dir = tempDir()
  try {
    const file = path.join(dir, 'machines.json')
    const a = sanitizeMachine({ host: 'a', username: 'dev' })
    const b = sanitizeMachine({ host: 'b', username: 'dev' })
    saveRegistry(file, { version: 1, currentId: b.id, machines: [a, b] })
    assert.equal(registryExists(file), true)
    const loaded = loadRegistry(file)
    assert.equal(loaded.machines.length, 2)
    assert.equal(loaded.currentId, b.id)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('loadRegistry drops a current id that names no machine', () => {
  const dir = tempDir()
  try {
    const file = path.join(dir, 'machines.json')
    saveRegistry(file, { version: 1, currentId: 'ghost', machines: [] })
    assert.equal(loadRegistry(file).currentId, null)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
