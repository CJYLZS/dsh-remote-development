import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { HostKeyGuard, makeKeyBlob, type KnownHostEntry } from '../src/hostkey.ts'

function memoryStore(): {
  read: () => Record<string, KnownHostEntry>
  write: (entries: Record<string, KnownHostEntry>) => void
  data: Record<string, KnownHostEntry>
} {
  const data: Record<string, KnownHostEntry> = {}
  return {
    read: () => data,
    write: (entries) => { Object.keys(data).forEach((k) => delete data[k]); Object.assign(data, entries) },
    data,
  }
}

test('accept-new records a first-seen key and trusts it afterwards', () => {
  const store = memoryStore()
  const guard = new HostKeyGuard('accept-new', store)
  const blob = makeKeyBlob('ssh-ed25519', 7)
  assert.deepEqual(guard.verify('h:22', blob), { kind: 'recorded' })
  assert.deepEqual(guard.verify('h:22', blob), { kind: 'trusted' })
  assert.equal(Object.keys(store.data).length, 1)
})

test('a changed key is rejected with a MITM reason', () => {
  const store = memoryStore()
  const guard = new HostKeyGuard('accept-new', store)
  guard.verify('h:22', makeKeyBlob('ssh-ed25519', 1))
  const decision = guard.verify('h:22', makeKeyBlob('ssh-ed25519', 2))
  assert.equal(decision.kind, 'rejected')
  if (decision.kind === 'rejected') assert.match(decision.reason, /CHANGED/)
})

test('verify mode rejects hosts never seen', () => {
  const guard = new HostKeyGuard('verify', memoryStore())
  const decision = guard.verify('h:22', makeKeyBlob('ssh-ed25519', 1))
  assert.equal(decision.kind, 'rejected')
})

test('off skips verification entirely', () => {
  const guard = new HostKeyGuard('off', memoryStore())
  assert.deepEqual(guard.verify('h:22', makeKeyBlob('a', 1)), { kind: 'trusted' })
})

test('forget clears the record so the next key is recorded again', () => {
  const store = memoryStore()
  const guard = new HostKeyGuard('accept-new', store)
  guard.verify('h:22', makeKeyBlob('ssh-ed25519', 3))
  guard.forget('h:22')
  assert.deepEqual(guard.verify('h:22', makeKeyBlob('ssh-ed25519', 9)), { kind: 'recorded' })
})
