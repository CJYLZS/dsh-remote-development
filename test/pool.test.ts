import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { samePoolTarget, SshPool } from '../src/pool.ts'
import type { ClientChannel, PoolTarget, SshClientLike } from '../src/pool.ts'

/** Fake channel emitting one data chunk and an immediate close. */
function fakeStream(): ClientChannel {
  const listeners = new Map<string, (v?: unknown) => void>()
  return {
    on(event: string, fn: (v?: unknown) => void): void { listeners.set(event, fn) },
    stderr: { on(): void {} },
    signal(): void {},
    close(): void {},
    end(): void {},
    emit(event: string, v?: unknown): void { listeners.get(event)?.(v) },
  } as unknown as ClientChannel
}

test('platform detection runs once and never re-enters itself', async () => {
  const commands: string[] = []
  const client = (): SshClientLike => {
    const handlers = new Map<string, (v?: unknown) => void>()
    return {
      on(event: string, fn: (v?: unknown) => void): unknown { handlers.set(event, fn); return undefined },
      connect(): void { queueMicrotask(() => handlers.get('ready')?.()) },
      exec(command: string, _o: unknown, cb: (err: Error | undefined, stream: ClientChannel) => void): void {
        commands.push(command)
        const stream = fakeStream()
        queueMicrotask(() => {
          cb(undefined, stream)
          queueMicrotask(() => stream.emit('data', Buffer.from('Linux\n')))
          queueMicrotask(() => stream.emit('close', 0, undefined))
        })
      },
      sftp(cb: (err: Error | undefined, sftp: unknown) => void): void { cb(new Error('unused'), undefined) },
      forwardOut(): void {},
      end(): void {},
    } as unknown as SshClientLike
  }

  const pool = new SshPool(
    { host: 'h', port: 22, username: 'u', password: 'p', privateKeyPath: '', passphrase: '', useAgent: false, keyboardInteractive: false, hostKeyMode: 'accept-new' },
    { connectTimeoutMs: 1000, commandTimeoutMs: 1000, maxOutputChars: 100, maxFileBytes: 100 },
    { read: () => ({}), write: () => {} },
    client,
  )

  // Two execs: the first detects the platform, the second must reuse it. The
  // detection command itself must not re-enter detection — the pre-fix
  // self-recursion ran ~1300 levels deep before the stack overflow healed.
  await pool.exec('echo one')
  await pool.exec('echo two')
  assert.deepEqual(commands, ['uname -s', 'echo one', 'echo two'])
})

/**
 * One fake client per connection. `alive` models ssh2's own socket guard:
 * exec on a client whose socket is gone throws the bare "Not connected" that
 * the real library throws.
 */
function fakeClientFactory(): { factory: () => SshClientLike; opens: () => number; kill: () => void } {
  let opens = 0
  let liveHandlers: Map<string, (v?: unknown) => void> | null = null
  let alive = false
  const factory = (): SshClientLike => {
    opens += 1
    alive = false
    const handlers = new Map<string, (v?: unknown) => void>()
    liveHandlers = handlers
    return {
      on(event: string, fn: (v?: unknown) => void): unknown { handlers.set(event, fn); return undefined },
      connect(): void { alive = true; queueMicrotask(() => handlers.get('ready')?.()) },
      exec(_c: string, _o: unknown, cb: (err: Error | undefined, stream: ClientChannel) => void): void {
        if (!alive) throw new Error('Not connected')
        const stream = fakeStream()
        queueMicrotask(() => {
          cb(undefined, stream)
          queueMicrotask(() => {
            stream.emit('data', Buffer.from('Linux\n'))
            stream.emit('close', 0, undefined)
          })
        })
      },
      sftp(cb: (err: Error | undefined, sftp: unknown) => void): void { cb(new Error('unused'), undefined) },
      forwardOut(): void {},
      end(): void { alive = false },
    } as unknown as SshClientLike
  }
  return {
    factory,
    opens: () => opens,
    kill: () => {
      alive = false
      liveHandlers?.get('close')?.()
    },
  }
}

const TARGET = {
  host: 'h', port: 22, username: 'u', password: 'p', privateKeyPath: '', passphrase: '',
  useAgent: false, keyboardInteractive: false, hostKeyMode: 'accept-new',
}
const TUNABLES = { connectTimeoutMs: 1000, commandTimeoutMs: 1000, maxOutputChars: 100, maxFileBytes: 100 }

test('a live connection that dies is dropped, so the next exec reconnects', async () => {
  const fake = fakeClientFactory()
  const pool = new SshPool(TARGET, TUNABLES, { read: () => ({}), write: () => {} }, fake.factory)

  await pool.exec('echo one')
  assert.equal(fake.opens(), 1)

  // The server restart / idle NAT drop that leaves the cached client a corpse.
  fake.kill()
  const second = await pool.exec('echo two')

  assert.equal(second.code, 0)
  assert.equal(fake.opens(), 2, 'a dead live connection is replaced, not reused')
})

test('ssh2 "Not connected" is a dead-connection message and retries once', async () => {
  const fake = fakeClientFactory()
  let calls = 0
  const factory = (): SshClientLike => {
    const client = fake.factory()
    const exec = client.exec.bind(client)
    client.exec = ((c: string, o: Record<string, unknown>, cb: (err: Error | undefined, stream: ClientChannel) => void): void => {
      calls += 1
      // The death notice has not been processed yet: ssh2's own guard speaks
      // instead of a channel error, and the pool must still retry.
      if (calls === 2) throw new Error('Not connected')
      exec(c, o, cb)
    }) as SshClientLike['exec']
    return client
  }
  const pool = new SshPool(TARGET, TUNABLES, { read: () => ({}), write: () => {} }, factory)

  const result = await pool.exec('echo after death')
  assert.equal(result.code, 0)
  assert.equal(fake.opens(), 2, 'the retry ran on a fresh connection')
})

test('sftp reuses one channel per pool and reopens only after invalidation', async () => {
  let sftpOpens = 0
  let ended = 0
  const client = (): SshClientLike => {
    const handlers = new Map<string, (v?: unknown) => void>()
    return {
      on(event: string, fn: (v?: unknown) => void): unknown { handlers.set(event, fn); return undefined },
      connect(): void { queueMicrotask(() => handlers.get('ready')?.()) },
      exec(_c: string, _o: unknown, cb: (err: Error | undefined, stream: ClientChannel) => void): void {
        const stream = fakeStream()
        queueMicrotask(() => cb(undefined, stream))
      },
      sftp(cb: (err: Error | undefined, sftp: unknown) => void): void {
        sftpOpens += 1
        const listeners = new Map<string, () => void>()
        const session = {
          on(event: string, fn: () => void): void { listeners.set(event, fn) },
          end(): void { ended += 1; listeners.get('close')?.() },
          emit(event: string): void { listeners.get(event)?.() },
        }
        queueMicrotask(() => cb(undefined, session))
      },
      forwardOut(): void {},
      end(): void {},
    } as unknown as SshClientLike
  }

  const pool = new SshPool(
    { host: 'h', port: 22, username: 'u', password: 'p', privateKeyPath: '', passphrase: '', useAgent: false, keyboardInteractive: false, hostKeyMode: 'accept-new' },
    { connectTimeoutMs: 1000, commandTimeoutMs: 1000, maxOutputChars: 100, maxFileBytes: 100 },
    { read: () => ({}), write: () => {} },
    client,
  )

  const first = await pool.sftp()
  const second = await pool.sftp()
  assert.equal(sftpOpens, 1, 'concurrent sftp calls share one channel')
  assert.equal(first, second)
  pool.invalidate()
  assert.equal(ended, 1, 'invalidation ends the cached channel')
  await pool.sftp()
  assert.equal(sftpOpens, 2, 'a fresh session opens after invalidation')
})

test('samePoolTarget compares every field that decides authentication', () => {
  const base: PoolTarget = {
    host: 'h', port: 22, username: 'u', password: 'p', privateKeyPath: '',
    passphrase: '', useAgent: false, keyboardInteractive: false, hostKeyMode: 'accept-new',
  }
  assert.equal(samePoolTarget(base, { ...base }), true)
  assert.equal(samePoolTarget(base, { ...base, password: 'other' }), false)
  assert.equal(samePoolTarget(base, { ...base, privateKeyPath: 'C:/k' }), false)
  assert.equal(samePoolTarget(base, { ...base, passphrase: 'pp' }), false)
  assert.equal(samePoolTarget(base, { ...base, username: 'v' }), false)
  assert.equal(samePoolTarget(base, { ...base, hostKeyMode: 'verify' }), false)
  assert.equal(samePoolTarget(base, { ...base, keyboardInteractive: true }), false)
  assert.equal(samePoolTarget(base, { ...base, useAgent: true }), false)

  const proxied: PoolTarget = { ...base, proxy: { host: 'b', port: 22, username: 'pu', password: 'pp', privateKeyPath: '', passphrase: '' } }
  assert.equal(samePoolTarget(proxied, { ...proxied, proxy: { ...proxied.proxy! } }), true)
  assert.equal(samePoolTarget(proxied, { ...proxied, proxy: { ...proxied.proxy!, password: 'x' } }), false)
  assert.equal(samePoolTarget(proxied, base), false, 'dropping the bastion is a change')
  assert.equal(samePoolTarget(base, { ...base, proxy: { host: '', port: 22, username: '', password: '', privateKeyPath: '', passphrase: '' } }), true)
})
