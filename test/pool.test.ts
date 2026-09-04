import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { SshPool } from '../src/pool.ts'
import type { ClientChannel, SshClientLike } from '../src/pool.ts'

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
