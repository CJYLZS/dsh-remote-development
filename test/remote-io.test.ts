import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { FsError, FsVersion } from '@deepseek-ai/dsh-fs'
import { writeRemoteText, editRemoteText, versionOf } from '../src/remote-io.ts'
import type { Stats, SFTPWrapper } from 'ssh2'

/** In-memory SFTP fake covering the surface remote-io drives. */
class FakeSftp {
  files = new Map<string, Buffer>()
  failRenameOntoExisting = false

  private stats(p: string): Stats {
    const data = this.files.get(p)
    const stats = {
      isFile: () => data !== undefined,
      isDirectory: () => false,
      isSymbolicLink: () => false,
      size: data?.length ?? 0,
      mtime: 1_700_000_000,
      mtimeMs: 1_700_000_000_000,
    } as unknown as Stats
    return stats
  }

  stat(p: string, cb: (err: Error | null, stats?: Stats) => void): void {
    if (!this.files.has(p)) return cb(errno('ENOENT'))
    cb(null, this.stats(p))
  }

  lstat(p: string, cb: (err: Error | null, stats?: Stats) => void): void {
    this.stat(p, cb)
  }

  readFile(p: string, cb: (err: Error | null, data?: Buffer) => void): void {
    const data = this.files.get(p)
    if (!data) return cb(errno('ENOENT'))
    cb(null, Buffer.from(data))
  }

  writeFile(p: string, data: string | Buffer, cb: (err: Error | null) => void): void {
    this.files.set(p, Buffer.from(data))
    cb(null)
  }

  /** Directories are not modeled: creation always succeeds. */
  mkdir(_p: string, cb: (err: Error | null) => void): void {
    cb(null)
  }

  rename(from: string, to: string, cb: (err: Error | null) => void): void {
    if (this.failRenameOntoExisting && this.files.has(to)) return cb(errno('EPERM'))
    const data = this.files.get(from)
    if (!data) return cb(errno('ENOENT'))
    this.files.delete(from)
    this.files.set(to, data)
    cb(null)
  }

  unlink(p: string, cb: (err: Error | null) => void): void {
    if (!this.files.delete(p)) return cb(errno('ENOENT'))
    cb(null)
  }
}

const NO_SIGNAL = undefined
const TIMEOUT = 1000

/** Production functions type the client as ssh2's SFTPWrapper; the fake covers the driven subset. */
const asSftp = (fake: FakeSftp): SFTPWrapper => fake as unknown as SFTPWrapper

/** An errno-style error carrying the string code, like a server error. */
function errno(code: string): Error {
  const err = new Error(code) as NodeJS.ErrnoException
  err.code = code
  return err
}

test('writeRemoteText creates unconditionally and reports the version', async () => {
  const sftp = new FakeSftp()
  const outcome = await writeRemoteText(asSftp(sftp), '/home/dev/a.txt', 'hello', undefined, NO_SIGNAL, TIMEOUT)
  assert.equal(outcome.operation, 'create')
  assert.equal(outcome.before, null)
  assert.equal(outcome.after, 'hello')
  assert.equal(sftp.files.get('/home/dev/a.txt')?.toString('utf8'), 'hello')
})

test('createIfAbsent refuses an existing target with FS_NOT_OBSERVED', async () => {
  const sftp = new FakeSftp()
  await writeRemoteText(asSftp(sftp), '/a.txt', 'one', undefined, NO_SIGNAL, TIMEOUT)
  await assert.rejects(
    () => writeRemoteText(asSftp(sftp), '/a.txt', 'two', { kind: 'createIfAbsent' }, NO_SIGNAL, TIMEOUT),
    (err: FsError) => err.code === 'FS_NOT_OBSERVED',
  )
})

test('replaceIfVersion refuses a stale version with FS_STALE_VERSION', async () => {
  const sftp = new FakeSftp()
  const first = await writeRemoteText(asSftp(sftp), '/a.txt', 'one', undefined, NO_SIGNAL, TIMEOUT)
  await assert.rejects(
    () => writeRemoteText(asSftp(sftp), '/a.txt', 'two', { kind: 'replaceIfVersion', version: FsVersion('999-nope') }, NO_SIGNAL, TIMEOUT),
    (err: FsError) => err.code === 'FS_STALE_VERSION',
  )
  const ok = await writeRemoteText(asSftp(sftp), '/a.txt', 'two', { kind: 'replaceIfVersion', version: first.version }, NO_SIGNAL, TIMEOUT)
  assert.equal(ok.operation, 'update')
  assert.equal(ok.before, 'one')
})

test('editRemoteText matches after CRLF normalization and restores CRLF', async () => {
  const sftp = new FakeSftp()
  await writeRemoteText(asSftp(sftp), '/crlf.txt', 'one\r\ntwo\r\n', undefined, NO_SIGNAL, TIMEOUT)
  const outcome = await editRemoteText(asSftp(sftp), '/crlf.txt', { oldString: 'two', newString: '2', replaceAll: false }, undefined, NO_SIGNAL, TIMEOUT)
  assert.equal(outcome.before, 'one\ntwo\n')
  assert.equal(outcome.after, 'one\n2\n')
  assert.equal(sftp.files.get('/crlf.txt')?.toString('utf8'), 'one\r\n2\r\n')
})

test('editRemoteText reports ambiguity and miss with stable codes', async () => {
  const sftp = new FakeSftp()
  await writeRemoteText(asSftp(sftp), '/a.txt', 'x\nx\n', undefined, NO_SIGNAL, TIMEOUT)
  await assert.rejects(
    () => editRemoteText(asSftp(sftp), '/a.txt', { oldString: 'x', newString: 'y', replaceAll: false }, undefined, NO_SIGNAL, TIMEOUT),
    (err: FsError) => err.code === 'FS_AMBIGUOUS_EDIT',
  )
  await assert.rejects(
    () => editRemoteText(asSftp(sftp), '/a.txt', { oldString: 'zz', newString: 'y', replaceAll: false }, undefined, NO_SIGNAL, TIMEOUT),
    (err: FsError) => err.code === 'FS_EDIT_NOT_FOUND',
  )
  const replaced = await editRemoteText(asSftp(sftp), '/a.txt', { oldString: 'x', newString: 'y', replaceAll: true }, undefined, NO_SIGNAL, TIMEOUT)
  assert.equal(sftp.files.get('/a.txt')?.toString('utf8'), 'y\ny\n')
  assert.equal(replaced.after, 'y\ny\n')
})

test('a version guard checked before the match rejects stale edits', async () => {
  const sftp = new FakeSftp()
  await writeRemoteText(asSftp(sftp), '/a.txt', 'content', undefined, NO_SIGNAL, TIMEOUT)
  await assert.rejects(
    () => editRemoteText(asSftp(sftp), '/a.txt', { oldString: 'content', newString: 'new', replaceAll: false }, { version: FsVersion('bogus') }, NO_SIGNAL, TIMEOUT),
    (err: FsError) => err.code === 'FS_STALE_VERSION',
  )
})

test('two writes of identical content produce the same version token', async () => {
  const sftp = new FakeSftp()
  const first = await writeRemoteText(asSftp(sftp), '/v.txt', 'same', undefined, NO_SIGNAL, TIMEOUT)
  const second = await writeRemoteText(asSftp(sftp), '/v.txt', 'same', { kind: 'replaceIfVersion', version: first.version }, NO_SIGNAL, TIMEOUT)
  assert.equal(second.version, first.version)
  void versionOf
})
