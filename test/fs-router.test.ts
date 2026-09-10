import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { Readable } from 'node:stream'
import { Context, Service } from '@deepseek-ai/cordis'
import { FsError } from '@deepseek-ai/dsh-fs'
import type { SFTPWrapper } from 'ssh2'
import type { SandboxMode } from '@deepseek-ai/dsh-sandbox'
import { RoutingFileSystem } from '../src/fs-router.ts'
import type { MachineRef, RemoteWorld } from '../src/world.ts'
import type { SshPool } from '../src/pool.ts'

/** The remote path the stub world routes to the stub machine. */
const REMOTE_FILE = '/remote/a.txt'

/** The machine record the stub world resolves anchors to. */
const MACHINE = { source: 'registry', machine: { id: 'host|22|dev' } } as unknown as MachineRef

/**
 * One-channel SFTP fake: serves the window bytes from one in-memory buffer
 * through a createReadStream with ssh2's inclusive start/end semantics.
 */
class WindowSftp {
  constructor(private readonly data: Buffer) {}

  createReadStream(_p: string, opts: { start?: number; end?: number } = {}): Readable {
    const stream = new Readable({ read() {} })
    const data = this.data
    queueMicrotask(() => {
      const start = opts.start ?? 0
      const end = Math.min(opts.end ?? data.length - 1, data.length - 1)
      if (start < data.length && start <= end) stream.push(data.subarray(start, end + 1))
      stream.push(null)
    })
    return stream
  }
}

/**
 * A world stub that routes `REMOTE_FILE` to {@link MACHINE} backed by the
 * given SFTP channel and leaves every other path local. `routeRemote`
 * overrides the machine an anchor resolves to, for the unconfigured refusal.
 */
function stubWorld(
  sftp: SFTPWrapper,
  routeRemote: (anchor: object) => MachineRef | null = () => MACHINE,
): RemoteWorld {
  const pool = { sftp: async () => sftp } as unknown as SshPool
  return {
    classifyHostPath: () => ({ kind: 'local' }),
    classifyRemotePath: (p: string) =>
      p === REMOTE_FILE ? { anchor: { dir: '/remote', meta: { username: 'dev', host: 'host', port: 22 } }, remotePath: p } : null,
    machineForAnchor: routeRemote,
    machineById: (id: string) => (id === MACHINE.machine.id ? MACHINE : null),
    poolFor: () => pool,
  } as unknown as RemoteWorld
}

/** The sandbox-policy fact the sandbox layer's constructor reads. */
class StubPolicy extends Service {
  readonly defaultMode: SandboxMode = 'danger-full-access'

  constructor(ctx: Context) {
    super(ctx, 'sandboxPolicy')
  }
}

/**
 * A routing filesystem over a real Context: a stub sandbox policy mounts so
 * the base classes' constructor reads resolve, and the router registers as
 * `fs`.
 */
async function bootRouter(world: RemoteWorld): Promise<RoutingFileSystem> {
  const ctx = new Context()
  await ctx.plugin(StubPolicy)
  return new RoutingFileSystem(ctx, world, 1000, 0, { cwd: process.cwd(), diffBasisMaxBytes: 1024 })
}

test('readByteRange routes a remote target to the machine window read', async () => {
  const fs = await bootRouter(stubWorld(new WindowSftp(Buffer.from('abcdefgh')) as unknown as SFTPWrapper))
  const target = await fs.resolve(REMOTE_FILE)
  const window = await fs.readByteRange(target, { offset: 2, length: 3 })
  assert.equal(Buffer.from(window).toString('utf8'), 'cde')
})

test('readByteRange refuses a remote path whose machine is gone', async () => {
  const fs = await bootRouter(stubWorld(new WindowSftp(Buffer.alloc(0)) as unknown as SFTPWrapper, () => null))
  await assert.rejects(
    () => fs.resolve(REMOTE_FILE),
    (err: FsError) => err.code === 'FS_IO_ERROR' && err.message.includes('no longer configured'),
  )
})

test('readByteRange falls through to the local backend for local targets', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'rdv-fs-router-'))
  try {
    const file = path.join(dir, 'a.txt')
    await writeFile(file, 'local bytes')
    const fs = await bootRouter(stubWorld(new WindowSftp(Buffer.alloc(0)) as unknown as SFTPWrapper))
    const target = await fs.resolve(file)
    const window = await fs.readByteRange(target, { offset: 6, length: 5 })
    assert.equal(Buffer.from(window).toString('utf8'), 'bytes')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
