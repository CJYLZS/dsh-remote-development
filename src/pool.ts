/**
 * Per-machine SSH connection pool (one persistent client per remote identity)
 * with TOFU host-key verification, password/key/agent/keyboard-interactive
 * auth, optional proxy jump, exec with bounded output + timeout + one stale-
 * connection retry, and a timeout-guarded SFTP surface.
 *
 * The pool is testable without a network: the `clientFactory` option injects
 * fake ssh2 clients. Windows remote machines are detected and refused with a
 * clear error — the Git Bash adapter is a reserved follow-up.
 * @module dsh-remote-development/pool
 */

import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'
import ssh2 from 'ssh2'
import type { ClientChannel, SFTPWrapper } from 'ssh2'
import { keyFingerprint } from './hostkey.ts'
import type { KnownHostEntry } from './hostkey.ts'
import type { ProxyConfig } from './config.ts'
import type { RemotePlatform } from './paths.ts'
import { truncateHead } from './paths.ts'

const { Client } = ssh2

/** Connection + command tunables shared by every pool (from plugin Config). */
export interface PoolTunables {
  connectTimeoutMs: number
  commandTimeoutMs: number
  maxOutputChars: number
  maxFileBytes: number
}

/** Everything needed to open one SSH connection. */
export interface PoolTarget {
  host: string
  port: number
  username: string
  password: string
  privateKeyPath: string
  passphrase: string
  useAgent: boolean
  keyboardInteractive: boolean
  proxy?: ProxyConfig
  hostKeyMode: string
}

/** One completed remote command. `signal` is non-null only when the command was killed. */
export interface RemoteExecResult {
  code: number | null
  signal: 'SIGTERM' | null
  stdout: string
  stderr: string
  timedOut: boolean
}

/** Raised when the remote machine is a Windows host (unsupported in v1). */
export class UnsupportedRemoteError extends Error {
  constructor() {
    super(
      'the remote machine runs Windows, which dsh-remote-development does not support yet '
      + '(POSIX remotes only in v1)',
    )
    this.name = 'UnsupportedRemoteError'
  }
}

/** Result of one `exec` channel opened by the factory (test seam). */
export interface OpenedChannel {
  stream: ClientChannel
}

/** Minimal shape of an ssh2 client the pool drives (real or fake). */
export interface SshClientLike {
  on(event: 'ready', listener: () => void): unknown
  on(event: 'error', listener: (err: Error) => void): unknown
  on(event: 'close', listener: () => void): unknown
  on(event: 'keyboard-interactive', listener: (name: string, instructions: string, lang: string, prompts: unknown[], finish: (answers: string[]) => void) => void): unknown
  connect(options: Record<string, unknown>): void
  exec(command: string, opts: Record<string, unknown>, cb: (err: Error | undefined, stream: ClientChannel) => void): void
  sftp(cb: (err: Error | undefined, sftp: SFTPWrapper) => void): void
  forwardOut(srcIP: string, srcPort: number, dstIP: string, dstPort: number, cb: (err: Error | undefined, channel: ClientChannel) => void): void
  end(): void
}

/** Creates one unconnected ssh2 client (injectable for tests). */
export type ClientFactory = () => SshClientLike

/** Durable known-hosts storage the pool's guard reads and writes. */
export interface HostKeyStore {
  read: () => Record<string, KnownHostEntry>
  write: (entries: Record<string, KnownHostEntry>) => void
}

const CHANNEL_DEAD_PATTERN =
  /channel open failure|open failed|unexpected .*session termination|session termination|disconnect/i

/**
 * One persistent SSH connection to a single remote identity. Concurrent calls
 * share the connection; a dead pooled connection is invalidated and retried
 * once on a fresh one. An epoch token orphans in-flight connects after a
 * target change or close.
 */
export class SshPool {
  private target: PoolTarget
  private tunablesSnapshot: PoolTunables
  private readonly hostKeys: HostKeyStore
  private readonly newClient: ClientFactory
  private client: SshClientLike | null = null
  private connecting: Promise<SshClientLike> | null = null
  private sftpSession: SFTPWrapper | null = null
  private proxyPool: SshPool | null = null
  private epoch = 0
  private platform: RemotePlatform = 'unknown'
  private detecting: Promise<void> | null = null

  /**
   * @param target - connection identity and credentials.
   * @param tunables - timeouts and output caps (live plugin config).
   * @param hostKeys - durable TOFU storage.
   * @param newClient - client factory (tests inject fakes).
   */
  constructor(target: PoolTarget, tunables: PoolTunables, hostKeys: HostKeyStore, newClient: ClientFactory = () => new Client() as unknown as SshClientLike) {
    this.target = { ...target }
    this.tunablesSnapshot = { ...tunables }
    this.hostKeys = hostKeys
    this.newClient = newClient
  }

  /** The identity this pool is pinned to. */
  get targetInfo(): Readonly<PoolTarget> {
    return this.target
  }

  /** The live tunables (output caps, timeouts) this pool applies. */
  get tunables(): Readonly<PoolTunables> {
    return this.tunablesSnapshot
  }

  /** Detected remote platform ('unknown' before the first command). */
  get platformInfo(): RemotePlatform {
    return this.platform
  }

  /** Replace connection tunables (a settings change reaches live pools). */
  retune(tunables: PoolTunables): void {
    this.tunablesSnapshot = { ...tunables }
  }

  /**
   * Drop the cached connection so the next call opens a fresh one. Called when
   * a channel error shows the pooled connection died server-side.
   */
  invalidate(): void {
    this.epoch++
    const client = this.client
    this.client = null
    const sftp = this.sftpSession
    this.sftpSession = null
    if (sftp) {
      try { sftp.end() } catch { /* already dead */ }
    }
    const pending = this.connecting
    this.connecting = null
    pending?.catch(() => {})
    if (this.proxyPool) {
      try { this.proxyPool.close() } catch { /* already closing */ }
      this.proxyPool = null
    }
    if (client) {
      try { client.end() } catch { /* already dead */ }
    }
  }

  /** Close the connection and orphan every in-flight connect. */
  close(): void {
    this.invalidate()
  }

  /** Connect (or return the live client). */
  connect(): Promise<SshClientLike> {
    if (this.client) return Promise.resolve(this.client)
    if (this.connecting) return this.connecting
    const epoch = this.epoch
    const pending = this.doConnect(epoch)
    this.connecting = pending
    const clear = (): void => {
      if (this.epoch === epoch && this.connecting === pending) this.connecting = null
    }
    pending.then(clear, clear)
    return pending
  }

  private async doConnect(epoch: number): Promise<SshClientLike> {
    const isCurrent = (): boolean => this.epoch === epoch
    const client = this.newClient()
    let settled = false
    const fail = (err: Error): never => {
      if (settled) throw err
      settled = true
      if (isCurrent() && this.client === client) this.client = null
      throw err
    }

    // Proxy jump: tunnel the target connection through the bastion.
    let sock: ClientChannel | undefined
    const proxy = this.target.proxy
    if (proxy && proxy.host) {
      try {
        this.proxyPool = new SshPool(
          {
            host: proxy.host,
            port: proxy.port || 22,
            username: proxy.username || this.target.username || 'root',
            password: proxy.password,
            privateKeyPath: proxy.privateKeyPath,
            passphrase: proxy.passphrase,
            useAgent: false,
            keyboardInteractive: false,
            hostKeyMode: this.target.hostKeyMode,
          },
          this.tunablesSnapshot,
          this.hostKeys,
          this.newClient,
        )
        const bastion = await this.proxyPool.connect()
        if (!isCurrent()) throw new Error('ssh target changed during proxy connect')
        sock = await new Promise<ClientChannel>((resolve, reject) => {
          bastion.forwardOut('127.0.0.1', 0, this.target.host, this.target.port, (err, channel) => {
            if (err) reject(new Error(`proxy forward to target failed: ${err.message}`))
            else resolve(channel)
          })
        })
      } catch (err) {
        return fail(err as Error)
      }
    }

    return new Promise<SshClientLike>((resolve, reject) => {
      const rejectOnce = (err: Error): void => {
        if (settled) return
        settled = true
        if (isCurrent() && this.client === client) this.client = null
        reject(err)
      }
      client.on('ready', () => {
        if (settled) return
        settled = true
        if (!isCurrent()) {
          try { client.end() } catch { /* tearing down anyway */ }
          reject(new Error('ssh target changed during connect'))
          return
        }
        this.client = client
        resolve(client)
      })
      client.on('error', (err) => rejectOnce(err))
      client.on('close', () => rejectOnce(new Error('ssh connection closed')))

      const buildOpts = (): Record<string, unknown> => {
        const opts: Record<string, unknown> = {
          host: this.target.host,
          port: this.target.port,
          username: this.target.username,
          readyTimeout: this.tunablesSnapshot.connectTimeoutMs,
          keepaliveInterval: 15000,
          keepaliveCountMax: 3,
          hostVerifier: (key: unknown): boolean => {
            if (this.target.hostKeyMode === 'off') return true
            let fingerprint: string
            try {
              fingerprint = keyFingerprint(key)
            } catch {
              return false
            }
            const hostId = `${this.target.host}:${this.target.port}`
            const stored = this.hostKeys.read()[hostId]
            if (stored) return stored.fingerprint === fingerprint
            if (this.target.hostKeyMode === 'verify') return false
            this.hostKeys.write({
              ...this.hostKeys.read(),
              [hostId]: { algo: 'unknown', fingerprint, firstSeen: new Date().toISOString() },
            })
            return true
          },
        }
        if (sock) opts.sock = sock
        if (this.target.useAgent && process.env.SSH_AUTH_SOCK) opts.agent = process.env.SSH_AUTH_SOCK
        if (this.target.password) {
          opts.password = this.target.password
          opts.tryKeyboard = true
        } else if (this.target.keyboardInteractive && !this.target.privateKeyPath) {
          opts.tryKeyboard = true
        }
        if (this.target.privateKeyPath) {
          const keyPath = this.target.privateKeyPath.startsWith('~/')
            ? path.join(homedir(), this.target.privateKeyPath.slice(1))
            : this.target.privateKeyPath
          let key: Buffer
          try {
            key = readFileSync(keyPath)
          } catch (err) {
            throw new Error(`cannot read private key "${keyPath}": ${(err as Error).message}`)
          }
          opts.privateKey = key
          if (this.target.passphrase) opts.passphrase = this.target.passphrase
        } else if (!this.target.password && !opts.agent) {
          throw new Error('no credentials: set a password or a private key path to connect')
        }
        return opts
      }

      let opts: Record<string, unknown>
      try {
        opts = buildOpts()
      } catch (err) {
        rejectOnce(err as Error)
        return
      }
      if (opts.tryKeyboard === true) {
        client.on('keyboard-interactive', (_name, _instructions, _lang, prompts, finish) => {
          finish(prompts.map(() => this.target.password))
        })
      }
      client.connect(opts)
    })
  }

  /**
   * Detect the remote platform once per target. Windows remotes are refused in
   * v1; detection failures land on 'posix' (the overwhelmingly common case).
   */
  async detectPlatform(): Promise<RemotePlatform> {
    if (this.platform !== 'unknown') return this.platform
    if (this.detecting) return this.detecting.then(() => this.platform)
    this.detecting = (async () => {
      try {
        // execOnce, not exec: exec() re-enters detectPlatform() first, and the
        // `detecting` assignment lands only after that call chain returns — a
        // self-recursion that runs to stack overflow, then "heals" through this
        // catch by firing the whole descent's uname channels at the real server.
        const res = await this.execOnce('uname -s', Math.min(this.tunablesSnapshot.commandTimeoutMs, 8000), {})
        if (/mingw|msys|cygwin|windows/i.test(res.stdout) || /mingw|msys|cygwin|windows/i.test(res.stderr)) {
          this.platform = 'windows'
          return
        }
        this.platform = 'posix'
      } catch {
        // No uname (unusual for a POSIX host) — assume POSIX; commands will
        // fail naturally if the machine is exotic.
        this.platform = 'posix'
      }
    })()
    try {
      await this.detecting
    } finally {
      this.detecting = null
    }
    return this.platform
  }

  /**
   * Run one remote command with bounded output, timeout kill, and one
   * stale-connection retry. Windows remotes fail loud before anything runs.
   * @param command - remote command line (run under the login shell).
   * @param opts - timeout override, stdin payload, and abort signal.
   * @returns exit facts and collected output.
   */
  async exec(command: string, opts: { timeoutMs?: number; stdin?: string; signal?: AbortSignal } = {}): Promise<RemoteExecResult> {
    const platform = await this.detectPlatform()
    if (platform === 'windows') throw new UnsupportedRemoteError()
    const timeoutMs = opts.timeoutMs ?? this.tunablesSnapshot.commandTimeoutMs
    let retried = false
    const attempt = (): Promise<RemoteExecResult> => this.execOnce(command, timeoutMs, opts)
    try {
      return await attempt()
    } catch (err) {
      if (retried || !CHANNEL_DEAD_PATTERN.test(String((err as Error).message))) throw err
      retried = true
      this.invalidate()
      return attempt()
    }
  }

  private execOnce(command: string, timeoutMs: number, opts: { stdin?: string; signal?: AbortSignal }): Promise<RemoteExecResult> {
    return this.connect().then(
      (client) =>
        new Promise<RemoteExecResult>((resolve, reject) => {
          client.exec(command, {}, (err, stream) => {
            if (err) {
              reject(new Error(`ssh exec failed: ${err.message}`))
              return
            }
            let stdout = ''
            let stderr = ''
            let settled = false
            let code: number | null = null
            let sig: 'SIGTERM' | null = null
            let timedOut = false
            const hardCap = Math.max(this.tunablesSnapshot.maxOutputChars * 4, 1024 * 1024)
            const settle = (): void => {
              if (settled) return
              settled = true
              clearTimeout(timer)
              offAbort()
              resolve({
                code,
                signal: sig,
                stdout: truncateHead(stdout, this.tunablesSnapshot.maxOutputChars),
                stderr: truncateHead(stderr, this.tunablesSnapshot.maxOutputChars),
                timedOut,
              })
            }
            const timer = setTimeout(() => {
              if (settled) return
              timedOut = true
              sig = 'SIGTERM'
              code = null
              try {
                stream.signal('SIGTERM')
              } catch { /* older ssh2 without signal support */ }
              const hardClose = setTimeout(() => {
                try { stream.close() } catch { /* already closed */ }
              }, 800)
              hardClose.unref()
              settle()
            }, timeoutMs)
            const onAbort = (): void => {
              if (settled) return
              timedOut = false
              sig = 'SIGTERM'
              code = null
              try {
                stream.signal('SIGTERM')
              } catch { /* older ssh2 without signal support */ }
              settle()
            }
            const offAbort = attachAbort(opts.signal, onAbort)
            stream.on('close', (c: number | undefined, s: string | undefined) => {
              if (settled) return
              code = typeof c === 'number' ? c : null
              sig = s === 'SIGTERM' ? 'SIGTERM' : sig
              settle()
            })
            stream.on('data', (d: Buffer) => {
              if (stdout.length < hardCap) stdout += d.toString('utf8')
            })
            stream.stderr?.on('data', (d: Buffer) => {
              if (stderr.length < hardCap) stderr += d.toString('utf8')
            })
            stream.on('error', (e: Error) => {
              if (settled) return
              settled = true
              clearTimeout(timer)
              offAbort()
              reject(new Error(`ssh stream error: ${e.message}`))
            })
            if (opts.stdin !== undefined) {
              stream.end(opts.stdin)
            }
          })
        }),
    )
  }

  /**
   * Resolve the pool's one shared SFTP session. The SFTP protocol multiplexes
   * every request over its single subsystem channel, so one session serves all
   * concurrent file operations; opening a channel per call would leak sessions
   * until the server's MaxSessions cap answers every open with a channel
   * failure. The cache drops on session death, so the next call reopens.
   */
  async sftp(): Promise<SFTPWrapper> {
    if (this.sftpSession) return this.sftpSession
    const client = await this.connectWithRetry()
    return new Promise<SFTPWrapper>((resolve, reject) => {
      client.sftp((err, sftp) => {
        if (err) {
          reject(new Error(`ssh sftp failed: ${err.message}`))
          return
        }
        // Session death (channel close, protocol error) clears the cache; an
        // 'error' listener here also keeps the event from crashing the process.
        const drop = (): void => {
          if (this.sftpSession === sftp) this.sftpSession = null
        }
        sftp.on('close', drop)
        sftp.on('error', drop)
        this.sftpSession = sftp
        resolve(sftp)
      })
    })
  }

  private async connectWithRetry(): Promise<SshClientLike> {
    try {
      return await this.connect()
    } catch (err) {
      if (!CHANNEL_DEAD_PATTERN.test(String((err as Error).message))) throw err
      this.invalidate()
      return this.connect()
    }
  }
}

/**
 * Attach an abort listener that runs `fn` once; returns the detach function.
 * @param signal - optional abort signal.
 * @param fn - listener to run on abort.
 * @returns a detacher safe to call unconditionally.
 */
function attachAbort(signal: AbortSignal | undefined, fn: () => void): () => void {
  if (!signal) return () => {}
  if (signal.aborted) {
    fn()
    return () => {}
  }
  const listener = (): void => fn()
  signal.addEventListener('abort', listener, { once: true })
  return () => signal.removeEventListener('abort', listener)
}

export type { ClientChannel, SFTPWrapper }
