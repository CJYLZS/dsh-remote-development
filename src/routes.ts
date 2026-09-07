/**
 * JSON routes the Web client uses to manage machines and pick remote
 * workspaces. Registered through `ctx.inject(['webServer'], …)` so a headless
 * composition (no webserver) simply never mounts them.
 * @module dsh-remote-development/routes
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import type { WebServer } from '@deepseek-ai/dsh-host-webserver'
import { RemoteWorld } from './world.ts'
import type { Machine } from './registry.ts'
import { normalizeRemotePath } from './paths.ts'

const ROUTE_PREFIX = '/dsh-remote-development'
const BODY_LIMIT_BYTES = 256 * 1024

/** One machine as the client may see it: credentials never leave the host. */
function publicMachine(m: Machine): Record<string, unknown> {
  return {
    id: m.id,
    name: m.name,
    host: m.host,
    port: m.port,
    username: m.username,
    privateKeyPath: m.privateKeyPath,
    useAgent: m.useAgent,
    keyboardInteractive: m.keyboardInteractive,
    hasPassword: m.password.length > 0,
    hasPassphrase: m.passphrase.length > 0,
    hostKeyMode: m.hostKeyMode,
    proxyHost: m.proxy?.host ?? '',
    workspace: m.workspace,
  }
}

/**
 * Read one JSON body with a size cap.
 * @param req - the request.
 * @returns the parsed body, or null when absent/over the cap/invalid.
 */
function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = []
    let size = 0
    let done = false
    const finish = (value: Record<string, unknown> | null): void => {
      if (done) return
      done = true
      resolve(value)
    }
    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > BODY_LIMIT_BYTES) {
        finish(null)
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      if (done) return
      const raw = Buffer.concat(chunks).toString('utf8').trim()
      if (!raw) return finish({})
      try {
        const parsed = JSON.parse(raw) as unknown
        finish(parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null)
      } catch {
        finish(null)
      }
    })
    req.on('error', () => finish(null))
  })
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body)
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text) })
  res.end(text)
}

/**
 * Register the JSON routes on the live web server.
 * @param ctx - plugin context (effects scope the disposers).
 * @param webServer - the running web server.
 * @param world - the remote world coordinator.
 */
export function registerRoutes(ctx: Context, webServer: WebServer, world: RemoteWorld): void {
  const machineFromBody = (body: Record<string, unknown>): Partial<Machine> => ({
    name: String(body.name ?? ''),
    host: String(body.host ?? ''),
    port: Number(body.port ?? 22),
    username: String(body.username ?? ''),
    password: String(body.password ?? ''),
    privateKeyPath: String(body.privateKeyPath ?? ''),
    passphrase: String(body.passphrase ?? ''),
    useAgent: body.useAgent === true,
    keyboardInteractive: body.keyboardInteractive === true,
    hostKeyMode: String(body.hostKeyMode ?? 'accept-new'),
    ...(typeof body.proxyHost === 'string' && body.proxyHost.trim()
      ? {
          proxy: {
            host: String(body.proxyHost),
            port: Number(body.proxyPort ?? 22),
            username: String(body.proxyUsername ?? ''),
            password: String(body.proxyPassword ?? ''),
            privateKeyPath: '',
            passphrase: '',
          },
        }
      : {}),
  })

  const resolveRef = (body: Record<string, unknown>) => {
    const id = String(body.machineId ?? body.id ?? '')
    const ref = id ? world.machineById(id) : null
    if (!ref) {
      const current = world.currentMachine()
      return current ? { source: 'registry' as const, machine: current } : null
    }
    return ref
  }

  const routes = [
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/machines`,
      handler: async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
        if (req.method === 'GET') {
          return sendJson(res, 200, {
            machines: world.listMachines().map(publicMachine),
            currentId: world.currentMachine()?.id ?? null,
          })
        }
        if (req.method === 'POST') {
          const body = await readJsonBody(req)
          if (!body) return sendJson(res, 400, { ok: false, error: 'invalid JSON body' })
          if (!String(body.host ?? '').trim()) return sendJson(res, 400, { ok: false, error: 'host is required' })
          const machine = world.upsertMachine(machineFromBody(body))
          return sendJson(res, 200, { ok: true, machine: publicMachine(machine) })
        }
        return sendJson(res, 405, { ok: false, error: 'method not allowed' })
      },
    },
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/machines/delete`,
      handler: async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
        if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
        const body = await readJsonBody(req)
        const id = String(body?.id ?? '')
        if (!id) return sendJson(res, 400, { ok: false, error: 'id is required' })
        return sendJson(res, 200, { ok: world.removeMachine(id) })
      },
    },
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/machines/current`,
      handler: async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
        if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
        const body = await readJsonBody(req)
        if (!body) return sendJson(res, 400, { ok: false, error: 'invalid JSON body' })
        const id = body.id === null ? null : String(body.id ?? '')
        return sendJson(res, 200, { ok: world.setCurrent(id) })
      },
    },
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/test`,
      handler: async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
        if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
        const body = await readJsonBody(req)
        if (!body) return sendJson(res, 400, { ok: false, error: 'invalid JSON body' })
        const ref = resolveRef(body) ?? world.ephemeralRef(machineFromBody(body))
        try {
          const pool = world.poolFor(ref)
          await pool.exec('echo dsh-remote-development-ok', { timeoutMs: Math.min(world.config.connectTimeoutMs + world.config.commandTimeoutMs, 30000) })
          return sendJson(res, 200, { ok: true, platform: pool.platformInfo })
        } catch (err) {
          return sendJson(res, 200, { ok: false, error: (err as Error).message })
        }
      },
    },
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/ls`,
      handler: async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
        if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
        const body = await readJsonBody(req)
        if (!body) return sendJson(res, 400, { ok: false, error: 'invalid JSON body' })
        const ref = resolveRef(body)
        if (!ref) return sendJson(res, 400, { ok: false, error: 'no machine available' })
        try {
          const path = normalizeRemotePath(String(body.path ?? '~'))
          const expanded = path === '~' || path.startsWith('~/')
            ? (await world.execOn(ref, 'echo $HOME', { timeoutMs: 8000 })).stdout.trim()
            : ''
          const dir = expanded ? normalizeRemotePath(path.replace(/^~/, expanded)) : path
          const result = await world.execOn(
            ref,
            `ls -1Ap ${JSON.stringify(dir)} 2>/dev/null | head -500`,
            { timeoutMs: world.config.commandTimeoutMs },
          )
          if (result.code !== 0) {
            return sendJson(res, 200, { ok: false, error: `cannot list ${dir}: ${result.stderr.trim() || `exit ${result.code}`}` })
          }
          const entries = result.stdout.split('\n').filter(Boolean).map((line) => {
            const isDir = line.endsWith('/')
            const name = isDir ? line.slice(0, -1) : line
            return { name, dir: isDir, path: dir === '/' ? `/${name}` : `${dir}/${name}` }
          })
          return sendJson(res, 200, { ok: true, path: dir, entries })
        } catch (err) {
          return sendJson(res, 200, { ok: false, error: (err as Error).message })
        }
      },
    },
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/mkdir`,
      handler: async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
        if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
        const body = await readJsonBody(req)
        if (!body) return sendJson(res, 400, { ok: false, error: 'invalid JSON body' })
        const ref = resolveRef(body)
        if (!ref) return sendJson(res, 400, { ok: false, error: 'no machine available' })
        const parent = normalizeRemotePath(String(body.path ?? ''))
        const name = String(body.name ?? '').trim()
        if (!name || name.includes('/')) return sendJson(res, 400, { ok: false, error: 'a single folder name is required' })
        const target = parent === '/' ? `/${name}` : `${parent}/${name}`
        try {
          const result = await world.execOn(ref, `mkdir ${JSON.stringify(target)}`, { timeoutMs: world.config.commandTimeoutMs })
          if (result.code !== 0) return sendJson(res, 200, { ok: false, error: result.stderr.trim() || `exit ${result.code}` })
          return sendJson(res, 200, { ok: true, path: target })
        } catch (err) {
          return sendJson(res, 200, { ok: false, error: (err as Error).message })
        }
      },
    },
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/anchor`,
      handler: async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
        if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
        const body = await readJsonBody(req)
        if (!body) return sendJson(res, 400, { ok: false, error: 'invalid JSON body' })
        const ref = resolveRef(body)
        if (!ref) return sendJson(res, 400, { ok: false, error: 'no machine available' })
        const remotePath = normalizeRemotePath(String(body.path ?? ''))
        if (!remotePath.startsWith('/')) return sendJson(res, 400, { ok: false, error: 'an absolute remote directory path is required' })
        try {
          const anchorPath = world.createAnchor(ref.machine, remotePath)
          return sendJson(res, 200, { ok: true, anchorPath, remotePath })
        } catch (err) {
          return sendJson(res, 200, { ok: false, error: (err as Error).message })
        }
      },
    },
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/session-remote`,
      handler: async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
        if (req.method !== 'GET') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
        const url = new URL(req.url ?? '/', 'http://localhost')
        const sessionId = url.searchParams.get('sessionId') ?? ''
        if (!sessionId) return sendJson(res, 400, { ok: false, error: 'sessionId is required' })
        const sessions = ctx.get('sessions')
        if (sessions === undefined) return sendJson(res, 200, { remote: false })
        try {
          const session = (sessions as unknown as { get: (id: string) => { header?: { cwd?: string } } | undefined }).get(sessionId)
          const cwd = session?.header?.cwd
          if (!cwd) return sendJson(res, 200, { remote: false })
          const local = world.classifyHostPath(cwd)
          if (local.kind !== 'remote') return sendJson(res, 200, { remote: false })
          return sendJson(res, 200, { remote: true, remotePath: local.route.remotePath })
        } catch (err) {
          return sendJson(res, 200, { remote: false, error: (err as Error).message })
        }
      },
    },
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/picker`,
      handler: async (_req: IncomingMessage, res: ServerResponse): Promise<void> => {
        // Which interaction the host's composed directory picker serves. Read
        // lazily and duck-typed: the seam lives in a host-only package the
        // plugin deliberately keeps out of its dependency graph, and an absent
        // or not-yet-mounted seam answers "unknown" instead of failing.
        type PickerFace = { capability?: () => { kind?: string } }
        const picker = (ctx as unknown as { get(key: string): unknown })
          .get('directoryPicker') as PickerFace | undefined
        let kind = 'unknown'
        try {
          const probed = picker?.capability?.().kind
          if (probed === 'native' || probed === 'browse') kind = probed
        } catch {
          // Seam present but not resolvable yet — same "unknown" answer.
        }
        return sendJson(res, 200, { kind })
      },
    },
    {
      kind: 'exact' as const,
      path: `${ROUTE_PREFIX}/status`,
      handler: async (_req: IncomingMessage, res: ServerResponse): Promise<void> => {
        const current = world.currentMachine()
        return sendJson(res, 200, {
          current: current ? publicMachine(current) : null,
          anchors: world.anchors().map((a) => ({ dir: a.dir, remotePath: a.remoteRoot })),
        })
      },
    },
  ]

  const disposers = routes.map((route) => webServer.register(route))
  ctx.effect(() => () => disposers.forEach((dispose) => dispose()), 'dsh-remote-development.routes')
}
