/**
 * Browser-side API for the plugin's host routes. Plain fetch against the
 * same-origin JSON endpoints; errors surface the host's `error` string.
 * @module dsh-remote-development/client/api
 */

/** One machine as the client sees it (credentials never leave the host). */
export interface ClientMachine {
  id: string
  name: string
  host: string
  port: number
  username: string
  privateKeyPath: string
  useAgent: boolean
  keyboardInteractive: boolean
  hasPassword: boolean
  hasPassphrase: boolean
  hostKeyMode: string
  proxyHost: string
  workspace: string
}

/** One remote directory row in the picker. */
export interface RemoteEntry {
  name: string
  dir: boolean
  path: string
}

const PREFIX = '/dsh-remote-development'

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const opts: RequestInit = { method, headers: {} }
  if (body !== undefined) {
    opts.headers = { 'Content-Type': 'application/json' }
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(PREFIX + path, opts)
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok || data.ok === false) {
    throw new Error(typeof data.error === 'string' ? data.error : `HTTP ${res.status}`)
  }
  return data as T
}

/** List saved machines. */
export function listMachines(): Promise<{ machines: ClientMachine[] }> {
  return call('GET', '/machines')
}

/** Add or update one machine. */
export function saveMachine(machine: Record<string, unknown>): Promise<{ machine: ClientMachine }> {
  return call('POST', '/machines', machine)
}

/** Delete one machine by id. */
export function deleteMachine(id: string): Promise<{ ok: boolean }> {
  return call('POST', '/machines/delete', { id })
}

/** Test one machine's connection (saved id or unsaved fields). */
export function testConnection(machine: Record<string, unknown>): Promise<{ ok: boolean; error?: string; platform?: string }> {
  return call('POST', '/test', machine)
}

/** List one remote directory level. */
export function listRemoteDir(machineId: string, path: string): Promise<{ ok: boolean; path: string; entries: RemoteEntry[]; error?: string }> {
  return call('POST', '/ls', { machineId, path })
}

/** Create one child directory on the remote. */
export function createRemoteDir(machineId: string, path: string, name: string): Promise<{ ok: boolean; path: string; error?: string }> {
  return call('POST', '/mkdir', { machineId, path, name })
}

/** Create (or reuse) the anchor workspace for a remote path. */
export function createAnchor(machineId: string, path: string): Promise<{ ok: boolean; anchorPath: string; remotePath: string; error?: string }> {
  return call('POST', '/anchor', { machineId, path })
}

/** Whether one session's workspace is remote (and its remote root). */
export function sessionRemote(sessionId: string): Promise<{ remote: boolean; remotePath?: string }> {
  return call('GET', `/session-remote?sessionId=${encodeURIComponent(sessionId)}`)
}

/** Which interaction the host's composed directory picker serves. */
export type PickerKind = 'native' | 'browse' | 'unknown'

/** Read the composed directory-picker capability from the host. */
export function pickerCapability(): Promise<{ kind: PickerKind }> {
  return call('GET', '/picker')
}
