/**
 * Machine registry: the durable list of saved SSH machines. Pure functions
 * over a file path so tests drive real files. Saved machines are STANDBY
 * connections; which machine serves a workspace is decided by that
 * workspace's anchor alone — the registry holds no "current" pointer.
 * @module dsh-remote-development/registry
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { ProxyConfig } from './config.ts'

/** One saved SSH machine. `id` is a stable opaque key (host-port-user derived). */
export interface Machine {
  id: string
  name: string
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
  workspace: string
  recentWorkspaces?: string[]
  /** Folder-icon color marking this machine's workspaces in the file tree ('' = theme default). */
  color: string
}

/** Durable registry shape (version 1). */
export interface RegistryData {
  version: 1
  machines: Machine[]
}

const REGISTRY_VERSION = 1

/**
 * Derive the stable machine id from its identity triple.
 * @param host - SSH host.
 * @param port - SSH port.
 * @param username - login user.
 * @returns the opaque machine id.
 */
export function machineId(host: string, port: number, username: string): string {
  return [host || '?', port || 22, username || '?'].join('|')
}

/**
 * Machine fields arriving from untrusted input. Secret fields (`password`,
 * `passphrase`, `proxy.password`) may be absent: on an update, absence keeps
 * the stored value — the public machine wire withholds secrets, so an edit
 * that leaves them out is a keep, not a clear — while an explicit string
 * (empty included) sets or clears.
 */
export type MachineInput = {
  [K in Exclude<keyof Machine, 'proxy'>]?: Machine[K] | undefined
} & { proxy?: Partial<ProxyConfig> }

/**
 * Fill defaults and drop whitespace on one machine record from untrusted input.
 * @param raw - partial machine fields (e.g. a UI payload or config row).
 * @returns the sanitized record with an id.
 */
export function sanitizeMachine(raw: MachineInput): Machine {
  const host = String(raw.host ?? '').trim()
  const port = Number(raw.port) > 0 ? Math.floor(Number(raw.port)) : 22
  const username = String(raw.username ?? '').trim()
  // A color reaches an interpolated stylesheet, so only a hex literal or a CSS
  // named color may pass; anything else (semicolons, braces, spaces) is dropped
  // rather than escaped — the empty string simply means "theme default".
  const color = String(raw.color ?? '').trim()
  const machine: Machine = {
    id: String(raw.id ?? '') || machineId(host, port, username),
    name: String(raw.name ?? '').trim() || host,
    host,
    port,
    username,
    password: String(raw.password ?? ''),
    privateKeyPath: String(raw.privateKeyPath ?? '').trim(),
    passphrase: String(raw.passphrase ?? ''),
    useAgent: raw.useAgent === true,
    keyboardInteractive: raw.keyboardInteractive === true,
    hostKeyMode: ['accept-new', 'verify', 'off'].includes(String(raw.hostKeyMode))
      ? String(raw.hostKeyMode)
      : 'accept-new',
    workspace: String(raw.workspace ?? '').trim(),
    color: /^(?:#[0-9a-fA-F]{3,8}|[a-zA-Z]+)$/.test(color) ? color : '',
  }
  if (raw.proxy && String(raw.proxy.host ?? '').trim()) {
    machine.proxy = {
      host: String(raw.proxy.host).trim(),
      port: Number(raw.proxy.port) > 0 ? Math.floor(Number(raw.proxy.port)) : 22,
      username: String(raw.proxy.username ?? '').trim(),
      password: String(raw.proxy.password ?? ''),
      privateKeyPath: String(raw.proxy.privateKeyPath ?? '').trim(),
      passphrase: String(raw.proxy.passphrase ?? ''),
    }
  }
  if (Array.isArray(raw.recentWorkspaces)) {
    machine.recentWorkspaces = raw.recentWorkspaces.map((w) => String(w)).filter(Boolean).slice(0, 8)
  }
  return machine
}

/**
 * Load the registry from disk; a missing or corrupt file is a fresh registry.
 * @param file - registry file path.
 * @returns the parsed (or fresh) registry data.
 */
export function loadRegistry(file: string): RegistryData {
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8')) as Partial<RegistryData>
    if (!raw || !Array.isArray(raw.machines)) return { version: REGISTRY_VERSION, machines: [] }
    const machines = raw.machines.map((m) => sanitizeMachine(m as Partial<Machine>))
    // Registries written before the "current machine" concept was removed
    // carry a currentId field; it is obsolete and simply dropped on load.
    return { version: REGISTRY_VERSION, machines }
  } catch {
    return { version: REGISTRY_VERSION, machines: [] }
  }
}

/**
 * Persist the registry atomically (temp file + rename).
 * @param file - registry file path.
 * @param data - the registry to write.
 */
export function saveRegistry(file: string, data: RegistryData): void {
  mkdirSync(dirname(file), { recursive: true })
  const tmp = file + '.tmp'
  writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 })
  renameSync(tmp, file)
}

/**
 * Whether the registry file exists at all.
 * @param file - registry file path.
 * @returns true when the file exists.
 */
export function registryExists(file: string): boolean {
  return existsSync(file)
}
