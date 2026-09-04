/**
 * Machine registry: the durable list of saved SSH machines and which one is
 * current. Pure functions over a file path so tests drive real files. Saved
 * machines are STANDBY connections; only an explicit "set current" (or the
 * config default on a fresh registry) activates one.
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
}

/** Durable registry shape (version 1). */
export interface RegistryData {
  version: 1
  currentId: string | null
  machines: Machine[]
}

/** Registry file layout; `null` currentId is a deliberate "no active machine". */
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
 * Fill defaults and drop whitespace on one machine record from untrusted input.
 * @param raw - partial machine fields (e.g. a UI payload or config row).
 * @returns the sanitized record with an id.
 */
export function sanitizeMachine(raw: Partial<Machine>): Machine {
  const host = String(raw.host ?? '').trim()
  const port = Number(raw.port) > 0 ? Math.floor(Number(raw.port)) : 22
  const username = String(raw.username ?? '').trim()
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
    if (!raw || !Array.isArray(raw.machines)) return { version: REGISTRY_VERSION, currentId: null, machines: [] }
    const machines = raw.machines.map((m) => sanitizeMachine(m as Partial<Machine>))
    const currentId = typeof raw.currentId === 'string' && machines.some((m) => m.id === raw.currentId)
      ? raw.currentId
      : null
    return { version: REGISTRY_VERSION, currentId, machines }
  } catch {
    return { version: REGISTRY_VERSION, currentId: null, machines: [] }
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
 * Whether the registry file exists at all (a present file with `currentId:
 * null` means "explicitly no active machine" and must not fall back to the
 * config default).
 * @param file - registry file path.
 * @returns true when the file exists.
 */
export function registryExists(file: string): boolean {
  return existsSync(file)
}
