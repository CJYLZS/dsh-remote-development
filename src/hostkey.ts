/**
 * Host-key fingerprint helpers (TOFU). ssh2 ≥1.17 hands `hostVerifier` the RAW
 * wire-format host-key blob (`string(algo) string(keydata)`), not the older
 * `{ algo, hash }` object — both shapes are accepted defensively.
 * @module dsh-remote-development/hostkey
 */

import { createHash } from 'node:crypto'

/**
 * Extract the SSH host-key algorithm name from a raw host-key blob.
 * @param blob - the ssh2 hostVerifier key argument.
 * @returns the algorithm name, or '' when unreadable.
 */
export function blobAlgorithm(blob: unknown): string {
  if (!Buffer.isBuffer(blob) || blob.length < 4) return ''
  try {
    const len = blob.readUInt32BE(0)
    return blob.toString('utf8', 4, 4 + len)
  } catch {
    return ''
  }
}

/**
 * SHA-256 fingerprint (unpadded base64, the known_hosts `SHA256:…` body) of a
 * host-key blob.
 * @param key - raw Buffer blob or the legacy `{ hash }` object.
 * @returns the fingerprint string.
 * @throws when no key material is present.
 */
export function keyFingerprint(key: unknown): string {
  const blob = Buffer.isBuffer(key) ? key : (key as { hash?: Buffer } | null)?.hash
  if (!blob) throw new Error('host key missing (hostVerifier received no key blob)')
  return createHash('sha256').update(blob).digest('base64')
}

/**
 * Build a wire-shaped host-key blob for tests: `string(algo) string(32 bytes)`.
 * @param algo - algorithm name.
 * @param seed - byte fill for the key data.
 * @returns the fake blob.
 */
export function makeKeyBlob(algo: string, seed = 1): Buffer {
  const algoBuf = Buffer.from(algo, 'utf8')
  const data = Buffer.alloc(32, seed)
  const blob = Buffer.alloc(4 + algoBuf.length + 4 + data.length)
  blob.writeUInt32BE(algoBuf.length, 0)
  algoBuf.copy(blob, 4)
  blob.writeUInt32BE(data.length, 4 + algoBuf.length)
  data.copy(blob, 8 + algoBuf.length)
  return blob
}

/** One trusted host-key record. */
export interface KnownHostEntry {
  algo: string
  fingerprint: string
  firstSeen: string
}

/** TOFU decision for one presented key. */
export type HostKeyDecision =
  | { kind: 'trusted' }
  | { kind: 'recorded' }
  | { kind: 'rejected'; reason: string }

/**
 * Stateful TOFU guard for one host:port. `verify` additionally rejects hosts
 * never seen before; `off` accepts everything.
 */
export class HostKeyGuard {
  private readonly known: Map<string, KnownHostEntry>

  /**
   * @param mode - the machine's host-key policy.
   * @param store - read/write access to the durable known-hosts map.
   */
  constructor(
    readonly mode: string,
    private readonly store: {
      read: () => Record<string, KnownHostEntry>
      write: (entries: Record<string, KnownHostEntry>) => void
    },
  ) {
    this.known = new Map(Object.entries(store.read()))
  }

  /**
   * Verify one presented host key per the TOFU policy.
   * @param hostId - `host:port` registry key.
   * @param key - the presented key blob.
   * @returns the decision; `recorded` means a first-seen key was just trusted.
   */
  verify(hostId: string, key: unknown): HostKeyDecision {
    if (this.mode === 'off') return { kind: 'trusted' }
    let fingerprint: string
    try {
      fingerprint = keyFingerprint(key)
    } catch {
      return { kind: 'rejected', reason: 'host key missing from the SSH handshake' }
    }
    const stored = this.known.get(hostId)
    if (stored) {
      if (stored.fingerprint === fingerprint) return { kind: 'trusted' }
      return {
        kind: 'rejected',
        reason:
          `host key for ${hostId} CHANGED (stored ${stored.fingerprint}, received ${fingerprint}) — ` +
          'possible man-in-the-middle; re-trust it from the settings page if this is expected',
      }
    }
    if (this.mode === 'verify') {
      return { kind: 'rejected', reason: `unknown host key for ${hostId} (hostKeyMode=verify)` }
    }
    const entry: KnownHostEntry = {
      algo: blobAlgorithm(key) || 'unknown',
      fingerprint,
      firstSeen: new Date().toISOString(),
    }
    this.known.set(hostId, entry)
    this.store.write(Object.fromEntries(this.known))
    return { kind: 'recorded' }
  }

  /**
   * Drop one host's trusted key so the next connect re-records it.
   * @param hostId - `host:port` registry key.
   */
  forget(hostId: string): void {
    this.known.delete(hostId)
    this.store.write(Object.fromEntries(this.known))
  }
}
