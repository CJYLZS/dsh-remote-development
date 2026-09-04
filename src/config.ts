/**
 * Plugin configuration schema. Schemastery is mandatory: the Loader applies
 * row `config` through it, and a zod schema rejects the undefined row config
 * (the dsh-remote postmortem lesson).
 * @module dsh-remote-development/config
 */

import z from '@deepseek-ai/schemastery'

/** Jump-host (bastion) connection settings; an empty `host` disables it. */
export interface ProxyConfig {
  host: string
  port: number
  username: string
  password: string
  privateKeyPath: string
  passphrase: string
}

/** Validated plugin configuration (schemastery applied the defaults). */
export interface ResolvedConfig {
  host: string
  port: number
  username: string
  password: string
  privateKeyPath: string
  passphrase: string
  workspace: string
  commandTimeoutMs: number
  connectTimeoutMs: number
  maxOutputChars: number
  maxFileBytes: number
  hostKeyMode: string
  useAgent: boolean
  keyboardInteractive: boolean
  proxy: ProxyConfig
  auditLog: boolean
  anchorRoot: string
  remoteRipgrep: string
}

export const Config = z.object({
  /** Default SSH host for CLI/headless use (empty → start with no machine). */
  host: z.string().default(''),
  /** Default SSH port. */
  port: z.number().step(1).min(1).max(65535).default(22),
  /** Default SSH login user. */
  username: z.string().default(''),
  /** Default password (only when the remote has no key). */
  password: z.string().default(''),
  /** Explicit private-key path (never auto-reads ~/.ssh). */
  privateKeyPath: z.string().default(''),
  /** Key passphrase when the key is encrypted. */
  passphrase: z.string().default(''),
  /** Default remote workspace root for CLI/headless use (empty → none). */
  workspace: z.string().default(''),
  /** Per-command timeout in milliseconds. */
  commandTimeoutMs: z.number().step(1).min(1000).default(20000),
  /** SSH connection establishment timeout in milliseconds. */
  connectTimeoutMs: z.number().step(1).min(1000).default(15000),
  /** Hard ceiling on collected remote command output, in characters. */
  maxOutputChars: z.number().step(1).min(1024).default(200000),
  /** Skip remote file reads larger than this many bytes (0 = no cap). */
  maxFileBytes: z.number().step(1).min(0).default(52428800),
  /** Host-key policy: `accept-new` (default) | `verify` | `off`. */
  hostKeyMode: z.string().default('accept-new'),
  /** Use the OpenSSH agent (SSH_AUTH_SOCK) when no password/key is configured. */
  useAgent: z.boolean().default(false),
  /** Allow keyboard-interactive auth (OTP/MFA) using the configured password. */
  keyboardInteractive: z.boolean().default(false),
  /** Jump host / bastion; an empty `host` means none. */
  proxy: z.object({
    host: z.string().default(''),
    port: z.number().step(1).min(1).max(65535).default(22),
    username: z.string().default(''),
    password: z.string().default(''),
    privateKeyPath: z.string().default(''),
    passphrase: z.string().default(''),
  }),
  /** Append executed remote commands to the audit log under the harness home. */
  auditLog: z.boolean().default(true),
  /** Root holding anchor workspace directories; empty → `$DSH_HOME/remote-workspaces`. */
  anchorRoot: z.string().default(''),
  /** ripgrep command name on the remote host for the grep/glob tools. */
  remoteRipgrep: z.string().default('rg'),
})

export type Config = ResolvedConfig
