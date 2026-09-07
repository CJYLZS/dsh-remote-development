/**
 * dsh-remote-development — lightweight remote development for DeepSeek
 * Harness.
 *
 * Host half. One plugin row mounts the whole remote execution world:
 *   • `ctx.fs` — RoutingFileSystem: anchor paths (and registered remote
 *     roots) serve reads/writes/edits over SFTP; everything else delegates
 *     to the inherited sandboxed local backend, untouched.
 *   • `ctx.subprocess` — RoutingSubprocessRuntime: spawns with a cwd under an
 *     anchor run over the SSH exec channel; remote terminals refuse with a
 *     clear model-facing error (v1 scope).
 *   • `ctx.shell` — RoutingBashExecutor (POSIX hosts): bash commands with a
 *     workdir under an anchor run remotely, bypassing the local sandbox
 *     wrapper; approval stays with the unchanged bash tool.
 *   • a session-scoped system-prompt section naming the remote root.
 *   • JSON routes for the Web client (machine registry + workspace picker).
 *
 * No model tools are added: the agent uses the SAME tools as a local
 * workspace, and the plugin translates execution to the remote host.
 * @module dsh-remote-development
 */

import { Context } from '@deepseek-ai/cordis'
import { Config } from './config.ts'
import type { ResolvedConfig } from './config.ts'
import { RemoteWorld } from './world.ts'
import { RoutingFileSystem } from './fs-router.ts'
import { RoutingSubprocessRuntime } from './subprocess-router.ts'
import { RoutingBashExecutor } from './shell-router.ts'
import { registerPrompt } from './prompt.ts'
import { registerRoutes } from './routes.ts'

export const name = 'dsh-remote-development'

/**
 * Service dependencies, declared at module level because this is a namespace
 * plugin: the Loader builds the fiber's inject from this list, and the
 * `static inject` of the manually constructed provider classes is ignored.
 * Every service those classes read directly must appear here or the
 * ancestor-only fiber walk throws "cannot get property … without inject":
 *   • systemPrompt — the prompt section registers on it.
 *   • sandboxPolicy — SandboxBashExecutor and SandboxedFileSystem read it.
 *   • sandbox — SandboxBashExecutor wraps every local command through
 *     `ctx.sandbox.confine`; without the declaration the walk from this
 *     plugin's fiber reaches root and every bash call crashes (the incident
 *     behind the 2025-07 bash-tool outage).
 *   • agents — the per-agent cwd override enumerates live agents.
 * (`subprocess` is read by LocalBashExecutor too, but this plugin provides
 * `ctx.subprocess` itself, so its own store satisfies the walk.)
 */
export const inject = ['systemPrompt', 'sandboxPolicy', 'sandbox', 'agents']

export { Config }

/** Local-backend defaults used when constructing the routing providers by hand. */
const LOCAL_FS_DIFF_BASIS_MAX_BYTES = 10 * 1024 * 1024
const BASH_TIMEOUT_MS = 120_000
const BASH_MAX_TIMEOUT_MS = 600_000
const BASH_MAX_OUTPUT_BYTES = 64_000
const BASH_MAX_SPILL_BYTES = 64 * 1024 * 1024
const BASH_GRACE_MS = 3_000

/**
 * Plugin body: construct the world and mount every routing provider.
 * @param ctx - the plugin context; registrations are effects scoped to it.
 * @param config - schemastery-validated plugin config.
 */
export function apply(ctx: Context, config: ResolvedConfig): void {
  const world = new RemoteWorld(config)
  ctx.effect(() => () => world.dispose(), 'dsh-remote-development.world')

  new RoutingFileSystem(ctx, world, config.commandTimeoutMs, config.maxFileBytes, {
    cwd: process.cwd(),
    diffBasisMaxBytes: LOCAL_FS_DIFF_BASIS_MAX_BYTES,
  })
  new RoutingSubprocessRuntime(ctx, world)

  // Remote command routing is a POSIX-host capability in v1: on win32 hosts
  // the base pwsh executor stays the ctx.shell provider (its row is not
  // disabled there) and this executor is not mounted at all.
  if (process.platform !== 'win32') {
    new RoutingBashExecutor(ctx, {
      cwd: process.cwd(),
      timeoutMs: BASH_TIMEOUT_MS,
      maxTimeoutMs: BASH_MAX_TIMEOUT_MS,
      maxOutputBytes: BASH_MAX_OUTPUT_BYTES,
      maxSpillBytes: BASH_MAX_SPILL_BYTES,
      graceMs: BASH_GRACE_MS,
    }, world)
  }

  registerPrompt(ctx, world)

  ctx.inject(['webServer'], (serviceCtx) => {
    registerRoutes(serviceCtx, serviceCtx.webServer, world)
  })
}
