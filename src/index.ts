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
 *   • `ctx.shell` — a routing executor keyed on the workdir: anchor paths run
 *     on the remote host's POSIX shell over SSH; local workdirs stay with the
 *     host platform's own sandboxed executor (bash on POSIX, pwsh on win32).
 *   • per-agent shell-tool visibility — a remote session sees the bash tool,
 *     a local session sees its platform's native tool, via scoped tool
 *     restrictions.
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
import { RoutingBashExecutor, RoutingPwshExecutor } from './shell-router.ts'
import { registerPrompt } from './prompt.ts'
import { registerToolVisibility } from './tool-visibility.ts'
import { registerRoutes } from './routes.ts'

export const name = 'dsh-remote-development'

/**
 * Service dependencies, declared at module level because this is a namespace
 * plugin: the Loader builds the fiber's inject from this list, and the
 * `static inject` of the manually constructed provider classes is ignored.
 * Every service those classes read directly must appear here or the
 * ancestor-only fiber walk throws "cannot get property … without inject":
 *   • systemPrompt — the prompt section registers on it.
 *   • sandboxPolicy — both routing executors and SandboxedFileSystem read it.
 *   • sandbox — the routing executors wrap every local command through
 *     `ctx.sandbox.confine`; without the declaration the walk from this
 *     plugin's fiber reaches root and every shell call crashes (the incident
 *     behind the 2025-07 bash-tool outage).
 *   • agents — the per-agent cwd override and tool visibility enumerate live
 *     agents.
 * (`subprocess` is read by the local executor halves too, but this plugin
 * provides `ctx.subprocess` itself, so its own store satisfies the walk.)
 */
export const inject = ['systemPrompt', 'sandboxPolicy', 'sandbox', 'agents']

export { Config }

/** Local-backend defaults used when constructing the routing providers by hand. */
const LOCAL_FS_DIFF_BASIS_MAX_BYTES = 10 * 1024 * 1024
const SHELL_TIMEOUT_MS = 120_000
const SHELL_MAX_TIMEOUT_MS = 600_000
const SHELL_MAX_OUTPUT_BYTES = 64_000
const SHELL_MAX_SPILL_BYTES = 64 * 1024 * 1024
const SHELL_GRACE_MS = 3_000

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

  // The routing executor is chosen by the HOST platform because only the
  // local fallback is platform-bound: a Windows host has no local bash, so it
  // twins the pwsh stack (local workdirs keep the inherited pwsh executor);
  // POSIX hosts twin the bash stack. Both route anchor workdirs to the
  // remote host's POSIX shell — the remote platform decides the remote
  // dialect, never the host platform.
  const shellBudgets = {
    cwd: process.cwd(),
    timeoutMs: SHELL_TIMEOUT_MS,
    maxTimeoutMs: SHELL_MAX_TIMEOUT_MS,
    maxOutputBytes: SHELL_MAX_OUTPUT_BYTES,
    maxSpillBytes: SHELL_MAX_SPILL_BYTES,
    graceMs: SHELL_GRACE_MS,
  }
  if (process.platform === 'win32') {
    new RoutingPwshExecutor(ctx, shellBudgets, world)
  } else {
    new RoutingBashExecutor(ctx, shellBudgets, world)
  }

  registerPrompt(ctx, world)
  registerToolVisibility(ctx, world)

  ctx.inject(['webServer'], (serviceCtx) => {
    registerRoutes(serviceCtx, serviceCtx.webServer, world)
  })
}
