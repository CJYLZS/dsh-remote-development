/**
 * Per-agent tool visibility for remote sessions. The plugin's patch mounts
 * BOTH shell tool stacks wherever the host platform allows it, so the model's
 * tool list must be narrowed per session: a remote session works in bash (the
 * remote host is POSIX by the pool's platform detection) and must not see the
 * pwsh tool, while a local session on a Windows host must not see the
 * plugin-added bash tool. POSIX local sessions keep bash for both worlds,
 * matching the base composition.
 *
 * The mechanism is the tools service's scoped restriction: one restriction
 * installed through the agent's own context, decided once per session start
 * from the session's durable cwd. Persistent shell tools are scope-local
 * registrations that `restrict()` cannot name; for those, the subprocess
 * router's remote terminal refusal is the model-facing guard.
 *
 * A remote session also settles its own PRESENTATION. `run_code`'s executor
 * launches a Node process in the session's directory and talks to it over a
 * control pipe; an anchor session owns neither half (the routing subprocess
 * provider serves no control pipe and no stderr pipe), so under a PTC-mode
 * deployment the model would be handed exactly one tool that can never run.
 * Presenting such a session natively keeps every file and shell tool directly
 * callable instead — the same honest refusal the terminal and `@` reference
 * surfaces make.
 * @module dsh-remote-development/tool-visibility
 */

import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-tools'
import { RemoteWorld } from './world.ts'

/**
 * The reserved PTC presentation transport. Spelled as a literal on purpose:
 * the name is part of the registry's stable contract ("run_code is a reserved
 * presentation transport"), while the module that exports its constant is a
 * type-only import here, so the built host half keeps no runtime dependency
 * on a package version that may predate that export.
 */
const PTC_TRANSPORT_NAME = 'run_code'

/**
 * The global shell tools one session must not see.
 * @param world - the remote world coordinator (path classification).
 * @param cwd - the session's durable working directory, when attached.
 * @param registered - whether a global tool name is registered at all; a
 *   name the composition never mounted must not enter the deny list (the
 *   restriction API rejects unknown names).
 * @param localPlatform - the host platform: the local-session deny applies
 *   only where the local dialect is pwsh and the plugin's patch added bash.
 * @returns the tool names to deny, empty when no restriction applies.
 */
export function denyListFor(
  world: Pick<RemoteWorld, 'classifyHostPath'>,
  cwd: string | undefined,
  registered: (name: string) => boolean,
  localPlatform: NodeJS.Platform,
): string[] {
  if (!cwd) return []
  if (world.classifyHostPath(cwd).kind === 'remote') {
    return ['pwsh'].filter(registered)
  }
  if (localPlatform === 'win32') return ['bash'].filter(registered)
  return []
}

/**
 * The scoped `ctx.tools` surface this module narrows. Structural rather than
 * `ToolRuntime`, so the presentation fallback is unit-testable without a live
 * registry; both members stay optional because a host older than the plugin's
 * peer floor may expose neither.
 */
export interface SessionToolSurface {
  /** Per-scope presentation override, resolved by the tool registry. */
  presentAs?: (mode: 'native') => unknown
  /** Monotonic denial installed after the extensible pre-execute gate. */
  guard?: (guard: (execution: { readonly name: string }) => string | undefined) => unknown
}

/**
 * Model-facing denial for the fallback path: a session whose presentation a
 * preset already owns keeps `run_code` on the wire, so the call itself has to
 * carry the reason instead of failing inside a runtime that cannot launch.
 */
export const REMOTE_CODE_EXECUTION_DENIED =
  'run_code is unavailable in a remote workspace: the program would run on this machine rather than on the remote host, '
  + 'so it could not reach the files and processes this session works with. '
  + 'Use the file tools and the bash tool directly — they already run on the remote host.'

/**
 * Give one remote session a callable tool surface under every deployment mode.
 *
 * `presentAs('native')` is the primary mechanism: it is the registry's own
 * per-scope override, so the generated SDK section re-renders from this scope
 * (empty for an agent presenting natively) and `run_code` drops off the wire.
 * It rejects when the scope's presentation is already declared — an agent
 * preset owns it — and there `guard()` is the last resort: the call is denied
 * with an actionable reason instead of failing deep inside the runtime.
 * @param tools - the calling session's scoped tool surface.
 * @param warn - diagnostic sink (the plugin logger) for an unsettled scope.
 * @returns how the session was settled; `unsettled` means the host exposed
 *   neither mechanism, so a PTC-mode deployment stays broken there.
 */
export function keepRemoteSessionCallable(
  tools: SessionToolSurface,
  warn: (message: string) => void,
): 'presented' | 'guarded' | 'unsettled' {
  if (typeof tools.presentAs === 'function') {
    try {
      tools.presentAs('native')
      return 'presented'
    } catch (error) {
      warn(
        'dsh-remote-development: this remote session has its tool presentation already declared, so run_code stays on the wire '
        + `(${error instanceof Error ? error.message : String(error)}); denying it instead.`,
      )
    }
  }
  if (typeof tools.guard === 'function') {
    tools.guard((execution) => execution.name === PTC_TRANSPORT_NAME ? REMOTE_CODE_EXECUTION_DENIED : undefined)
    return 'guarded'
  }
  warn(
    'dsh-remote-development: this host exposes neither tools.presentAs() nor tools.guard(), '
    + 'so a PTC-mode deployment cannot run code in a remote workspace.',
  )
  return 'unsettled'
}

/**
 * Install the per-agent visibility restriction and presentation for every
 * agent, present and future. The fiber lives in the agent's context, so agent
 * disposal unregisters it (the same discipline as the prompt module's cwd
 * override).
 * @param ctx - plugin context.
 * @param world - the remote world coordinator.
 */
export function registerToolVisibility(ctx: Context, world: RemoteWorld): void {
  const fibers = new Map<Agent, ReturnType<Context['inject']>>()
  const install = (agent: Agent): void => {
    if (fibers.has(agent)) return
    fibers.set(agent, agent.ctx.inject(['tools'], (scope) => {
      const cwd = agent.session?.header?.cwd
      if (!cwd) return
      const deny = denyListFor(
        world,
        cwd,
        (name) => scope.tools.get(name) !== undefined,
        process.platform,
      )
      // An empty deny list must not register: the restriction API treats an
      // empty filter as a configuration bug and fails loud.
      if (deny.length > 0) scope.tools.restrict({ deny })
      if (world.classifyHostPath(cwd).kind !== 'remote') return
      keepRemoteSessionCallable(scope.tools, (message) => ctx.logger.warn(message))
    }))
  }
  const dispose = (agent: Agent): void => {
    const fiber = fibers.get(agent)
    if (fiber === undefined) return
    fibers.delete(agent)
    void fiber.dispose().catch((error: unknown) => {
      ctx.logger.warn(`dsh-remote-development: tool visibility cleanup failed: ${error instanceof Error ? error.message : String(error)}`)
    })
  }
  for (const agent of ctx.agents.list()) install(agent)
  ctx.on('agent/created', ({ agent }) => { install(agent) })
  ctx.on('agent/disposed', ({ agent }) => { dispose(agent) })
}
