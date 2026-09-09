/**
 * Per-agent shell-tool visibility for remote sessions. The plugin's patch
 * mounts BOTH shell tool stacks wherever the host platform allows it, so the
 * model's tool list must be narrowed per session: a remote session works in
 * bash (the remote host is POSIX by the pool's platform detection) and must
 * not see the pwsh tool, while a local session on a Windows host must not see
 * the plugin-added bash tool. POSIX local sessions keep bash for both worlds,
 * matching the base composition.
 *
 * The mechanism is the tools service's scoped restriction: one restriction
 * installed through the agent's own context, decided once per session start
 * from the session's durable cwd. Persistent shell tools are scope-local
 * registrations that `restrict()` cannot name; for those, the subprocess
 * router's remote terminal refusal is the model-facing guard.
 * @module dsh-remote-development/tool-visibility
 */

import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-tools'
import { RemoteWorld } from './world.ts'

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
 * Install the per-agent visibility restriction for every agent, present and
 * future. The fiber lives in the agent's context, so agent disposal
 * unregisters it (the same discipline as the prompt module's cwd override).
 * @param ctx - plugin context.
 * @param world - the remote world coordinator.
 */
export function registerToolVisibility(ctx: Context, world: RemoteWorld): void {
  const fibers = new Map<Agent, ReturnType<Context['inject']>>()
  const install = (agent: Agent): void => {
    if (fibers.has(agent)) return
    fibers.set(agent, agent.ctx.inject(['tools'], (scope) => {
      const deny = denyListFor(
        world,
        agent.session?.header?.cwd,
        (name) => scope.tools.get(name) !== undefined,
        process.platform,
      )
      // An empty deny list must not register: the restriction API treats an
      // empty filter as a configuration bug and fails loud.
      if (deny.length === 0) return
      scope.tools.restrict({ deny })
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
  ctx.on('agent/session-start', ({ agent }) => { install(agent) })
  ctx.on('agent/disposed', ({ agent }) => { dispose(agent) })
}
