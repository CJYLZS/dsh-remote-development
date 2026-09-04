/**
 * The session-scoped system-prompt section. Injected only when the calling
 * session's cwd sits under an anchor, so plain local sessions never see a
 * remote section — the same session-scope rule the harness applies to every
 * model-visible context.
 *
 * The module also overrides the harness's global `cwd` prompt variable per
 * agent: the global value is the session's local anchor directory — an
 * internal handle that does not exist on the remote host — so a remote
 * session's model-visible cwd becomes the remote path its commands run in.
 * @module dsh-remote-development/prompt
 */

import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-agent'
import { RemoteWorld } from './world.ts'
import { remoteBasename } from './paths.ts'

/**
 * Register the prompt section and the per-agent cwd override.
 * @param ctx - plugin context.
 * @param world - the remote world coordinator.
 */
export function registerPrompt(ctx: Context, world: RemoteWorld): void {
  ctx.systemPrompt.section({
    name: 'dsh-remote-development',
    order: 88,
    text: (promptContext) => {
      const agent = promptContext?.agent
      const cwd = agent?.session?.header?.cwd
      if (!cwd) return ''
      const local = world.classifyHostPath(cwd)
      if (local.kind !== 'remote') return ''
      const anchor = local.route.anchor
      const machine = world.machineForAnchor(anchor)
      if (!machine) return ''
      const who = `${machine.machine.username || 'user'}@${machine.machine.host}`
      const name = remoteBasename(local.route.remotePath) || local.route.remotePath
      return [
        '## Remote workspace',
        `This session's workspace is a remote directory: ${who}:${local.route.remotePath} ("${name}").`,
        'All file tools (read/write/edit/ls/grep/glob) and shell commands operate on that remote host directly.',
        `File paths in tool calls are remote paths under ${local.route.remotePath}; the local workspace directory on this machine is only a handle and does not mirror the remote files.`,
      ].join('\n')
    },
  })

  // Scoped registrations shadow the global `cwd` variable (nearest scope
  // wins), so every agent gets its own override whose provider re-reads the
  // session cwd at assembly time: remote sessions report the remote path,
  // local sessions pass the harness value through unchanged. The fiber lives
  // in the agent's context, so agent disposal unregisters it.
  const fibers = new Map<Agent, ReturnType<Context['inject']>>()
  const install = (agent: Agent): void => {
    if (fibers.has(agent)) return
    fibers.set(agent, agent.ctx.inject(['systemPrompt'], (scope) => {
      scope.systemPrompt.variable('cwd', (context) => {
        const cwd = context.agent?.session?.header?.cwd
        if (!cwd) return undefined
        const local = world.classifyHostPath(cwd)
        return local.kind === 'remote' ? local.route.remotePath : cwd
      })
    }))
  }
  const dispose = (agent: Agent): void => {
    const fiber = fibers.get(agent)
    if (fiber === undefined) return
    fibers.delete(agent)
    void fiber.dispose().catch((error: unknown) => {
      ctx.logger.warn(`dsh-remote-development: cwd override cleanup failed: ${error instanceof Error ? error.message : String(error)}`)
    })
  }
  for (const agent of ctx.agents.list()) install(agent)
  ctx.on('agent/created', ({ agent }) => { install(agent) })
  ctx.on('agent/disposed', ({ agent }) => { dispose(agent) })
}
