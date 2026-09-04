/**
 * The plugin's `@` trigger source: when the active session's workspace is
 * remote, the reference menu shows one explicit "not supported yet" row, so
 * the limitation is stated instead of failing silently or erroring.
 * @module dsh-remote-development/client/reference
 */

import type { Context as ClientContext } from '@deepseek-ai/cordis'
import type { InputTriggerSource } from '@deepseek-ai/dsh-client-ui-input-trigger/client'
import type { Translate } from '@deepseek-ai/dsh-client-ui-slots'
import type { sessionRemote } from './api.ts'

/**
 * Register the notice source on the `@` trigger.
 * @param ctx - client root context.
 * @param sessionRemoteFn - the session-remote API call.
 * @param t - localized copy.
 */
export function registerReferenceSource(
  ctx: ClientContext,
  sessionRemoteFn: typeof sessionRemote,
  t: Translate,
): void {
  const source: InputTriggerSource = {
    trigger: '@',
    name: 'dsh-remote-development',
    showGroupTitle: false,
    async candidates(session, req) {
      if (req.quoted === true) return []
      let remote = false
      try {
        remote = (await sessionRemoteFn(session.sessionId)).remote
      } catch {
        return []
      }
      if (!remote) return []
      return [{
        name: t('reference.unsupportedName'),
        description: t('reference.unsupportedDescription'),
        value: 'rdv:reference-unsupported',
      }]
    },
    onPick: () => 'handled',
  }
  ctx.effect(() => ctx.inputTriggers.registerSource(source), 'dsh-remote-development: @ source')
}
