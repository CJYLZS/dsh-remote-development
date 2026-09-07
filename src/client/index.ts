/**
 * Browser half of dsh-remote-development: the settings section, the unified
 * workspace directory-flow occupant, and the `@` reference notice. Registers
 * everything through `ctx.slots` because the declaring entries may activate
 * later or be replaced.
 * @module dsh-remote-development/client
 */

import type { Context as ClientContext } from '@deepseek-ai/cordis'
// Type-only: pulls the SlotMap merges declaring the settings + directory-flow slots.
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
import type {} from '@deepseek-ai/dsh-client-ui-workspace/client'
// Type-only: the SlotRegistry service merge (ctx.slots) and the locale face (ctx.locale).
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import type {} from '@deepseek-ai/dsh-client-locale/client'
// Type-only: the input-trigger service merge (ctx.inputTriggers).
import type {} from '@deepseek-ai/dsh-client-ui-input-trigger/client'
import * as api from './api.ts'
import { DICTIONARIES, NS } from './locales.ts'
import { injectStyles } from './styles.ts'
import { RemoteFlow } from './flow.tsx'
import { MachinesSection } from './settings.tsx'
import { registerReferenceSource } from './reference.ts'

/** Required services (cordis fiber inject). */
export const inject = ['slots', 'uiWorkspace', 'locale', 'inputTriggers']

/**
 * Client plugin body.
 * @param ctx - client root context.
 */
export function apply(ctx: ClientContext): void {
  ctx.effect(() => injectStyles(), 'dsh-remote-development: stylesheet')
  ctx.effect(() => {
    const disposers = DICTIONARIES.map(([locale, dict]) => ctx.locale.register(NS, locale, dict))
    return () => { for (const dispose of disposers) dispose() }
  }, 'dsh-remote-development: dictionaries')

  const t = ctx.locale.bind(NS)

  ctx.slots.inject('settings.section', () => ctx.slots.register({
    name: 'settings.section',
    id: 'dsh-remote-development',
    order: 45,
    label: () => t('settings.title'),
    inject: () => ({
      listMachines: api.listMachines,
      saveMachine: api.saveMachine,
      deleteMachine: api.deleteMachine,
      testConnection: api.testConnection,
      t,
    }),
  }, MachinesSection))

  const flowInjected = (): ({
    pickLocal: () => Promise<string | null>
    listLocalDir: (path?: string) => Promise<{ path: string; home: string; crumbs: { name: string; path: string; hidden: boolean }[]; entries: { name: string; path: string; hidden: boolean }[]; truncated: boolean }>
    createLocalDir: (path: string, name: string) => Promise<string>
    pickerKind: () => Promise<{ kind: api.PickerKind }>
    listMachines: typeof api.listMachines
    listRemoteDir: typeof api.listRemoteDir
    createRemoteDir: typeof api.createRemoteDir
    createAnchor: typeof api.createAnchor
    t: typeof t
  }) => ({
    pickLocal: () => ctx.uiWorkspace.pickDirectory(),
    // 本机 browse interaction: the host's own listing/creation primitives —
    // the verbs a WSL/SSH/headless boot's composed picker actually serves.
    listLocalDir: (path) => ctx.uiWorkspace.listDirectory(path),
    createLocalDir: (path, name) => ctx.uiWorkspace.createDirectory(path, name),
    pickerKind: api.pickerCapability,
    listMachines: api.listMachines,
    listRemoteDir: api.listRemoteDir,
    createRemoteDir: api.createRemoteDir,
    createAnchor: api.createAnchor,
    t,
  })
  // Priority -1 shadows the built-in directory-picker surface (browse/native
  // register at the default 0): both flows are single-slot occupants, and
  // equal priorities collide at load. Lowest renders, so this dialog serves
  // the hole and the built-in takes back over when this plugin unloads —
  // independent of activation order.
  ctx.slots.inject('conversation.hero.workspace.directoryFlow', () =>
    ctx.slots.inject('sidebar.workspaces.directoryFlow', function* () {
      yield ctx.slots.register({
        name: 'conversation.hero.workspace.directoryFlow', inject: flowInjected, priority: -1,
      }, RemoteFlow)
      yield ctx.slots.register({
        name: 'sidebar.workspaces.directoryFlow', inject: flowInjected, priority: -1,
      }, RemoteFlow)
    }))

  registerReferenceSource(ctx, api.sessionRemote, t)
}
