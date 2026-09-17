/**
 * Remote-workspace presentation in the workspace shell. The in-box tree and
 * workspace list are fixed components the plugin cannot re-render, so the
 * plugin reaches them the only way it can, from its own client bundle:
 * generated attribute selectors that recolor folder icons, and an alias
 * rewriter that shows each anchor's remote path wherever the shell displays
 * the anchor's local directory — the file tree's root header and the
 * workspace list's hover card.
 *
 * Workspace rows carry no data hooks, so their rules match the row's title.
 * Two machines mounting the same remote directory would share that title, so
 * the host settles a unique one (the machine name is appended) and this module
 * renames the colliding Workspaces onto it; a title that stays ambiguous emits
 * no row rule at all rather than painting both rows with one machine's color.
 * @module dsh-remote-development/client/tree-mark
 */

import { anchorStatus } from './api.ts'
import type { AnchorStatus } from './api.ts'

/** One anchor to mark (color '' = the theme default). */
export interface AnchorMark {
  dir: string
  color: string
  /** Title of the anchor's workspace row; defaults to the directory basename. */
  title?: string
  /** False when some other workspace shows this title too (its row rules are then omitted). */
  titleUnique?: boolean
}

/** One Workspace row as the client Workspace service exposes it. */
export interface WorkspaceTitleRow {
  workspaceId: string
  /** Canonical local directory of the Workspace. */
  path: string
  /** Current display title. */
  title: string
}

/**
 * Structural face of the client Workspace service. Duck-typed on purpose: the
 * plugin keeps the controller package out of its dependency graph, and a
 * composition without that service simply keeps every title as it is.
 */
export interface WorkspaceFace {
  list: {
    getSnapshot(): { items: readonly WorkspaceTitleRow[] }
    subscribe(listener: () => void): () => void
  }
  rename(workspaceId: string, title: string): Promise<unknown>
}

/** The only context capability the marker needs: a service lookup. */
export interface ServiceLookup {
  get(key: string): unknown
}

/** The marker color for machines that set none. */
export const DEFAULT_TREE_COLOR = 'var(--dsw-alias-brand-primary, #4a9eff)'

/** The charset a color may carry — a hex literal or a CSS named color, nothing that could leave a declaration. */
const SAFE_COLOR = /^(?:#[0-9a-fA-F]{3,8}|[a-zA-Z]+)$/

const TAG_SELECTOR = 'style[data-plugin-css="dsh-remote-development-tree"]'

/** Escape one path for use inside a CSS quoted attribute value. */
function cssString(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

/** The workspace title an anchor adopts: its directory basename. */
function workspaceTitleOf(dir: string): string {
  const parts = dir.split(/[\\/]/).filter(Boolean)
  return parts[parts.length - 1] ?? ''
}

/**
 * Whether two local paths name the same directory. The shell stores a
 * Workspace's canonical path while the host reports the anchor directory as it
 * was created, so trailing separators are ignored, and two Windows paths
 * compare case-insensitively (POSIX paths stay case-sensitive).
 * @param a - one local path.
 * @param b - the other local path.
 * @returns true when both name the same directory.
 */
export function sameLocalDir(a: string, b: string): boolean {
  const left = a.replace(/\\/g, '/').replace(/\/+$/, '')
  const right = b.replace(/\\/g, '/').replace(/\/+$/, '')
  if (left === right) return true
  return /^[a-zA-Z]:/.test(left) && /^[a-zA-Z]:/.test(right) && left.toLowerCase() === right.toLowerCase()
}

/**
 * Pair every anchor with the title its workspace row shows, and flag the
 * titles that more than one workspace displays. A title two rows share cannot
 * be colored per row — the rules would match both, and the last one would win
 * — so the marker leaves those rows on the theme default instead of painting
 * one of them with the other machine's color. Anchors the Workspace list does
 * not (yet) contain keep the title the host settled for them, and Workspaces
 * that are not anchors still occupy their title.
 * @param anchors - the anchors as the host reports them.
 * @param items - the current Workspace rows.
 * @returns one mark per anchor, in list order.
 */
export function anchorMarks(anchors: readonly AnchorStatus[], items: readonly WorkspaceTitleRow[]): AnchorMark[] {
  const byDir = new Map<string, WorkspaceTitleRow>()
  const titleCounts = new Map<string, number>()
  const seenTitle = (title: string): void => { titleCounts.set(title, (titleCounts.get(title) ?? 0) + 1) }
  for (const item of items) {
    const anchor = anchors.find((a) => sameLocalDir(a.dir, item.path))
    // A Workspace whose path matches no anchor (or a duplicate match) is an
    // ordinary local Workspace: it only competes for the title.
    if (anchor === undefined || byDir.has(anchor.dir)) { seenTitle(item.title); continue }
    byDir.set(anchor.dir, item)
    seenTitle(item.title)
  }
  for (const anchor of anchors) if (!byDir.has(anchor.dir)) seenTitle(anchor.title)
  return anchors.map((anchor) => {
    const title = byDir.get(anchor.dir)?.title ?? anchor.title
    return { dir: anchor.dir, color: anchor.color, title, titleUnique: (titleCounts.get(title) ?? 1) === 1 }
  })
}

/**
 * Build the marker stylesheet. One rule block per anchor covers every place
 * the shell can show it: the anchor as a row inside a local file tree (exact
 * match, plus a separator-prefixed selector for its subtree), a file tree
 * rooted at it (every directory row, plus the header's folder icon), and the
 * sidebar's workspace row for it. Workspace rows expose no data hooks, so
 * their rules reach the row through its own `aria-label`s, which carry the
 * workspace title in both locales — zh delimits it with curly quotes, en
 * ends the label with it. A title shared with another workspace is skipped:
 * those rules cannot tell the rows apart, so emitting them would color both
 * rows with the last machine's color.
 * @param anchors - the anchors to mark.
 * @returns the CSS text, empty when there is nothing to mark.
 */
export function anchorTreeCss(anchors: readonly AnchorMark[]): string {
  return anchors.map(({ dir, color, title, titleUnique }) => {
    const value = cssString(dir)
    const subtree = cssString(dir + (dir.includes('\\') ? '\\' : '/'))
    const safe = SAFE_COLOR.test(color) ? color : DEFAULT_TREE_COLOR
    const selectors = [
      `[data-files-entry="directory"][data-files-path="${value}" i] svg`,
      `[data-files-entry="directory"][data-files-path^="${subtree}" i] svg`,
      `[data-files-root="${value}" i] li[data-files-entry="directory"] svg`,
      `[data-files-root="${value}" i] > div:first-child > svg`,
    ]
    if (titleUnique !== false) {
      const name = cssString(title ?? workspaceTitleOf(dir))
      selectors.push(
        `div[role="treeitem"]:has([aria-label*="“${name}”"]) > span:first-child svg`,
        `div[role="treeitem"]:has([aria-label$=" ${name}"]) > span:first-child svg`,
      )
    }
    return selectors.join(',\n') + ` { color: ${safe}; }\n`
  }).join('')
}

/**
 * The display parts of one remote path, split the way the shell splits a
 * root for its header: the directory keeps its trailing separator and the
 * name is the last segment.
 * @param remotePath - the anchor's remote workspace path.
 * @returns the two spans the tree header draws.
 */
export function rootLabelParts(remotePath: string): { directory: string; name: string } {
  const trimmed = remotePath.replace(/[/\\]+$/, '')
  if (trimmed === '') return { directory: '', name: remotePath }
  const cut = Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\')) + 1
  return { directory: trimmed.slice(0, cut), name: trimmed.slice(cut) }
}

/**
 * The remote path one displayed path text stands for, or `undefined` when the
 * text names no anchor. The shell abbreviates home paths to a leading `~` on
 * POSIX, so the match peels that tilde and compares the remaining suffix
 * against each anchor directory; an unabbreviated text matches exactly.
 * @param text - the displayed path text.
 * @param aliases - the anchor directory to remote path table.
 * @returns the remote path, or undefined.
 */
export function aliasForHoverText(text: string, aliases: ReadonlyMap<string, string>): string | undefined {
  const candidate = text.startsWith('~') ? text.slice(1) : text
  if (candidate === '') return undefined
  for (const [dir, remote] of aliases) {
    if (dir.endsWith(candidate)) return remote
  }
  return undefined
}

/** The anchor directory to remote path table behind the alias rewriter. */
let aliases = new Map<string, string>()

let aliasObserver: MutationObserver | undefined
let aliasApplyScheduled = false

/** Coalesce one alias pass per mutation burst. */
function scheduleAliasApply(): void {
  if (aliasApplyScheduled) return
  aliasApplyScheduled = true
  setTimeout(() => {
    aliasApplyScheduled = false
    applyAliases()
  }, 0)
}

/**
 * Rewrite the anchor's local directory to its remote path at every display
 * point the shell renders it. Text changes go through the existing text
 * nodes' values — never their membership — so React's reconciler keeps every
 * element it owns; a re-render that writes the local path back is caught by
 * the observer and rewritten again.
 */
function applyAliases(): void {
  // The file tree's root header: the spans under `[data-files-path]` and the
  // tooltip on it. The `data-files-*` attributes themselves stay local — they
  // are the data plane the tree navigates by.
  for (const container of document.querySelectorAll<HTMLElement>('[data-files-state="tree"][data-files-root]')) {
    const remote = aliases.get(container.dataset.filesRoot ?? '')
    const path = container.querySelector<HTMLElement>('[data-files-path]')
    if (remote === undefined || path === null) continue
    const text = path.firstElementChild
    if (text === null) continue
    const { directory, name } = rootLabelParts(remote)
    const spans = text.children
    if (spans.length !== 2) continue
    const directoryNode = spans[0]?.firstChild
    const nameNode = spans[1]?.firstChild
    if (!(directoryNode instanceof Text) || !(nameNode instanceof Text)) continue
    if (directoryNode.nodeValue !== directory) directoryNode.nodeValue = directory
    if (nameNode.nodeValue !== name) nameNode.nodeValue = name
    if (path.title !== remote) path.title = remote
  }
  // The workspace hover card portals to the body when it opens; its path row
  // is the second child of the card's content.
  for (const portal of document.body.children) {
    if (!(portal instanceof HTMLElement)) continue
    const content = portal.firstElementChild
    if (content === null || content.children.length !== 3) continue
    const row = content.children[1]
    if (!(row instanceof HTMLElement)) continue
    const node = row.firstChild
    if (!(node instanceof Text)) continue
    const remote = aliasForHoverText(node.nodeValue ?? '', aliases)
    if (remote !== undefined && node.nodeValue !== remote) node.nodeValue = remote
  }
}

/** The service lookup handed in at start; absent in compositions without one. */
let services: ServiceLookup | undefined

/** The Workspace service this module has subscribed to, if any. */
let subscribedFace: WorkspaceFace | undefined
let unsubscribeFace: (() => void) | undefined

/**
 * Workspace titles this module already tried to disambiguate this session.
 * One attempt per workspace and title: if the operator renames the Workspace
 * back, that deliberate choice wins instead of being overwritten on the next
 * refresh.
 */
const titleAttempts = new Set<string>()

let refreshInFlight: Promise<void> | null = null
let refreshQueued = false

/**
 * Resolve the client Workspace service through the context, without depending
 * on its package: the lookup is duck-typed and any missing piece (no service,
 * no snapshot, no rename) simply leaves the titles alone.
 * @returns the service face, or undefined.
 */
function workspaceFace(): WorkspaceFace | undefined {
  try {
    const service = services?.get('workspaces')
    if (service === null || typeof service !== 'object') return undefined
    const face = service as Partial<WorkspaceFace>
    if (typeof face.rename !== 'function' || typeof face.list?.getSnapshot !== 'function') return undefined
    return face as WorkspaceFace
  } catch {
    return undefined
  }
}

/** The current Workspace rows, or an empty list when the service is absent. */
function workspaceItems(): readonly WorkspaceTitleRow[] {
  try {
    return workspaceFace()?.list.getSnapshot().items ?? []
  } catch {
    return []
  }
}

/**
 * Track the Workspace list so a title collision that appears later still
 * resolves: the shell creates the Workspace after the anchor, and a create,
 * delete, or rename can bring a duplicate title into existence at any time.
 * @param face - the resolved Workspace service.
 */
function watchWorkspaceTitles(face: WorkspaceFace): void {
  if (subscribedFace === face) return
  unsubscribeFace?.()
  subscribedFace = face
  try {
    unsubscribeFace = typeof face.list.subscribe === 'function'
      ? face.list.subscribe(() => { void refreshTreeMark() })
      : undefined
  } catch {
    subscribedFace = undefined
    unsubscribeFace = undefined
  }
}

/**
 * Give colliding remote anchors distinct titles. The host settles the title
 * (machine name appended) and this renames the Workspace onto it. Only a
 * Workspace still showing the shell's own default title is touched, so a name
 * the operator chose is never overwritten.
 * @param anchors - the anchors as the host reports them.
 */
async function syncWorkspaceTitles(anchors: readonly AnchorStatus[]): Promise<void> {
  const face = workspaceFace()
  if (face === undefined) return
  watchWorkspaceTitles(face)
  const items = workspaceItems()
  for (const anchor of anchors) {
    if (anchor.title === anchor.defaultTitle) continue
    const item = items.find((i) => sameLocalDir(i.path, anchor.dir))
    if (item === undefined || item.title !== anchor.defaultTitle) continue
    const key = `${item.workspaceId}\u0000${anchor.title}`
    if (titleAttempts.has(key)) continue
    titleAttempts.add(key)
    try {
      await face.rename(item.workspaceId, anchor.title)
    } catch {
      // A failed rename retries on the next refresh; the row keeps its title.
      titleAttempts.delete(key)
    }
  }
}

/**
 * One marker pass: read the anchors, settle the colliding Workspace titles,
 * then rewrite the stylesheet from the titles the rows actually show.
 */
async function runRefresh(): Promise<void> {
  const { anchors } = await anchorStatus()
  aliases = new Map(anchors.map((a) => [a.dir, a.remotePath]))
  await syncWorkspaceTitles(anchors)
  const tag = document.querySelector(TAG_SELECTOR)
  if (tag) tag.textContent = anchorTreeCss(anchorMarks(anchors, workspaceItems()))
  scheduleAliasApply()
}

/**
 * Create the marker stylesheet tag, start the alias observer, and load the
 * initial anchor set. They outlive the call; later changes rewrite them
 * through {@link refreshTreeMark}.
 * @param lookup - context service lookup, for the client Workspace service.
 * @returns the remover (composition teardown).
 */
export function startTreeMark(lookup?: ServiceLookup): () => void {
  if (typeof document === 'undefined') return () => {}
  services = lookup
  const tag = document.createElement('style')
  tag.dataset.pluginCss = 'dsh-remote-development-tree'
  document.head.appendChild(tag)
  if (typeof MutationObserver === 'function') {
    aliasObserver = new MutationObserver(scheduleAliasApply)
    aliasObserver.observe(document.body, { childList: true, subtree: true, characterData: true })
  }
  void refreshTreeMark()
  return () => {
    tag.remove()
    aliasObserver?.disconnect()
    aliasObserver = undefined
    unsubscribeFace?.()
    unsubscribeFace = undefined
    subscribedFace = undefined
    services = undefined
    titleAttempts.clear()
    aliases = new Map()
  }
}

/**
 * Re-fetch the anchors and rewrite the marker stylesheet and the alias table.
 * A failed fetch keeps the previous coloring and aliases: a stale marker
 * beats a missing one, and nothing else can act on a failed status read.
 * Calls coalesce: a refresh requested while one runs queues exactly one more
 * pass, so the Workspace subscription cannot pile up overlapping fetches.
 * @returns the running pass.
 */
export function refreshTreeMark(): Promise<void> {
  if (typeof document === 'undefined') return Promise.resolve()
  if (refreshInFlight !== null) {
    refreshQueued = true
    return refreshInFlight
  }
  refreshInFlight = (async () => {
    do {
      refreshQueued = false
      try {
        await runRefresh()
      } catch {
        // Swallowed: the previous stylesheet and aliases stay until the next refresh.
      }
    } while (refreshQueued)
  })().finally(() => { refreshInFlight = null })
  return refreshInFlight
}
