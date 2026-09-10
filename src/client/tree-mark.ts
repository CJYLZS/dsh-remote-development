/**
 * Remote-workspace presentation in the workspace shell. The in-box tree and
 * workspace list are fixed components the plugin cannot re-render, so the
 * plugin reaches them the only way it can, from its own client bundle:
 * generated attribute selectors that recolor folder icons, and an alias
 * rewriter that shows each anchor's remote path wherever the shell displays
 * the anchor's local directory — the file tree's root header and the
 * workspace list's hover card.
 * @module dsh-remote-development/client/tree-mark
 */

import { anchorStatus } from './api.ts'

/** One anchor to mark (color '' = the theme default). */
export interface AnchorMark {
  dir: string
  color: string
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
 * Build the marker stylesheet. One rule block per anchor covers every place
 * the shell can show it: the anchor as a row inside a local file tree (exact
 * match, plus a separator-prefixed selector for its subtree), a file tree
 * rooted at it (every directory row, plus the header's folder icon), and the
 * sidebar's workspace row for it. Workspace rows expose no data hooks, so
 * their rules reach the row through its own `aria-label`s, which carry the
 * workspace title in both locales — zh delimits it with curly quotes, en
 * ends the label with it.
 * @param anchors - the anchors to mark.
 * @returns the CSS text, empty when there is nothing to mark.
 */
export function anchorTreeCss(anchors: readonly AnchorMark[]): string {
  return anchors.map(({ dir, color }) => {
    const value = cssString(dir)
    const subtree = cssString(dir + (dir.includes('\\') ? '\\' : '/'))
    const name = cssString(workspaceTitleOf(dir))
    const safe = SAFE_COLOR.test(color) ? color : DEFAULT_TREE_COLOR
    return [
      `[data-files-entry="directory"][data-files-path="${value}" i] svg`,
      `[data-files-entry="directory"][data-files-path^="${subtree}" i] svg`,
      `[data-files-root="${value}" i] li[data-files-entry="directory"] svg`,
      `[data-files-root="${value}" i] > div:first-child > svg`,
      `div[role="treeitem"]:has([aria-label*="“${name}”"]) > span:first-child svg`,
      `div[role="treeitem"]:has([aria-label$=" ${name}"]) > span:first-child svg`,
    ].join(',\n') + ` { color: ${safe}; }\n`
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

/**
 * Create the marker stylesheet tag, start the alias observer, and load the
 * initial anchor set. They outlive the call; later changes rewrite them
 * through {@link refreshTreeMark}.
 * @returns the remover (composition teardown).
 */
export function startTreeMark(): () => void {
  if (typeof document === 'undefined') return () => {}
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
    aliases = new Map()
  }
}

/**
 * Re-fetch the anchors and rewrite the marker stylesheet and the alias table.
 * A failed fetch keeps the previous coloring and aliases: a stale marker
 * beats a missing one, and nothing else can act on a failed status read.
 */
export async function refreshTreeMark(): Promise<void> {
  if (typeof document === 'undefined') return
  try {
    const { anchors } = await anchorStatus()
    aliases = new Map(anchors.map((a) => [a.dir, a.remotePath]))
    const tag = document.querySelector(TAG_SELECTOR)
    if (tag) tag.textContent = anchorTreeCss(anchors)
    scheduleAliasApply()
  } catch {
    // Swallowed: the previous stylesheet and aliases stay until the next refresh.
  }
}
