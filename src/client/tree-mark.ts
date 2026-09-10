/**
 * Remote-workspace marking in the workspace tree. The in-box file tree is a
 * fixed component the plugin cannot re-render, but its rows and root carry
 * stable `data-files-*` attributes, so the plugin reaches it the only way it
 * can: generated attribute selectors that recolor folder icons, injected as a
 * second stylesheet next to the plugin's static one.
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
 * Create the marker stylesheet tag and load the initial anchor set. The tag
 * outlives the call; later changes rewrite it through {@link refreshTreeMark}.
 * @returns the tag remover (composition teardown).
 */
export function startTreeMark(): () => void {
  if (typeof document === 'undefined') return () => {}
  const tag = document.createElement('style')
  tag.dataset.pluginCss = 'dsh-remote-development-tree'
  document.head.appendChild(tag)
  void refreshTreeMark()
  return () => tag.remove()
}

/**
 * Re-fetch the anchors and rewrite the marker stylesheet. A failed fetch
 * keeps the previous coloring: a stale marker beats a missing one, and
 * nothing else can act on a failed status read.
 */
export async function refreshTreeMark(): Promise<void> {
  if (typeof document === 'undefined') return
  try {
    const { anchors } = await anchorStatus()
    const tag = document.querySelector(TAG_SELECTOR)
    if (tag) tag.textContent = anchorTreeCss(anchors)
  } catch {
    // Swallowed: the previous stylesheet stays until the next refresh.
  }
}
