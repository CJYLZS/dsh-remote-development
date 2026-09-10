import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { anchorTreeCss, DEFAULT_TREE_COLOR } from '../src/client/tree-mark.ts'
import { anchorStatusRows } from '../src/routes.ts'
import { RemoteWorld } from '../src/world.ts'
import { sanitizeMachine } from '../src/registry.ts'
import type { Config } from '../src/config.ts'

function baseConfig(anchorRoot: string): Config {
  return {
    host: '',
    port: 22,
    username: '',
    password: '',
    privateKeyPath: '',
    passphrase: '',
    workspace: '',
    commandTimeoutMs: 20000,
    connectTimeoutMs: 15000,
    maxOutputChars: 200000,
    maxFileBytes: 52428800,
    hostKeyMode: 'accept-new',
    useAgent: false,
    keyboardInteractive: false,
    proxy: { host: '', port: 22, username: '', password: '', privateKeyPath: '', passphrase: '' },
    auditLog: false,
    anchorRoot,
    remoteRipgrep: 'rg',
  }
}

test('anchorTreeCss covers the anchor row, its subtree, and a tree rooted at it', () => {
  const dir = '/anchors/dev.example.com-22-dev/myapp'
  const css = anchorTreeCss([{ dir, color: '#22c55e' }])
  assert.ok(css.includes(`[data-files-entry="directory"][data-files-path="${dir}" i] svg`),
    'the anchor itself appearing as a row in a local tree must match exactly')
  assert.ok(css.includes(`[data-files-entry="directory"][data-files-path^="${dir}/" i] svg`),
    'descendants must match through a separator-prefixed subtree selector')
  assert.ok(css.includes(`[data-files-root="${dir}" i] li[data-files-entry="directory"] svg`),
    'a tree rooted at the anchor must color every directory row')
  assert.ok(css.includes(`[data-files-root="${dir}" i] > div:first-child > svg`),
    'a tree rooted at the anchor must color the header folder icon')
  assert.ok(css.includes(`div[role="treeitem"]:has([aria-label*="“myapp”"]) > span:first-child svg`),
    'the sidebar workspace row must match through the zh quote-delimited label')
  assert.ok(css.includes(`div[role="treeitem"]:has([aria-label$=" myapp"]) > span:first-child svg`),
    'the sidebar workspace row must match through the en name-suffixed label')
  assert.ok(css.includes('color: #22c55e'), 'the machine color must be used')
})

test('anchorTreeCss escapes Windows path separators inside attribute selectors', () => {
  const dir = 'D:\\remote-dev\\host-22-dev\\myapp'
  const css = anchorTreeCss([{ dir, color: 'emerald' }])
  const escaped = 'D:\\\\remote-dev\\\\host-22-dev\\\\myapp'
  assert.ok(css.includes(`[data-files-path="${escaped}" i] svg`), 'backslashes must be escaped in the CSS string')
  assert.ok(css.includes(`[data-files-path^="${escaped}\\\\" i] svg`), 'the subtree prefix must carry the platform separator')
  assert.ok(css.includes(`div[role="treeitem"]:has([aria-label$=" myapp"]) > span:first-child svg`),
    'the workspace-row rule uses the bare basename, untouched by path escaping')
  assert.ok(css.includes('color: emerald'))
})

test('anchorTreeCss never interpolates a color that could leave a declaration', () => {
  const css = anchorTreeCss([
    { dir: '/anchors/a', color: 'red;} body { display: none' },
    { dir: '/anchors/b', color: '' },
  ])
  assert.ok(!css.includes(';}'), 'a hostile color must not survive sanitization')
  assert.ok(!css.includes('{ display'), 'no injected rule block may appear')
  assert.equal(css.split('color:').length - 1, 2, 'both anchors fall back, one declaration each')
  assert.ok(css.includes(`color: ${DEFAULT_TREE_COLOR}`), 'unset and unsafe colors use the default token')
})

test('anchorTreeCss emits nothing for an empty anchor list', () => {
  assert.equal(anchorTreeCss([]), '')
})

test('anchorStatusRows joins every anchor with its machine color', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'rdv-tree-mark-'))
  try {
    const world = new RemoteWorld(baseConfig(root))
    const machine = sanitizeMachine({ host: 'dev.example.com', username: 'dev', port: 22, color: '#22c55e' })
    world.upsertMachine(machine)
    world.createAnchor(machine, '/home/dev/myapp')
    const rows = anchorStatusRows(world)
    assert.equal(rows.length, 1)
    assert.equal(rows[0]!.remotePath, '/home/dev/myapp')
    assert.equal(rows[0]!.machineId, machine.id)
    assert.equal(rows[0]!.color, '#22c55e')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('anchorStatusRows leaves an orphaned anchor without a machine or color', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'rdv-tree-mark-'))
  try {
    const world = new RemoteWorld(baseConfig(root))
    const machine = sanitizeMachine({ host: 'dev.example.com', username: 'dev', port: 22 })
    world.upsertMachine(machine)
    world.createAnchor(machine, '/home/dev/myapp')
    world.removeMachine(machine.id)
    const rows = anchorStatusRows(world)
    assert.equal(rows.length, 1)
    assert.equal(rows[0]!.machineId, '')
    assert.equal(rows[0]!.color, '')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
