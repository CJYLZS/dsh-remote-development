import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { anchorTreeCss, anchorMarks, sameLocalDir, DEFAULT_TREE_COLOR, rootLabelParts, aliasForHoverText } from '../src/client/tree-mark.ts'
import { anchorStatusRows, uniqueAnchorTitles } from '../src/routes.ts'
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

test('anchorTreeCss keys the workspace-row rules on the title the row shows', () => {
  const dir = '/anchors/dev.example.com-22-dev/myapp'
  const css = anchorTreeCss([{ dir, color: '#22c55e', title: 'myapp (build-box)' }])
  assert.ok(css.includes('div[role="treeitem"]:has([aria-label*="“myapp (build-box)”"]) > span:first-child svg'),
    'a disambiguated title must be the one matched, not the directory basename')
  assert.ok(!css.includes('“myapp”'), 'the bare basename must not stay in the row rules')
  assert.ok(css.includes(`[data-files-path="${dir}" i] svg`), 'the path rules stay keyed on the directory')
})

test('anchorTreeCss emits no workspace-row rule for a title two workspaces share', () => {
  const css = anchorTreeCss([
    { dir: '/anchors/a/app', color: '#22c55e', title: 'app', titleUnique: false },
    { dir: '/anchors/b/app', color: '#ef4444', title: 'app', titleUnique: false },
  ])
  assert.ok(!css.includes('role="treeitem"'), 'an ambiguous title must not color either row')
  assert.ok(css.includes('color: #22c55e'), 'the file-tree rules of each anchor survive')
  assert.equal(css.split('color:').length - 1, 2, 'one declaration per anchor, paths only')
})

test('uniqueAnchorTitles appends the machine to a basename two machines share', () => {
  const titles = uniqueAnchorTitles([
    { defaultTitle: 'app', label: 'prod', remotePath: '/srv/app' },
    { defaultTitle: 'app', label: 'stage', remotePath: '/srv/app' },
    { defaultTitle: 'logs', label: 'prod', remotePath: '/var/log' },
  ])
  assert.deepEqual(titles, ['app (prod)', 'app (stage)', 'logs'])
})

test('uniqueAnchorTitles falls back to the remote path when labels collide too', () => {
  const titles = uniqueAnchorTitles([
    { defaultTitle: 'app', label: 'build', remotePath: '/srv/app' },
    { defaultTitle: 'app', label: 'build', remotePath: '/opt/app' },
  ])
  assert.notEqual(titles[0], titles[1])
  assert.match(titles[0]!, /^app \(build\) -[0-9a-f]{8}$/)
  assert.match(titles[1]!, /^app \(build\) -[0-9a-f]{8}$/)
})

test('sameLocalDir ignores a trailing separator and Windows case', () => {
  assert.equal(sameLocalDir('/home/dev/app/', '/home/dev/app'), true)
  assert.equal(sameLocalDir('D:\\anchors\\app', 'd:/anchors/app'), true)
  assert.equal(sameLocalDir('/home/dev/App', '/home/dev/app'), false)
  assert.equal(sameLocalDir('/home/dev/app', '/home/dev/other'), false)
})

test('anchorMarks flags a title another workspace already shows', () => {
  const anchors = [
    { dir: '/anchors/a/app', remotePath: '/srv/app', machineId: 'a', color: '#22c55e', defaultTitle: 'app', title: 'app' },
    { dir: '/anchors/b/app', remotePath: '/srv/app', machineId: 'b', color: '#ef4444', defaultTitle: 'app', title: 'app' },
  ]
  const collided = anchorMarks(anchors, [])
  assert.deepEqual(collided.map((m) => m.titleUnique), [false, false])
  assert.deepEqual(collided.map((m) => m.title), ['app', 'app'])

  const settled = anchorMarks(anchors, [
    { workspaceId: 'w1', path: '/anchors/a/app', title: 'app (prod)' },
    { workspaceId: 'w2', path: '/anchors/b/app', title: 'app (stage)' },
  ])
  assert.deepEqual(settled.map((m) => m.title), ['app (prod)', 'app (stage)'])
  assert.deepEqual(settled.map((m) => m.titleUnique), [true, true])
})

test('anchorMarks lets a local workspace keep an anchor row unmarked', () => {
  const anchors = [
    { dir: '/anchors/a/app', remotePath: '/srv/app', machineId: 'a', color: '#22c55e', defaultTitle: 'app', title: 'app' },
  ]
  const marks = anchorMarks(anchors, [
    { workspaceId: 'w1', path: '/anchors/a/app', title: 'app' },
    { workspaceId: 'local', path: '/home/dev/app', title: 'app' },
  ])
  assert.equal(marks[0]!.titleUnique, false, 'a local workspace showing the same title makes the row rule unsafe')
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

test('anchorStatusRows names the machine when two hosts mount the same directory', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'rdv-tree-mark-'))
  try {
    const world = new RemoteWorld(baseConfig(root))
    const prod = sanitizeMachine({ host: 'prod.example.com', username: 'dev', port: 22, name: 'prod', color: '#22c55e' })
    const stage = sanitizeMachine({ host: 'stage.example.com', username: 'dev', port: 22, name: 'stage', color: '#ef4444' })
    world.upsertMachine(prod)
    world.upsertMachine(stage)
    world.createAnchor(prod, '/srv/app')
    world.createAnchor(stage, '/srv/app')
    const rows = anchorStatusRows(world)
    assert.equal(rows.length, 2)
    assert.deepEqual(rows.map((r) => r.defaultTitle), ['app', 'app'])
    assert.deepEqual([...rows.map((r) => r.title)].sort(), ['app (prod)', 'app (stage)'])
    assert.deepEqual(rows.map((r) => r.color).sort(), ['#22c55e', '#ef4444'])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('anchorStatusRows keeps a lone anchor on its plain basename', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'rdv-tree-mark-'))
  try {
    const world = new RemoteWorld(baseConfig(root))
    const prod = sanitizeMachine({ host: 'prod.example.com', username: 'dev', port: 22, name: 'prod' })
    world.upsertMachine(prod)
    world.createAnchor(prod, '/srv/app')
    const rows = anchorStatusRows(world)
    assert.equal(rows[0]!.defaultTitle, 'app')
    assert.equal(rows[0]!.title, 'app', 'a lone anchor must keep the title the shell derives')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('rootLabelParts splits a remote path the way the shell draws a root', () => {
  assert.deepEqual(rootLabelParts('/home/dev/myapp'), { directory: '/home/dev/', name: 'myapp' })
  assert.deepEqual(rootLabelParts('/app'), { directory: '/', name: 'app' })
  assert.deepEqual(rootLabelParts('D:\\remote\\app'), { directory: 'D:\\remote\\', name: 'app' })
})

test('aliasForHoverText matches exact and tilde-abbreviated displays', () => {
  const aliases = new Map([
    ['C:\\Users\\dev\\.dsh\\remote-workspaces\\h\\app', '/home/dev/app'],
    ['/home/dev/.dsh/remote-workspaces/h/app', '/srv/app'],
  ])
  assert.equal(aliasForHoverText('C:\\Users\\dev\\.dsh\\remote-workspaces\\h\\app', aliases), '/home/dev/app')
  assert.equal(aliasForHoverText('~/.dsh/remote-workspaces/h/app', aliases), '/srv/app')
  assert.equal(aliasForHoverText('C:\\somewhere\\else', aliases), undefined)
  assert.equal(aliasForHoverText('~', aliases), undefined)
})
