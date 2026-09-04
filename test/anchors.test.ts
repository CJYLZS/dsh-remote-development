import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { ANCHOR_META_FILE, anchorDirFor, createAnchorDir, matchRemotePath, remotePathFor, scanAnchors } from '../src/anchors.ts'
import { sanitizeMachine } from '../src/registry.ts'

function tempDir(): string {
  return mkdtempSync(path.join(tmpdir(), 'rdv-anchors-'))
}

const machine = sanitizeMachine({ host: 'dev.example.com', username: 'dev', port: 22 })

test('anchorDirFor names the directory host-user-port/basename', () => {
  const dir = anchorDirFor('/root', machine, '/home/dev/myapp')
  assert.equal(dir, path.join('/root', 'dev.example.com-dev-22', 'myapp'))
})

test('createAnchorDir is idempotent for the same origin', () => {
  const root = tempDir()
  try {
    const first = createAnchorDir(root, machine, '/home/dev/myapp')
    assert.equal(existsSync(path.join(first, ANCHOR_META_FILE)), true)
    const second = createAnchorDir(root, machine, '/home/dev/myapp')
    assert.equal(first, second)
    const meta = JSON.parse(readFileSync(path.join(first, ANCHOR_META_FILE), 'utf8')) as { remotePath: string }
    assert.equal(meta.remotePath, '/home/dev/myapp')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('a colliding basename is disambiguated by a hash', () => {
  const root = tempDir()
  try {
    const first = createAnchorDir(root, machine, '/home/dev/myapp')
    const other = sanitizeMachine({ host: 'dev.example.com', username: 'dev', port: 22 })
    const second = createAnchorDir(root, other, '/srv/other/myapp')
    assert.notEqual(first, second)
    assert.match(second, /myapp-[0-9a-f]{8}$/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('scanAnchors finds every created anchor', () => {
  const root = tempDir()
  try {
    createAnchorDir(root, machine, '/home/dev/myapp')
    createAnchorDir(root, machine, '/home/dev/other')
    const anchors = scanAnchors(root)
    assert.equal(anchors.length, 2)
    const roots = anchors.map((a) => a.remoteRoot).sort()
    assert.deepEqual(roots, ['/home/dev/myapp', '/home/dev/other'])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('remotePathFor maps an anchor path onto its remote root', () => {
  const root = tempDir()
  try {
    const dir = createAnchorDir(root, machine, '/home/dev/myapp')
    const anchors = scanAnchors(root)
    assert.equal(remotePathFor(anchors[0]!, path.join(dir, 'src', 'index.ts')), '/home/dev/myapp/src/index.ts')
    assert.equal(remotePathFor(anchors[0]!, dir), '/home/dev/myapp')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('matchRemotePath claims remote-coordinate paths (longest root wins)', () => {
  const root = tempDir()
  try {
    createAnchorDir(root, machine, '/home/dev')
    const other = createAnchorDir(root, machine, '/home/dev/deep')
    void other
    const anchors = scanAnchors(root)
    const hit = matchRemotePath('/home/dev/deep/src/x.ts', anchors)
    assert.equal(hit?.remotePath, '/home/dev/deep/src/x.ts')
    assert.equal(hit?.anchor.remoteRoot, '/home/dev/deep')
    const shallow = matchRemotePath('/home/dev/other', anchors)
    assert.equal(shallow?.remotePath, '/home/dev/other')
    assert.equal(matchRemotePath('/var/log', anchors), null)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
