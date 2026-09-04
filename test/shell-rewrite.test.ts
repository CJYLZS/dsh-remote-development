import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { rewriteAnchorSpellings } from '../src/shell-router.ts'

const HOME = '/home/dev'

const PROJ = { dir: `${HOME}/.dsh/remote-workspaces/127.0.0.1-root-22/proj`, remoteRoot: '/srv/proj' }
// Prefixes PROJ's basename — must be replaced as its own anchor.
const TOOLS = { dir: `${HOME}/.dsh/remote-workspaces/127.0.0.1-root-22/proj-tools`, remoteRoot: '/opt/tools' }
const ANCHORS = [PROJ, TOOLS]

test('absolute anchor paths map to their remote roots, longest first', () => {
  const out = rewriteAnchorSpellings(`ls ${PROJ.dir} && ls ${TOOLS.dir}`, ANCHORS, HOME)
  assert.equal(out, 'ls /srv/proj && ls /opt/tools')
})

test('subpaths under an anchor keep their remainder', () => {
  const out = rewriteAnchorSpellings(`cat ${PROJ.dir}/src/a.ts`, ANCHORS, HOME)
  assert.equal(out, 'cat /srv/proj/src/a.ts')
})

test('~ and $HOME spellings of an anchor map too', () => {
  const rel = PROJ.dir.slice(HOME.length)
  const out = rewriteAnchorSpellings(`cd ~${rel} && ls $HOME${rel}`, ANCHORS, HOME)
  assert.equal(out, 'cd /srv/proj && ls /srv/proj')
})

test('text without anchor references is returned verbatim', () => {
  const text = 'echo hello && ls /tmp'
  assert.equal(rewriteAnchorSpellings(text, ANCHORS, HOME), text)
})
