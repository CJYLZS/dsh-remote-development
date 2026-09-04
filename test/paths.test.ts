import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { normalizeRemotePath, joinRemotePath, remoteDirname, remoteBasename, relUnder, shq, argvToRemoteCommand, shortHash, truncateHead } from '../src/paths.ts'

test('normalizeRemotePath collapses separators and resolves dot segments', () => {
  assert.equal(normalizeRemotePath('/home//dev/./project/'), '/home/dev/project')
  assert.equal(normalizeRemotePath('/a/b/../c'), '/a/c')
  assert.equal(normalizeRemotePath('/'), '/')
  assert.equal(normalizeRemotePath('a/../b'), 'b')
  assert.equal(normalizeRemotePath(''), '')
})

test('joinRemotePath joins and lets absolute rest win', () => {
  assert.equal(joinRemotePath('/home/dev', 'src/index.ts'), '/home/dev/src/index.ts')
  assert.equal(joinRemotePath('/home/dev', '/etc/hosts'), '/etc/hosts')
  assert.equal(joinRemotePath('/home/dev', ''), '/home/dev')
})

test('remoteDirname and remoteBasename split paths', () => {
  assert.equal(remoteDirname('/home/dev/project'), '/home/dev')
  assert.equal(remoteDirname('/project'), '/')
  assert.equal(remoteBasename('/home/dev/project'), 'project')
  assert.equal(remoteBasename('/'), '')
})

test('relUnder returns the relative path or null', () => {
  assert.equal(relUnder('/home/dev', '/home/dev/src/x.ts'), 'src/x.ts')
  assert.equal(relUnder('/home/dev', '/home/dev'), '')
  assert.equal(relUnder('/home/dev', '/etc/hosts'), null)
  assert.equal(relUnder('/home/dev', '/home/devil'), null)
})

test('shq quotes single quotes safely', () => {
  assert.equal(shq("it's"), `'it'\\''s'`)
  assert.equal(shq('plain'), `'plain'`)
})

test('argvToRemoteCommand quotes every element', () => {
  assert.equal(argvToRemoteCommand(['rg', '--regexp=a b', '--', "it's"]), `'rg' '--regexp=a b' '--' 'it'\\''s'`)
})

test('shortHash is a stable 8-hex suffix', () => {
  assert.equal(shortHash('/a'), shortHash('/a'))
  assert.match(shortHash('/a'), /^[0-9a-f]{8}$/)
  assert.notEqual(shortHash('/a'), shortHash('/b'))
})

test('truncateHead keeps the head within the ceiling', () => {
  assert.equal(truncateHead('abcdef', 3), 'abc')
  assert.equal(truncateHead('ab', 3), 'ab')
})
