import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { machineFromBody } from '../src/routes.ts'

test('machineFromBody treats an absent secret as keep and a string as set-or-clear', () => {
  const absent = machineFromBody({ name: 'a', host: 'h', port: 22, username: 'u' })
  assert.equal(absent.password, undefined)
  assert.equal(absent.passphrase, undefined)

  const cleared = machineFromBody({ name: 'a', host: 'h', port: 22, username: 'u', password: '', passphrase: '' })
  assert.equal(cleared.password, '')
  assert.equal(cleared.passphrase, '')

  const set = machineFromBody({ name: 'a', host: 'h', port: 22, username: 'u', password: 'pw', passphrase: 'pp' })
  assert.equal(set.password, 'pw')
  assert.equal(set.passphrase, 'pp')
})

test('machineFromBody keeps the proxy password when the body omits it', () => {
  const absent = machineFromBody({ name: 'a', host: 'h', port: 22, username: 'u', proxyHost: 'bastion' })
  assert.equal(absent.proxy?.host, 'bastion')
  assert.equal('password' in (absent.proxy ?? {}), false)

  const set = machineFromBody({ name: 'a', host: 'h', port: 22, username: 'u', proxyHost: 'bastion', proxyPassword: 'bp' })
  assert.equal(set.proxy?.password, 'bp')
})
