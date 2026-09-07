import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { inject } from '../src/index.ts'

/**
 * Regression guard for the bash-tool outage: this plugin is a namespace
 * plugin, so the Loader builds the fiber's inject from the module's `inject`
 * export alone — the `static inject` of the manually constructed provider
 * classes is ignored. SandboxBashExecutor (RoutingBashExecutor's base) reads
 * `ctx.sandbox` and `ctx.sandboxPolicy` directly; a missing declaration makes
 * the ancestor-only fiber walk reach root and throw `cannot get property
 * "sandbox" without inject` on every bash call. LocalBashExecutor's
 * `ctx.subprocess` read is satisfied by this plugin's own provider, so the
 * module list must cover the other four services the mounted surface reads.
 */
test('module inject declares every service the mounted providers read directly', () => {
  for (const service of ['systemPrompt', 'sandboxPolicy', 'sandbox', 'agents'] as const) {
    assert.ok(inject.includes(service), `inject must declare "${service}"`)
  }
})
