import { test } from 'node:test'
import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const patchPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'cordis.patch.yml')
// Checkouts may carry CRLF; normalize so the row assertions are ending-agnostic.
const patch = readFileSync(patchPath, 'utf8').replace(/\r\n/g, '\n')

/** Row block for one id: from its `- id:` line to the next `- id:`/`- insert:` line. */
function rowBlock(id: string): string {
  const pattern = new RegExp(`- id: ${id}\\n([\\s\\S]*?)(?=\\n  - id:|\\n- id:|\\n- insert:|\\n*$)`)
  const match = patch.match(pattern)
  assert.ok(match, `patch must contain a row with id "${id}"`)
  return match[0]
}

test('patch disables every base execution-world row the plugin replaces', () => {
  for (const id of ['fs-sandbox', 'subprocess', 'bash-sandbox', 'pwsh-sandbox']) {
    assert.match(rowBlock(id), /disabled: true/, `row "${id}" must be disabled so the plugin is the only provider`)
  }
})

test('patch mounts the bash tool on every host platform', () => {
  // The per-agent visibility layer hides whichever dialect a session must not
  // use, so the row itself must not be platform-gated: on win32 the base
  // bundle's `process.platform === 'win32'` disable has to be overridden.
  assert.match(rowBlock('tool-bash'), /disabled: false/, 'tool-bash must be force-enabled (the base bundle disables it on win32)')
})

test('patch inserts the plugin row', () => {
  assert.match(patch, /- insert:\n\s+- id: dsh-remote-development\n\s+name: '?dsh-remote-development'?/)
})

test('patch does not re-gate the pwsh tool', () => {
  // tool-pwsh keeps the base bundle's own platform gating (POSIX hosts never
  // mount it); a patch row here would flip that gate the wrong way on POSIX.
  assert.ok(!patch.includes('- id: tool-pwsh'), 'the patch must not carry a tool-pwsh row')
})
