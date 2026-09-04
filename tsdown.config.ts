/**
 * Build for both halves. The host half emits an ESM Node library (all
 * @deepseek-ai/* and ssh2 imports stay external — the profile resolves them).
 * The client half emits the loader artifact: a classic-script CJS factory
 * registered via window.__ModuleLoader__.load, with the module-table entries
 * (react, ui-primitives) left external.
 */
import { defineConfig } from 'tsdown'

const PLUGIN_ID = 'dsh-remote-development'

/** Module-table entries the client bundle may require (platform baseline). */
const CLIENT_EXTERNALS = [
  'react',
  'react/jsx-runtime',
  'react-dom',
  '@deepseek-ai/cordis',
  '@deepseek-ai/dsh-client-store',
  '@deepseek-ai/dsh-client-ui-slots',
  '@deepseek-ai/dsh-client-ui-primitives',
]

const isExternalDep = (specifier: string): boolean =>
  /^@deepseek-ai\//.test(specifier) || /^ssh2/.test(specifier) ||
  CLIENT_EXTERNALS.includes(specifier)

export default defineConfig([
  {
    entry: ['src/index.ts'],
    outDir: 'lib',
    format: ['esm'],
    platform: 'node',
    target: 'es2022',
    fixedExtension: false,
    deps: { neverBundle: isExternalDep, alwaysBundle: (specifier: string) => !isExternalDep(specifier) && !specifier.startsWith('node:') },
    clean: false,
    sourcemap: true,
  },
  {
    entry: { client: 'src/client/index.ts' },
    outDir: 'lib',
    format: 'cjs',
    platform: 'browser',
    target: 'es2022',
    fixedExtension: false,
    deps: { neverBundle: (specifier) => CLIENT_EXTERNALS.includes(specifier), alwaysBundle: (specifier) => !CLIENT_EXTERNALS.includes(specifier) && !specifier.startsWith('node:') },
    clean: false,
    sourcemap: true,
    outputOptions: {
      entryFileNames: 'client.js',
      // banner/footer/intro live in outputOptions: tsdown's top-level aliases
      // cover banner/footer only, and a dropped intro leaves exports/module as
      // free variables — the loader factory then throws "exports is not
      // defined" when the client module system executes it.
      banner: `window.__ModuleLoader__.load({ id: ${JSON.stringify(PLUGIN_ID)}, factory: (require) => {`,
      footer: 'return module.exports; } });',
      intro: 'var module = { exports: {} }; var exports = module.exports;',
    },
  },
])
