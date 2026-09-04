/**
 * Build for both halves. The host half emits a self-contained ESM Node
 * library: @deepseek-ai/* imports stay external (the profile resolves them),
 * while ssh2 and its pure-JS dependencies are bundled in. Bundling ssh2 is
 * what keeps `dsh plugin add` working on a default profile — as an installed
 * dependency it carries an install script that pnpm ≥10 blocks, and pnpm reads
 * build permission only from the workspace root, so no declaration in this
 * package can grant it.
 *
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
  /^@deepseek-ai\//.test(specifier) ||
  CLIENT_EXTERNALS.includes(specifier)

/** ssh2's optional native accelerators, plus any prebuilt binary they reach for. */
const isOptionalNative = (specifier: string): boolean =>
  specifier === 'cpu-features' || specifier === 'nan' || specifier.endsWith('.node')

/** Virtual module id standing in for every optional native accelerator. */
const NATIVE_STUB_ID = '\0rdv-native-stub'

/**
 * Resolve ssh2's optional native requires to a module that throws when the
 * require runs, selecting ssh2's pure-JS cipher path identically on every
 * consumer platform. ssh2 wraps both requires in `try/catch`, so the throw is
 * the documented fallback rather than a failure.
 *
 * The two alternatives are both wrong: bundling a resolved `.node` file ships
 * the build host's platform/ABI binary to every consumer, and leaving the
 * requires unresolved emits the build host's pnpm store path.
 */
const nativeStubPlugin = {
  name: 'rdv-native-stub',
  resolveId(id: string) {
    return isOptionalNative(id) ? NATIVE_STUB_ID : null
  },
  load(id: string) {
    if (id !== NATIVE_STUB_ID) return null
    return "throw new Error('optional native accelerator is not bundled; ssh2 uses its pure-JS path')\n"
  },
}

/**
 * CJS globals the bundled ssh2 sources read at module scope. `require` also
 * keeps esbuild/rolldown from resolving ssh2's dynamic requires at build time,
 * which is what leaves the native stubs to run-time.
 */
const HOST_BANNER = [
  "import { createRequire as __rdvCreateRequire } from 'node:module'",
  "import { fileURLToPath as __rdvFileURLToPath } from 'node:url'",
  "import { dirname as __rdvDirname } from 'node:path'",
  'const require = __rdvCreateRequire(import.meta.url)',
  'const __filename = __rdvFileURLToPath(import.meta.url)',
  'const __dirname = __rdvDirname(__filename)',
].join('\n')

export default defineConfig([
  {
    entry: ['src/index.ts'],
    outDir: 'lib',
    format: ['esm'],
    platform: 'node',
    target: 'es2022',
    fixedExtension: false,
    deps: {
      neverBundle: isExternalDep,
      alwaysBundle: (specifier: string) => !isExternalDep(specifier) && !specifier.startsWith('node:'),
    },
    plugins: [nativeStubPlugin],
    clean: false,
    sourcemap: true,
    outputOptions: { banner: HOST_BANNER },
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
