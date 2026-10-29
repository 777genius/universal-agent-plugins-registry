import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { test } from 'node:test'

const expectedDefaults = {
  dedupe: [],
  extensions: ['.mjs', '.js', '.json', '.node'],
  resolveOnly: [],
  moduleDirectories: ['node_modules'],
  modulePaths: [],
  ignoreSideEffectsForRoot: false,
  allowExportsFolderMapping: true,
}
type ResolverModule = {
  DEFAULTS: Record<string, string[] | boolean>
  nodeResolve: (options?: { extensions?: string[] }) => unknown
}

const nuxtRequire = createRequire(import.meta.resolve('nuxt'))
const nitroRequire = createRequire(nuxtRequire.resolve('nitropack/package.json'))
const commonJS = nitroRequire.resolve('@rollup/plugin-node-resolve')
const esm = pathToFileURL(join(dirname(commonJS), '../es/index.js')).href
const { rollup } = nitroRequire('rollup')
const implementations = [
  ['CommonJS', nitroRequire(commonJS) as ResolverModule],
  ['ESM', await import(esm) as ResolverModule],
] as const

for (const [name, implementation] of implementations) {
  test(`${name} resolver keeps the recursively frozen public defaults`, () => {
    assert.deepEqual(implementation.DEFAULTS, expectedDefaults)
    assert.ok(Object.isFrozen(implementation.DEFAULTS))
    for (const value of Object.values(implementation.DEFAULTS)) {
      if (Array.isArray(value)) {
        assert.ok(Object.isFrozen(value))
        assert.throws(() => value.push('.changed'), TypeError)
      }
    }
  })

  test(`${name} resolver preserves default extension order and caller options in a real bundle`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'uap-node-resolve-'))
    try {
      await writeFile(join(directory, 'entry.js'), 'export { value } from "./dependency";\n')
      for (const extension of ['mjs', 'js', 'custom']) {
        await writeFile(join(directory, `dependency.${extension}`), `export const value = "from-${extension}";\n`)
      }
      const custom = { extensions: ['.custom'] }
      for (const [options, marker] of [[undefined, 'from-mjs'], [custom, 'from-custom']] as const) {
        const bundle = await rollup({ input: join(directory, 'entry.js'), plugins: [implementation.nodeResolve(options)] })
        try {
          const generated = await bundle.generate({ format: 'es' })
          assert.ok(generated.output[0].code.includes(marker))
        } finally { await bundle.close() }
      }
      assert.deepEqual(custom, { extensions: ['.custom'] })
      assert.equal(Object.isFrozen(custom.extensions), false)
      assert.deepEqual(implementation.DEFAULTS, expectedDefaults)
    } finally { await rm(directory, { recursive: true, force: true }) }
  })
}
