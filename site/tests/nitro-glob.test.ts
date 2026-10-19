import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { test } from 'node:test'
import { gunzipSync } from 'node:zlib'
import { ModuleKind, ScriptTarget, transpileModule } from 'typescript'
import { globby } from '../patches/nitro-glob.ts'

const nuxtRequire = createRequire(import.meta.resolve('nuxt'))
const nitroDirectory = dirname(nuxtRequire.resolve('nitropack/package.json'))
const runtimePath = join(nitroDirectory, 'dist/shared/uap-glob.mjs')

async function fixture(files: Record<string, string>, run: (directory: string) => Promise<void>) {
  const directory = await mkdtemp(join(tmpdir(), 'uap-nitro-glob-'))
  try {
    for (const [path, content] of Object.entries(files)) {
      await mkdir(dirname(join(directory, path)), { recursive: true })
      await writeFile(join(directory, path), content)
    }
    await run(directory)
  } finally { await rm(directory, { recursive: true, force: true }) }
}

test('installed Nitro adapter equals its pinned TypeScript source compilation', async () => {
  const source = await readFile(new URL('../patches/nitro-glob.ts', import.meta.url), 'utf8')
  const generated = transpileModule(source, { compilerOptions: { module: ModuleKind.ESNext, target: ScriptTarget.ES2022 } }).outputText
  assert.equal(await readFile(runtimePath, 'utf8'), generated)
})

// A direct tinyglobby alias loses keep.txt and negative-only discovery;
// applying every negative globally loses later reinclusions and ignoring ! loses exclusions.
test('ordered exclusions, deduplication, negative-only patterns and global ignores retain Nitro semantics', async () => {
  await fixture({ 'drop.txt': '', 'keep.txt': '', 'nested/drop.txt': '', '.hidden': '', 'extensionless': '' }, async cwd => {
    const runtime = await import(pathToFileURL(runtimePath).href) as { globby: typeof globby }
    for (const implementation of [globby, runtime.globby]) {
      const options = { cwd, dot: true }
      assert.deepEqual((await implementation(['**', '!**/*.txt', 'keep.txt'], options)).sort(), ['.hidden', 'extensionless', 'keep.txt'])
      assert.deepEqual(await implementation(['*.txt', '!drop.txt', 'keep.txt', '!keep.txt'], options), [])
      assert.deepEqual((await implementation(['**', '**', 'keep.txt'], options)).sort(), ['.hidden', 'drop.txt', 'extensionless', 'keep.txt', 'nested/drop.txt'])
      assert.deepEqual((await implementation(['**', '!**/*.txt', '**'], options)).sort(), ['.hidden', 'extensionless'])
      assert.deepEqual((await implementation(['!**/*.txt'], options)).sort(), ['.hidden', 'extensionless'])
      assert.deepEqual((await implementation(['!/*.txt'], options)).sort(), ['.hidden', 'extensionless', 'nested/drop.txt'])
      assert.deepEqual(await implementation([], options), [])
      assert.deepEqual((await implementation('**', { ...options, ignore: ['!**/*.txt'] })).sort(), ['.hidden', 'extensionless'])
    }
  })
})

// Removing dot/brace/absolute support or dropping negated ignore discovers the wrong handlers.
test('actual Nitro route discovery keeps hidden brace extensions, methods and ignored handlers', async () => {
  await fixture({
    'api/.hidden.mts': '', 'api/hello.get.ts': '', 'api/nested/index.cjs': '',
    'api/ignored.ts': '', 'api/readme.txt': '',
  }, async rootDir => {
    const { createNitro, scanServerRoutes } = await import(pathToFileURL(join(nitroDirectory, 'dist/core/index.mjs')).href)
    const nitro = await createNitro({ rootDir, srcDir: rootDir, preset: 'static', logLevel: 0, compatibilityDate: '2026-10-04', imports: false, ignore: ['!api/ignored.ts'] })
    try {
      const handlers: { route: string, handler: string, method?: string }[] = await scanServerRoutes(nitro, 'api', '/api')
      assert.deepEqual(handlers.map(handler => [handler.route, handler.method]), [['/api/.hidden', undefined], ['/api/hello', 'get'], ['/api/nested', undefined]])
      assert.ok(handlers.every(handler => handler.handler.startsWith(`${rootDir}/api/`)))
    } finally { await nitro.close() }
  })
})

// A global-negative adapter drops keep.txt; a file-extension glob loses dotfiles/extensionless assets.
// Dropping compression exclusions creates .gz.gz/.br.gz artifacts instead of preserving existing bytes.
test('actual Nitro public copy/compression preserves reinclusion, dotfiles and extensionless assets', async () => {
  const content = 'compressible fixture content\n'.repeat(80)
  await fixture({
    'public/keep.txt': content, 'public/drop.txt': content, 'public/.hidden': content,
    'public/extensionless': content, 'public/already.txt.gz': content, 'public/already.txt.br': content,
    'public/ignored/nested.txt': content,
  }, async rootDir => {
    const { createNitro, copyPublicAssets } = await import(pathToFileURL(join(nitroDirectory, 'dist/core/index.mjs')).href)
    const nitro = await createNitro({ rootDir, srcDir: rootDir, preset: 'static', logLevel: 0, compatibilityDate: '2026-10-04', imports: false,
      ignore: ['**/*.txt', '!public/keep.txt', 'public/ignored'], compressPublicAssets: { gzip: true, brotli: false } })
    try {
      await copyPublicAssets(nitro)
      const output: string = nitro.options.output.publicDir
      assert.deepEqual((await readdir(output)).sort(), ['.hidden', '.hidden.gz', 'already.txt.br', 'already.txt.gz', 'extensionless', 'extensionless.gz', 'keep.txt', 'keep.txt.gz'])
      for (const file of ['.hidden', 'extensionless', 'keep.txt']) {
        assert.equal(await readFile(join(output, file), 'utf8'), content)
        assert.equal(gunzipSync(await readFile(join(output, `${file}.gz`))).toString(), content)
      }
      assert.equal(await readFile(join(output, 'already.txt.gz'), 'utf8'), content)
      assert.equal(await readFile(join(output, 'already.txt.br'), 'utf8'), content)
      // Read actual Rollup asset metadata without running a build.
      const { getRollupConfig } = await import(pathToFileURL(join(nitroDirectory, 'dist/rollup/index.mjs')).href)
      const id = '#nitro-internal-virtual/public-assets-data'
      const plugins = getRollupConfig(nitro).plugins.flat(Infinity)
      const virtual = plugins.find((plugin: { name?: string, resolveId?: unknown }) => plugin?.name === 'virtual' && typeof plugin.resolveId === 'function' && (plugin.resolveId as (id: string) => string | null)(id))
      assert.ok(virtual)
      const { code }: { code: string } = await virtual.load(virtual.resolveId(id))
      const metadata = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
      assert.deepEqual(Object.keys(metadata.default).sort(), (await readdir(output)).map(file => `/${file}`).sort())
      assert.equal(metadata.default['/keep.txt.gz'].encoding, 'gzip')
      assert.equal(metadata.default['/.hidden'].size, Buffer.byteLength(content))
    } finally { await nitro.close() }
  })
})

// A broken third import or ignore handling leaks worker/build internals into static route exclusions.
test('actual Cloudflare routes include hidden/extensionless files and exclude build internals', async () => {
  await fixture({ '_worker.js/index.js': '', '_worker.js.map': '', 'nitro.json': '',
    '.hidden': '', 'extensionless': '', 'nested/index.html': '', 'explicit/private.txt': '' }, async directory => {
    const { writeCFRoutes } = await import(pathToFileURL(join(nitroDirectory, 'dist/presets/cloudflare/utils.mjs')).href)
    await writeCFRoutes({ options: { output: { dir: directory }, baseURL: '/', publicAssets: [],
      cloudflare: { pages: { routes: { exclude: ['/explicit/*'] } } } } })
    const routes: { version: number, include: string[], exclude: string[] } = JSON.parse(await readFile(join(directory, '_routes.json'), 'utf8'))
    assert.equal(routes.version, 1)
    assert.deepEqual(routes.include, ['/*'])
    assert.deepEqual(routes.exclude, ['/explicit/*', '/.hidden', '/extensionless', '/nested'])
  })
})
