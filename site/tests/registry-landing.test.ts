import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, test } from 'node:test'
import { destination, finalizeRegistryLanding, landingPaths, redirectHtml } from '../scripts/finalize-registry-landing.mjs'

const temporaryDirectories: string[] = []
afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'uap-registry-landing-'))
  temporaryDirectories.push(root)
  await mkdir(join(root, 'plugins'))
  await writeFile(join(root, 'index.html'), 'old home')
  await writeFile(join(root, 'plugins/index.html'), 'old directory')
  return root
}

test('redirects only the two human landing pages, preserving all other bytes', async () => {
  const root = await fixture()
  const preserved = ['404.html', '200.html', 'robots.txt', 'sitemap.xml', '_nuxt/app.js',
    'discovery/latest.json', 'discovery/snapshots/1.json', 'security/latest.json',
    'security/snapshots/1.json', 'registry/index.json', 'registry/schemas/1/latest.json',
    'schemas/discovery-latest.schema.json', 'plugins/example/index.html', 'plugins/_payload.json',
    'other-machine-endpoint/data.bin']
  for (const path of preserved) {
    await mkdir(dirname(join(root, path)), { recursive: true })
    await writeFile(join(root, path), Buffer.from([0, 255, 1, 2, 10]))
  }
  assert.deepEqual(await finalizeRegistryLanding(root), landingPaths)
  for (const path of landingPaths) assert.equal(await readFile(join(root, path), 'utf8'), redirectHtml)
  for (const path of preserved) assert.deepEqual(await readFile(join(root, path)), Buffer.from([0, 255, 1, 2, 10]))
  assert.deepEqual(await finalizeRegistryLanding(root), landingPaths)
})

test('uses a fixed canonical destination and script-free automatic and manual navigation', () => {
  assert.equal(destination, 'https://777genius.github.io/universal-agent-plugins/plugins/')
  assert.ok(redirectHtml.includes(`http-equiv="refresh" content="0; url=${destination}"`))
  assert.ok(redirectHtml.includes(`rel="canonical" href="${destination}"`))
  assert.ok(redirectHtml.includes(`<a href="${destination}">`))
  assert.doesNotMatch(redirectHtml, /<script|window\.|location\.|_nuxt/)
})

test('missing landing fails before modifying the other landing', async () => {
  const root = await fixture()
  await rm(join(root, 'plugins/index.html'))
  await assert.rejects(finalizeRegistryLanding(root), /ENOENT/)
  assert.equal(await readFile(join(root, 'index.html'), 'utf8'), 'old home')
})

test('rejects symlinked landing ancestors before modifying anything', async () => {
  const root = await fixture()
  await rm(join(root, 'plugins'), { recursive: true })
  await symlink(root, join(root, 'plugins'))
  await assert.rejects(finalizeRegistryLanding(root), /unsafe registry landing path/)
  assert.equal(await readFile(join(root, 'index.html'), 'utf8'), 'old home')
})
