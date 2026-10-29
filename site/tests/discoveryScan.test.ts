import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import type { DiscoveryScanRecord } from '../types/discoveryScan.ts'
import { discoveryScanManifestUrl, discoveryScanPage } from '../utils/discoveryScan.ts'

const record: DiscoveryScanRecord = {
  name: 'search-tools', description: 'Explore public documents', repository: 'Example/plugins',
  package_path: 'packages/search', revision: 'a'.repeat(40), version: '1.0.0', components: { extensions: 0, mcp: 0, skills: 1 },
  manifest_digest: `sha256:${'b'.repeat(64)}`, tree_digest: `sha256:${'c'.repeat(64)}`,
}

describe('saved scan browsing', () => {
  it('searches names, descriptions and repositories case-insensitively', () => {
    const other = { ...record, name: 'other', description: 'Write code', repository: 'Other/code' }
    for (const query of [' SEARCH ', 'PUBLIC DOCUMENTS', 'example/PLUGINS']) {
      assert.deepEqual(discoveryScanPage([record, other], query).records, [record])
    }
    assert.equal(discoveryScanPage([record, other], 'missing').total, 0)
    assert.deepEqual(discoveryScanPage([record, other], ' ').records, [record, other])
  })

  it('bounds pages, preserves order and counts filtered results before paging', () => {
    const records = Array.from({ length: 65 }, (_, index) => ({ ...record, name: `package-${index}` }))
    const first = discoveryScanPage(records, '', 1)
    const last = discoveryScanPage(records, '', 99)
    assert.deepEqual(first.records, records.slice(0, 30))
    assert.deepEqual(discoveryScanPage(records, '', 2).records, records.slice(30, 60))
    assert.deepEqual(last, { records: records.slice(60), total: 65, page: 3, pageCount: 3 })
    assert.equal(discoveryScanPage(records, '', -1).page, 1)
    assert.equal(discoveryScanPage(records, '', Number.NaN).page, 1)
    assert.deepEqual(discoveryScanPage(records, 'package-64', 3), { records: [records[64]], total: 1, page: 1, pageCount: 1 })
    assert.deepEqual(discoveryScanPage([], ''), { records: [], total: 0, page: 1, pageCount: 1 })
  })

  it('links the exact immutable manifest and encodes path segments', () => {
    assert.equal(discoveryScanManifestUrl({ ...record, package_path: '' }), `https://github.com/Example/plugins/blob/${record.revision}/plugin.json`)
    assert.equal(discoveryScanManifestUrl({ ...record, package_path: 'packages/tool #?%/日本語' }), `https://github.com/Example/plugins/blob/${record.revision}/packages/tool%20%23%3F%25/%E6%97%A5%E6%9C%AC%E8%AA%9E/plugin.json`)
  })

  it('rejects non-immutable revisions, unsafe repositories and ambiguous paths', () => {
    assert.equal(discoveryScanManifestUrl({ ...record, revision: 'main' }), null)
    for (const repository of ['https://evil.test/repo', 'owner/repo/extra', '../repo', 'owner/repo?redirect=x']) {
      assert.equal(discoveryScanManifestUrl({ ...record, repository }), null)
    }
    for (const package_path of ['../plugin', 'a/./plugin', '/plugin', 'a//plugin', 'a\\plugin', 'plugin\n']) {
      assert.equal(discoveryScanManifestUrl({ ...record, package_path }), null)
    }
  })
})
