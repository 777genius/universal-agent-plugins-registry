import type { DiscoveryScanRecord } from '../types/discoveryScan.ts'

export function discoveryScanPage(records: DiscoveryScanRecord[], query: string, requestedPage = 1) {
  const term = query.trim().toLowerCase()
  const matches = term
    ? records.filter(record => [record.name, record.description, record.repository].some(value => value.toLowerCase().includes(term)))
    : records
  const pageCount = Math.max(1, Math.ceil(matches.length / 30))
  const page = Math.min(pageCount, Math.max(1, Number.isFinite(requestedPage) ? Math.trunc(requestedPage) : 1))
  return { records: matches.slice((page - 1) * 30, page * 30), total: matches.length, page, pageCount }
}

export function discoveryScanManifestUrl(record: Pick<DiscoveryScanRecord, 'repository' | 'revision' | 'package_path'>): string | null {
  const repository = record.repository.split('/')
  if (repository.length !== 2 || repository.some(segment => !/^[A-Za-z0-9_.-]+$/.test(segment) || segment === '.' || segment === '..')) return null
  if (!/^[a-f0-9]{40}$/i.test(record.revision)) return null
  const path = record.package_path ? record.package_path.split('/') : []
  if (path.some(segment => !segment || segment === '.' || segment === '..' || segment.includes('\\') || [...segment].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127))) return null
  return `https://github.com/${repository.map(encodeURIComponent).join('/')}/blob/${record.revision}/${[...path, 'plugin.json'].map(encodeURIComponent).join('/')}`
}
