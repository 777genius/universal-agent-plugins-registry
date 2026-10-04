export interface DiscoveryScanRecord {
  name: string
  description: string
  repository: string
  package_path: string
  revision: string
  version: string | null
  components: { extensions: number, mcp: number, skills: number }
  manifest_digest: string
  tree_digest: string
}

export interface DiscoveryScan {
  schema_version: 1
  source_run: number
  source_commit: string
  observed_at: string
  scan_complete: false
  validation_payload_digest: string
  records: DiscoveryScanRecord[]
}
