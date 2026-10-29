import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { authenticationIndicator } from '../utils/authentication.ts'
import type { DistributionView } from '../types/registry.ts'

const release: Pick<DistributionView, 'id' | 'release_sequence' | 'targets'> = {
  id: 'upstream/example', release_sequence: 3,
  targets: [
    { client: 'codex', authentication: 'required', delivery: 'managed', scopes: ['user'] },
    { client: 'cursor', authentication: 'not_required', delivery: 'managed', scopes: ['user'] },
    { client: 'kiro', authentication: 'unknown', delivery: 'managed', scopes: ['user'] },
  ],
}

describe('card authentication indicator', () => {
  it('uses resolved target policy instead of contradictory product legacy hints', () => {
    const plugin = { authentication: 'none', distribution: release }
    assert.equal(authenticationIndicator(plugin.distribution, ['codex'], false).state, 'required')
    const legacyRequired = { authentication: 'oauth', distribution: release }
    const result = authenticationIndicator(legacyRequired.distribution, ['cursor'], false)
    assert.equal(result.state, 'not_required')
    assert.match(result.detail, /upstream\/example · release 3/)
    assert.match(result.detail, /cursor: no authentication required/)
  })
  it('keeps automatic detection and unresolved targets unknown', () => {
    assert.equal(authenticationIndicator(release, ['cursor'], true).state, 'unknown')
    assert.match(authenticationIndicator(release, ['cursor'], true).detail, /Select agents/)
    assert.equal(authenticationIndicator(undefined, ['cursor'], false).state, 'unknown')
    assert.equal(authenticationIndicator(release, [], false).state, 'unknown')
    assert.equal(authenticationIndicator(release, ['vscode'], false).state, 'unknown')
  })
  it('explains mixed and unknown requirements without an open-lock claim', () => {
    const mixed = authenticationIndicator(release, ['cursor', 'codex'], false)
    assert.equal(mixed.state, 'unknown')
    assert.equal(mixed.label, 'Authentication varies by agent')
    assert.match(mixed.detail, /cursor: no authentication required; codex: authentication required/)
    assert.equal(authenticationIndicator(release, ['kiro'], false).state, 'unknown')
    assert.doesNotMatch(authenticationIndicator(release, ['codex'], false).label, /OAuth/)
  })
})
