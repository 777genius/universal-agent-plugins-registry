# Runtime dependency advisory remediation — isolated qualification

Date: 2026-11-09. Related issue: #453. Not a Directory or Pi capability change.

## Existing failure

A recent **live** three-OS npm advisory audit fails on unpublished candidate closures:
- `firebase-tools@15.34.2`: 9 advisories, including `archiver`, `glob`, `minimatch`.
- `@hubspot/cli@8.15.0`: 13 advisories, including high `follow-redirects` and nested `glob`, `minimatch`.
- Context7 passed and is intentionally **out of scope**.

The old October audit was valid only for its exact bytes and advisory feed. Never turn down thresholds or misclassify a failure as pass.

## Planned candidate and evidence steps

1. Probe stable published root versions `firebase-tools@15.35.0` and `@hubspot/cli@8.18.0`, keeping all existing reviewed overrides unless npm rejects them. This is a candidate probe, not a proven fix. Use real npm registry on GitHub-hosted Linux with scripts disabled and isolated temporary directories. Produce exact `package-lock.json`, root integrity, `npm audit` JSON and tool versions as artifacts; audit findings remain red.
2. Review the exact dependency graph and patched versions. If advisories survive, find a patch from a compatible root or minimally scoped, validated transitive override; no arbitrary version-range substitution.
3. Only after zero-audit candidate and lock reproducibility, commit each package `package.json` plus `package-lock.json`, update reviewed candidate record's root integrity, runtime lock digest, package tree and manifest digest atomically, and reverify package closure.
4. Three-OS `Runtime remediation platform qualification` must pass **every** exact-head existing check: real cold runtime setup, pinned npm signatures, advisory audit zero, MCP `initialize`/`tools/list` exact tools, no process leaks, and negative/fail-closed tests. Package versions and approval requirements remain explicit. Review security notes.
5. Do not edit signed historical releases, application auth, Pi client target policies, or producer signing/publishing permissions in this PR.

## Initial acceptance scope

One read-only GitHub Actions preparation workflow with the two exact root candidate versions, no repository mutations and no secrets. Publication is a separate protected operation after E2E. Keep PR Draft until every gate is satisfied. Avoid feature flags, migrations and duplicate engines.
