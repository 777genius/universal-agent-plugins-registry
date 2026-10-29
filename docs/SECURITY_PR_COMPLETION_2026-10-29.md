# Security PR completion — 2026-10-29

## Goal and scope

Finish the open security fixes without breaking package identity, installation,
generated compatibility packages, or signed Directory history. Keep Dependabot
configured for security updates only. Do not change installer releases,
authentication requirements, client support claims, or unrelated dependencies.

## Findings

The 15 open Dependabot PRs modify individual copies of runtime locks. None
updates the complete runtime digest, package release identity, and generated
compatibility output. All currently fail the required catalog validation.
The dated September candidate copies match the old live packages, but their
historical audit and smoke observations cannot qualify a new closure.

| Runtime | Open PRs | Completion |
| --- | --- | --- |
| HubSpot | #353, #357, #371, #372, #376, #382, #384, #385 | One coherent security closure and new package release |
| Firebase | #368, #369, #370, #383 | One coherent security closure and new package release |
| Context7 community package | #364, #365, #366 | One coherent security closure and new package release |

Fresh advisory audits determine additional required fixes. Keep exact existing
root pins where compatible patched dependencies are available; prefer an
upstream security release over an incompatible transitive major override.
The independent `upstash/context7` distribution remains outside this change.

## Implementation

1. Update authoritative `plugins/<id>` runtime manifests and locks with install
   scripts disabled. Review dependency changes against actual advisories.
2. Recompute runtime lock hashes and bump each portable package patch version.
   Preserve reviewed historical runtime policies. If a root version is reused
   with changed overrides, bind the new policy to its exact lock digest.
3. Verify the published Directory signature. Bind predecessor releases to their
   actual accepted source revisions, preserve their immutable identity fields,
   and append a release and matching policy for each corrected package.
4. Regenerate registry review outputs and OpenAI compatibility packages from
   source. Preserve frozen legacy catalogs and dated audit/smoke/signature data.
5. Bind fresh qualification to the exact new source trees, runtime identities,
   and reviewed MCP server/tool expectations. Reuse the existing three-OS
   qualification harness with its isolation and credential boundaries intact.
6. Merge the successor only after review and required checks pass. Close the
   individual Dependabot PRs as superseded by that complete fix.

## Other important open PRs

- #351: refresh frozen discovery validation inputs and early tree limits onto
  current main. Preserve configurable limits and SkillSpector error contracts.
- #320: refresh Playwright package-data working directory and stale npm lock
  recovery onto current main. Preserve other reviewed launchers, current client
  policies, and immutable predecessor identity.

Each remains a separate focused PR, with targeted regression checks and a fresh
review. Integrate their changes sequentially to avoid conflicting registry
metadata or concurrent publication changes.

## Completion gates

- Exact closure audit: no known vulnerabilities for the installed dependency
  scope; review npm signatures during actual cold installation.
- Focused registry, launcher, bridge, discovery, and generated-output checks.
- Real GitHub-hosted Linux, macOS, and Windows cold installation, MCP
  `initialize` and `tools/list`, unchanged package bytes, and process cleanup.
- Required `portable-catalog` and `upstream-promotion-policy` checks, CodeQL,
  and review of concrete findings before each merge.
- Verify the merged source and the existing signed Directory publication path.
  Report authentication-dependent service calls separately from credential-free
  installation and tool-discovery evidence.
