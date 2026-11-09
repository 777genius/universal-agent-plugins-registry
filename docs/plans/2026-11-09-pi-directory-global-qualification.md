# Pi global Directory compatibility: scoped qualification and safe publication

Date: 2026-11-09. Status: Draft / qualification required. Owner goal: Pi Skills/MCP should work with compatible packages across the whole catalog, not just native-extension-only packages.

## Findings (from source and pinned releases)

- The published UAP CLI 0.1.102 has Pi user and project Skills, stdio/Streamable HTTP MCP, and native extension adapters. SSE and generic app components are **not** Pi-compatible.
- Current `registry/directory.json`: 31 products, 37 active distribution/release policies, **0 of 37 include Pi**. All 37 have Skills or MCP (none is extension-only). Context7 has both `upstash/context7` (HTTP OAuth) and `777genius/context7` (local stdio) active, each missing Pi.
- The registry source and generated snapshot schemas, builder's `CLIENT_IDS`, the publication validator, legacy mirror site, and CI's fixed catalog matrix also currently lack Pi.
- **Compatibility blocker:** The existing release-readiness workflow pins CLI **0.1.89**. Its directory reader's `validClient` calls `domain.IsSupportedClient`; that binary has no Pi. Adding `pi` to a shared signed v1 snapshot would cause 0.1.89 clients to reject the entire snapshot, not merely skip Pi. Do not publish such a snapshot without an explicitly qualified compatibility/migration decision.

## Intended behavior / strict scope

1. Keep the unchanged Agent Plugins 1.0 manifest contract. Pi is a **target capability** for eligible Skills and supported MCP transports, not an all-packages success promise. Deny unsupported SSE/apps, missing mandatory components and client-native trust as before. Local and pinned Git installs remain independent of Directory.
2. Qualify Pi **without model tokens** on real public 0.1.102 and the immutable active packages: representative stdio (community Context7), Streamable HTTP (upstream Context7 and a remote package), skills-only (Marketing Kit), and extension-only positive/negative controls. Check user/project isolation, add→info→update→repair→remove, idempotence, foreign-file preservation and expected auth_pending. Real model login/OAuth is not claimed.
3. Produce source-based coverage for each of the **37 active release policies**. Only add a Pi target for a pinned package with verified compatible mandatory components and valid acquisition. Authentication must come from source/transport review; unknown is preferable to false `not_required`. Do not mutate historical policy bytes or revocation and never fabricate evidence.
4. Before amending published target policies, verify old-reader compatibility with the **actual pinned 0.1.89 CLI**, newest public CLI, and site. Maintain signed immutability and anti-rollback. If compatibility cannot be preserved within Directory v1, do **not** silently force a breaking signed snapshot; document migration choices and expose safe exact-pinned-source Pi installation as an explicit separate user choice, not an alias policy bypass.
5. Update the canonical client identifiers, Schema 1 allowlists, preview/builders, docs and publication acceptance matrix **together**; no stale positive `pi` badges in the website before the actual signed sequence has been published. Do not add Directory v2, alternate signature schemes, a second installer engine or feature flags.
6. Run all existing builder unit/schema/static tests plus exact signed candidate readiness on published source and physical client tests. Keep PR Draft and protected signing/promotion approvals intact. After published sequence, verify CDN and product site mirror/selector against exact signed snapshot, with no invented activation.

## Verified checkpoint (2026-11-09)

- Published UAP 0.1.102 with native Pi 1.5.0 passed 18/18 representative user/project lifecycle cases on Linux/macOS/Windows: [GitHub Actions evidence](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/42657104676).
- Source inventory on Linux: **35 of 36 eligible active policies planned**, **one suspended distribution excluded**; `marketing-kit` **refused** because its `hubspot-crm@0.1.0` signed dependency is not admitted for Pi. Treat this as a failed catalog gate, not an install PASS. See [per-policy JSON artifact](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/42661240785/artifacts/13694512188).
- The inventory now covers both user and project scopes on all three runner OSes; pending CI results are evidence to inspect, not proof of completion.
- Runtime remediation npm audits for Firebase/HubSpot are genuine independent security failures, not Pi successes; no waiver or new signed target is authorized by this checkpoint.

## Acceptance gates

- Direct-source Pi representative lifecycle across three OS plus all source-policy user/project planning on each OS. Record each refusal (not a PASS), exact source pins and receipts, and deliberate suspended-distribution exclusion.
- Registry generator and 1.0.89/1.0.102 readers handle candidate per documented migration decision; all 37 active policy changes have real validated coverage.
- Exact head CI, independent review, protected candidate/signing/promotion workflow, signed sequence + Pages feed, UI and post-merge E2E successful. Merely passing schema tests is insufficient.

## Estimates and risk

| Workstream | Complexity /10 | Risk /10 | Approximate delta |
| --- | ---: | ---: | ---: |
| Direct pinned Pi lifecycle tests | 5 | 4 | 200–500 LOC |
| Canonical schema/client list + builder | 3 | 5 | 50–160 LOC + generated data |
| Readiness matrix + conservative policy | 7 | 8 | 250–700 LOC, up to 37 policy records |
| Signed rollout and compatibility acceptance | 8 | 9 | Mostly evidence/CI, not novel product code |
| Documentation/UI parity | 2 | 2 | 50–200 LOC |

Clean Architecture / SOLID / DRY. The central invariant is that signed install authority never follows an unqualified UI label.
