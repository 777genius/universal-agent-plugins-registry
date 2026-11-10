# Marketing Kit: complete Copilot shared-backend authorization

Date: 2026-11-10. Scope: review Directory v1 source, bounded saved-dependency qualification, deterministic preview, regression tests. No new client engine, keys, signing, or bypass.

## Proven root cause

The protected Directory signed snapshot 45, staged by publication `42888897655`, differs from deployed snapshot 44 in **one** distribution: the active Marketing Kit release 1 policy adds `copilot` but not `vscode`. Public UAP CLI `0.1.91` calls `directoryEligibilityTargets`, which expands `BackendSiblings(copilot)` to include `vscode` because both share the `github-copilot` backend. Consequently `releaseEligibility` rejects the root's six-client saved `add`: `incomplete_targets` for the missing sibling. The protected [readiness attempt](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/42888897655) failed at `managed:add` with `directory_refused`. The signed dependencies already authorize both Copilot (managed) and VS Code (prepared), so only the root policy is incomplete.

This is a policy-contract bug, **not** a reason to remove shared-backend verification, treat prepared VS Code as installed, or change vendor/CLI runtime behavior.

## Scoped fix

1. Add the exact `vscode` companion entry (authentication `required`, `scopes:[user]`, `delivery:prepared`) immediately after `copilot` in the Marketing Kit source policy. Retain existing six actual saved-install targets, all release identities and dependencies.
2. In the independent managed acceptance case, distinguish **seven signed policy grants** from **six requested saved-install clients**. Check the companion delivery and the same sibling authorization in every required dependency, but never claim actual VS Code native activation. The policy coverage of this prepared companion is **policy metadata only**; the real Copilot native lifecycle still needs its own run.
3. Update deterministic review-preview and narrowly scoped tests to catch an otherwise apparently valid Copilot-only policy. Keep legacy five-client snapshots supported, and reject wrong delivery/auth/scope, unrelated target expansions, missing siblings and forged saved action receipts.
4. Run current-head Registry/validate/CodeQL/Pages/readiness tests and independent review. After merge, **protected publication must supersede staged signed sequence 45** with a reviewed new sequence; never mutate the already signed 45 snapshot.

## Mandatory gates and publication boundary

- Released CLI 0.1.91's exact `BackendSiblings`/Directory eligibility semantics and every pinned dependency source verified in tests.
- Legacy deployed 44 remains immutable; previously signed 45 remains an immutable staging record. Its current failure is real and must not be reclassified as passing.
- GitHub's protected `directory-publication` environments must authenticate a legitimate supersession of `publication_id=42888897655, sequence=45`; only then can a newer candidate be signed and checked for production rollout. No hand-edited ledger, direct ref update, implicit `resume` of faulty 45, credential forwarding, or audit waiver.
- Before closure: protected publisher runs fresh saved Marketing Kit Copilot six-target E2E and fixed catalog matrix, signs and deploys the corrected sequence, verifies production marker/latest and public CLI resolution. Until then merge != production E2E.
- Keep separate modern Pi feed #451 and UAP #837 independent; no Pi grants are introduced by this Marketing Kit fix.

## Reviewer passes

- **R1 functional:** Copilot backend requires prepared VS Code policy, but target selection remains six; inspect all dependency policies.
- **R2 safety:** legacy five-client source remains accepted; incorrect/absent sibling and extra targets are denied, not ignored; no native VS Code claim.
- **R3 release:** source output determinism, immutable signed 44/45, explicit protected supersede/approval, post-deploy consumer verification.
