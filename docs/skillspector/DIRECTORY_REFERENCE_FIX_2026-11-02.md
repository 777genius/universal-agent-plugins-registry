# Directory reference accuracy (SkillSpector v2.13.1, issue #402)

## Verified baseline

- Pinned upstream: `NVIDIA/SkillSpector@f3b25697d76256998ca9d42c198d256258d4c035` (v2.13.1).
- daisyUI at `saadeghi/daisyui@bf3bac3a397b543e55641ecb2d60a2ed961f09ec`, `skills/daisyui/SKILL.md:28` links to `./components/`. Its bounded file inventory includes `components/accordion.md` and other descendants. Scanner currently reports `missing`/`reference_missing` for the directory, although 73/73 files were inspected.
- Upstream main added a general `uninspected` result but also introduced `complete_with_caveats` and other incompatible differences. Never silently track main or relax report completeness.
- Registry v3 and UAP landing strictly validate reference status and target-path invariants. Any producer change must be coordinated with both consumers.

## Decision: minimal, explicit, temporary scanner maintenance patch

1. Keep upstream v2.13.1 SHA and locked dependencies. In a deterministic pre-scan step, apply a **small exact-anchor patch** to its resolver and ledger builder; fail closed if the pinned source differs.
2. Only treat an **explicit directory destination** as present if an in-scope descendant is already in `known_paths`, the scanner's bounded acquired inventory. No filesystem traversal, symlink following, executable evaluation, second source download or scanning extra files.
3. Mark `status=uninspected`, `target_path=<canonical directory>`, `disposition=partial`, plus a `referenced_uninspected` ledger event. Do **not** call a directory analyzed or complete; absent directories stay `missing`; references outside the root stay `rejected`. Do not hide unresolved runtime dependencies.
4. Include a versioned patch marker in the static scan profile identity. Old evidence remains historically visible; it must not impersonate a current scan under patched semantics.
5. Extend Registry schema/normalizer/contract and UAP's strict browser decoder together. The raw scanner report digest and evidence must be preserved; UI only renders it, never reclassifies it.

## Acceptance: reviewer lenses

**Security:** Exact pinned-code anchors and patch provenance; if inventory lacks descendants, preserve missing; reject traversal, encoded traversal, symlink-only references and prefix collisions. No new scanner execution capabilities or network credentials. Even the directory **with** inspected children remains a partial scan.

**UX:** Explain that the linked folder exists in the inspected bundle but directory-wide behavior is not necessarily understood. Distinguish `referenced_uninspected` from genuine missing files, and never increase the "fully checked" count for this case.

**Operations:** Do not raise GitHub Actions resource budgets or reset scanning history. Prior report identities remain historical; promote with tested consumer compatibility before publication. Track daisyUI and Cloudflare separately from still-pending n8n/Phoenix scan coverage.

## Gates

- Deterministic patched-resolver and scanner CLI regression: existing folder, missing folder, prefix sibling, omitted-inventory folder, traversal and symlink safety; raw status and coverage ledger.
- Registry unit tests, JSON schema, old history compatibility, workflow pin/provenance validation.
- UAP decoder fixtures, rejects falsely complete evidence, browser E2E.
- Code review (logic, security, operations), latest-head CI and publication E2E for exact merge SHA.
- Do not close #402 until production daisyUI and Cloudflare evidence has actually been re-scanned and verified.

## Out of scope

No blanket "all scanned" claim, no suppressing missing-reference findings, no baseline rewrites, no changes to content safety heuristics or unbounded scan concurrency. Upstream fork/merge is not available through the connected account; this maintenance patch is removable when a compatible tagged upstream scanner is released.
