# SkillSpector: coherent plugin scans and accurate reasons

Owner goal: available Skills of a small plugin should receive scan results together wherever possible, rather than perpetually displaying 6/15 or 2/5. Published counts must be honest: absence of current scan evidence is not equivalent to safety or complete analysis.

## Reproduced baseline (published v3, 2026-11-01 18:54 UTC)

- Cloudflare bridge: 3 complete + 10 partial, no pending out of 13.
- czlonkowski/n8n-skills: 6 partial, 9 pending out of 15.
- arize-ai/phoenix plugin: 2 partial, 3 pending out of 5. Additional standalone names are ambiguous; never guess a directory.
- daisyUI: 1 partial with directory link falsely reported missing; upstream/contract issue #402.
- Global: 17,694 selected, 3,520 complete, 6,594 partial, 45 error, 7,535 pending, 1,057 historical-only. This is a bounded rolling queue, not full inventory scan each run.

## Investigation, decision and constraints

- Current workflow: 8 partitions, each max 128 attempts and 2,100 seconds, every six hours; discovery budget 1,200 s and 8 workers; same bounded acquisition limits.
- Root causes must be separated: queued but never attempted, retry-scheduled transient, deterministic parser/reference limitation, source unresolvable, and old/stale evidence.
- Single-run full inventory scan is mathematically infeasible within current budgets; changing only the UI to hide backlog is not acceptable.
- Batch coherence: when a **small identified plugin group fits available attempts** within its partition/lane, prefer starting its outstanding roots together; do not starve large packages, retries, or independent standalone roots. Avoid an extra scheduler or service; update existing fair_lane/plan_attempts with deterministic order and bounded fairness. Preserve persisted queue cursors and compatibility.
- Reuse existing valid reports. Avoid recomputation for complete matching roots, and never requeue deterministic limitations without new source/scanner/profile identities. No unbounded retries.
- Investigate directory links in NVIDIA/SkillSpector without guessing: exact path existence != content analysis. Coordinate upstream regression, schema semantics and scanner pin before declaring the daisyUI cause resolved.

## Focused implementation

1. Add red/green tests that model a small multi-Skill plugin (including 15-item n8n) versus many standalone sources; assert bounded scheduled group coherence, no starvation, exact selected/partial/pending counters, unchanged deterministic order and reproducibility.
2. Improve existing planner's selection for small groups within remaining capacity. Do not increase total worker limits or change signed evidence formats unless tested need is demonstrated.
3. Add an explicit test proving error vs permanent limit vs deferred/no attempt remain different. Validate discovery ambiguity with Phoenix candidates; do not infer an exact source.
4. Record before/after counts and per-iteration cost for n8n and Phoenix using immutable report fixtures; canary via workflow_dispatch on controlled corpus before normal publication.
5. Validate fresh report digest, source pins, signed publication, registry CI, and landing consumer compatibility. Only merge and publish with verified full CI.

## Three critical lenses

**UX critic:** An inventory count of 15 is a promise users will read as “all 15 checked.” Therefore display current, waiting and failed explicitly; schedule improvement cannot excuse dishonest labels.

**Security critic:** Repairing directory false positives by dropping warnings would forge evidence. Require traversal/symlink tests and provenance-preserving schema migration; avoid copying an incompatible upstream branch into current pinned v3.

**Ops critic:** Prioritizing one 15-skill group might starve thousands of other sources. Keep bounded fairness and a measurable backlog across lanes; do not increase runner allocations without capacity measurements.

## Out of scope

No disabling scans, no hidden pending, no forced complete classification, no dynamic code execution, no modification of source Skills, and no unrelated importer/installer changes. Refer to landing draft PR #645 for visual presentation and demo UX.