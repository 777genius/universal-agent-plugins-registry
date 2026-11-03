# SkillSpector: prioritize the current Outdated backlog

## Evidence (published v3 snapshot, 2026-11-03)

At report commit `dea678cd92c6bf9f31557dcabaeb38840cba0a0e`, 17,742 selected roots comprise 2,509 complete, 5,487 partial, 46 error, and 9,700 pending. The pending count includes 8,531 historical reports; the other 1,169 have no retained current report. The last completed production workflow #41698092644 made 974 current attempts and published all eight partitions. It does not imply 974 new fully complete inspections.

Most current partial checks represent genuine static-analysis limitations: 4,676 retained attempt reasons are `reference_missing`. A larger scan budget or declaring these reports clean does not resolve missing referenced material. Changing the pinned scanner/profile to suppress warnings would invalidate prior compatible results and is outside this scheduling correction.

## Scope

With the same bounded per-partition attempt and wall-clock budgets, move up to half of the otherwise evenly allocated new-Skill slots to the **changed** lane when it has available historical/source-changed work. Always preserve at least 16 new admissions when that many were originally allocated, so a coherent small plugin can still fit. Keep the entire due-retry allocation and nonzero new-Skill slots. This speeds up the visible `Outdated` cohort without concealing pending work or modifying scanner evidence, source identity, policy digest, retries, durable checkpoints, or publication rules.

Do not change the default 256-attempt limit, two-hour schedule, eight worker partitions, 2,100-second budgets, or historical eligibility. The active new-policy production run #41715686633 may complete under the preceding scheduling order; only a run actually built from this change can establish its throughput.

## Verification and stop conditions

- The new regression creates 30 historical current targets, 30 new targets, a scheduled retry, and an already-current report. Under 41 slots it expects more historical refreshes, at least one new source, the due retry, no duplicate selection, and unchanged matching report reuse.
- Existing lane fairness, retry backoff, immutable-source, plugin grouping, checkpoint/resume and publication tests must remain green.
- PR CI must include a real pinned-scanner canary; merge only with passing validation/reviews. The next main production run must publish verified evidence, and its completion counts must be reported without claiming that all historical or partial sources are resolved.

This is queue prioritization, not a claim that every partial/blocked source can become fully inspected.
