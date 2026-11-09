# SkillSpector: reduce real Partial and Error (fail closed)

Source of truth: immutable published v3 report `54e653bb03edea589ec9f59cf497044c79309a68`, Registry main `ff540b156c3829bb543650a549de0d5ec1cd9128`. This plan does **not** assert that zero Partial is achievable for arbitrary third-party Skills.

## Verified baseline
18,027 selected: **5,330 current Complete**, **11,759 current Partial**, **49 current Error**, 889 Pending (including 813 historical). Counts come from independently parsing all 2,043 published shards / 17,951 records, and filtering `freshness=current`.

Current Partial reasons overlap: `reference_missing` 10,726 (7,030 have that reason alone), `analyzer_incomplete` 3,407, `static_parse_limit` 2,708, `recovery_conflict` 1,780, `obfuscated_instruction_text` 807. Current Error: **34 acquisition_failed**, **11 input_limit_exceeded**, **4 acquisition_transfer_limit**. Many failed roots' exact pinned `SKILL.md` files are reachable on GitHub. Their error message `The immutable source could not be acquired completely` happens *after* the initial pinned-repository fetch; retrying `PinnedRepository._acquire` would miss the actual failure boundary.

## P0 — this PR: bounded missing-blob acquisition transport retry only
Touch `scripts/skillspector_acquisition.py`, targeted tests and this plan. Retry `git fetch --stdin` for *verified public GitHub origin* only when Git reports an explicit transient rate-limit/5xx or DNS/connectivity failure. Maximum 2 retries with a finite delay inside the existing preparation budget. Never retry offline mirrors, Git 403/404, invalid/missing source refs, changed SHA, inconsistent object bytes, oversized content, pack transfer limit, timed-out budget or untrusted remote. If any failed fetch modifies the pack inventory, fail closed rather than retry. Preserve exact blob OID checks, data bounds, existing output schema/profiles/retry/CAS/Ed25519. Existing exhausted errors do not magically become Complete; postmerge qualification is mandatory.

Acceptance: offline deterministic tests for transient→success, repeated transient→error, permanent failure/no retry, offline/no retry, exhausted budget/no retry, new pack/no retry and transfer-limit/no retry; run existing acquisition/bridge/recovery/publication tests, review, exact-head CI and actual pinned real-root canary before merge.

## P1 — separate upstream-scanner PR
The current global producer remains SkillSpector 2.13.1; v2.13.3 source-qualified nine-root cohort is independently signed and must not be silently substituted globally. On the maintained v2.13.3 development branch, classify only demonstrable *nonfile* references correctly (documented domains, configuration examples, version syntax), with adversarial tests preserving real missing scripts, commands and suspicious content. Run real no-LLM positive/negative source scans and compare findings; versioned rollout separately with independent provenance/profile, producer and UAP browser/API E2E.

## P2 — separate operational qualification
Address 1,780 recovery conflicts with provenance-preserving reconciliation, not deleting original findings/uncertainty. Requalify 26 already exhausted transient errors only by a reviewed versioned retry-policy change, never resetting attempts invisibly. For 11 oversized roots and 4 bounded transfer failures, measure and validate a finite alternative profile; impossible/unavailable sources must retain an explicit incomplete verdict. Avoid global size-cap increases without resource and attack-surface proof.

## Trade-offs (1–10)
| Stage | Complexity | Security regression risk | Expected test confidence | Approx. production LOC |
|---|---:|---:|---:|---:|
| P0 transport retry | 3 | 3 | 8 | 20–45 |
| P1 reference classification | 6 | 7 | 7 | 40–180/class |
| P2 recovery/resources/policy | 8 | 9 | 6 | 100–350/stage |

Out of scope for P0: changing findings/status/report schemas, pretending Partial=Complete, changing source pins, undocumented bypasses, disabling validation, globally switching scanners, touching signed release/anti-rollback or installation policy. An exact genuine incomplete analysis must remain visibly Partial; a genuine unreachable input must remain Error or unavailable until demonstrably resolved.
