# SkillSpector v2.13.3 migration: bounded, evidence-first canary

## Baseline (immutable evidence)

- Current Registry scanner: NVIDIA/SkillSpector **v2.13.1** at `f3b25697d76256998ca9d42c198d256258d4c035`, with the pinned directory-reference maintenance patch.
- Upgrade candidate: upstream release **v2.13.3** at `38a1dfe93325d2f8bfcd4f8d0241eed706334915` (released 2026-11-02).
- Published Registry report commit `c0ef077c3f4abc0df39054d6c3a1f7265cf5476c`, source `6212d52ece6bcfefebb35c1420dbe694b087e9f3`.
- Validated all **2,035** actual manifest-listed shards (SHA-256, byte length and record count); **17,743** unique records. Current: **5,813 Complete / 11,574 Partial / 48 Error**; 391 selected Pending (308 stale).
- **10,881** current Partial records include `reference_missing`; **8,006** have that code as their only reported reason. **3,444** current Partial include `analyzer_incomplete`, **2,719** `static_parse_limit`; reason counts overlap.
- The new upstream releases improve some false shell/static-parser limits, but do **not** claim to solve genuine missing files, runtime-generated dependencies, opaque content or arbitrary skill execution.

## Strict scope of this PR

A read-only, no-LLM hosted CI comparison at two immutable upstream SHAs, using identical inputs, fixed process/static analyzer budgets, and true fail-on-incomplete behavior. Test control (no references), a true missing executable (must remain Partial), a JSON VERSION literal, a typed data-field table, and the immutable real asc-workflow Skill at `rorkai/app-store-connect-cli-skills@7de1ef7cc831f62d205dfa589063f3831f66391b` (verified SKILL.md Git blob `121e813665d7fe7512e4a59ad0c341b92d8d124c`). Retain JSON evidence only, no raw untrusted source or secrets.

**This PR MUST NOT change production scanner SHA, report profiles, selection, scheduling, retry policy, statuses or signed publications.** The comparison does not currently attempt to apply the production v2.13.1-only directory patch on the v2.13.3 checkout; results are therefore diagnostic, not a production-quality equivalence proof.

## Implementation/review risks

1. **Correctness (critical):** Do not call any input Complete merely because an upstream parser no longer emits `reference_missing`. Verify inspected inventory, real missing executable, symlinks, traversal, directory references and opaque inputs independently on pinned real Git sources.
2. **Safety (critical):** Scanner is static/no-LLM and never executes Skill code; check that the new release retains safe acquisition, analysis limits and no credential leakage. No suppression baselines or bypassed certificate checks.
3. **Compatibility (high):** v2.13.3 scanner and raw findings may differ. Existing v3 consumer and Registry validation have two specific current profiles and explicit scanner identity. A production change requires versioned policy + compatibility design, not silently blessing old records or globally reclassifying them.
4. **Throughput (high):** Changing profile globally may make 17k current records Outdated. Measure a bounded source cohort first, and avoid resetting historical evidence or retry state; preserve CAS and durable checkpoints.

## Next gates before any production upgrade

1. Successful exact-head hosted canary with machine-readable before/after evidence; analyze *reasons and findings*, not merely total Complete.
2. Two independent critical review rounds (correctness/false-complete; security/CAS/compatibility), fix findings and retest exact HEAD.
3. Controlled real-Git acquisition E2E with both scanners, necessary production maintenance patch compatibility, transitive/reference/opaque adversarial cases and immutable source SHA verification.
4. Version the new scanner/profile identity; coordinate Registry schema, per-source reuse semantics and UAP consumer.
5. Measured cohort rollout and real 8/8 -> assemble -> publish -> immutable shard integrity read-back -> Chromium/API E2E. No mass status suppression.

**Goal:** increase genuinely complete scans without faking status; full Complete for every third-party Skill is not a valid claim when the author ships missing/unscannable inputs.
