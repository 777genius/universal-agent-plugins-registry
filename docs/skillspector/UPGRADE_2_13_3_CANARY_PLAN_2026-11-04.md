# SkillSpector fork v2.13.3: pinned, fail-closed upgrade canary

## Baseline and discovered regression

- Registry production uses NVIDIA/SkillSpector **2.13.1** commit
  `f3b25697d76256998ca9d42c198d256258d4c035`, plus its existing
  `uap-directory-inventory-v1` maintenance patch.
- The unmodified upstream **2.13.3**
  (`38a1dfe93325d2f8bfcd4f8d0241eed706334915`) does **not** fix
  JSON `VERSION` reference extraction or external-path completeness.
- Hosted original comparison run
  [41918916064](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/41918916064)
  proved both original versions falsely reported `Complete` for the
  explicit `[outside script](../outside-runner.sh)` reference while preserving
  missing-executable and symlink/directory incompleteness. The result remains a
  regression; never classify that old success as accepted security coverage.
- Current **candidate** is an immutable user-owned fork SHA
  `777genius/SkillSpector@018daa3afa2fa3ad084dda251fb562c5045cb423`,
  stacked on upstream v2.13.3. The fork adds narrow JSON `VERSION`
  extraction correction and conservative `referenced_uninspected` ledger
  accounting for out-of-bundle Markdown parent traversal and local file URIs, preserving rejected
  status and no outside-file reads. Candidate is NOT yet production qualified.

## Published evidence, not promises

Published Registry snapshot at `c0ef077c3f4abc0df39054d6c3a1f7265cf5476c`
contained **2,035 SHA-256-verified shards**, **17,743** distinct records,
**5,813 Complete, 11,574 Partial, 48 Error**, and 391 selected Pending.
The 10,881 `reference_missing` Partial cohort includes many real references;
one diagnostic found only 11 strict VERSION rows in nine records. No candidate
upgrade has yet improved the published count.

## Read-only acceptance

1. Immutable real `asc-workflow` Git source at
   `7de1ef7cc831f62d205dfa589063f3831f66391b`, SHA1 blob
   `121e813665d7fe7512e4a59ad0c341b92d8d124c`; both scans
   use the **same exact unchanged inputs**, no LLM and strict incompleteness.
2. Verify source tree/path/symlink SHA-256 fingerprints before/after each scan;
   verify both scanner release strings and fork checkout immutable commit/module
   blobs. Apply precisely the same vetted conservative directory-inventory
   compatibility patch to both scanner checkouts.
3. Reproduce production false Complete on traversal as negative baseline,
   and require the **fork** to return `Partial` with
   `referenced_uninspected`. Both must keep an actually missing executable,
   uninspected directory, external symlink and opaque input Partial.
4. Reproduce false `VERSION` reference in the old release; require the
   fork to return real `Complete` when that is the only issue.
5. Publish machine-readable comparison JSON even when a safety gate fails.
   Fail hosted CI when any fork regression is observed; do not weaken tests
   to make old raw 2.13.3 pass.

## Release/rollout gates — not part of this diagnostic PR

- Complete exact-head hosted CLI comparison, inspect artifact and independently
  review scanner+Registry+UAP findings in two critical review rounds.
- Prove producer and consumer schema compatibility, including rejected PARTIAL
  reference records and `referenced_uninspected`, without equating fully
  examined content with installation safety.
- Introduce versioned scanner/profile identity and bounded cohort rollout.
  Preserve immutable old shards, retry history, proper current/stale status
  and publication compare-and-swap. Never mass relabel already scanned records.
- Only after a safe production boundary run real 8/8 scan/assemble/publish,
  validate immutable hashes and signed references, then consumer Chromium/API
  E2E. No cancellation or duplicate expensive full scans.

**Non-goals:** blanket suppression of missing references; executing untrusted
skill scripts; falsely marking all 17k third-party Skills Complete;
unrelated UAP installation or signed-directory policy changes.
