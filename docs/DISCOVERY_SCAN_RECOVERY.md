# Discovery scan recovery

Discovery acquisition and inert package validation are separate jobs with
independent bounded budgets. Signing and publication remain separate and accept
only a complete, schema-checked candidate. No package code is executed.

## What survives a failure

- Acquisition writes `acquisition.json` atomically after completed search
  partitions and partition splits. A partial checkpoint retains the remaining
  queue, but cannot be used as a complete search result.
- Validation writes `validation.json` atomically after completed repositories.
  Only results bound to the same immutable source and package inputs can be
  reused. A repository scan error must be retried, not cached as success.
- Both jobs upload their checkpoint with `always()` after the bounded build
  step, including after a step timeout. The job budget reserves additional time
  for this upload. Runner loss, cancellation or the overall job timeout can
  still prevent upload; only an artifact confirmed in GitHub is durable.

Artifacts are immutable, attempt-specific and retained for seven days.
Checkpoints may be resumed for at most 24 hours; retention is not a freshness
extension. Original observation time is preserved, not rewritten to look new.
They contain scan metadata and validated records, not tokens or package trees.

## Minimal retry

Inspect the exact run, its failed job and checkpoint artifacts with `gh` first.
Use `gh run rerun RUN_ID --failed` for a failed acquisition or validation job.
Do not dispatch a new full scan or rerun all successful jobs.

A rerun uses only unexpired checkpoint artifacts from an earlier attempt of
that same run. It selects the highest earlier attempt by name and immutable
artifact ID. There is no cross-run checkpoint import. The builder rejects
incompatible, corrupt, partial-for-validation or stale inputs.

If acquisition already succeeded, GitHub's failed-job rerun preserves that job
and validation downloads its exact artifact ID. It does not repeat code search.
On a validation retry, repository metadata is resolved again and only matching
completed validation results are reused. Previous last-known-good bytes are
authenticated again from the exact acquisition ledger commit.

An incomplete candidate is a successful scan step with `complete=false`, followed
by a deliberately failing report job. Rerunning that report alone does no work.
Inspect diagnostics before explicitly retrying the validation job by its job ID.
Candidate artifacts are also attempt-specific, so retry never overwrites one.

Signing failures are not scan failures. Recheck ledger/CAS state and retry only
the unproven publication phase when safe. A same-feed supersession is not
permission to publish a competing snapshot. Existing issuer, signing,
completeness, drop-guard and append-only rules are unchanged.

The production run `36844656131` predates checkpoint support. It timed out after
five hours and retained only publisher identity, not its 6350 candidate paths.
Those search results cannot be recovered from the aggregate progress logs.
The published last-known-good feed was not replaced by that failed scan.

Related: registry issue #328 remains open. Resumable scan recovery does not prove
the separate integrated approval-wait longer than 72 hours acceptance scenario.
