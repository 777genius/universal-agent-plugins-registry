# SkillSpector production scheduling: measured cadence correction (2026-11-04)

## Baseline

- [Run #41779096019](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/41779096019): 05:24–07:58 UTC (154 min).
- [Run #41786208711](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/41786208711): 06:32–08:54 UTC (142 min), all eight partitions, assembly and publication successful.
- Published immutable report commit `db4fd15a9ade43f93e1510116a2bd86529a4906d`, generated 08:42 UTC: 17,754 selected, 5,870 Complete, 11,718 Partial, 47 Error, 119 Pending (of which 43 stale). Independently verified all 2,032 shard digests and byte counts.
- 09:40 UTC queue: #41792022664 running, #41799434029 and #41807295944 pending; one noncancelling `main` concurrency group. An hourly cron cannot make single-ref runs execute faster than their measured >2-hour wall clock.

## Change (strictly scoped)

Change scheduled cron from hourly `19 * * * *` to every three hours `19 */3 * * *`. Update only the existing cadence assertion in `tests/test_skillspector_workflow_v3.py`. Keep `workflow_dispatch`, source discovery, 8 partitions, 256 attempts each, scanner/profile SHA, checkpoint recovery, `queue: max`, cancellation policy and CAS publication untouched.

## Review and acceptance

1. Exact-head workflow contract tests, hosted Python validation, CodeQL, controlled pinned scanner scan→assemble, security review, two independent code review passes.
2. No merge until existing main production run's publication or authenticated supersession/recovery is confirmed; ensure no unacknowledged work is lost.
3. SHA-guarded squash merge; confirm scheduled workflow is deployed to `main`; verify later production run and immutable digest/read-back.
4. Live UAP consumer acceptance remains separately tracked in [UAP PR #701](https://github.com/777genius/universal-agent-plugins/pull/701).

**This improves scheduler stability; it does not reclassify Partial.** False references and other parser limits belong to [issue #413](https://github.com/777genius/universal-agent-plugins-registry/issues/413) and require real pinned canaries plus a versioned analysis-policy rollout. If measured runtimes later exceed three hours or pending backlog grows substantially, reassess capacity separately rather than blindly scheduling more overlapping runs.
