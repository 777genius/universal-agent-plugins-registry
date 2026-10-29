# Signed community coverage continuation — 2026-10-29

Reuse the existing `fix/skillspector-coverage-20261029` work at
`1819d2b739a19b2aac04238ba122bd30ccbb831e`, comprising:

- `42f676f0c7aaf94b4d9f42abced95bebd1ecf576`: scope plugin discovery before document limits.
- `cbe4d4ad1c2af85666fff01651b0691f2bc2258d`: inventory signed community packages incrementally.
- `1819d2b739a19b2aac04238ba122bd30ccbb831e`: reserve inventory time before the catalog crawl.

The exact-head [branch workflow](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/40737846016)
completed preparation, all eight scan workers and assembly; publication was
skipped. This is prior implementation evidence, not production acceptance of
the budget correction below. The original branch remains unchanged.

## Reproduced retry boundary and correction

The standalone repository phase creates a subdeadline when community packages
are present. Its `repository_states` call checked that deadline, but the
`GitHubAPI` object's internal GraphQL retries still used the overall discovery
budget. Repeated HTTP 403 responses with `Retry-After: 120` could consume the
entire 1,200-second window before community acquisition began. No cold plugin
group was recorded as attempted, so the next run could repeat the starvation.

The initial correction scoped the API's existing work budget to the standalone
batch loop and restored the caller's budget in `finally`. Its API retry policy
and backoff remained unchanged.

The new regression uses the real API request/retry implementation, a fake
HTTP opener and clock, and inert plugin acquisition. Before the correction it
fails with ten GraphQL requests, 1,200 elapsed seconds and no community
acquisition. That correction stopped at five requests and 600 seconds, acquired
the plugin with 600 seconds remaining, emitted its verified current skill root,
and retained the standalone unavailable state. Those measurements describe the
initial correction, not the final execution order below.

Follow-up review reproduced a remaining boundary: `WorkBudget.wait` deliberately
honors the complete server delay before checking its deadline. With 90 seconds
remaining, one `Retry-After: 120` crossed both the standalone half-window and
the overall deadline, leaving no plugin acquisition despite the scoped API
budget. The final correction runs independent plugin inventory first, within
half the remaining window, then gives standalone resolution the remaining
overall budget. Completed inventory and its attempted-group history survive a
later API backoff. A plugin that consumes its half-window leaves the other half
for standalone progress. Directory-only ordering and shared backoff semantics
remain unchanged. Regression tests cover both directions and the 90/120 case.

Independent review also reproduced a combined-feed boundary: 10,000 community
packages plus one distinct Directory package can emit 10,001 plugin states,
and one Skill in each package can emit 10,001 plugin coverage rows. V3 now
bounds both arrays and persisted cold-group scheduling history at the existing
20,000-root inventory capacity. Legacy v2 keeps its 10,000 limits. Per-package
inventory, shard/file counts and byte limits keep their separate bounds.

When enumeration finds more Skill documents than the signed expected count,
the plugin denominator retains the larger count. A fixture with one valid
Skill and one invalid Skill document therefore retains two total Skills and
one selected root, with the inventory mismatch reason. Finishing the valid
root cannot make the uninspected second Skill disappear from the denominator.

Validation in the isolated worktree:

```sh
python -m unittest tests.test_skillspector_acquisition tests.test_skillspector_community tests.test_skillspector_contract tests.test_skillspector_coverage tests.test_skillspector_coverage_v3 tests.test_skillspector_discovery tests.test_skillspector_exceptions tests.test_skillspector_profile_measurement tests.test_skillspector_publication tests.test_skillspector_publication_transport tests.test_skillspector_records_v3 tests.test_skillspector_reports tests.test_skillspector_workflow_v3
git diff --check
```

The initial retry correction passed all **200 tests** in 16.498 seconds.
After integrating the publication repair and the independent boundary/count
corrections, the same complete workflow suite passed **209 tests** in 49.652
seconds. Its community suite independently passed **16 tests** in 38.204
seconds. Both diff checks passed. The test environment is the pinned publication
virtualenv prepared for this repair.

After the final plugin-first half-window correction, the same complete workflow
suite passed **212 tests** in 39.958 seconds. The new regressions first failed
against the prior implementation, then verified completed plugin progress across
a 90-second/120-second backoff boundary, standalone progress after plugin budget
exhaustion, and unchanged Directory-only order. Independent review accepted the
producer and regression changes; `git diff --check` passed.

## Rollout acceptance

1. Independently review and validate the exact integrated publication and
   community-coverage head. Merge through the repository's
   required checks and ordinary protected workflow.
2. Deploy the paired v3 consumer before producer publication: 20,000 inventory
   roots, 30,000 source states, and 20,000 plugin state/coverage rows. Consumer
   [PR 554](https://github.com/777genius/universal-agent-plugins/pull/554) already
   supplied the root/source bounds; the paired correction adds the combined
   package-array bounds. Per-package, shard, aggregate byte and request limits
   stay independent.
3. A trusted main run must acquire the signed community feed, publish its
   exact community sequence/digest and explicit package inventory outcomes,
   complete all eight workers and assembly, and atomically publish the exact
   validated artifact. Legacy report files and prior useful evidence must
   remain available. Exceeding the bounded inventory capacity must preserve
   the previous publication rather than truncate a stable tail.
4. Verify every published shard and digest with the real consumer, then check
   representative signed Directory, community and standalone source joins on
   the live site. A verified plugin without skills must remain distinct from
   an unresolved or unavailable skill-bearing source.
5. Verify continuation against the persisted snapshot: matching complete and
   permanently limited attempts are reused, due retry/new/changed work can
   advance, and untouched cold groups precede repeatedly failing groups.
   Publication success is required to retain this progress between runs.

Acceptance requires observable, bounded progress and honest source/analysis
states. Parser, missing-reference and other persistent limitations can keep
valid reports partial; 100% complete analysis is not a rollout requirement.
