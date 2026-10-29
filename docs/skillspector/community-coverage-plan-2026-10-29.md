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

Scope the API's existing work budget to the standalone batch loop and restore
the caller's budget in `finally`. The API retry policy and backoff remain the
same. The community acquisition phase retains the overall discovery budget.

The new regression uses the real API request/retry implementation, a fake
HTTP opener and clock, and inert plugin acquisition. Before the correction it
fails with ten GraphQL requests, 1,200 elapsed seconds and no community
acquisition. Afterward it stops at five requests and 600 seconds, acquires the
plugin with 600 seconds remaining, emits its verified current skill root, and
retains the standalone unavailable state. The caller's API budget is restored.

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
