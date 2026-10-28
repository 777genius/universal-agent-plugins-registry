# Bounded Git tree publication recovery

The first production v3 artifact was produced by commit
`29550c9fc0b5703a7f241187cae2ae2592bdc823` in
[run 40686109468](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/40686109468).
Its analysis, source revisions, scanner profiles, findings, and manifest are
unchanged by this transport fix. The uploader is a separate code revision;
it does not replace the producer revision recorded in the artifact.

## Observed failure and bounded recovery

Both hosted publication attempts failed with HTTP 502. The operator verified
that all eight original inline-content staging trees existed with their exact
expected Git object identities. Repeating the final 1,297-entry, 247,164-byte
flat tree request through authenticated `gh api` also returned 502. A separate
620-entry immediate-child tree request returned 422 with GitHub's explicit
processing-timeout advice to construct the tree incrementally. This identifies
the final tree operation as the blocker; it does not establish a documented
universal API entry limit.

Two operator probes using 128-entry fresh prefixes succeeded with the exact
expected roots `a87263dbc203b626eeb67ce07555f91c4a094b6a` and
`2f8de2243da308869a7b622a4dc42f3f2d603568`. No commit or branch reference was
changed by those probes.

The v3 publisher now builds immediate-child trees from the leaves upward, with
at most 128 entries and 256 KiB per tree request. Each prefix is independently
hashed and its API response entries, modes, types, hash, and truncation flag
are checked before continuing. A `base_tree` is always a freshly created,
verified prefix. An existing subtree can be reused only when its hash exactly
matches the complete filtered subtree. The unfiltered previous root is never
used as a base. Inline-content uploads retain their 8 MiB byte budget and now
also cap each staging tree at 128 entries, so many tiny shards cannot bypass
the count bound. Report bytes and Git blob identities stay unchanged.

The v3 API transport bounds each request to 30 seconds, the full transport to
600 seconds, and retries to three attempts. Only reads and content-addressed
blob/tree writes can retry transient failures. Commit and reference writes do
not retry automatically. Diagnostics contain method, path, status, request ID,
and attempt count; they omit credentials and response/request bodies.

## Independent verification of the exact artifact

The metadata fixture contains every intended path and Git blob identity:

| Property | Verified result |
| --- | --- |
| Total files | 1,297 |
| Preserved v1/v2 files | 673, including unindexed historical v2 shards |
| New v3 files | 624, including 620 referenced shards |
| Inline-content staging requests | 8, unchanged |
| Final assembly requests | 9 |
| Largest assembly request | 128 entries, 20,546 bytes |
| Fresh incremental bases | 4 |
| Final root | `6d0b750dacc3599b04b4e3720356a91fc88f8806` |
| v3 subtree | `f83133cc8502d4f414b84d7fbb7684276bbedf49` |
| v3 shards subtree | `7d3263f92c0608d0aad7b6ea181a6323c65fb7ed` |

The test API uses native `git mktree --missing -z` to encode every prefix and
native `git ls-tree` to inspect the final files. It does not use the production
hash function as its oracle. Both the fixture test and a full offline call to
the actual publisher on the retained production artifact produced the exact
root above. The full call also verified both current-main checks, the original
baseline as the commit parent, and one non-force reference update in the fake
API. No live publication or new scan occurred in this rehearsal.

Reproduce the tree, API failure-injection, and publisher-boundary tests with:

```sh
python3 -m unittest tests.test_skillspector_publication_transport \
  tests.test_skillspector_coverage_v3 tests.test_skillspector_workflow_v3
```

The fixture is `tests/fixtures/skillspector-publication-tree-2026-10-28.json`.
The [rehearsal evidence](publication-transport-rehearsal-2026-10-28.json) records
source hashes, artifact manifest hash, request counts, and elapsed time.
The full workflow boundary suite passed 182 tests in 29.607 seconds. The new
tests also run in that existing boundary-test step.
Current-main, artifact-policy, controlled-corpus, freshness, and atomic
non-force reference guards remain in effect during operator recovery.
