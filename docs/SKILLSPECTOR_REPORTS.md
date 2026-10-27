# SkillSpector catalog reports

The landing site's Plugins and Skills lists display informational static results
from SkillSpector beside the existing LintAI assessment. These results do not
change installation policy or the signed Directory, Discovery, or Security feeds.

## Automatic discovery

`SkillSpector static reports` runs every six hours, when its implementation or
registry inputs change on `main`, and on manual dispatch. It reads up to 50 public
all-time catalog pages and 10,000 listing candidates. Public GitHub repositories
are resolved to immutable commits. Each provider name must match a unique
declared frontmatter name in an actual `SKILL.md`; listing slugs are not guessed
directory names. Root skills are supported.

The checked-in `registry/skillspector-selection.json` remains a reviewed seed,
including the existing 128 roots. New plugin skill roots come from exact published
sources in `registry/index.json`. A plugin report covers selected skills, not all
components of that plugin. A verified current subject supersedes its older seed;
transient discovery failures retain previous immutable selections. MCP-only
packages have no skill root for this scanner.

Discovery emits a generated `selection.json` and `coverage.json`. The summary
records observed listings, explicit bounds, resolution diagnostics and reusable
repository/name resolution results. Unchanged revisions and name hints can reuse
their previous resolution. Unsupported publishers, ambiguous or missing names,
unavailable repositories, invalid documents and budget limits stay explicit.
A complete catalog browse does not mean all its skills were resolved or scanned.
The generated selection is capped at 10,000 roots and passed unchanged through
every scan and publication job.

## Bounded background scanning

Eight partitions each attempt at most 128 skills per run. Every partition has a
35-minute cooperative work budget within a 45-minute job, including bounded
source preparation. New and changed identities advance before scheduled retries;
older attempts receive priority within the retry queue. Results and attempt
timestamps persist between runs. A source not yet attempted is counted as
pending, with no fabricated scan record. Acquisition and scan failures produce
explicit results and retry state, so one unavailable source cannot repeatedly
hold up the rest of the queue.

Read-only jobs acquire inert Git blobs and run pinned SkillSpector 2.13.1 commit
`f3b25697d76256998ca9d42c198d256258d4c035` with
`--no-llm --format json --fail-on-incomplete`. They do not execute skill scripts,
follow transitive repositories, or apply author-provided suppressions. Static
dependency checks can contact OSV; this is not an offline profile. No model
credentials are needed or passed to the scanner.

Per-skill limits remain 512 files, 4 MiB of input, a 60-second scanner deadline
and 8 MiB of scanner output. Each public record retains at most 32 findings and
16 errors, with the full finding count and an explicit truncation flag. The v2
profile reuses complete and partial results for seven days and retries errors
after one day. Reuse requires the same immutable source identity, scanner and
profile. Carried records retain their original scan date and content digest;
publishing a fresh manifest does not make an old scan fresh. The per-run limits
mean 1,024 is the maximum number of fresh attempts, not a guaranteed number of
completed analyses.

## Publication and UI

A read-only assembly job verifies all partitions, the generated selection,
scanner/profile, timestamps and coverage counts. A separate main-only job
validates that artifact again and atomically publishes a v2 manifest,
content-addressed repository shards and bounded progress data on the existing
`skillspector-reports` branch. It preserves the legacy v1 report and the previous
generation of shards. Publication rejects stale source commits, older reports
and non-fast-forward races. It never runs on pull requests or manual dispatches
from other branches.

The fixed v2 entry point is `reports/skillspector/v2/index.json`. Its 4 MiB
manifest contains at most 10,000 shard descriptors and explicit selected,
reported and pending counts for up to 10,000 roots. Each repository shard holds
at most 256 records and 8 MiB. Large repositories split into several shards;
content-addressed paths and SHA-256 identify their exact bytes. Selection and
retry data support the next background run and are not downloaded by the site.

The site shares its manifest and shard cache across both catalogs. It fetches
only repositories needed by mounted cards, with at most four shard requests in
flight, and verifies bytes, digest, scanner/profile and record identity. A failed
shard affects its repository's state. Until v2 is first published, only a missing
v2 manifest (HTTP 404) permits fallback to the unchanged legacy v1 report.

Loading, unavailable, incomplete and failed checks stay distinct. An absent
assessment in an available repository report remains neutral as “Not checked.”
Plugin cards without skills omit the indicator. Results older than seven days
or from a different plugin revision are historical. Standalone catalog listings
do not provide an immutable source revision, so their matched reports remain
explicitly historical even when recently scanned. Findings are heuristics for
review; an absence of findings is not a safety guarantee.

## Verification and rollout

Manual workflow dispatch on a feature branch with `discovery_pages=1` and
`maximum_attempts=8` provides a small real integration run. It exercises
discovery, immutable acquisition, the actual scanner, partition assembly and
publication validation, and cannot publish. Scheduled and main-push runs use
50 pages and 128 attempts per partition. Independent review and repository CI
precede merge. Production verification checks actual public data and live
desktop/mobile rendering in addition to deterministic browser fixtures.

The paired UAP `landing/scripts/skillspector-live-smoke.mjs` is explicitly enabled
with `UAP_E2E_LIVE_SKILLSPECTOR=1`. It checks the deployed site, real manifest,
shards and catalog APIs without interception, including pinned finding links.

Run the focused Python suite with the repository's pinned dependencies:

```sh
python3 -m unittest discover -s tests -p 'test_skillspector*.py'
```

The legacy generator and validator remain available for v1 compatibility tests.
The new command entry points are:

```sh
python3 -m scripts.discover_skillspector_sources --help
python3 -m scripts.skillspector_coverage scan --help
python3 -m scripts.skillspector_coverage merge --help
python3 -m scripts.publish_skillspector_coverage previous --help
python3 -m scripts.publish_skillspector_coverage check --help
python3 -m scripts.publish_skillspector_coverage publish --help
```

Publication uses only the literal repository and data branch defined in its
script. A contents-write credential is enabled only in the isolated publication
step; discovery and scanner jobs receive no write credentials.
