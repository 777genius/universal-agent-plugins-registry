# SkillSpector catalog reports

The landing site's Plugins and Skills lists display informational static results
from SkillSpector beside the existing LintAI assessment. These reports describe
bounded inspection of immutable skill roots. They do not certify packages,
change installation policy or the signed Directory, Discovery, or Security feeds,
or establish installation, activation, OAuth, MCP health, or runtime behavior.
The detailed evidence contract is in [Report v3](skillspector/REPORT_V3.md).

## Automatic discovery

`SkillSpector static reports` runs every six hours, when its implementation or
configured registry inputs change on `main`, and on manual dispatch. Discovery
combines three sources:

- The currently valid signed Directory publication supplies the exact published
  plugin distributions displayed by the Directory.
- The currently valid signed community Discovery publication supplies package
  roots, immutable revisions, availability, expected skill counts, and package
  tree and manifest digests. Both publications are verified against their pinned
  trust keys before their source identities enter discovery.
- The public skills.sh catalog supplies at most 50 all-time listing pages and
  10,000 listing candidates. GitHub repositories are resolved to immutable
  commits. Provider names and explicit path hints must resolve to actual bounded
  `SKILL.md` documents; slugs are not guessed directory names. Root skills are
  supported.

The Directory takes precedence when both signed feeds identify the same
repository and package path. A different revision is never made current merely
by deduplication. `registry/skillspector-selection.json` remains a reviewed
bootstrap, and a verified current subject supersedes its older seed. Transient
discovery failures retain useful previous immutable selections as historical
evidence.

For a plugin, discovery inventories only immediate `skills/*/SKILL.md` roots
under its published package path. The scanner later acquires each selected
skill's complete subtree, including its helpers. A plugin report covers those
skills, rather than all package components. A package explicitly without skills
is `not_applicable`; an unavailable or unresolved package is not treated as
skill-free. Verified roots from a partially resolved package may be scanned
while its inventory remains incomplete. If enumeration exceeds the signed
expected count, the larger denominator and count-mismatch reason remain visible.

Cold plugin inventory groups packages by repository and exact revision, using
at most eight acquisition workers. A complete inventory is reusable only at the
same pin and resolver version; community reuse also requires matching signed
skill counts and package tree and manifest digests. Failed or incomplete
inventories are retried. When community packages are present, the catalog crawl
gets a bounded subdeadline. Plugin inventory then runs first within half the
remaining resolution window, leaving the rest for standalone resolution. A later
API backoff cannot erase completed inventory. Actually started cold groups
persist in scheduling history, so untouched groups get their turn ahead of
previously attempted groups.

Discovery emits a generated `selection.json` and `coverage.json`. The latter
records source publication identities, listing and package resolution states,
explicit bounds, diagnostics, selected roots, and reusable resolution results.
Unchanged standalone revisions and name hints can reuse validated resolution.
Unsupported publishers, ambiguous or missing names, invalid documents,
unavailable repositories, and exhausted budgets remain explicit. A complete
catalog browse does not mean every listed skill was resolved or analyzed.

V3 bounds the selected skill inventory, combined plugin inventory, plugin states,
plugin coverage rows, and cold-group scheduling history at 20,000 each. Source
resolution states may reach 30,000 because listing observations coexist with
selected roots outside that catalog. The listing bound remains 10,000. Exceeding
the selected-root capacity fails discovery with the candidate count and retains
the previous publication; it does not silently discard a tail. These global
bounds do not raise per-package document, file, shard, or byte limits.

## Bounded background scanning

Normal runs use eight partitions, each attempting at most 128 skills within a
2,100-second cooperative work budget and a 45-minute job. Discovery has its own
1,200-second budget. The scan queue rotates through separate new, retry, and
changed lanes. Matching completed records do not re-enter the queue simply
because time has passed. Eligible retries carry explicit next-attempt times;
changed source or analysis identities need new evidence. A root that has not
been attempted remains pending, with no fabricated scan record.

Results, exact-source attempts, bounded attempt history, and the queue cursor
persist between runs. Evidence reuse requires the same immutable source,
scanner, and declared analysis profile. Complete matching v3 results have no
seven-day expiration. Carried records retain their original scan date and tree
digest; a new manifest timestamp does not make them freshly scanned. Historical
results may remain visible while their current target waits for analysis.

Read-only jobs acquire inert Git blobs and run pinned SkillSpector 2.13.1 commit
`f3b25697d76256998ca9d42c198d256258d4c035` with
`--no-llm --format json --fail-on-incomplete`. They do not execute skill scripts,
follow transitive repositories, or apply author-provided suppressions. Static
dependency checks can contact OSV, so this is not an offline profile. Model
credentials are not passed to the scanner. Repository acquisition and skill
preparation are bounded separately, with a 120-second preparation allowance.

| V3 analysis profile | Input files | Input bytes | Per-artifact analysis | Internal workflow | Scanner process |
| --- | ---: | ---: | ---: | ---: | ---: |
| `static-standard-v3` | 512 | 4 MiB | 30 seconds | 45 seconds | 60 seconds |
| `static-extended-v3` | 2,048 | 16 MiB | 90 seconds | 150 seconds | 180 seconds |

Worker admission reserves enough remaining time for the intended profile.
Unstarted work is deferred without inventing a failed attempt or shrinking its
profile. Scanner output and diagnostics remain bounded at 8 MiB each.

Partial and failed results receive cause-based retry state. Standard-profile
resource limits can schedule an extended attempt; exhausting the extended
budget stops escalation. Transient acquisition, network, and OSV failures use
15-minute, one-hour, and four-hour backoff, subject to a maximum of four attempts
per exact analysis identity. Persistent parser, missing-reference, unsupported
content, and similar limitations remain blocked until the relevant identity
changes. Raising a deadline does not claim to resolve such limitations. The
maximum of 1,024 attempts per normal run is a ceiling, not a guarantee of that
many completed analyses.

## Evidence and coverage

V3 records bind repository, immutable revision, selected root, whole-tree digest,
scanner, and profile. Execution state, exit code, measured acquisition/analysis
durations, analyzer coverage, and content findings remain separate. Findings
retain IDs, evidence, positions, occurrences, and grouping fingerprints; upstream
coverage findings and reference diagnostics remain available as coverage context.
Grouping does not merge distinct evidence merely because its displayed title
matches. Finding counts distinguish raw occurrences, content signals, and
displayed groups. Bounded evidence truncation is explicit and keeps a report
partial. Newly normalized automated findings default to `unreviewed`; exact
registry review annotations may mark known false positives. Severity is not
human confirmation.

A missing reference alone does not establish whether a file is defective,
generated later, provided by an installed dependency, or supplied by a caller's
project. Its retained path, excerpt, and analyzer context support review without
inventing runtime conclusions. Old records keep their actual status and original
analysis identity; unknown historical timings are not filled in.

Discovery resolution is separate from analysis progress. For the selected
population and each plugin, coverage satisfies:

```text
selected = complete + partial + error + pending
reported = complete + partial + error + stale
stale <= pending
```

Historical evidence counts as a report while its current target remains pending;
it does not count as current complete analysis. Pending roots are neither failed
nor completed scans. An absent assessment in an available report remains neutral
as “Not checked.”

## Publication and UI

A read-only assembly job verifies every partition, the generated selection,
scanner and profiles, timestamps, retry state, and coverage counts. A separate
main-only publication job has contents-write permission and validates the exact
artifact again before passing `GITHUB_TOKEN` to the publisher command. It
publishes the v3 manifest, content-addressed repository shards,
selection, discovery summary, and bounded attempt state to the existing
`skillspector-reports` branch. Controlled regression artifacts cannot replace
the catalog publication.

The current entry point is `reports/skillspector/v3/index.json`. Its limits are
independent of the 20,000-root inventory:

| Data | Bound |
| --- | --- |
| Manifest | 16 MiB; at most 10,000 shard descriptors |
| Repository shard | 8 MiB and at most 256 records |
| Referenced shards in aggregate | 256 MiB |
| Generated selection | 32 MiB |
| Attempt state | 64 MiB |
| Discovery summary | 16 MiB |
| Worker artifact | 32 MiB |

Large repositories split into multiple shards. Content-addressed paths and
SHA-256 identify their exact bytes. The publisher preserves supported v1/v2
files byte for byte and the previous v3 manifest's shards alongside the new
generation. It creates only the filtered report tree, with bounded blob staging
and immediate-child tree writes. For each assembly prefix, the tree POST must
return the expected Git SHA; a nonrecursive GET then verifies that SHA, an
untruncated listing, and every expected entry before the object can be reused as
a prefix.

Publication rejects obsolete source commits and older report timestamps. After
uploading objects, it checks `main` again and performs a single non-force ref
update; a non-fast-forward race fails rather than overwriting another result.
The workflow does not publish from feature branches or pull requests. Only the
isolated publication job has contents-write permission; analysis and assembly
jobs remain read-only.

The landing consumer reads v3 first. Only a missing manifest (HTTP 404) permits
fallback to v2, and only a missing v2 manifest permits fallback to v1. Malformed
data, integrity failures, and network errors remain visible as unavailable
reports. The shared session cache fetches findings only for repositories needed
by mounted cards, with at most four shard requests in flight, and verifies shard
bytes, digest, scanner/profile, and record identity. Selection and retry files
support background work and are not downloaded by the site.

Loading, unavailable, incomplete, pending, and historical states stay distinct.
Plugin coverage shows how many known skill roots have complete current analysis;
a partly inspected plugin cannot receive a no-static-findings status. A plugin
without skills omits the indicator. V3 standalone assessments use the published
source-resolution state and exact analysis identity, so a resolved current
standalone report can be current even though the listing itself supplies no
immutable revision. Historical identity, unresolved discovery, and differing
plugin revisions remain explicit. V3 does not impose a seven-day age cutoff.
Findings are heuristics for review; an absence of findings is not a safety
guarantee.

## Legacy compatibility

V1 and v2 publications and their validators remain available for compatibility.
Legacy v2 keeps its 10,000-root limit and original cache policy. Importing old
records into v3 preserves their source, scanner/profile, scan date, actual
status, and legacy marker as historical evidence; it does not manufacture
complete grouping, timings, or current coverage. The v3-first, 404-only fallback
supports older published data without hiding a broken current report. Legacy
command modules remain for compatibility tests; normal workflow commands use v3.

## Verification and operation

Manual dispatch on a feature branch with `corpus=catalog`, `discovery_pages=1`,
and `maximum_attempts=8` gives a bounded real integration run through discovery,
immutable acquisition, the actual scanner, assembly, and publication validation.
It cannot publish. `corpus=controlled` runs the checked-in immutable regression
corpus as an artifact and cannot replace catalog data, including on `main`.
Scheduled and normal main-push runs use 50 pages and 128 attempts per partition.
Independent review and CI precede merge; production verification separately
checks the actual published data and live desktop/mobile rendering.

The paired UAP `landing/scripts/skillspector-live-smoke.mjs` is explicitly enabled
with `UAP_E2E_LIVE_SKILLSPECTOR=1`. It checks the deployed site, real manifest,
shards, and catalog APIs without interception, including pinned finding links.
Reproducible measurements and their limitations are linked from
[Report v3](skillspector/REPORT_V3.md); they are historical evidence rather than
claims about current production coverage.

Run the focused Python suite with the repository's pinned dependencies:

```sh
python3 -m unittest discover -s tests -p 'test_skillspector*.py'
```

Current command entry points are:

```sh
python3 -m scripts.discover_skillspector_sources --help
python3 -m scripts.skillspector_coverage_v3 scan --help
python3 -m scripts.skillspector_coverage_v3 merge --help
python3 -m scripts.publish_skillspector_coverage_v3 previous --help
python3 -m scripts.publish_skillspector_coverage_v3 check --help
python3 -m scripts.publish_skillspector_coverage_v3 publish --help
```

Publication uses only the literal repository and report branch defined in its
script. Discovery and scan jobs receive no write credentials.
