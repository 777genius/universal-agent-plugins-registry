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

A read-only assembly job verifies each available partition, the generated selection,
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
| Referenced shards in aggregate | 512 MiB |
| Generated selection | 32 MiB |
| Attempt state | 64 MiB |
| Discovery summary | 16 MiB |
| Worker artifact | 32 MiB |
| Recovery acknowledgement control | 32 MiB; at most 1,024 retained run attempts and 192 total artifact dispositions per run |
| Publication preparation lease | 4 KiB |

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
`maximum_attempts=8`, and `scan_budget_seconds=300` gives a bounded real integration run through discovery,
immutable acquisition, the actual scanner, assembly, and publication validation.
It cannot publish. `corpus=controlled` runs the checked-in immutable regression
corpus as an artifact and cannot replace catalog data, including on `main`.
Scheduled and normal main-push runs use 50 pages and 128 attempts per partition.
Manual dispatch also offers finite 256/512 attempt caps with the same 2,100-second
maximum work budget; the normal default remains 128 until larger measured runs
justify changing it.
The scanner budget defaults to 2,100 seconds per partition, divided into three
700-second invocations. Each invocation resumes the validated cumulative local
checkpoint, adds at most 43 outcomes (three when the total attempt cap is eight),
and uploads a separately named immutable checkpoint artifact. The total attempt
cap remains the selected finite cap across all three invocations. Manual 300- and 600-second budgets use one invocation;
600 seconds leaves enough admission room for the full extended profile and
preparation allowance. Small catalog runs still download the existing report
snapshot and pay discovery/assembly costs; the scanner budget does not bound
that separate I/O. Controlled smoke runs avoid the prior snapshot cost.
Independent review and CI precede merge; production verification separately
checks the actual published data and live desktop/mobile rendering.

## Durable checkpoints and recovery

The scanner atomically writes an initial empty worker and replaces it after
each completed outcome, keeping the record and its consecutive attempt history
together. An interrupted replacement leaves the previous complete checkpoint.
Completed outcomes are not dependent on later source success or cleanup. The
workflow packages the last valid checkpoint after a failed scan step, uploads
it with `always()`, and allows assembly after failed scan partitions when
preparation succeeded. Assembly requires an independently supplied expected
partition count and explicit partial-worker acceptance. Missing partitions
remain pending and retain prior evidence; execution diagnostics report them.
Assembly validates both supported download layouts: a single flat four-file
checkpoint package and multiple artifact-named package directories. It builds
an explicit worker list bound to the current run, attempt and selection rather
than assuming that a single match creates a named subdirectory. Unexpected,
stale-attempt and symlink files are rejected.

A failed-job retry keeps validated prepared progress when an earlier checkpoint
has the same or a lower attempt count from an independent execution. Resume
does not acknowledge that skipped artifact. If its alternate evidence was
outside preparation's bounded window, the next normal recovery can still
reconcile its original findings; a regression verifies that an unseen warning
is retained as an explicit conflict rather than discarded, including the actual
CLI acknowledgement step between resume and the next preparation.

Strict worker discovery writes a private, bounded consumption manifest alongside
the exact worker paths supplied to merge. After successful merge and publication
validation, acknowledgement uses that manifest and independently authenticates
each matching remote ZIP. An artifact receives a receipt only when its complete
provenance, original file digests, current run/attempt/source and exact selection
match the consumed package. Earlier or same-attempt artifacts not selected for
merge receive neither an acknowledgement nor a rejection. Existing preparation
receipts and its cursor are preserved. Current-run receipts remain incomplete,
even if all currently visible artifacts were consumed: the run is unfinished and
additional uploads may become visible later. The next completed-run preparation
reconciles that evidence before closing the receipt. The private consumption
manifest is not part of the published report schema.

Each scan step has a 15-minute timeout; the 55-minute scan job reserves ten
minutes beyond all three step ceilings for setup, packaging and upload. The
cooperative 700-second budget is shorter again. A hard runner loss can still
lose work since the last remotely acknowledged slice; a local atomic file
cannot survive destruction of that runner. A completed remote upload is the
durability boundary. Artifact retention is explicitly 90 days. Recovery must
run within that window; expiration of unacknowledged artifacts is reported as
an operator error, not silently interpreted as successful delivery.

Every checkpoint package contains only the bounded original selection,
discovery summary, cumulative worker and provenance manifest. Their digests,
sizes, exact file set and regular-file types are verified. Recovery checks the
GitHub artifact archive SHA-256 independently from the internal file digests.
Archive paths, duplicates, symlinks and excess expansion are rejected, and
artifact redirects never forward the API Authorization header.

Main catalog preparation automatically walks unacknowledged canonical main
runs in the 90-day window. Each preparation reads at most five pages of 100 run
entries and replays at most eight artifact-producing runs. A published cursor
preserves the created-at anchor, page and offset, so newly arriving runs cannot
reset the walk or hide older entries beyond the first 500. After exhausting an
anchored cycle, the next preparation starts a fresh cycle for new arrivals.
Legacy runs without checkpoint packages do not fill acknowledgement storage.
The 32 MiB acknowledgement limit accommodates the serialized declared worst
case of 1,024 run attempts with 192 accepted or quarantined artifact identifiers
each, using bounded 64-bit identifiers. This covers 360 six-hourly runs over
90 days plus 664 manual/push attempts. The limit is a ceiling, not a reserved
allocation; a 400-run, 24-artifact case occupies about 1 MiB. Both oversized files
and malformed controls are rejected by strict publication validation. Reading
older valid acknowledgement caches permits a finite repair envelope of 64 MiB
and 2,048 run attempts, then compacts to the strict 32 MiB/1,024-run budget by
age, count and encoded size. The anchored cursor is preserved. Evicting an old
acknowledgement can cause idempotent artifact rechecks; it does not remove
published scan evidence or erase pending work. Downloads
have a finite 1 GiB aggregate compressed-byte budget and 128 MiB archive limit.
The read-only Actions token authenticates the actual repository, workflow,
original main branch, head SHA, event, run attempt and artifact metadata.
The producing SHA must also belong to the history of the explicit
`refs/heads/main` SHA. Exact-SHA ancestry comparisons avoid treating a separate
tag named `main` as authority to run unreviewed code.
Feature-branch artifacts cannot become production evidence after their commit
is merged. Controlled corpus and obsolete-policy artifacts are acknowledged
with explicit exclusion reasons and are never recovered as current analysis.
Malformed, expired, controlled and obsolete-policy artifacts receive bounded
quarantine reasons in the recovery status and acknowledgements. Their invalid
outcomes are excluded while independent valid artifacts continue to recover.
Transient transport failures remain failures and do not permanently quarantine
a recoverable network request.
The bounded recovery status has a separate 256 KiB limit, covering the complete
declared quarantine workload, 500 rejected run rows and a current-run retry's
additional 192 artifact rows; diagnostic size cannot abort an otherwise valid
bounded recovery batch.
The same-run preparation retry can stage up to 1,728 packages: eight prior runs
and one current run, each with at most 192 artifacts. This extra retry allowance
is included in both staging and status limits. Reconciliation diagnostics have
separate counters for equivalent executions, conflicting independent executions
and unavailable predecessors, with at most 32 source examples in total.
Recovery cursor queries allow validated percent escapes only in the query;
repository routes retain their strict path boundary. Retry logs use fixed
literal text. Terminal transport errors contain only canonical operation,
target and HTTP-status labels plus the local attempt counter; request paths,
queries, response headers, parser keys, payloads and response-body details are
never included. Exhausted transport budgets and invalid or oversized API JSON
raise a separate transport error. Unavailable API evidence defers recovery
before cursor or quarantine receipts advance; it does not classify an immutable
checkpoint as invalid. Retrying the same local plan clears unacknowledged
staging and rereads the preserved remote artifacts.

Recovered outcomes enter the new selection only through exact immutable source
identity, current scanner/policy and consecutive attempt lineage. Original scan
times and findings remain intact. A changed revision stays pending/historical.
Snapshots from one producing run/attempt must extend an exact prefix; conflicting
snapshots and untrusted or structurally incomplete retry histories are rejected.
An authenticated execution with an exact, complete, self-consistent current-epoch
history suffix can arrive before its predecessor artifact because recovery reads
a bounded window. The suffix contains the current attempt count's entries;
older policy or revision epochs may legitimately remain as a bounded history
prefix and are preserved exactly. The production history census found this
older prefix in 3,393 of 6,491 current records, so whole-history length is not
used as a substitute for current-epoch lineage validation.
Recovery preserves its actual attempt count and history, marks the evidence
uncertain, and continues independent healthy work and cursor progress. The
original report cannot qualify as complete or No remarks while this uncertainty
remains. A later actual parent can supply useful prior content after a child
acquisition error without changing the child's latest error, count or history;
the uncertainty remains until a fresh scan resolves it. A real nine-packed-run
regression exercises this window boundary and proves that the parent can arrive
in the following preparation without resetting counts or repeating a fatal
recovery loop. Separate authenticated executions can differ in timings while
producing identical normalized analysis.
Those duplicates preserve the original published scan and history, comparing
source content digest, exit state/code, coverage and findings substantively.
When independent executions disagree, recovery retains an original report with
warnings and exposes the disagreement as partial analysis with incomplete
grouping and normalization. Other original outcomes remain in their immutable
checkpoint artifacts. Diagnostics retain at most 32 examples. Recovery does not
reset scan counts or history: a bounded fresh retry preserves the existing
backoff/escalation policy, and the four-attempt cap remains exhausted once
reached.
The new valid bundle is used as the prior state by scanning and assembly, so an
acknowledged completed attempt does not run or increment again. The exact count
of uniquely recovered roots is saved in the current preparation status and
passed into final assembly's `execution_summary.recovered_sources`; it is not
copied from an older publication. Recovery state, the cursor and quarantine diagnostics
are included in the optional `recovery.json` control file after a valid merge;
the public pointer and its acknowledgements advance in one atomic publication.
Already acknowledged runs are not downloaded again. Neither recovery transport
nor assembly receives contents-write permission.

The publisher retains both obsolete-main checks and non-force report-branch
updates. Preparation records the exact observed report-branch SHA in
`publication-base.json`; assembly carries that lease into the candidate bundle.
A same-main candidate cannot overwrite a newer report assembled after its prior
snapshot, even when its generated timestamp is newer. Missing or mismatched
leases defer existing-branch publication before writes. An exact byte-identical
published retry remains idempotent. It emits a structured delivery status and Actions summary. Supersession
returns success only when the report has a validated remote acknowledgement for
its actual current run/attempt, naming `superseded_with_durable_recovery`.
Without that receipt it returns exit status 3. Publication errors return status
1, with `failed_with_durable_recovery` when a receipt exists. The next main
catalog preparation automatically retries eligible retained evidence; a branch
or controlled run cannot use this route to publish. Production success still
requires observing the public report commit and current coverage counts.

Checkpoint, plan and final report artifact names include the Actions run
attempt. Prepare/report output names are passed to dependent jobs, so a failed
job-only rerun still uses the correct original plan. A retried main scan first
authenticates and restores the latest earlier-attempt checkpoint for its exact
partition and selection; sources already recovered by a rerun of prepare are
not restored or counted twice. Same-run resume logs `restored_sources`
separately from recovered-root counts. Controlled main job retries skip
production resume both in the workflow condition and at the CLI boundary.

A path-scoped pull request canary uses the same pinned real scanner, checkpoint
packaging, assembly and publication validation with one controlled partition,
eight maximum attempts and a 300-second scanner budget. One preparation output
resolves this configuration for all downstream jobs. PR analysis runs on hosted
Ubuntu with read-only permissions, fetches no production prior bundle, and is
excluded from both direct production publication and production recovery. The
controlled corpus remains immutable.
Read-only PR canaries group concurrency by their exact commit SHA, so an
obsolete PR commit cannot hold feedback for newer changes in its queue. Reruns
of one commit stay grouped. Main and manual-dispatch runs retain the existing
ref-based serialization, `queue: max` and `cancel-in-progress: false`.

The actual controlled PR canary [run 41668642584](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/41668642584)
produced a real eight-outcome checkpoint. Its archive SHA-256 was
`befe1795f58a2b0b8bd8194a8c237a4b176db79a4f0290000706e9b1980fcfc6`.
Validating the downloaded flat archive through worker discovery, real merge and
the publisher's artifact check produced 15 selected roots: two complete, six
partial and seven pending. The same workflow shell has regression coverage for
flat and named directory layouts. Branch artifacts remain validation evidence;
this observation does not claim production publication.

Operators can inspect the workflow checkpoint artifacts, `recovery-status.json`
in the plan artifact and the published `recovery.json` acknowledgements, then
dispatch a 300/600-second main catalog scan to retry promptly. To inspect the
commands locally, run `python3 -m scripts.skillspector_recovery --help` and its
`pack`, `recover` or `acknowledge` subcommand help. A failed recovery never
deletes the earlier public bundle or remote artifacts.

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
