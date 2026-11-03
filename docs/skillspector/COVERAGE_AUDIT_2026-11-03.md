# SkillSpector coverage audit, 2026-11-03

This audit examines the immutable [published report commit
`3c0bd61eeafb5369f62b93c6c50cee223ebfd490`](https://github.com/777genius/universal-agent-plugins-registry/tree/3c0bd61eeafb5369f62b93c6c50cee223ebfd490/reports/skillspector/v3),
produced from registry source `320c30d3a508d0c59a4a87ac36d3d5b216dff41d`
by [workflow run 41635762917, attempt 1](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/41635762917/attempts/1).
These are observations of that snapshot. A later run or publication can have different counts.

The accompanying [aggregate JSON](coverage-audit-2026-11-03.json) records exact
counts and policy identities. All 2,028 manifest-listed shards were downloaded;
their exact byte lengths and SHA-256 digests were checked against the immutable
manifest before counting. They contain 15,655 report records and total
315,862,831 bytes. No shard download or identity check failed. This census does
not claim a separate full-bundle schema validation: its integrity checks are the
manifest-to-shard byte/digest binding, followed by JSON extraction and count
reconciliation. Real scan bundles described below passed the production bundle
and publication validators separately. Raw shards are not duplicated here.

## What is pending

The selected population is 17,743 roots. It partitions into 2,119 current
complete, 4,328 current partial, 44 current error and 11,252 pending. Pending
includes 9,164 historical records and 2,088 roots with no report. Historical
evidence remains useful, but does not establish current analysis.

Discovery marks 17,631 selected identities current and 112 historical. Joining
those identities to the scan records gives the actionable denominators:

| Cohort | Roots |
| --- | ---: |
| Current selected root with historical report | 9,128 |
| Current selected root with no report | 2,012 |
| Current pending total | 11,140 |
| Historical excluded root with historical report | 36 |
| Historical excluded root with no report | 76 |
| Historical excluded total | 112 |

There are also 23 scheduled retries among current incomplete reports: 19 require
the existing extended profile, two follow transient-failure backoff, and two are
analyzer retries. A scheduled retry is admitted only when its due time and the
worker's full-profile budget allow it. The counts above do not assert that every
scheduled retry was due at the snapshot's generation time.

The other current incomplete reports are deliberately blocked or exhausted:
4,243 partial reports are blocked, 66 partial reports are exhausted, and 40 error
reports are exhausted. The 2,119 complete reports have no scheduled retry. A
change to source or analysis policy can make an otherwise settled identity
eligible again; clearing attempt history is not a valid way to create progress.

## Why records are historical

Comparison with the two scanner profile identities declared by the published
manifest explains all 9,164 historical records:

| Source revision relative to current target | Scanner/profile policy | Records |
| --- | --- | ---: |
| Same revision | Older profile | 5,110 |
| Changed revision | Older profile | 2,892 |
| Changed revision | Same profile | 1,162 |
| Same revision | Same profile | 0 |

An older profile participates in 8,002 historical records, or 87.3% of stale
evidence. Revision changes participate in 4,054, overlapping the older-profile
cohort in 2,892 cases. These are overlapping causes, not additive percentages.
This argues for preserving scanner/profile identities for orchestration-only
changes. It does not authorize relabeling old-profile evidence current. Reusing
analysis across a changed repository revision would require proof that the
entire selected root and relevant analysis scope are unchanged; that proof is
not supplied by this audit.

## Why current reports are incomplete

The denominator here is 4,372 current incomplete records: 4,328 partial plus 44
error. A record can have several reasons, so incidence counts do not partition
that denominator.

| Reason | Current incomplete records containing it |
| --- | ---: |
| `reference_missing` | 4,071 |
| `analyzer_incomplete` | 1,274 |
| `limitations` | 1,274 |
| `static_parse_limit` | 987 |
| `obfuscated_instruction_text` | 297 |
| `referenced_uninspected` | 170 |
| `opaque_content` | 144 |
| `runtime_limit` | 83 |
| `reference_unresolved` | 37 |
| `acquisition_failed` | 29 |
| `output_limit` | 18 |
| `input_limit_exceeded` | 11 |
| `acquisition_transfer_limit` | 4 |

Missing references occur in 93.1% of current incomplete reports. The retained
missing-reference rows comprise 24,563 quoted/code references, 6,378 plain
paths, 232 Markdown links, 118 inline commands and one Markdown image. These
row counts include repeated references and are not counts of distinct missing
files or affected roots. They also do not establish that a reference is a false
positive. Runtime-produced files and dependencies outside the bundled root are
still outside the scanner's acquired inspection scope.

The dominant retry disposition is blocked `reference_missing` (3,653 records),
followed by blocked obfuscation (249), parser limits (183) and opaque content
(142). Seventy-nine records exhausted the extended budget and 27 exhausted
transient retries. Increasing a process deadline cannot resolve the typical
missing-reference or bounded-parser limitation. The existing finite profiles
remain the starting policy.

One narrow reference-classification defect was reproduced in the immutable
`rorkai/app-store-connect-cli-skills` source at
`7de1ef7cc831f62d205dfa589063f3831f66391b`: the JSON scalar
`"VERSION": "1.0.0",` on line 153 is recorded as a missing path. The full
published current cohort contains 11 strict JSON version-scalar rows across
nine records. This is a candidate for a separately qualified scanner fix with
positive and adversarial tests. It is not grounds to discard other missing
references, to claim those nine roots completely inspected, or to omit the
required analysis-policy identity change.

## Discovery and elapsed time

Catalog enumeration completed 50 pages, observing all 9,911 listings declared
by the provider in that snapshot. There are zero `catalog_not_observed` reasons.
The current evidence therefore does not support increasing the page ceiling.
Overall discovery remains incomplete because name/source resolution and plugin
availability are separate from catalog enumeration.

Source states are 17,631 resolved, 112 historical, 1,769 unresolved, 371
unavailable and 164 unsupported. Source states can include both catalog and
plugin-root observations, so this population differs from the 17,743 selected
roots. Source reasons include 942 ambiguous names, 853 missing skills, 264
repository acquisition failures, 59 unavailable repositories and 134 unavailable
community sources. Plugin states are 1,946 resolved, 566 not applicable, 1,349
unavailable and 55 unresolved; a plugin can contain zero, one or several roots.

Attempt 1 spent 582 seconds preparing, including 304 seconds in discovery.
Individual scan steps spent 843–1,206 seconds, below the 2,100-second worker
budget. Assembly took 403 seconds and publication 489 seconds. These phases
include different work and should not be compared as scanner-only timing.
The preparation artifact currently includes the previous report bundle, which
every scan partition downloads; the 315.86 MB shard population makes that
repeated I/O a material part of a full-catalog integration run.

The original run's exact attempt-1 execution window was 12:26:46–13:13:37 UTC.
Joining every retained attempt-history timestamp to that window confirms
exactly 128 attempts in each partition: 1,024 attempts on 1,024 distinct roots.
Thus the count ceiling bound all eight partitions before their work deadlines.
Summed acquisition and analysis durations per partition were 705.69–1,062.33
seconds; scan-step durations also include orchestration/normalization overhead.

This supports bounded manual choices of 256 or 512 attempts under the unchanged
2,100-second work deadline, 32 MiB worker-output ceiling and full-profile
admission rules. Normal admission remains 128 until a larger real canary
measures useful progress. The v2 ceiling remains 128. A larger admission ceiling
is permission to try more work if it fits, not a promise that every selected
attempt will execute. Controlled-corpus smoke runs avoid the full previous-bundle
and catalog costs and should be labeled accordingly.

## Real local acquisition, scanner and retry checks

The local validation used SkillSpector `2.13.1` at immutable upstream commit
`f3b25697d76256998ca9d42c198d256258d4c035`, locked dependencies installed with
`uv sync --frozen --no-dev --python 3.12`, and the existing verified
`uap-directory-inventory-v1` maintenance patch. The registry's pinned workflow
Python dependencies were used. No LLM analysis was enabled.

This container requires an outbound proxy. The hardened Git acquisition
environment intentionally does not inherit that proxy, so an initial direct
online attempt failed DNS resolution. Subsequent checks used the existing
explicit offline mirror boundary with real Git objects pre-fetched at the
controlled corpus's exact revisions. They exercise immutable object identity,
bounded whole-root acquisition, materialization, the real scanner,
normalization, persistence and publication validation. They do not substitute
for online acquisition in GitHub Actions.

Two separate one-attempt invocations against the 13-root Cloudflare controlled
subset completed in 61.10 seconds. The first outcome survived exact checkpoint
resume into the second invocation. `agents-sdk` completed execution with partial
analysis in 6.64 scanner seconds; `cloudflare` completed execution with partial
analysis in 48.09 scanner seconds. The resulting bundle had two partial roots,
11 pending and no errors, and passed the production bundle/publication checks.

A second check exercised the two known prior-failure sources and the actual
Cloudflare standard-to-extended retry. It completed in 154.38 seconds:

| Root | Profile | Attempt | Scanner seconds | Result |
| --- | --- | ---: | ---: | --- |
| `asc-workflow` | Standard | 1 | 2.72 | Partial: parser and missing-reference limits |
| `cloudflare` | Extended | 2 | 109.11 | Partial: parser and missing-reference limits |
| `react-native-best-practices` | Standard | 1 | 38.52 | Partial: parser limits |

All three executed successfully under the execution contract, had no acquisition
errors, and assembled into a bundle accepted by the production validators.
Cloudflare's prior `runtime_limit` disappeared under the extended profile;
its remaining limitations correctly prevented a complete claim. Controlled
regression artifacts remain excluded from production catalog publication.

A third check injected a process failure immediately after the first real
scanner result had been atomically checkpointed. The failing child process
exited with code 23. A fresh CLI process loaded that checkpoint, finished the
remaining admitted sources, and preserved the first record/attempt transaction
exactly, including scan time, findings and retry history. Each of the three
final outcomes had attempt count one. Strict-prefix assembly accepted both the
earlier and later checkpoints without duplicating attempts; the resulting
15-root controlled bundle contained three partial reports, 12 pending and no
errors. Production bundle/publication validation passed. This complete check
took 69.05 seconds. It demonstrates process-crash recovery while the local
checkpoint remains; remote artifact acknowledgment and hard-runner-loss recovery
have separate transport/provenance tests and CI acceptance gates.

The full workflow-selected discovery, acquisition, scanner, publication and
contract suite, plus the checkpoint/partial-recovery/transport regressions,
passed locally: 283 tests in 41.94 seconds. This is local test evidence, not a
claim that the draft changes have been merged or observed in production.

## Delivery decisions supported by this audit

Preserve exact scanner/profile identities for checkpointing and orchestration.
Persist completed outcomes before later work and cleanup. Upload bounded remote
slices, reconcile strict cumulative prefixes, and recover only authenticated
main-origin results at matching immutable subjects and attempt lineage. Permit
explicit partial assembly while reporting absent partitions. Keep source,
coverage, findings, retry state and current/historical evidence distinct.

Do not clear blocked retry state, broadly suppress references, remove finite
limits, classify historical reports current, or call partial analysis clean.
Measure any later admission/cadence adjustment and qualify analyzer changes
against real counterexamples. Branch and local validation demonstrate behavior
under their stated conditions; a later production publication is a separate
observation.
