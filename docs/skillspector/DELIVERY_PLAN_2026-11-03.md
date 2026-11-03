# SkillSpector: complete catalog filters and durable scan delivery

Plan date: 2026-11-03. Status: initial implementation plan for independent critique; this is a delivery contract, not a claim that the changes or production scans have completed.

## Owner request and delivery boundaries

The Skills catalog must show all installable Skills by default. A single compact **Filters** button opens an accessible dialog with two independently controlled, initially unchecked checkboxes: **Scanned by SkillSpector** and **No remarks**. The controls must continue to work with search, sort, pagination, shareable URLs, back/forward navigation, and mobile layouts. The second checkbox must never classify incomplete, stale, absent, malformed, unavailable, or unexecuted inspection as having no remarks.

The scan work must address the actual production backlog, not merely change the catalog presentation. Discovery, source resolution, queue admission, acquisition, analysis, result persistence, publication, and site consumption are one delivery chain. Short manual scans should start early, while the work remains in draft, and must exercise real immutable source acquisition and the real scanner. Useful completed work must survive subsequent failures. Finite resource limits are necessary, but reaching a boundary must preserve completed results and defer the remaining work explicitly.

All authoring, implementation, and independent critique for this work uses GPT-6.1 Sol with xhigh reasoning, as explicitly requested by the owner. PRs remain draft during development. Push every commit immediately after it is created. Put this plan into the draft PRs before implementation, and push each meaningful plan revision after independent critique. Do not merge, publish a release, or claim production success solely because a branch run or local test passes. Production observation is a separate acceptance step.

Scope is the Skills catalog and the existing SkillSpector static report pipeline. Preserve the separate LintAI/security indicators. Do not conflate static inspection with installation permission, package validity, activation, OAuth, runtime health, vendor endorsement, or security certification. Preserve the frozen VS Code implementation and the authoring capability preservation boundary. The registry's retired site is not the implementation destination.

## Repositories, authoritative paths, and starting evidence

The frontend work continues in [universal-agent-plugins PR #687](https://github.com/777genius/universal-agent-plugins/pull/687), branch `fix/skillspector-current-scan-discovery-20261103`. Its inspected starting head is `96e44276a0f16abd03b557e06fa52f0ba3bd9e8f`. The scanner work is in [universal-agent-plugins-registry](https://github.com/777genius/universal-agent-plugins-registry), starting from `320c30d3a508d0c59a4a87ac36d3d5b216dff41d`. The scanner draft is [registry PR #408](https://github.com/777genius/universal-agent-plugins-registry/pull/408); both draft PR descriptions link to this authoritative plan and to each other. Pin factual code references to the inspected commits when describing the baseline; use the implementation commit SHAs in the final evidence report.

Read and preserve both root `AGENTS.md` files. Registry changes also follow `docs/ECOSYSTEM_GUARDRAILS.md`. The product repository's `docs/AUTHORING_CAPABILITY_PRESERVATION.md` has been read; this work does not retire legacy capabilities. Re-read any deeper `AGENTS.md` that applies to the actual files before changing them.

Verified baseline code locations:

| Layer | Current files | Observed behavior or constraint |
| --- | --- | --- |
| Skills UI and URL state | `landing/components/registry/SkillsCatalog.vue`, `landing/utils/skillsCatalog.ts` | Current default is scanned; an all/scanned select is hidden during search. |
| Acquisition and pagination | `landing/composables/useSkillsCatalog.ts` | Scan filtering is explicitly disabled when search is nonempty. Acquisition is bounded at five catalog pages and 64 verified candidates per load; visible batches are 48. |
| Exact report matching | `landing/utils/skillSpectorCurrent.ts` | Current scanned predicate requires matching v3 source state, one selected standalone root, immutable revision/path, completed execution, complete or partial coverage, and at least one inspected file. |
| Report transport and validation | `landing/composables/useSkillSpector.ts`, `landing/utils/skillSpectorCatalog.ts`, `landing/utils/skillSpectorV3.ts` | Preserve shared client, SHA-256 shard verification, bounded concurrency, and v3-first fallback behavior. Confirm exact validator fields before extending eligibility. |
| Localized presentation | `landing/features/skills-catalog/locales/*.json`, `landing/features/skills-catalog/catalog.scss` | All nine maintained locales must contain the new UI text. |
| Discovery | `scripts/discover_skillspector_sources.py` | Current documented catalog crawl is capped at 50 pages/10,000 candidates, with a 20,000 selected-root ceiling. Previous unresolved sources can remain historical. |
| Scan execution and merge | `scripts/skillspector_coverage_v3.py` | Source outcomes accumulate in memory and the CLI writes the worker file after `scan_partition` returns. A process interruption can therefore lose earlier outcomes from that partition. |
| Workflow orchestration | `.github/workflows/skillspector-reports.yml` | Normal runs have eight partitions, at most 128 attempts each, 2,100-second work budgets, 45-minute scan jobs, and a six-hour cron. Upload and downstream assembly currently follow successful job execution. |
| Publication | `scripts/publish_skillspector_coverage_v3.py` | Publication rejects artifacts whose `source_commit` no longer equals `main`; the delivery audit observed supersession returned as successful handling. Verify exact exit/status behavior before changing it. |
| Existing contracts | `scripts/skillspector_contract.py`, `schemas/skillspector-*.schema.json`, `docs/skillspector/REPORT_V3.md`, `docs/SKILLSPECTOR_REPORTS.md` | Execution, analyzer coverage, findings, current/historical identity, and retry state already have separate meanings. Extend the existing contract minimally. |

The prior production audit observed run `41635762917`, publication `3c0bd61eeafb5369f62b93c6c50cee223ebfd490`, and selected counts of 17,743 = 2,119 complete + 4,328 partial + 44 error + 11,252 pending, with 9,164 stale. These are a timestamped baseline to reproduce and diagnose, not a promise that 11,252 roots are all eligible for scanning. A source that discovery no longer observes may be historical and intentionally excluded. Repository revision currently participates in source identity, so an unrelated repository commit can invalidate a root's prior current evidence. Content-based reuse is not assumed to exist.

The registry implementation investigation reproduced additional exact census data from that publication: catalog enumeration completed 50 pages with 9,911 observed listings and provider total 9,911; there were **zero** `catalog_not_observed` reasons. Source states were 17,631 resolved, 112 historical, 1,769 unresolved, 371 unavailable and 164 unsupported. Plugin states were 1,946 resolved, 566 not applicable, 1,349 unavailable and 55 unresolved. Known source-reason counts included 853 `skill_not_found`, 942 `ambiguous_name`, 59 repository unavailable, 264 repository acquisition failed and 134 community source unavailable. These denominators are source/plugin states, not selected scan records. Do not expand the 50-page ceiling on this evidence; current discovery incompleteness concerns resolution, not a demonstrated truncated catalog crawl.

The published bundle has 2,028 shards totaling about 315.86 MB. The observed run spent 582 seconds preparing (304 seconds in discovery), 843–1,206 seconds per scan partition, 403 seconds assembling, and 489 seconds publishing. Scan workers did not consume the full 2,100-second budget. A sample of 136 evenly spaced shards (1,203 records) found revision and same-revision policy turnover among stale evidence, and current incomplete evidence dominated by missing references rather than runtime limits. This is a diagnostic sample, not a population-weighted estimate. Full runnable-cohort accounting is still required before deciding whether to adjust throughput or analyzer behavior.

## Product semantics: two independent filters

The dialog presents two native or equivalently accessible checkboxes. Both are false on an ordinary visit to the Skills tab. Each changes one explicit boolean state. Their logical combination is AND; the state of one checkbox does not silently check or disable the other. “No remarks” is the stricter subset of scanned results, so enabling both returns the same set as enabling No remarks alone. This overlap is expected and should be documented in helper text without forcing the control states to match.

### Scanned by SkillSpector

Use the current inspected predicate as the starting point, tighten malformed input handling if necessary, and preserve the important distinction between an execution finishing and analysis completing. A Skill is scanned only if the currently published, verified v3 report joins unambiguously to that exact provider listing and immutable source state, its execution completed, its analysis is complete or partial, and it actually inspected at least one relevant file. A partial result with inspected files qualifies for Scanned and remains visibly partial on its card/detail. Pending, not started, errored, stale/historical, empty inspection, unresolved selection, ambiguous selection, or v2/v1 fallback do not qualify.

The listing-to-source join must use the existing canonical repository/listing identity checks. A result for a neighboring Skill, a plugin aggregate, a renamed repository without validated alias evidence, a previous revision, or a different root cannot qualify merely because the names are similar. Do not use the cheap current-source index as final evidence: final decisions require the validated report shard.

Return the exact eligible matched record from a shared selector and apply both filter predicates to that one record. Never combine a report-wide “some current scan” boolean with a separate report-wide “some clean record” boolean. A dirty target and clean neighboring Skill in the same repository must fail No remarks for the target.

### No remarks

The user-facing label means **complete current static inspection with zero content findings**. It does not mean “safe,” “approved,” or “no known malware.” Helper text must say that this filter requires complete current analysis and excludes incomplete or unavailable checks.

Eligibility requires all Scanned identity/provenance conditions plus all of the following:

1. The actual record and its analyzer coverage both say complete, with a supported current scanner/profile identity and completed execution.
2. The inspected root has a nonzero file inventory and all files in the claimed inspection scope are fully inspected. No partially inspected, uninspected, omitted, unsupported, or excluded content remains under that complete claim. Use the existing validated contract's completeness invariants rather than creating a competing frontend interpretation. If the validator does not enforce a required invariant, add the narrow contract check and regression case.
3. Content findings are exactly empty in the authoritative validated representation. A nonzero raw finding count, nonzero grouped finding count, or nonempty finding array fails the filter. Confirm the current field names and grouping rules and test adversarial disagreement between them. Do not use severity, review state, display truncation, or a missing summary field as a proxy for zero findings.
4. No analyzer errors, coverage limitation reasons, redaction/normalization truncation that prevents complete evidence, or pending retry state can turn a record into a clean result. If these fields are inconsistent with complete coverage, the record fails closed and should be rejected by validation where appropriate.
5. Missing or unrecognized fields fail closed. Legacy imports, fallback reports, future unknown contracts, unavailable shards, bad digests, invalid JSON, timeouts, and request cancellation never produce No remarks.

All content findings count for the requested filter, including findings annotated as false positives. This is the conservative, auditable meaning of “zero content findings.” Existing finding review annotations remain visible; this work does not silently hide findings based on review disposition. If the product later needs “no actionable remarks,” that is a separate explicit policy and control.

Truth table and representative records:

| Record state | All default | Scanned checked | No remarks checked | Both checked |
| --- | --- | --- | --- | --- |
| Complete current, nonzero inspected scope, zero findings | Include | Include | Include | Include |
| Complete current, one or more content findings of any severity/review state | Include | Include | Exclude | Exclude |
| Partial current, some inspected files, zero reported findings | Include | Include | Exclude | Exclude |
| Partial current, no inspected files | Include | Exclude | Exclude | Exclude |
| Error, pending, historical, unresolved, missing report, or invalid evidence | Include | Exclude | Exclude | Exclude |

“Include” here means the Skill remains otherwise installable and matches the user's search/provider catalog constraints. The filters do not widen installation support or add publishers to the released CLI.

## Frontend implementation design

### Compact accessible dialog

Replace the current all/scanned select with one Filters button beside the search and existing sort control. Keep the Filters button visible during search. Reuse the established dialog primitive in the repository if it provides focus trapping, Escape handling, accessible naming, inert background, and focus return; inspect current usage before introducing a new component. A small shared primitive is preferable to hand-rolled modal mechanics. Do not add a dependency if the existing Reka UI stack already provides the behavior.

The dialog contains its title, the two checkboxes, concise helper text for each, an obvious Close control, and optionally a Reset filters action that clears both booleans. Apply selections immediately; there is no separate unsaved draft state or surprising Apply requirement. The button may show a small active-filter count when one or two controls are selected, but should remain compact at mobile widths. Avoid placing the two long labels permanently in the catalog toolbar. Keep coverage diagnostics out of the dialog's primary task.

Keyboard acceptance: Enter/Space opens the button; focus enters the dialog; Tab/Shift+Tab remain in its interactive controls; Space changes an individual checkbox; Escape and Close dismiss it; focus returns to Filters. The dialog has an accessible title and descriptive text where helpful, visible focus styling, sufficient target sizes, and no offscreen or clipped content at a narrow viewport. Checkbox state is exposed through native checked state or correct ARIA semantics. Screen-reader status changes should announce loaded/matching results without repeatedly announcing verbose scan coverage.

### Canonical state and URLs

Use explicit booleans in the composable API, such as `scannedOnly` and `noRemarksOnly`, rather than extending the old mutually exclusive all/scanned enum. Name the shared eligibility mode/helper so it can express all four boolean combinations. Keep booleans in one canonical state object or a clearly typed pair; avoid parallel unsynchronized modes in component, route, and composable.

Canonical fresh/default URL has neither filter parameter. Encode checked state explicitly, for example `skillScan=scanned` and `skillRemarks=none`, and omit unchecked state. Before implementing, inspect existing route helper ownership and choose exact names once in tests/docs. Preserve existing `skillScan=all` links as the unfiltered default; normalize them to omitted state when the user changes filters. Old absent `skillScan` now means all by owner request. Recognize only supported exact values, not arbitrary truthy strings. Unknown, repeated, or malformed parameter values must fall back predictably to unchecked instead of enabling privileged eligibility.

Keep unrelated route parameters, selected Skills tab, query, view, and locale. Toggling filters resets catalog acquisition and visible results, not the search text or sort choice. Back/forward navigation restores both filters. Serialize router writes or use the existing navigation race handling so rapid toggles and typing cannot restore stale state. Test route navigation that arrives while a replace is pending. Avoid retaining a different hidden filter when switching away from and back to the Skills tab unless that behavior is already explicit in route state.

### Search, paging, and report acquisition

Remove the current `!query.trim()` exception from scan filtering. Compute `requiresReport = scannedOnly || noRemarksOnly`. Unfiltered loading fetches no SkillSpector manifest/shards solely for filter eligibility. Cards can continue their existing lazily mounted assessment requests. Filtered search must process the provider's returned candidate set through the same verified predicates as browsing. Preserve the provider's actual search pagination contract; if search has only one result page, do not invent subsequent search requests, but still consume every candidate in that page across verification windows.

Separate four concepts: upstream cursor/page, unverified candidate queue, verified matching result buffer, and displayed count. Filter changes increment the request generation immediately, abort fetches where possible, reset all four concepts, and ignore stale report completions. Fetch a bounded window, verify candidates with bounded concurrency, preserve remaining candidates, and expose Show more while there are queued candidates, undisplayed matches, or genuine upstream pages. Sparse filtered windows may legitimately have zero visible matches while more candidates remain; say that more can be searched and retain the continuation action. Do not present that intermediate state as an exhaustive “no matches.”

The existing five-page/64-candidate bounds can remain initial responsiveness limits if measurements support them. They must be per acquisition window, never an undocumented cap on the total result set or a reason to drop queued candidates. Ensure a six-page fixture and more than 64 candidates can be completely traversed. Display batches remain 48 unless existing UI constraints require otherwise. Avoid unnecessarily fetching all report shards or all catalog pages before showing the first result. Use the current source-state index only to skip impossible candidates; a missing/unavailable index must produce a clear unavailable state, never a positive eligibility decision.

Maintain separate catalog transport failure and scan-evidence failure flags. If some candidates have verified eligibility and another shard fails, retain the verified cards and show a truthful partial availability notice plus Retry. If the report is unavailable altogether, unfiltered mode still works; selected evidence-dependent filters fail closed and offer clearing filters or retrying. An empty, valid v3 snapshot differs from missing v3 with legacy fallback. A retry must revisit failed evidence candidates rather than permanently losing them from the queue.

### Card wording, localization, and visual review

Preserve current partial/complete/historical detail and separate security badge presentation. No remarks must not create a green “safe” or “approved” badge. All nine locale dictionaries receive equivalent labels, checkbox helpers, dialog actions, active count, filtered empty/continuation text, and evidence-unavailable wording. Check key parity with the repository's i18n script and review desktop, mobile, and Arabic RTL layout. Use existing typography, control spacing, colors, and focus treatments.

## Registry diagnosis before choosing throughput changes

Reproduce the latest valid published bundle and write a machine-readable, bounded diagnostic summary plus a readable table in the PR evidence. Do not build a new telemetry service. Reuse `measure_skillspector_coverage.py`, existing validators, and queue planning functions where possible, extending their output only for actionable gaps.

Required denominator partitions:

| Measurement | Why it changes the action |
| --- | --- |
| Total catalog listing observations vs current resolved vs unresolved vs historical states | Separates discovery/resolution limits from runnable scanner backlog. |
| Selected current source IDs vs historical-only selected IDs | Prevents counting intentionally excluded historical roots as workers failing to run. |
| Current complete, partial, error, never-attempted, stale and changed identities | Shows what the next run can actually improve. |
| Due retries, future backoff, blocked/exhausted retries and per-reason counts | Distinguishes waiting work from permanent unsupported content or capped retries. |
| Candidate counts per lane, partition, repository group, and oldest wait | Reveals fairness, hot-repository, and partition skew. |
| Actual worker starts, attempts, completions, deferred admissions, acquisition/analysis durations and bytes | Determines whether attempts, time, data volume, or source acquisition is the effective limit. |
| Discovery stop reasons, observed page/listing counts, resolution budget usage, and reused inventories | Tests whether catalog breadth or cold source resolution is the bottleneck. |
| Source-revision churn and unchanged-root opportunities | Quantifies invalidation from repository commits before proposing content reuse. |
| Worker outcomes generated, durably stored, merged, published, superseded and recovered | Identifies lost work between analysis and visible delivery. |

For every count, state whether it measures listing states, unique roots, source analysis identities, attempts, or repositories. Counts from different denominators must not be subtracted as if interchangeable. Reconcile the published analysis identity invariant `selected = complete + partial + error + pending`; stale is historical evidence within pending and is not a fifth additive coverage bucket. Provide at least the top ten reason cohorts with exact counts and representative immutable subjects.

Estimate burn-down from measured completed current analyses per actual run duration and eligible backlog, not `8 × 128` alone. Include discovery/selection churn and retry cost. If one partition has much less usable time or a large repository monopolizes acquisition, fix that specific cause before multiplying workers. If most pending records are historical-only, advancing current discovery and resolution is the needed remedy. If partial results are dominated by parser or missing-reference limits, increasing runtime is not a completeness fix.

## Minimal durable execution architecture

Preserve the existing v3 selection, source-state, worker, merge, shard, and publication model. Do not introduce a database, daemon, external queue, or new service. Add the smallest validated checkpoint/recovery path that closes the observed loss windows and makes per-attempt progress reusable.

### Worker checkpoint contract

Write an initial valid empty worker envelope before scanning starts, then atomically replace the bounded worker checkpoint after each completed and normalized outcome. The checkpoint binds the original `source_commit`, selection digest, scanner/profile/policy, partition index/count, immutable subject and source digest, attempt count/history, execution, coverage, and findings exactly as the existing worker contract does. Validate each checkpoint before exposing it to assembly. Redact public record text before persistence; do not persist scanner environment, credentials, raw arbitrary stdout, or unbounded findings as a recovery shortcut.

Checkpoint writes use a same-directory temporary regular file, bounded serialization, flush/fsync where supported, atomic replace, and cleanup. A partially written next outcome cannot corrupt previously committed outcomes. Store the record and its retry/attempt state together. A crash during a later attempt cannot advance that later attempt's count or erase the prior checkpoint. Re-entering the same worker must validate the checkpoint and either resume the uncompleted suffix or make duplicate recovery idempotent; it must not double-count a completed attempt.

Generate or update the checkpoint envelope timestamp on every write so it is at least as recent as every contained outcome timestamp. Do not freeze `generated_at` at process startup. A later `PinnedRepository.close()` failure must not erase an earlier checkpoint; checkpoint persistence precedes and remains independent of cleanup. The minimal scanner interface may accept a checkpoint callback receiving the existing validated cumulative worker document initially and after each appended outcome, with the CLI callback using `write_bounded` for `--output`.

Separate process-local checkpointing from remote durability. An atomic local file survives a scanner exception or process timeout while the runner filesystem remains, but it cannot by itself survive sudden runner loss. The workflow therefore uploads validated completed checkpoints at bounded durable slice boundaries and on failure/cancellation where Actions allows. Prefer a small number of bounded worker slices with a publication/recovery stage per slice over a long monolithic attempt list. The exact slice count/budget must be chosen after initial timing measurements, documented as a cost/recovery tradeoff, and finite. Do not claim that `if: always()` alone guarantees recovery from a dead machine.

Durability guarantee: once a checkpoint has been remotely acknowledged, a later scanner crash, other partition failure, workflow timeout, main advancement, or retry must not cause it to be forgotten. The currently in-flight, not-yet-acknowledged attempt may need rerunning after hard runner loss. Report that bounded loss window honestly. For ordinary subprocess crashes or cooperative deadlines, every earlier completed local outcome is uploaded and recoverable. If per-slice upload is impossible within current Actions primitives, use a narrowly scoped artifact upload mechanism between slices; do not grant report branch write credentials to untrusted scanner execution merely to avoid orchestration work.

### Partial worker failure and assembly

Upload checkpoint files with a condition that runs after a failed scan step. Assembly runs when preparation is valid and at least one validated checkpoint is available, even if another scan partition fails or times out. One partition's infrastructure failure must not prevent publication of unrelated completed results. Preserve prior records for missing partitions, leave their unattempted work pending, and expose missing/failed partition diagnostics. Do not synthesize successful outcomes or empty scans for missing files.

Set an explicit scan-step timeout shorter than the overall job timeout, with the cooperative scan budget shorter again. Reserve setup and upload/cleanup headroom using measured setup times. A job-wide hard timeout can prevent `always()` steps from running. The workflow's manual dispatch needs an explicit bounded `scan_budget_seconds` input (for example 300/600/2,100, after validating admission feasibility), separate from maximum attempts and discovery budget. Eight attempts alone is not a short wall-clock guarantee. Controlled-corpus smoke tests avoid the large prior-bundle/catalog preparation cost; catalog smoke tests must state that I/O overhead honestly.

Relax any current “all partitions required” merge gate only through an explicit bounded incomplete-run contract. Retain exact partition ownership, one coherent selection snapshot per merge, no duplicate subjects, no conflicting attempts, consecutive retry counts, no timestamp regression, and no cross-selection laundering. A malformed worker must be rejected and reported. It must not be silently counted as an empty successful partition. A recovery run may select only validated worker artifacts; record each accepted artifact identity and rejection reason.

Bind expected partition count independently to the trusted preparation plan/workflow input, for example `--expected-partition-count`, and make partial acceptance explicit, for example `--allow-partial-workers`, with strict defaults preserved. Validate worker envelopes before accessing partition fields. Inferring expected count from the first worker would let a count-one artifact masquerade as a complete eight-partition plan. Persist received/missing partition identifiers and counts in a bounded execution summary, updating strict schemas/readers compatibly if a new optional field is needed. For cumulative immutable slice artifacts, verify that later snapshots extend earlier outcomes exactly or select a validated strict prefix; never discard malformed/conflicting artifacts merely because another has a later timestamp.

When merging retry outcomes, retain useful prior content evidence if a later attempt errors, while storing the later failure in retry/execution history under the existing contract. Never relabel older evidence as freshly complete. Missing outcomes and deferred admission consume no attempt. The current pattern that discards an already executed outcome when the worker byte ceiling is reached must be addressed: reserve bounded outcome capacity before admission or persist a separate validated chunk so a completed attempt is not lost merely because earlier findings filled the aggregate file. A single oversized record needs an explicit bounded/truncated partial record, not an unbounded artifact or false complete result.

### Recovery and publication races

Keep public report publication atomic and content-addressed. Retain the current branch CAS/fast-forward protection and exact artifact validation before write credentials are enabled. Preserve legacy v1/v2 report bytes as the existing publisher does. Do not change signed Directory/Discovery/Security feeds as a side effect of static display report publication.

A change to registry `main` during a scan must not turn useful scan work into an unnoticed success with no delivery. Preserve the obsolete run's validated selection snapshot and worker checkpoints as durable recovery input. Recovery against the new current selection reuses a result only when repository identity, immutable revision, path, source digest, scanner, profile/policy, and attempt lineage match. Reassemble the output under the new current source commit using freshly validated discovery metadata; do not simply rewrite the old manifest's provenance. Changed or unavailable subjects stay historical or pending, as appropriate.

Keep the old-main rejection guard as the default until safe recovery is proven. An alternative narrow optimization may permit an original-source publication when current `main` descends from that source and every analysis/publication-relevant policy/runtime input is demonstrably byte-identical, but only with a complete reviewed dependency inventory and explicit unchanged provenance; do not implement a casual path allowlist that misses imported helpers, schemas or pinned scanner policy. Prefer exact-identity result recovery over weakening provenance guards.

A concurrent report publication also needs a bounded reread-and-merge retry, or an explicit recoverable conflict result with a queued recovery path. Never force-update the report branch. Never report plain success when neither publication nor durable scheduling of recovery occurred. Workflow summary/status must distinguish published, recovered, superseded-with-durable-recovery, deferred, and failed. Recovery input must be discoverable by a subsequent manual/scheduled run and remain available past a short artifact retention window until acknowledged by a valid public bundle or an explicit bounded retention policy.

Production recovery has the same trust boundary as direct production publication. Accept remote artifacts only after verifying that the actual producing run belongs to this trusted repository and canonical workflow, its workflow source belongs to protected main history, and run/attempt, artifact digest, original selection/discovery snapshot, source commit and policy identity match. Worker JSON self-reported provenance is insufficient: an arbitrary feature-branch workflow can fabricate it. Feature-branch and controlled-corpus artifacts remain useful branch validation evidence and are excluded from production recovery as well as direct publication. Validate run provenance and all artifact bytes before enabling write credentials. Include foreign repository/workflow, branch-produced, controlled-corpus and mismatched-attempt recovery rejection tests.

Require the original run's actual `head_branch` to be main (or an equivalently verified immutable trusted-main execution attestation), with original head SHA, event and corpus input bound to the envelope. A branch commit becoming reachable from main after merge does not retrospectively authorize artifacts produced while that run was a feature-branch execution.

Do not let later worker timestamps override a newer complete current record without validating source and attempt lineage. Duplicate artifacts from job retries must deduplicate by exact outcome identity. Conflicting records for the same identity fail visibly. Recovery of an earlier source revision must not make that source current after discovery has observed a newer revision.

## Retry, resource budgets, and backlog progression

Keep the existing standard and extended static analysis profiles as the starting policy: standard 512 files/4 MiB/60-second scanner process; extended 2,048 files/16 MiB/180-second scanner process, with their documented internal limits. Reserve enough wall-clock time for preparation, the full intended profile, checkpointing, redaction, upload, and cleanup before starting work. Do not shrink a per-source profile merely because a partition is near its deadline. Defer that source without consuming an attempt and allow another eligible source that fits only if doing so does not create starvation.

Classify partial/error reasons into resource-limited, transient, permanent unsupported/incomplete, and source-invalid cohorts using the existing retry policy. A resource-limited standard result may schedule the existing extended profile. Extended exhaustion does not imply complete analysis and should stop blind escalation. Transient acquisition/network/OSV failures keep bounded backoff and an exact attempt cap. Parser limitations, missing references, opaque or excluded content, and unsupported content remain partial until the source/scanner policy changes. No scheduled retry is required just to make the dashboard look busy.

Choose run frequency, attempt count, partitions and slice size from the diagnosis. The initial 8 × 128 ceiling is not a throughput commitment. Increasing a ceiling is appropriate only if workers reach it with time and artifact capacity remaining; increasing a deadline is appropriate only if measured resource-limited cohorts can benefit and cancellation/recovery stays safe. Preserve fairness across new/retry/changed lanes and repositories. A large plugin group can make coherent progress without blocking all other groups. Record the largest and oldest current runnable cohorts before/after the first real run.

Catalog coverage beyond the first 50 pages is a separate discovery issue. If diagnosis shows that the cap causes current listings to oscillate into `catalog_not_observed`, introduce a persisted bounded crawl cursor or stable multi-slice inventory using existing discovery checkpoints. A partial crawl cannot declare unseen listings removed. Distinguish “not seen in this bounded slice” from “confirmed absent after a complete observation cycle.” Reuse previous immutable resolutions as historical until current observations justify freshness; do not grant current status from absence. If a bounded crawl really is exhaustive under the provider contract, record that fact and stop condition explicitly.

Content-based reuse across unrelated repository commits is an optional measured optimization, not a shortcut for the present correctness fix. Only implement it if the baseline shows material churn and the implementation can prove the selected root's complete acquisition tree and analysis-relevant reference scope unchanged at the new immutable revision. Bind evidence reuse to tree digest, scanner/profile/policy and relevant dependencies; retain original scan date and provenance. If those proofs are unavailable, keep exact-revision behavior and report its cost rather than broadening freshness incorrectly.

## Delivery phases and gates

### Phase 0 — publish the plan and establish reproducible baselines

1. Confirm both branch heads, open/draft state and applicable instructions. Convert PR #687 to draft as authorized. Create a scanner branch/draft PR for the implementation plan, or attach the cross-repository plan in its first commit. Push each commit immediately. Link both PRs and name their scope/dependency.
2. Commit this detailed plan before implementation. Run at least two independent critique rounds with different emphases: product/accessibility/search semantics, and scanner correctness/durability/throughput/security boundaries. Each critic must identify concrete failure scenarios and acceptance gaps, not merely approve prose. Reconcile findings into the plan, push the revision, then ask a further independent critic to test the revised plan against the owner request.
3. Gather and preserve the quantitative baseline above. Mark unknowns explicitly. Select manual scan inputs and immutable representative sources from actual failure/backlog cohorts.
4. Trigger a bounded real feature-branch catalog scan immediately once the workflow input/ref is confirmed, using the existing small options (one discovery page/eight maximum attempts) as the initial smoke test. This is read-only analysis and validation; it cannot replace production reports. In parallel with its runtime, continue plan review and frontend work. Record run URL, exact ref, input values and eventual conclusion.

The earliest controlled-corpus smoke run can start before a branch workflow adds explicit time-budget inputs; record existing timeout limitations. Repeat against the changed head after implementation. Existing catalog “small” inputs bound counts but still pay large prior-publication and assembly overhead, so label them accurately. Include retry of observed resource/network failure cohorts where the existing policy permits it, without resetting blocked retry state to manufacture work.

Gate: pushed plan, cross-linked draft PRs, independent critique disposition, baseline denominators and a real short scan started. Do not wait for the full backlog to clear before beginning implementation.

### Phase 1 — implement the UI/filter contract

1. Add a pure shared current inspected/no-remarks eligibility helper with exact contract fields, preserving the existing scanned semantics and fail-closed boundaries.
2. Replace the enum with two independent booleans and route helpers. Make default unfiltered, maintain legacy all links, validate parameter shapes, preserve unrelated route state.
3. Add the compact accessible Filters dialog using an existing primitive. Keep it available during search and on mobile. Localize all nine dictionaries.
4. Apply the shared predicate in browse and search. Retain candidates across bounded windows and evidence retries. Keep valid results when some evidence fails. Fix empty/continuation wording and generation cancellation.
5. Add focused predicate/route/composable tests and Playwright scenarios below. Run the relevant landing tests, i18n check, lint/build and browser cases required by CI. Push every commit immediately.

Gate: deterministic fixture tests demonstrate all four filter combinations and the accessibility/search/paging/race cases. Unfiltered default continues to show the provider catalog when report infrastructure is unavailable.

### Phase 2 — close durable progress and recovery gaps

1. Add atomic per-outcome checkpointing and resume/idempotency validation. Ensure attempt and record are committed together and completed outcomes are not discarded at byte bounds.
2. Add bounded remote durable slices and always-on-failure checkpoint upload, with isolated write permissions. Preserve the exact selection/discovery snapshot and artifact provenance needed for recovery.
3. Allow validated partial-run assembly with explicit partition failure/missing diagnostics and preservation of prior evidence. Add malformed/conflicting/duplicate artifact tests.
4. Add main/report-branch supersession recovery with strict identity joins and honest workflow status. Prove recovery is reachable from a subsequent run and not left as a manual artifact scavenger hunt.
5. Add measured queue/discovery improvements supported by the diagnosis, using finite limits and cause-based retry. Update operational docs with the exact new guarantees and remaining hard-loss window.

Gate: injected later-source crash, failed partition, exhausted cooperative budget, artifact size boundary, main advancement and publication race all preserve acknowledged earlier outcomes without false current evidence.

### Phase 3 — real end-to-end runs and current-source progress

1. Run a short branch scan through discovery, immutable acquisition, real pinned scanner, checkpoints, upload, partial assembly and publication validation. Confirm artifacts using the same validators the publisher uses.
2. Run the controlled immutable regression corpus, including known previous failures and a multi-root plugin. Keep controlled artifacts excluded from production publication.
3. Exercise recovery with a deliberately interrupted later attempt after an earlier outcome has been durably acknowledged. Resume from a fresh process/run and compare exact evidence identities, attempt counts, findings and scan times.
4. Run a broader bounded catalog scan sized from observed throughput. Compare current complete/partial/error/pending cohorts, due retries, resolution progress and oldest runnable wait with baseline. Include representative standard-to-extended retries and permanent partial limits.
5. Connect the generated valid v3 bundle to the landing E2E fixtures or local verified endpoint. Demonstrate real report data flowing through the Filters controls without relaxing validation. Keep deterministic fixtures for rare failures.

Gate: actual scanner evidence and filter behavior agree for representative clean, finding, partial, failed, historical and unavailable sources. Report exact results, including limitations; a successful workflow alone is insufficient.

### Phase 4 — independent final critique, fixes and review handoff

Run final independent reviews in parallel when the owner-authorized delegation is available: frontend/product/accessibility, registry/durability/recovery, and integration/security/evidence consistency. Review the final diff and exact head SHAs; earlier reviews of the initial plan do not count as final code review. Reviewers must test credible counterexamples and identify severity, code location and reproduction. Fix valid findings in small commits, push immediately, and rerun the focused verification affected by each fix. Do not repeat unrelated expensive tests after every prose-only correction.

Update this plan's completion checklist and PR descriptions to describe the actual final behavior and evidence. Leave draft status until required checks and independent reviews are satisfied. Confirm PR #687 is no longer titled/described as making scanned results the default. Cross-link exact frontend and scanner heads, real workflow runs, artifact identities and verification outcomes. The final user report must distinguish completed code, successful branch integration, changes awaiting merge, and production verification still pending.

### Phase 5 — coordinated merge and production observation, only within authorization

The frontend can safely ship before scanner backlog improvement because its evidence filters fail closed and its default is all Skills. Prefer registry correctness/durability first when both are ready, then the frontend. Do not block a correct UI on clearing all historical or unsupported partial content. Do not claim total backlog completion when current runnable work is merely reduced.

After authorized merges, trigger a small main scan with the real publication path, then observe the resulting public v3 manifest and content-addressed shards, source commit, generated timestamp, selection/coverage counts, and recovery state. Confirm no old-main supersession silently discards its results. Confirm the live Directory's Skills tab defaults to all, dialog states start unchecked, search plus filters works, and desktop/mobile/RTL layout is usable. Record the production report branch commit and site deployment identity. If the source changes between observations, refresh evidence rather than quoting stale counts as current.

## Required deterministic scenarios

### Frontend and contract matrix

- Default route and `skillScan=all`: both checkboxes unchecked; installable Skills remain visible even when the report endpoint fails. A manifest is not fetched solely to decide unfiltered eligibility.
- Scanned only: current complete with findings and current nonempty partial are included; empty partial, error, queued, stale, historical, ambiguous, other-root and other-revision records are excluded.
- No remarks only: only current complete nonempty inspection with zero authoritative findings qualifies. Scanned checkbox remains unchecked. Both checked gives the same eligibility set.
- Raw/grouped findings disagreement, missing counts, nonempty findings with zero summary, false-positive annotations, zero files, incomplete files, errors/coverage reasons, normalization truncation, unsupported profile and legacy fallback all fail No remarks.
- A dirty target plus a fully clean neighboring Skill in the same repository fails No remarks for the target; only the exact record selected by current source state can qualify.
- Filtered provider search includes matching eligible results and excludes ineligible results. Clearing/changing search preserves checkbox state. Sorting preserves filters and resets acquisition.
- More than 48 verified matches display through Show more; more than 64 candidates and more than five pages remain reachable. A first empty filtered window with later matches keeps continuation visible. Duplicate provider items do not duplicate cards.
- Search result candidates left after a verification window remain reachable even if upstream search reports no further pages. Clearing filters shows the full candidate catalog without retaining a stale filtered buffer.
- Expected filtered result IDs come from an explicit independent fixture table, not a test oracle that calls the production eligibility predicate again. Include exact expected IDs for every checkbox combination, search intersection and subsequent page.
- A shard failure preserves successful verified cards, surfaces evidence failure and retries failed candidates. A valid empty v3 report produces a different status from unavailable report or v2 fallback.
- Rapid search/filter/sort changes and late manifest/shard replies do not append results from an earlier generation. Back/forward restores both booleans and query without router loops. Unknown/repeated query parameters have documented unchecked behavior.
- Full dialog keyboard cycle, Escape/close/focus restoration, checkbox independence, accessible names/descriptions, screen-reader state, 320-pixel viewport, zoom and Arabic RTL. Run the existing relevant browser projects and capture reviewable desktop/mobile screenshots.

### Registry persistence and correctness matrix

- One successful source followed by scanner process failure, unhandled exception, cooperative timeout, acquisition failure, and simulated termination: first outcome/attempt remain in the valid checkpoint; no phantom second attempt appears.
- Checkpoint write interrupted before atomic replace: previous checkpoint remains parseable and resumes. Symlink/nonregular output, overlarge output and malformed provenance are rejected.
- Remote durable slice acknowledged then runner killed: a fresh recovery run reuses the earlier outcome exactly; only unacknowledged in-flight work can rerun. No duplicate attempt increments.
- One of eight partitions absent/failed and others valid: valid progress assembles and publishes/recoverably stages; prior evidence for missing partitions persists, unattempted roots remain pending, failure status remains visible.
- Duplicate identical artifacts, retries with the same output, conflicting outcomes, mixed selection digests, scanner/profile mismatch, wrong partition, attempt count gaps and future/regressing timestamps: deterministic deduplication or explicit rejection, never silent corruption.
- Aggregate worker limit and single huge finding output: prior progress remains usable; the last completed outcome is committed/chunked or explicitly bounded partial; the next source is deferred before execution when it cannot fit.
- Main advances between prepare and publish: validated old results are durably retained and eligible exact identities recover into a new current bundle; changed revision cannot be marked current from old evidence.
- Report branch advances concurrently: bounded CAS conflict handling preserves both valid progress sets or records an explicit recoverable conflict. No force push or overwrite.
- Partial standard resource result schedules extended profile; permanent unsupported/missing-reference result does not loop; transient failure follows backoff and exact attempt caps; not-yet-started work consumes no attempt.
- New/retry/changed lanes and small/large repositories make measured progress under finite budgets. Skew and starvation counterexamples are covered by queue tests.
- Partial catalog crawl does not declare unseen sources removed. A complete observation cycle and actual provider deletion have distinct tested outcomes. Historical evidence never becomes current through deduplication or recovery alone.
- Malformed/digest-invalid shards, unexpected files, control/selection mismatch, redaction failures, unknown scanner identities, controlled-corpus publication attempts and feature-branch publication attempts remain rejected.
- Recovery rejects artifacts actually produced by a feature branch, foreign repository/workflow, controlled corpus, or wrong run attempt even when their self-reported worker metadata imitates trusted main.

## Acceptance evidence and completion checklist

Each gate is complete only when its evidence is linked from the relevant PR and the plan is updated with exact refs. Use existing repository CI and test commands after inspecting their current definitions; do not invent passing results or replace meaningful integration tests with source-text assertions.

- [ ] Both draft PRs contain this plan and cross-links, with exact current heads.
- [ ] At least two independent plan critique rounds have concrete dispositions and pushed revisions.
- [ ] Quantitative baseline reconciles selected/current/historical/retry/discovery cohorts and diagnoses the dominant bottlenecks.
- [ ] An early short real scan was started and its final result recorded.
- [ ] Default all Skills, compact dialog, two independent unchecked filters, conservative No remarks semantics and all nine locale updates are implemented.
- [ ] Search, sorting, shareable state, sparse windows, continuation, evidence retries and stale-async cancellation pass focused tests and browser verification.
- [ ] Per-outcome checkpoints, bounded remote durability, partial-run assembly and exact-identity recovery pass failure injection and fresh-process verification.
- [ ] Main/report publication races produce published or durably recoverable progress with truthful status.
- [ ] Retry/resource/discovery changes are tied to measured causes; finite ceilings and remaining partial limitations are documented.
- [ ] Real branch catalog scan, controlled corpus and interrupted-run recovery have validated artifacts and linked runs.
- [ ] Final independent parallel code reviews are resolved against the final pushed heads; required CI is green.
- [ ] PR titles/descriptions, operational docs and this checklist describe the final implementation without stale default-scanned claims.
- [ ] Any authorized production rollout is observed separately, with report commit, site deployment, counts, filters and remaining backlog explicitly recorded.

## Rollback and operational fallback

Keep changes separable by layer. If the dialog/filter UI regresses, revert its commits to the last known working catalog while keeping the all-Skills default if practical; do not roll back durable scan progress. If a new report bundle fails validation, leave the previous valid public manifest in place and recover from validated checkpoints. A failed publication must not delete the previous bundle or its shards. If cadence or concurrency stresses acquisition providers, lower bounded admitted work while preserving checkpoints and pending state; do not erase attempt history to reset a queue.

Retain an operator command/runbook to inspect current runnable backlog, locate unacknowledged checkpoints, validate recovery inputs, rerun a small safe slice, and verify the resulting publication. Document exact permissions and retention bounds. The handoff must state the strongest achieved durability guarantee and the remaining in-flight hard-runner-loss window in plain language.

## Critique and implementation decision log

Initial draft: 2026-11-03. Source facts were inspected at the pinned starting heads above; production counts originate from the delivery audit and must be reproduced before throughput decisions. No implementation or production completion is asserted by this draft.

Independent critique round 1, GPT-6.1 Sol xhigh: accepted explicit recovery run/workflow trust provenance and same-repository clean-neighbor exclusion. Earlier source-confirmed critique was incorporated for independently bound partition counts, validation before partition reads, dynamic checkpoint timestamps, cleanup-failure survival, timeout/upload headroom, exact zero-findings semantics and independent test oracles. Reviewer found no other plan-level blockers after those changes. Report bundle verification remains hash/content-address based; only Directory/Discovery/Security discovery inputs are described as signed feeds.

Independent critique round 2, GPT-6.1 Sol xhigh: reviewer rechecked the revised plan and confirmed both round-one blockers resolved. No further plan-level blockers were identified. Exact slice size, remote recovery discovery/retention mechanism and manual budget choices remain implementation decisions that must be measured, recorded and verified before the corresponding completion boxes can be checked; the plan does not assert those decisions are already implemented.

For each later round, append reviewer identity/model, reviewed plan/head, material findings, accepted/rejected disposition with reasoning, and the pushed revision commit. For implementation adjustments, record only decisions that materially change semantics, failure boundaries, durability guarantees, measured budget choices or rollout order. Keep abandoned approaches out of the final product description.
