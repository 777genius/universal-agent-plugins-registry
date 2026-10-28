# SkillSpector display reports v3

These reports describe bounded static analysis of immutable skill roots. They
do not certify plugins, change installation policy, execute plugin code, or
establish runtime behavior. Metadata review, static analysis, and a human
behavioral audit are different kinds of evidence.

## Baseline before rollout

The reproducible baseline is `baseline-2026-10-28.json`, measured from report
commit `6e8e8552a71f9d1a848758f5ea20d3f24f7ce8d1` (2026-10-28 07:11:32 UTC).

| Population | Count |
| --- | ---: |
| Catalog listings observed | 9,911 |
| Repositories observed / resolved | 1,115 / 1,068 |
| Selected immutable skill roots | 7,510 |
| Roots with any report | 3,824 |
| Complete analysis | 1,163 |
| Partial analysis | 2,622 |
| Failed analysis | 39 |
| Pending analysis | 3,686 |

The leading causes, counted once per source, were missing local references
(2,387), parser limits (626), incomplete analyzers (541), runtime limits (73),
and input limits (28). These overlapping counts are lower bounds because the
legacy publication capped diagnostics. Generic `limitations` also appeared on
901 sources. Discovery separately recorded 713 ambiguous names, 837 missing
skills, 36 unavailable repositories, and 161 unsupported sources.

The most recent publication reused 2,800 unchanged reports, including 1,981
incomplete reports; it added 1,024 reports. An unchanged timestamp denotes
cache reuse, not a measured fresh failed retry. Historical source acquisition
and analysis durations were not recorded and remain unknown. Of 29,158 raw
reported signals, only 19,811 entries were published; 189 reports were
truncated. The exact number of unique problems cannot be recovered.

Reproduce with a checkout of the report branch:

```sh
python3 scripts/measure_skillspector_coverage.py \
  --git-repository /path/to/skillspector-reports \
  --output /tmp/skillspector-baseline.json
```

## Evidence contract

Version 3 is published separately under `reports/skillspector/v3/`. The v1/v2
bytes remain available during migration. A reader falls back only after a
404; malformed reports, failed integrity checks, and network errors are visible
as unavailable reports.

Each record binds its repository, immutable revision, selected root and whole
tree digest to the scanner revision and analysis profile. `execution` records
process state, exit code and measured acquisition/analysis durations.
`coverage` retains file counts, per-analyzer results, explicit limitations and
the original upstream coverage findings. Execution failures are separate from
signals about the skill's contents.

Coverage also retains the scanner's reference entries and public ledger
diagnostics: source paths and positions, reference targets, evidence snippets,
reference status, and analyzer context. These additive arrays are optional for
earlier v3 fixtures and legacy records. A missing reference can point to a file
created by the skill, a dependency installed later, or a file in the caller's
project. Absence from the inspected tree alone does not establish which case
applies. The source excerpt remains available for review; the publisher does
not infer a safe runtime-generated file or a defective package from absence.
Bounded evidence truncation is explicit and keeps the report partial.

`reference-evidence-reprojection-2026-10-28.json` verifies the additive contract
against 18 retained full scanner reports: all 394 reference entries and 1,297
ledger entries survive, including their positions and snippets. Source,
scanner, profile, finding counts, grouping and the 3 complete / 15 partial
statuses stay unchanged. Planned external references remain inert context;
they do not turn a completed static scope into a failed inspection.

`raw_finding_count` counts upstream occurrences including coverage signals.
`finding_count` counts content signals; `finding_group_count` counts displayed
content groups. A group retains IDs, the full match fingerprint, evidence,
confidence, snippets, positions and occurrences. Different evidence is never
merged merely because its displayed title or message matches. Source size and
publication bounds remain explicit. A truncated projection is partial.

Automated severity is not human confirmation. Newly normalized findings are
`unreviewed`. The publication validator rejects claims of human confirmation.
Known scanner coverage rules are retained in `coverage.original_findings`;
confirmed concealed executable content remains a content signal even when it
also has incomplete inspection coverage.

Old reports retain their actual status and original scanner/profile. They are
historical during the v3 refresh, with unknown timing and incomplete grouping
evidence. A legacy marker cannot bypass current coverage checks.

## Independent counters

Catalog resolution (`catalog_coverage`, `source_states`, `plugin_states`) is
separate from analysis. An explicitly skill-free plugin is `not_applicable`.
Unresolved names retain candidates; unavailable sources retain historical
evidence without inventing a current revision. A previously verified exact
`SKILL.md` path that disappears at a newly inspected revision is `skill_removed`;
its original report remains historical. An inaccessible repository alone is
never evidence of deletion.

For a selected analysis population:

```text
selected = complete + partial + error + pending
reported = complete + partial + error + stale
stale <= pending
```

Historical reports are useful evidence for pending current sources. They are
never counted as current complete analysis. The same arithmetic applies per
plugin; a plugin with three completed and ten partial skills displays 3 of 13.

## Queue and execution rollout

The queue persists bounded attempt history, explicit next attempts and
separate new/retry/changed lanes. Content, scanner or profile changes create a
new scan identity. Complete matching results are reused without a seven-day
expiration; partial results are classified by cause.

The initial standard budget retains the observed 45-second internal workflow
and 60-second process limit. The extended profile has a 150-second workflow,
180-second process cap, and larger bounded input. Per-artifact limits remain
below the workflow limit, which remains below the actual remaining process
deadline. Controlled measurements and exception-specific evidence accompany
activation; raising a deadline does not claim to fix parser or missing-file
limitations.

The real two-round CLI run, including automatic extended retries and byte-exact
reuse of the other records, is documented in `CLI_E2E_2026-10-28.md`.

Cold Git acquisition is measured separately in
`COLD_ACQUISITION_2026-10-28.md`. Validated object IDs are fetched in bounded
batches before local byte and identity checks, preserving the whole analysis
root and the original preparation deadline. Discovery uses the same bounded
reader only for its validated `SKILL.md` candidates.

This work excludes Cisco, removal of Cloudflare, and changes to any plugin's
functionality. It adds no broad network or credential-rule suppression.
