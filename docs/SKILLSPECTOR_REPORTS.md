# SkillSpector catalog reports

The landing site's Plugins and Skills lists display informational static results
from SkillSpector beside the existing LintAI assessment. These results do not
change installation policy or the signed Directory, Discovery, or Security feeds.

## Background operation

`SkillSpector static reports` runs daily at 03:19 UTC, when its implementation or
selection changes on `main`, and on manual dispatch from `main`. A read-only job
fetches selected immutable Git sources, materializes inert files, and runs the
pinned SkillSpector 2.13.1 commit with `--no-llm --format json --fail-on-incomplete`.
It does not execute skill scripts, follow transitive repositories, or apply
author-provided suppressions. Static dependency checks can contact OSV; this is
not an offline profile. No model credentials are needed or passed to the scanner.

`registry/skillspector-selection.json` is the bounded, reviewed selection (up to
64 exact skill roots). Plugin entries select individual skills within the
published plugin source; the result never covers every component of a plugin.
Use the repository, revision, and package path of the actual published Directory
release when adding plugin entries. `path` must point to a root containing
`SKILL.md`. For standalone skills, the displayed name is read from that file.

The current 28-root selection includes 15 skill roots from the three
skill-bearing package sources represented in published Directory snapshot 42:
Context7, Cloudflare, and Agent Notifications. It also covers 13 standalone
skills from the live Skills catalog, including Cloudflare's `turnstile-spin` and
12 of the first 14 popular listings observed on 2026-10-27. Standalone roots and
frontmatter names were inspected at their recorded commits; the Cloudflare
standalone source uses the bridge's published upstream revision. This is a
reviewed sample, not a scan of the entire provider catalog. MCP-only packages
have no skill root for this scanner, and revoked plugin releases are excluded.

Each configured entry produces a result, including acquisition and scan failures.
Limits are 256 files, 4 MiB of input, a 60-second scanner deadline per skill, and
8 MiB of scanner output. Each public record retains at most 32 findings and 16
errors, with the full finding count and an explicit truncation flag. Complete
results may be reused for less than 24 hours only when source identity, content,
scanner, and profile match; their original scan date is preserved.

## Publication and UI

A separate job validates the JSON again against the exact workflow source commit
and selection, then writes only `reports/skillspector/v1/index.json` on the
`skillspector-reports` branch. It never runs on pull requests. Publication rejects
older reports and non-fast-forward races. The landing site reads the fixed public
raw GitHub URL once per session, independently of site builds.

The report identifies its source workflow commit, scanner commit, static profile,
selection digest, and each skill's source commit and content digest. The consumer
shows loading, unavailable, incomplete, and failed checks explicitly; a missing
assessment in an available report remains neutral as “Not checked.” Plugin cards
without skills omit the SkillSpector indicator. Results
older than seven days or from a different plugin revision are historical.
Standalone catalog entries do not carry an immutable revision, so their matched
reports are explicitly historical even when recently scanned. Findings are
heuristics for review, and an absence of findings is not a safety guarantee.

## Local verification

Install the repository's pinned Python validation dependencies and the exact
SkillSpector commit from the workflow, using its frozen lockfile. Then run:

```sh
python3 -m unittest tests.test_skillspector_reports tests.test_skillspector_publication
python3 -m scripts.skillspector_reports \
  --scanner /absolute/path/to/SkillSpector/.venv/bin/skillspector \
  --source-commit "$(git rev-parse HEAD)" --output /tmp/skillspector/index.json
python3 -m scripts.publish_skillspector_reports check \
  --report /tmp/skillspector/index.json --source-commit "$(git rev-parse HEAD)"
```

The `previous` and `publish` subcommands use only the literal repository, report
branch, and report path defined in the publication script. Publication requires a
repository-scoped contents-write token and belongs to the trusted workflow.
