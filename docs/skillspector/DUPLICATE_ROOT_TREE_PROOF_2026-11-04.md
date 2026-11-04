# SkillSpector: resolve identical duplicate Skill roots without guessing

## Immutable production evidence, 2026-11-04

The last established report (commit `db4fd15a`) had 26 selected historical `ambiguous_name` roots: 18 in `microsoft/azure-skills`, 7 in `google/agents-cli` and 1 in `juliusbrussee/caveman` (issue #417). At their exact immutable revisions:

- `microsoft/azure-skills@33200af2901bce6da01ce37498aa2b68e0c43f7c`, roots `skills/microsoft-foundry` and `.github/plugins/azure-skills/skills/microsoft-foundry`: their immediate regular blobs AND nested Git tree OIDs match (checked using GitHub Content API). This appears to be a mirrored copy.
- `google/agents-cli@f4e994044164ff6617f0799900dba0fc091ef0e3`, roots `skills/google-agents-cli-deploy` and `src/google/agents/cli/skills/data/google-agents-cli-deploy`: their immediate files and nested tree OIDs match.
- **Negative counterexample:** `juliusbrussee/caveman@2e068f735253cce28256744804785f01887d9646`, roots `skills/caveman` and `plugins/caveman/skills/caveman` differ (README versus `agents/` and `assets/`). Must remain ambiguous.

These spot checks need full exact-Git-tree proof before treating a selected root as current; matching `SKILL.md` alone is insufficient.

## Scope (only source identity discovery)

When exactly two candidate directories share a declared Skill name **and the catalog gives no explicit path**, read their **exact subtree Git object IDs** under the same vetted immutable commit and bounded current Git transport. A Git tree SHA represents all nested files, names, modes and blobs recursively. Only if both complete tree IDs are identical, choose a deterministic shortest/lexical root for scanning. Otherwise retain `ambiguous_name` and historical evidence unchanged. Never infer a path from slug or parent folder names.

Use the existing `bounded_tree` subprocess/deadline/output limits with a nonrecursive option, no dynamic code execution or new network client. No scanner profile/policy changes, no finding suppression, no forced Complete, no retry reset, no feature flags. Source selection includes the real path and revision.

## Required E2E

- Hermetic real Git object fixtures with **two truly identical nested directory trees** -> one selected current source; differing nested file, different mode, symlink or malformed Git tree -> ambiguous.
- Explicit catalog path keeps its authority even if names duplicated. Distinct duplicates still report all candidates.
- Immutable Microsoft/Google real-source canary or production run must prove at least some of the 25 formerly ambiguous selected roots become resolvable; Caveman remains ambiguous.
- Exact-head Python/CodeQL/security reviews, controlled pinned scanner -> assemble, SHA-guarded merge only after existing main publication, then new main 8/8 -> immutable publication and real UAP consumer readback. Do not assert that resolving 25 roots makes them Complete: actual scanning may still return Partial.

Stop if tree equality cannot be established inside the existing bounds. This is an evidence-backed discovery correction, not permission to choose arbitrary duplicates.
