# Universal Agent Plugins: final architecture and E2E launch plan

Status: corrected, implementation-aware plan reviewed 2026-09-03.

This is the authoritative plan for the already completed repository split and the
remaining public E2E closure. It replaces older drafts that treated the rename,
release `0.1.36`, or Directory sequence 13 as future work. Historical evidence is
kept in Git history; this file describes the current contract and the shortest
safe path to completion.

## 1. Product boundary

The public product has two deliberately separate repositories:

| Repository | User-facing job | Authoritative contents |
| --- | --- | --- |
| [`777genius/universal-agent-plugins`](https://github.com/777genius/universal-agent-plugins) | Install and lifecycle manager | Go engine, Agent Plugins loader, client adapters, SDK, npm facade, releases, product README |
| [`777genius/universal-agent-plugins-registry`](https://github.com/777genius/universal-agent-plugins-registry) | Community directory | Reviewed packages, community bridges, signed Directory/Discovery feeds, static site, submission workflow |

The rename is complete and must not be repeated:

```text
plugin-kit-ai           -> universal-agent-plugins
universal-agent-plugins -> universal-agent-plugins-registry
```

The original GitHub repository IDs and commit history are retained. The Go module
path remains `github.com/777genius/plugin-kit-ai`; changing it is a separate,
breaking API migration and is not part of this launch.

### Non-negotiable contracts

- [`Agent Plugins 1.0`](https://agent-plugins.org/specification) `plugin.json` is
  the installed package authority.
- `mcp.json`, skills, and supported components are loaded losslessly before a
  client adapter is selected.
- `plugin.yaml` is legacy `plugin-kit-ai` authoring input only. It is not part of
  an installed Agent Plugin and cannot override `plugin.json`.
- Agent Plugins 1.1 is parse-only experimental coverage until its specification
  is stable. It cannot affect signing, short-name defaults, or production install.
- The CLI command is `agentplugins`; the npm facade is
  `universal-agent-plugins`. The facade delegates to the checked Go binary.
- `plugin-kit-ai` and `plugin-kit-ai-runtime` remain separate legacy npm
  packages; they are not silently republished under the facade name.
- A short name resolves only to a reviewed Directory default. Discovery results
  always retain publisher, repository, exact commit, package path, and digest.
- Targets are explicit. `--target codex,cursor` means those two clients; the CLI
  never silently installs into every detected client.
- Directory/Discovery are optional discovery services. Explicit local paths and
  immutable Git selectors continue to work when either feed is unavailable.
- Schema validity, preparation, installation, activation, OAuth, and runtime
  health are separate evidence states. No green schema check is a runtime claim.
- No OAuth, telemetry, package execution, Docker, or system-package installation
  is implicit.
- Multi-target planning is complete before mutation. If a selected target fails,
  changed targets are rolled back using the existing journal/recovery contract.

## 2. Architecture decision

### Selected: split product and registry, shared lifecycle engine

🎯 10/10   🛡️ 9/10   🧠 4/10  Approximate maintenance scope: 0-600 lines per
release/compatibility change.

The CLI owns parsing, planning, lifecycle, rollback, and client adapters. The
registry owns reviewed metadata and generated signed feeds. The registry never
duplicates the Go engine or npm facade.

### Rejected alternatives

1. **Move the complete engine and catalog into one monorepo.**
   🎯 6/10   🛡️ 7/10   🧠 10/10  Approx. 10,000-20,000 lines. This needlessly
   changes the Go module, legacy packages, release graph, and external consumers.
2. **Keep a second CLI implementation in the registry.**
   🎯 4/10   🛡️ 5/10   🧠 8/10  Approx. 1,000-3,000 lines. Two installers would
   drift in state, rollback, security fixes, and release provenance.

## 3. Source and trust model

The registry has three distinct source states:

- **upstream**: the pinned upstream repository itself contains the standard files;
- **community bridge**: generated `plugin.json`/`mcp.json` metadata built from a
  pinned upstream commit while an upstream packaging PR is pending;
- **local/exact**: a user-provided path or immutable Git selector, outside the
  reviewed short-name namespace.

A bridge is not a fork of upstream runtime code. Its signed record stores the
upstream URL, exact commit, package path, generated-file digests, attribution, and
bridge status. Promotion from bridge to upstream is a new signed Directory
sequence; historical bridge bytes are immutable.

The registry is the only writer of reviewed Directory and Discovery data. The
static Pages mirror is a byte-for-byte verified cache, not a second registry.
Discovery is an index of schema-conformant packages and popularity signals, not
manual certification or runtime proof.

## 4. Implemented baseline (verified)

The following facts were re-read from the public repositories on 2026-09-03:

- CLI main: `1401e44ac46b5efa870a29193299b4bd560a5060`.
- Registry main: `edb9150062276c7087513941a8d25311f6729953`.
- Public GitHub release: [`agentplugins-v0.1.37`](https://github.com/777genius/universal-agent-plugins/releases/tag/agentplugins-v0.1.37), immutable and non-draft, with six native binaries, checksums, and `release-manifest.json`.
- Release validation and six-platform run: `33725125998` (green).
- Pages integration run: `33731389982` (green), including product site and
  signed compatibility mirror.
- Registry Directory sequence 27: 26 products and 30 distributions.
- Registry Discovery sequence 27: 2,875 records. Latest pointers, padded
  snapshots, envelopes, search projection, and mirror metadata return HTTP 200;
  local signature verification passes.
- The CLI product page is branded **Universal Agent Plugins** and documents
  explicit multi-target commands such as `--target codex,cursor`.
- The public npm package currently remains `universal-agent-plugins@0.1.35`.
  `npm view` confirms `latest=0.1.35` and the renamed repository/homepage.
- Production CLI search was proven from a fresh home without downloading a
  package:

  ```bash
  AGENTPLUGINS_HOME=<fresh-temp-home> agentplugins search context7 \
    --format json --trust all --client codex
  ```

  It returned Directory/Discovery sequence 27, ten deterministic results, and
  reviewed `context7` first.
- Public npm `0.1.35` lifecycle was proven in a fresh canonical `/private/tmp`
  home for explicit `codex,cursor` targets: `add -> info -> update -> repair ->
  remove -> list`, with zero active installations at the end. Remove retained
  ownership-verified data and reported the explicit purge command.
- A Kiro-inclusive macOS dry-run failed closed before mutation because automatic
  Kiro ACP containment is unavailable on macOS. This is an intentional safe
  result, not a Kiro runtime pass.
- No real user project, OAuth credential, vendor account, Docker container, new
  VM, LXC instance, or snapshot was used. Heavy checks ran on GitHub-hosted CI;
  local checks used disposable homes and synthetic packages.
- Registry Dependabot PR [#156](https://github.com/777genius/universal-agent-plugins-registry/pull/156)
  is a separate `actions/setup-go` v7 dependency update. Its applicable checks
  are green, but it is not part of this launch closure and must be reviewed as a
  release-workflow change before merge.

## 5. Remaining launch gate

Only the npm cutover is still externally gated:

1. In npm package settings, rebind the single Trusted Publisher for
   `universal-agent-plugins` to repository `777genius/universal-agent-plugins`,
   workflow `agentplugins-npm-publish.yml`, environment `npm-agentplugins`.
2. Read the publisher configuration back before publishing. Do not use a token
   workaround and do not leave two publishers enabled.
3. Publish one immutable `0.1.37` package from the exact released main commit.
4. Verify npm provenance, tarball contents, repository/homepage metadata, and
   the `latest` tag.
5. Repeat the disposable lifecycle against `0.1.37` for explicit targets. Run
   successful Codex/Cursor lifecycle on supported runners; where Kiro ACP is not
   available, require an explicit preflight failure with zero mutation rather
   than claiming a runtime pass.

This gate requires npm owner/settings access. It cannot be completed safely from
GitHub or the local filesystem alone. No other code change should be made to
work around it.

## 6. E2E matrix

### Discovery and feed integrity

- Fetch `latest.json`, the referenced snapshot, envelope, signing key, and search
  projection from both public origins.
- Verify signature, key ID, sequence, source commit, digest, schema, and complete
  object closure before accepting a candidate.
- Verify a delayed/older event cannot replace a newer mirror; invalid, expired,
  mixed, or incomplete candidates leave the last-good mirror active.
- Confirm short-name resolution uses reviewed Directory only, while Discovery
  remains publisher-qualified and exact-SHA.

### Installer lifecycle

For every release candidate, use a new disposable home and test project:

```text
add -> info -> update -> repair -> remove -> list
```

Use explicit targets (`codex,cursor`, then a separate Kiro preflight where
available). Assert exact source commit, package path, tree digest, distribution
identity, client state, rollback journal, and final cleanup. Do not execute an
unreviewed Discovery package merely to test resolution.

Conformance-corpus results are CI evidence only. Do not post them to an external
discussion (including Agent Plugins conformance discussions) without an explicit
maintainer approval.

Kiro ACP `2.20.0` capability probes are recorded separately; capability probes do not replace the five-result launch matrix. Their sequence is not asserted until ordered external evidence exists.

### Failure and compatibility lanes

- one deliberate multi-target failure proves no partial client state remains;
- local path and immutable Git installs work with Directory/Discovery disabled;
- cold cache, warm cache, and offline cache preserve deterministic behavior;
- tampered pointer/envelope/snapshot, unknown key, expired snapshot, stale
  sequence, incomplete Discovery, and conflicting duplicate IDs fail closed;
- bridge-to-upstream promotion changes only a new signed sequence;
- old exact source SHAs remain fetchable from the compatibility history/mirror;
- cancellation or crash during mutation leaves journal recovery safe and
  ownership-verified cleanup complete.

## 7. Mirror and release rules

- Registry publication generates signed data from committed catalog inputs.
- A successful Registry Pages publish may wake the CLI mirror with a
  `repository_dispatch`; the payload is only a hint. The mirror re-fetches and
  verifies public bytes and never trusts the payload as authorization.
- The mirror has no signing key and cannot edit mappings. It stages a complete
  tree and swaps only after all checks pass.
- A delayed event can never lower the active sequence. The last complete signed
  snapshot remains available during a failed scan or deploy.
- `AGENTPLUGINS_DIRECTORY_ORIGIN` and `AGENTPLUGINS_DISCOVERY_ORIGIN` are test and
  private-mirror overrides. A remote response never rewrites production defaults.
- Generated snapshots are not hand-edited. Historical sequences, envelopes,
  release assets, attestations, and evidence are immutable.

## 8. Security and operational edge cases

The implementation must fail closed for:

- occupied or renamed repository identities, stale GitHub redirects, broken
  `uses:` references, missing Pages deployment, and npm publisher mismatch;
- unsigned, expired, mixed-key, stale, or partial feed trees;
- duplicate product IDs, duplicate package paths, bridge/upstream identity
  conflicts, and a bridge promoted without a new sequence;
- source repository transfer, archive, deletion, force-push, or a missing exact
  commit;
- unsupported client, missing activation capability, OAuth denial, cancelled
  browser flow, or unavailable Kiro ACP;
- permission errors, interrupted downloads, cancellation, crash, timeout, and
  process restart during multi-target mutation;
- `/tmp` versus `/private/tmp` identity differences on macOS;
- stale cache after a successful update, and remove retaining data until the
  user explicitly requests purge.

Never solve these cases by weakening source isolation, silently selecting another
client, executing package code during indexing, or accepting a partial mutation.

## 9. Verification commands

Run only against fresh clones, exact commits, and disposable homes:

```bash
gh api repos/777genius/universal-agent-plugins
gh api repos/777genius/universal-agent-plugins-registry
gh api repos/777genius/universal-agent-plugins/commits/main --jq .sha
gh api repos/777genius/universal-agent-plugins-registry/commits/main --jq .sha
gh run list --repo 777genius/universal-agent-plugins --limit 20
gh run list --repo 777genius/universal-agent-plugins-registry --limit 20
gh release view agentplugins-v0.1.37 --repo 777genius/universal-agent-plugins
npm view universal-agent-plugins version dist-tags repository.url homepage
```

Registry focused gates:

```bash
python3 scripts/build_bridges.py check
python3 scripts/build_registry.py --check
python3 -m unittest tests.test_build_bridges tests.test_build_registry
python3 -m unittest tests.test_workflow_contracts tests.test_run_launch_evidence_e2e
```

CLI gates include pinned Go contract tests, npm facade smoke tests, six-platform
release validation, public search, and the disposable lifecycle matrix. GitHub
Actions is authoritative for Linux/Windows and for platform-specific checks;
macOS-only failures caused by Darwin path or namespace semantics must be recorded
as environment limitations, not fixed by changing production contracts.

## 10. Acceptance checklist

- [x] Repository roles and names are final; original IDs/history are retained.
- [x] CLI remains Go-based with the compatible `plugin-kit-ai` module path.
- [x] Canonical npm facade exists only in the CLI repository; legacy packages are
      separate.
- [x] Agent Plugins 1.0 `plugin.json` is authoritative; `plugin.yaml` is legacy
      authoring input only.
- [x] Six native `agentplugins-v0.1.37` artifacts, checksums, and manifest are
      public and verified.
- [x] Directory 27 and Discovery 27 are signed, complete, public, and distinct;
      Discovery has 2,875 records at the recorded checkpoint.
- [x] CLI Pages product site and byte-for-byte compatibility mirror are green.
- [x] Public CLI Discovery search works without package execution.
- [x] Public npm `0.1.35` add/info/update/repair/remove proof exists for explicit
      Codex/Cursor targets in a fresh home.
- [x] Local/exact Git installs and fail-closed trust separation are covered by CI.
- [x] Multi-target planning, rollback, ownership cleanup, and no-real-project
      safety contracts are covered by focused tests and CI.
- [ ] npm Trusted Publisher is rebound to the renamed CLI repository.
- [ ] npm `0.1.37` is published with provenance and verified from a clean project.
- [ ] Post-publish `0.1.37` lifecycle evidence is recorded here.
- [ ] Final post-cutover smoke is green for GitHub, Pages, Registry, Actions, and
      npm at the same documented release tuple.

## 11. Delivery order from the current state

```text
re-read exact main/release/feed pointers
  -> npm owner rebinds Trusted Publisher
  -> publish immutable npm 0.1.37 with provenance
  -> clean-project multi-target lifecycle
  -> append exact evidence and digests in a small docs PR
  -> run required checks and merge
  -> announce only claims supported by the checklist
```

Do not create another registry, database, VM, snapshot, installer engine, or
parallel npm publisher for this launch. The next architectural expansion should
wait for a second real consumer or a confirmed repeated compatibility need.

## 12. Rollback and ownership

- Pause npm publication without deleting the last immutable package.
- Stop Directory/Discovery pointer advancement while serving the last complete
  signed snapshot.
- Stop the mirror job without deleting its last-good assets.
- Suspend a bad distribution in a higher signed sequence.
- Prefer a narrow workflow/package revert over renaming repositories back; name
  reuse can destroy redirects and make recovery worse.
- Keep all temporary homes, staging files, and test projects disposable and
  ownership-labelled. Remove only exact UAP-owned transient data after a run.

## 13. Evidence update template

When the npm gate is completed, append one short dated entry containing:

```text
CLI main SHA:
Registry main SHA:
GitHub release/tag:
npm version + provenance URL:
Directory sequence + digest:
Discovery sequence + record count + digest:
Pages/mirror verification:
Clean-home lifecycle result per target:
Rollback/failure-path result:
```

Do not include tokens, cookies, private filesystem paths, account names, or raw
OAuth material. A package being indexed or schema-valid must never be described
as manually runtime-tested unless the corresponding E2E evidence is present.
