# Runtime security qualification

The [runtime remediation workflow](../.github/workflows/runtime-remediation-qualification.yml)
qualifies the active Context7, Firebase, and HubSpot developer plugin sources
against the reviewed
[October 29 candidate record](../registry/upstream-promotion-audit/runtime-dependencies/2026-10-29/remediation-candidates.json).
It performs a real cold installation and credential-free MCP discovery on
GitHub-hosted Linux, macOS, and Windows runners. A passing result applies to the
recorded source commit and exact package trees.

## Candidate record and historical evidence

The format-version-2 record points directly to `plugins/<product_id>`. It binds
each plugin version, manifest digest, package-tree digest, exact runtime
configuration, lock digest, and root npm tarball integrity. The harness allows
only the three reviewed product IDs and npm root package names. Runtime and
plugin versions come from the record and must exactly match the source
manifests and dependency lock; ranges and tags are rejected.

Each candidate also contains `expected_mcp`, with a `serverInfo` name and
version and a complete, unique `toolNames` list. These are reviewed acceptance
criteria, not observations of the new dependency closure. The MCP server's own
version need not equal its containing npm package version. The hosted run must
observe the exact expected identity and tools before it can pass.

The September 30 candidate copies, audit results, signature observations, and
launcher smoke results remain historical evidence for their original bytes.
The current harness does not load those smoke results or execute those frozen
candidate copies. Future source changes require an updated, reviewed candidate
record and fresh hosted results; an old passing run cannot qualify changed
bytes.

## What each hosted run checks

1. Validate every source identity and digest before executing a dependency.
   Require the reviewed launcher digest, exact Node `24.20.0`, and npm `12.0.2`
   with its separately pinned tarball integrity. Check that the source checkout
   matches the workflow's recorded commit.
2. Copy each exact package to a disposable root. Give it an empty project,
   home, configuration directories, npm cache, and plugin data. Keep npm
   lifecycle scripts disabled and reject an existing runtime or bundled
   `node_modules` tree. Only the small documented operating-system environment
   allowlist and reviewed manifest environment reach the child process.
3. Invoke the actual launcher, which installs the pinned runtime into plugin
   data. Send MCP `initialize`, `notifications/initialized`, and `tools/list`.
   Require the expected server identity, exact complete tool names, object
   input schemas, and clean protocol stdout. Make no tool calls.
4. Terminate the owned process tree and require bounded cleanup. Verify the
   installed runtime marker, root package version, lock bytes, and entrypoint.
5. Require a successful npm advisory audit with zero reported vulnerabilities
   in the installed scope. Verify registry signatures for every npm-audited
   installed registry package and record available verified attestations.
   Require the source and copied package trees to remain unchanged.

Firebase intentionally omits optional dependencies according to its reviewed
runtime policy. Advisory and signature evidence describes the installed scope;
it does not certify uninstalled optional packages. Available npm attestations
also do not establish complete source-to-artifact binding.

## Running and reviewing qualification

These local checks parse repository data and exercise inert test processes;
they do not install or run the plugin dependencies:

```sh
node scripts/qualify_runtime_remediation.mjs --validate-only
node tests/runtime_remediation_contract.mjs
```

The workflow runs for pull requests changing any of the three active plugin
directories, the current record, the harness, or the associated validator and
tests. It can also be dispatched on a reviewed branch. Dependency execution is
restricted to disposable GitHub-hosted runners; local and self-hosted runtime
execution is rejected. The workflow retains pinned actions, read-only
repository permissions, and checkout credentials disabled.

Review all three platform jobs and their
`runtime-remediation-<os>-<run_id>-<run_attempt>` artifacts. The
`runtime-remediation-evidence.json` artifact includes the candidate-record
digest, source commit, exact package/runtime identities, reviewed expectations,
observed MCP identity and tool names, audit/signature checks, and process
cleanup. Partial evidence is retained on failure. A missing platform result, a
failed check, an advisory, or a source/record mismatch prevents qualification;
do not replace those results with a historical success.

These checks cover installation, process startup, and unauthenticated discovery
under an empty project. They do not verify account access, authenticated service
operations, client activation, installer releases, or Directory publication.
Keep those claims and their evidence separate when reviewing the security fix.
