# Credential-free candidate platform qualification

`runtime-remediation-qualification.yml` checks the exact PR head or dispatched
commit on `ubuntu-24.04`, `macos-15`, and `windows-2025` with Node `24.20.0`.
This is three OS runner targets, not a six-architecture matrix. The workflow
has read-only permissions, persists no checkout credentials, and builds no
installer. It runs on changes to its script/workflow, this audit subtree, or
the registry runtime validator and its tests. It can also be dispatched manually.

Each job processes the three candidates sequentially. The script independently
reproduces the framed package-tree digest, then binds the exact candidate list,
versions, manifest, lock, reviewed launcher and runtime identity to
`remediation-candidates.json`. Historical launcher smoke evidence supplies the
expected server identities and exact tool names; it does not qualify new bytes.

Every candidate is copied into a new disposable directory with fresh HOME,
USERPROFILE, config, npm cache, temporary files, plugin data and project. Child
environments inherit only PATH and explicit Windows loader variables. Cloud,
account and GitHub credentials are not forwarded. Empty plugin data and absent
runtime/node_modules are asserted before invoking the unchanged launcher with
the resolved candidate MCP arguments. The content-addressed runtime marker,
installed root version and unchanged lock/package bytes are checked afterward.

The MCP boundary permits only `initialize`, `notifications/initialized`, and
`tools/list`. Invalid/non-JSON stdout, errors, unexpected IDs, incomplete tool
sets, output limits and timeouts fail the check. No `tools/call` is sent.
After the complete tools/list response the harness explicitly terminates its
owned process tree and records the requested signal before dispatch. It does
not send EOF as a separate shutdown test: the upstream HubSpot CLI prints a
human-readable lifecycle line on nested server exit. This qualification proves
startup and tool discovery, not graceful EOF shutdown, and does not change that
upstream behavior. Pre-proof stdout errors and unexpected deaths still fail.
Cleanup errors are recorded, not thrown from event callbacks. An exact direct
ChildProcess PID fallback cannot turn failed tree cleanup into success; pipe
handles are released after a bounded five-second wait so failed cleanup cannot
leave the evidence phase hanging. HubSpot's manifest must bind `HUBSPOT_CLI_VERSION` to the
runtime version and disable standalone mode. This is a static check of the
subprocess fallback configuration: tools/list does not execute `hs` commands.

The trusted npm CLI is pinned to `12.0.2` and registry tarball integrity
`sha512-uIXokLlBj6FpNUTQX1PmT5pz7BlIN9QlixX+zdaSNHsd0qUXsbDLr50xzY6Sw7cJVr0uzHKDOle0swmPW/p5Qw==`.
Its published Node range includes `^24.15.0`. Installation uses setup-node's
bundled npm with scripts disabled; the exact package-lock integrity is checked
before executing the new CLI. A disposable PATH shim binds the launcher's npm
to that CLI. Windows uses an npm.cmd shim with the candidate's reviewed
`cmd.exe /d /s /c` fixed npm ci command; this harness does not rewrite the
candidate launcher or interpolate user paths/arguments into that command.

After cold materialization, `npm audit --omit=dev --json` must report zero
known vulnerabilities; Firebase also uses `--omit=optional`. Then `npm audit
signatures --omit=dev` (with Firebase's optional omission) must exit successfully
and verify registry signatures for every npm-audited installed registry package.
Evidence records verified available attestation counts. This is not verification
of uninstalled optional packages or a complete upstream source-to-artifact
binding; npm audit is an observation of the current advisory database.

`runtime-remediation-evidence.json` is uploaded per runner even on failure. It
records the exact source SHA, run/attempt, platform/architecture, Node/npm pins,
record/smoke digests, candidate identities, cold roots, per-phase results,
protocol/server/tool evidence, marker, audit counts, signature counts, exit
handling and bounded output digests. Raw stdout and inherited environments are
not persisted. Each completed candidate is saved independently; earlier evidence
survives a later failure. The workflow is green only when all candidates pass.
Review all three exact-SHA artifacts before claiming three-platform evidence.

Locally, only `node --check scripts/qualify_runtime_remediation.mjs` and
`node scripts/qualify_runtime_remediation.mjs --validate-only` are appropriate.
The latter reads and validates candidate bytes without installing dependencies,
starting MCP or touching user projects. Actual runtime mode requires both
`GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`; use the workflow's
`node scripts/qualify_runtime_remediation.mjs --output runtime-remediation-evidence.json`.

Passing this boundary does not prove client activation, authentication, provider
operations, every supported Node version, other architectures, Directory
publication readiness, or installer release qualification. Candidate publication
and installer release remain separate decisions under the existing procedures.
