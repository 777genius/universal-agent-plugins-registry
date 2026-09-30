# Bundled runtime dependency remediation candidates

These are unpublished source packages, prepared from registry commit
`ac6806deb2fa77c618770a44d634c1f54e21639f`. They do not change the Directory,
published package sources, compatibility projections, or public runtime pins.

| Product | Existing runtime | Candidate runtime | Candidate package / next sequence |
| --- | --- | --- | --- |
| Context7 community distribution | `@upstash/context7-mcp@4.0.5` | `@upstash/context7-mcp@4.1.1` | `0.2.3` / `5` |
| Firebase | `firebase-tools@15.29.0` | `firebase-tools@15.32.0` | `0.2.4` / `6` |
| HubSpot Developer | `@hubspot/cli@8.14.0` | `@hubspot/cli@8.15.0` | `0.2.4` / `6` |

All candidates retain the existing exact security overrides. HubSpot also needs
same-major `js-yaml@4.3.2` and `moment@2.31.0`: updating its root alone leaves
affected dependencies. The new Firebase closure uses `protobufjs@7.6.6`; its
ignored script is accounted for by exact path/version/integrity. Optional
Firebase `fsevents` and `re2` remain omitted. HubSpot retains the existing exact
`esbuild@0.25.12` ignored-script and `fsevents@2.3.3` optional-script tuples.
New validator policy keys are additive; historical keys remain unchanged.

## Evidence and limits

`remediation-candidates.json` binds each complete candidate package, its exact
lock digest, the original audited spike lock digest, and the unchanged published
tree digest. Candidate lock names were converted from temporary spike names to
`agentplugins-runtime-<id>`; all dependency entries are identical. The reviewed
launcher and MCP arguments in the historical smoke records were unchanged.
The current candidate launcher includes the Windows bootstrap fix described below.

Each product's `audit-result.json` records zero known npm advisories observed on
2026-09-30. Audit results depend on the advisory database at that time and are
not a security certification. `npm-metadata.json` records exact root integrity
and repository metadata. Firebase and HubSpot advertise Git heads; their
source-to-artifact bindings have not been independently verified. Context7's
metadata provides no Git head. `npm-signatures-result.json` records successful
registry signature verification for every installed package in each candidate
closure, with npm attestation counts. Uninstalled platform-specific optional
packages and complete upstream source-to-artifact bindings were not verified.

`smoke-result.json` records successful credential-free `initialize` and
`tools/list` under installer-bundled Node `24.19.0`, using fresh temporary HOME
and project directories. Context7 returned 2 tools, Firebase 19, and HubSpot 22.
No tools were called. Firebase's MCP `serverInfo.version` (`0.3.0`) and HubSpot's
(`0.0.1`) are internal server versions, not the root CLI versions.

The first smoke launched installed npm entrypoints directly after `npm ci
--ignore-scripts` (with `--omit=optional` for Firebase).
`launcher-smoke-result.json` additionally records a successful cold bootstrap
through each complete candidate's unchanged reviewed launcher and MCP arguments,
with fresh plugin data, HOME and project directories. All three again returned
the expected tools. Neither smoke proves client activation, authentication,
provider operations, other operating systems, or every Node version allowed by
the package's declared engines.
Static package/runtime validation passed for all three candidates. Nine
existing tests covering historical runtime policies, exact overrides,
install-script accounting, and tampered integrity passed.

## Release boundary

The owner approved publication of these three updates on 2026-09-30, recorded
in PR #341. The candidate packages remain unpublished until the actual
publication procedure succeeds; this approval does not authorize an installer
release. A follow-up removed temporary candidate wording from package READMEs
and dated audit claims. HubSpot's manifest now sets `HUBSPOT_CLI_VERSION=8.15.0`
and `HUBSPOT_MCP_STANDALONE=false`: inspection of its integrity-verified npm
tarball showed that ambient standalone mode otherwise selected an `npx`
subprocess with the stale `8.14.0` version. The launcher puts the
locked local CLI first on PATH. These follow-up tree digests are bound in
`remediation-candidates.json`; prior smoke records remain historical evidence,
not exact-tree platform qualification for the follow-up.

The first three-OS qualification (`36757638737`) exposed Windows
`spawnSync("npm.cmd")` failing with `EINVAL`. The unpublished candidates now
invoke `cmd.exe /d /s /c` with only fixed npm bootstrap tokens; plugin paths
remain separate cwd/env values and user MCP arguments remain direct Node argv.
The registry admits this exact reviewed launcher digest additively, preserving
all historical published launcher bytes. Fresh exact-source platform evidence
is required; the failed run is not qualification evidence for these new trees.

These packages are community distributions without bridge recipes. The
`upstream_bridge_promotion.py` path requires a watched, merged official upstream
Agent Plugin and currently materializes a Chrome DevTools bridge. It cannot
truthfully be used to promote these npm root updates. `build_bridges.py` also
requires pinned Git recipe provenance; no recipe or upstream maintainer proof
is invented here. The separate `upstash/context7` default distribution is not
changed by the community Context7 candidate.

Before moving a candidate into `plugins/<id>`, resolve the predecessor's current
`revision: null` source to its accepted immutable SHA while preserving its
recorded version/tree/manifest identity. Append a new release and policy using
the proposed sequence; never replace a prior release's digests with new bytes.
The exact candidate commit still needs independent review, required CI,
release-required provenance checks and platform qualification beyond the tested
Node 24.19.0 macOS bootstrap. Materialize and review compatibility outputs and the new
Directory release through the existing publication procedure. Publication
requires explicit owner approval. Nothing in this audit record is a released
or runtime-qualified Directory entry.
