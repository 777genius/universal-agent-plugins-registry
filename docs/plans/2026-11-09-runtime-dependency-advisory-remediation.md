# Runtime dependency advisory remediation — isolated qualification

Date: 2026-11-09. Related issue: #453. Not a Directory or Pi capability change.

## Existing failure

A recent **live** three-OS npm advisory audit fails on unpublished candidate closures:
- `firebase-tools@15.34.2`: 9 advisories, including `archiver`, `glob`, `minimatch`.
- `@hubspot/cli@8.15.0`: 13 advisories, including high `follow-redirects` and nested `glob`, `minimatch`.
- Context7 passed and is intentionally **out of scope**.

The old October audit was valid only for its exact bytes and advisory feed. Never turn down thresholds or misclassify a failure as pass.

## Planned candidate and evidence steps

1. Probe stable published root versions `firebase-tools@15.35.0` and `@hubspot/cli@8.18.0`, keeping all existing reviewed overrides unless npm rejects them. This is a candidate probe, not a proven fix. Use real npm registry on GitHub-hosted Linux with scripts disabled and isolated temporary directories. Produce exact `package-lock.json`, root integrity, `npm audit` JSON and tool versions as artifacts; audit findings remain red.
2. Review the exact dependency graph and patched versions. If advisories survive, find a patch from a compatible root or minimally scoped, validated transitive override; no arbitrary version-range substitution.
3. Only after zero-audit candidate and lock reproducibility, commit each package `package.json` plus `package-lock.json`, update reviewed candidate record's root integrity, runtime lock digest, package tree and manifest digest atomically, and reverify package closure.
4. Three-OS `Runtime remediation platform qualification` must pass **every** exact-head existing check: real cold runtime setup, pinned npm signatures, advisory audit zero, MCP `initialize`/`tools/list` exact tools, no process leaks, and negative/fail-closed tests. Package versions and approval requirements remain explicit. Review security notes.
5. Do not edit signed historical releases, application auth, Pi client target policies, or producer signing/publishing permissions in this PR.

## Initial acceptance scope

One read-only GitHub Actions preparation workflow with the two exact root candidate versions, no repository mutations and no secrets. Publication is a separate protected operation after E2E. Keep PR Draft until every gate is satisfied. Avoid feature flags, migrations and duplicate engines.

## Reviewed HubSpot 8.18.0 upstream tool change (2026-11-10)

The owner clarified that vendor tool behavior belongs to HubSpot and approved
proceeding with **new-CLI compatibility as the priority**, provided that the
plugin README discloses the externally transmitting `submit-feedback` tool.
This is approval to review/qualify the vendor's tool inventory, **not** blanket
end-user consent to call a network/write tool on someone else's behalf.

The isolated 8.18.0 candidate adds exactly `search-knowledge-base` (remote
read-only lookup) and `submit-feedback` (potential external submission of
feedback text together with HubSpot account context and CLI version). The
candidate MCP E2E now checks the exact complete tool list, tool annotations and
feedback input contract. A tool-list PASS does not claim `tools/call` or logged-in
user confirmation. Upstream MCP instructions may encourage autonomous feedback;
MCP client approval/deny controls remain the user's responsibility. The
existing published `plugins/hubspot-developer/README.md` is immutable as part
of the old 8.15.0 source tree; `stage_runtime_remediation_preview.py` writes
the exact disclosure into the **new unsigned 8.18.0 candidate README**, to be
reviewed and retained when the new immutable release is qualified. See the
upstream 8.18.0 tool sources.

No signed release, old Directory feed, tool permission setting, or historical
package version has been changed as part of the isolated preview. Promotion
still requires exact lock digest validation, three-OS secure runtime E2E and
explicit newly versioned package publication; don't quietly mutate the old
signed runtime or misrepresent a candidate as already installed.

## Exact-head qualification and safe promotion checklist (2026-11-10)

### Four scoped review passes

1. **Integrity and advisories.** Retain original GitHub-hosted candidate ZIPs,
   verify their ZIP CRC, SHA-256 and exact manifest/lock bytes, and cross-check
   root package version, npm integrity, lock SHA-256, and real zero-vulnerability
   `npm audit`. Never edit the generated lock or re-resolve it in another npm
   version. In the unchanged **published** 0.2.5 source, the live audit still
   fails (9 Firebase and 13 HubSpot advisories); that is not a waiver candidate.
2. **Executable behavior.** On current source SHA
   `e997b3b9a04024393b08e7482c8d2f07e496219d`, the read-only
   [candidate run #42804832308](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/42804832308)
   passed both root probes and three disposable OS MCP previews: Context7
   (2 tools), Firebase (19), and HubSpot (24). Real cold launcher,
   `initialize`/`tools/list`, scripts disabled, exact tool annotations and
   feedback input schema, zero installed-closure audits and npm registry
   signatures are covered. These are **unsigned preview** results, not approval
   of a published runtime, installer activation, authenticated tools/call, or
   end-user feedback transmission. Any source commit requires fresh exact-head
   qualification; green results from earlier SHAs are not transferable.
3. **Privacy and permission boundary.** Preserve the *new version's* README
   disclosure of `submit-feedback` external data transmission and
   `search-knowledge-base` remote search. Do not infer consent from upstream
   MCP server instructions or from `tools/list`. Leave existing installer/client
   permission and authentication gates unchanged. No unauthenticated preview
   should call `submit-feedback`.
4. **Immutable release provenance.** Independently review source, audit
   evidence, signed prior release identity, new release metadata, target policies,
   and publication rules. A separate CodeRabbit review was requested; it does
   not replace human/security approval. Merge only with all required checks on
   the **final** HEAD and successful protected post-merge verification.

### Release delivery (not performed by the preview)

- Reacquire the five exact run artifacts through an approved GitHub workflow
  artifact client, verify original archive SHA-256/CRC and expected files, then
  place the exact verified `package.json` and `package-lock.json` bytes under
  each product's runtime directory. Keep Firebase `15.35.0` and HubSpot
  `8.18.0`; use npm 12.0.2/Node 24.20.0 for reproduction, scripts disabled.
  The lock SHA-256 are Firebase
  `2bcb58637dc986c4caf43571e4e509ab05048d1e5ef994061ec1b1935bc5e41d`
  and HubSpot
  `c024a5cba8b3584985cdae1df1f80f2135a014dda73ecc483ba4c4e6bebf5f7e`.
- Package the modified runtime and documented tool surface under **new plugin
  version 0.2.6**, never under old signed 0.2.5. Verify source bytes, package
  tree and manifest SHA-256 before recording them in the reviewed candidate
  record. Keep `context7` unchanged.
- For each existing distribution, the next release is **sequence 8** after
  existing 0.2.5 sequence 7. Before adding 8, reconcile the old unresolved
  source revision in the review Directory with the already authenticated,
  immutable signed sequence-7 source binding; only a byte-identical historic
  source revision binding is acceptable. Do not alter any historical version,
  tree/manifest digest, signed release identity, prior target policy or evidence.
  Append release 8 and its one-for-one policy; preserve authentication requirements,
  installer minimum and delivery semantics absent a separate reviewed change.
  Source revision for the new release follows the existing protected post-merge
  binding process; never pre-claim a signed/public release from ephemeral ZIPs.
- Regenerate and check deterministic Directory review outputs using
  `python3 scripts/build_registry.py --check` and existing tests. Remove
  preview-only staging machinery as appropriate when committed-source
  qualification supersedes it; do not leave a stale preview job failing against
  the newly published 0.2.6 source.
- Run the *committed-source* three-OS qualification on the exact final PR HEAD,
  independently examine all artifacts and CodeQL/security review, safely merge
  with normal branch protection, then verify the protected signed publication,
  immutable sequence marker/digest, consumer resolution and post-merge E2E.
  A successful preview is never sufficient to merge.

### Verified source delivery and release binding — 2026-11-10

The prior GitHub artifact-bytes transfer limitation is **resolved without a
write-token workflow**. The original current-head artifact ZIPs were read
through the approved GitHub artifact connector, independently SHA-256/CRC
verified, and their exact UTF-8 npm lock bytes re-read through the file
interface into the standard GitHub Git-blob API. Blob SHA-1 was verified
against the independently computed Git object hashes before any tree or
commit update:

- Firebase `package-lock.json`: SHA-256
  `2bcb58637dc986c4caf43571e4e509ab05048d1e5ef994061ec1b1935bc5e41d`;
  Git blob `9deefca7b9e17c095c095dd91f74eff33482cbad`.
- HubSpot `package-lock.json`: SHA-256
  `c024a5cba8b3584985cdae1df1f80f2135a014dda73ecc483ba4c4e6bebf5f7e`;
  Git blob `e7dfeada25d8e1fcb0d0fd25483ae7577b81787e`.

The protected ledger `directory-publication-ledger` signed snapshot 43
currently contains sequences **through 6** for Firebase and HubSpot, not
sequence 7. The review source already contains **unresolved, unsigned**
sequence 7 / plugin `0.2.5`. Do not call this particular review entry
previously published or signed. The exact predecessor package trees were
verified byte-identical between main `e8d3d940f2faa60ab8391156b279f8f71315b9d6`
and the PR source, so bind their existing sequence 7 entries to this
immutable predecessor commit without changing version, package path, tree,
manifest, or authentication claims. Supersede its install eligibility and
append sequence 8 / `0.2.6` with distinct exact runtime lock and package
digests. Signer validation and protected publication must still validate
the currently authenticated production feed and the monotonic sequence
transition; this note is not a claim that 0.2.5 was signed.

The versioned source commit must atomically include both exact locks, root
manifests, runtime descriptors, HubSpot privacy README/MCP pin, immutable
closure policy, candidate audit metadata, and Directory review source/output.
The stale read-only candidate-probe workflow and staging script should be
removed after committed-source qualification supersedes them: no plugin
version 0.2.5 may be rewritten and no preview result counts as a production
signature. Keep all three OS runtime audit/MCP/signature checks required.
After final HEAD CI and independent review, merge normally and verify the
protected signer, published snapshot, resolver, and consumer E2E. Never
weaken audit thresholds, change the old signed source revisions or publish
the preview directly.
