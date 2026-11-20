# Pi Directory: manual-only genuine signed saved 72/72 acceptance

Status: **test-only Draft; no production Pi source, approval or PASS.** Related:
Registry [#479](https://github.com/777genius/universal-agent-plugins-registry/issues/479),
merged #520/#522, and docs/DIRECTORY_SINGLE_PROTOCOL.md.

## Scope and invariants

Extend the existing four-package Marketing Kit acceptance to the other active
Directory release policies without changing any trust boundary. A pinned
universal-agent-plugins@0.1.114 and native Pi 1.5.0 must use the **default
public signed origin**, no test keys, credentials, feed/transport overrides or
synthetic fixtures. A real signed Pi target is necessary for **each** root and
every locked dependency; an absent/unsigned target is FAILURE.

Six deterministic catalog shards on each of Ubuntu 24.04, macOS 15, Windows
2025 cover 36 active release policies × User/Project = **72 scopes/OS** (216
OS-scope executions in 18 jobs). One active policy in a suspended distribution
is excluded, not passed. If active policy count, version, or source changes,
fail closed for renewed review. Every case has two fresh isolated profiles and
proves:

1. Authentic CLI-signed info Pi entitlement and snapshot; exact authored
   source/release/digests; non-authored Registry-local revisions are checked
   against signed immutable digests, **not current CI HEAD**.
2. Managed saved add; complete immutable dependency lock, transitive edges,
   one signed policy for each dependency, signed feed/snapshot consistency,
   native saved list receipts/owner IDs, real Pi native file hashes, and
   read-only CLI doctor. Opposite scope remains unchanged.
3. Repeat add, update and intact repair each keep lock bytes, owner identities,
   native projection and uap.toml unchanged at that step; independent cold
   install --locked --yes preserves signed pins with new owners.
4. Remove the root and its managed children, assert no remaining owners or
   native projection, and preserve unrelated disposable profile files.

The workflow_dispatch positive jobs are manual-only, never a required PR
status check. No current run can be counted PASS while protected publication
sequence 48 lacks Pi. A future 18/18 job SUCCESS requires inspecting **original**
per-OS/shard logs and saved artifacts, all 72/72 per OS, no skipped/refused
cases; no synthetic signed-test cohort or 70/72 dry-run may substitute.

This harness does **not** validate live OAuth or remote MCP tool execution;
those remain separately reported activation/runtime gates. It does not sign,
publish, provision keys, change existing legacy snapshots, or authorize Pi
claims. The #479 distinct signer/origin requirement conflicts with the latest
single-feed/signer decision in the protocol; the **owner/editor must resolve
that explicitly**, along with protected publication permission, before any
positive manual dispatch. Preserve #513/#514/#517 denial. CDN/Pages/site parity,
negative cross-feed/rollback/replay/revocation tests, and CLI routing/legacy
compatibility remain independent production acceptance gates.

## Review / delivery

- Three review passes: catalog math and null-source pinning; receipt/native
  source-binding and edge cases; exact-head original Validate, CodeQL and
  policy jobs, external review comments and manual-only workflow safety.
- Original source CI and real native positive results must be reported
  separately. Queued/skipped are never PASS. Repair only demonstrated code
  defects; leave the PR Draft until these executed source checks and external
  review are complete.
- Estimate: 400 Python lines + 125 test lines + 62 workflow lines + 55
  documentation lines. Complexity 6/10; preproduction reliability 5/10;
  confidence in **production** lifecycle results 0/10 before authorized run.
