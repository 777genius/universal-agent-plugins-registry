# Discovery Index operations

Discovery is a signed static feed of conformant, unreviewed public Agent
Plugins 1.0 packages. It is not a database, package mirror, runtime endorsement,
or source of reviewed short names.

`.github/workflows/discovery-index.yml` runs three bounded schedules:

- every six hours: refresh known source heads and availability;
- daily: discover new public `plugin.json` paths;
- weekly: reconcile removed, renamed, transferred, or missed sources.

The scan job receives only GitHub's read-only job token. It never receives a
signing or publishing secret and never executes acquired package content. The
`discovery-publication` job receives a Discovery-only Ed25519 key plus the
repository-scoped publisher App. A complete candidate is appended to the
`directory-publication-ledger` branch and tagged immutably. Only then does
`discovery/latest.json` advance and the exact ledger tree deploy to Pages.

An incomplete scan, invalid signature, stale ledger head, non-atomic push, or
failed production observation leaves the last-known-good pointer unchanged.
The website reads that pointer at runtime, so a fresh index does not require a
frontend rebuild.

Validation uses a frozen source set for each scan. Repository identity, exact
commit SHA, availability and display metadata are resolved once and saved
atomically after each successful metadata batch. A resumed slice resolves only
missing repositories and validates only unfinished packages. Upstream pushes
are observed by the next scan, not by replacing inputs underneath this scan.
Unavailable repositories are also frozen for that observation.

The checkpoint remains bound to the original acquisition, implementation,
configuration and validation context. It expires 24 hours after the original
observation; neither a slice nor a retry renews that timestamp or the phase
wall budget. Completed package outcomes survive a yield, but an unfinished
individual blob read is not a durable result. A failed or budget-exhausted scan
must not be described as a completed or published index.

The reproducible 2026-08-27 scale spike is recorded in
`spike-2026-08-27.json`: 2,659 exact manifest paths across 967 repositories,
with no duplicate repository/path identities. Candidate validity is deliberately
not inferred from search; the first complete signed run records the authoritative
validation breakdown.

Production trust is pinned in `trusted-keys.json`. Discovery keys are separate
from reviewed Directory keys. Unreviewed records exclude ChatGPT because static
package conformance cannot prove the registered app binding ChatGPT requires.
