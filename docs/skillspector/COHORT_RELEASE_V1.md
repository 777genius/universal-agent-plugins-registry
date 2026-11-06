# SkillSpector 2.13.3: signed nine-source cohort release

Scope: only the pinned 7 Braids and 2 sitemap-manager Skill roots. This is
**static inspection completeness**, not a safety endorsement, permission to
install, or blanket conversion of the catalog's genuine Partial reports.

## Independent trust and publication boundary

- The existing `skillspector-reports` branch remains the complete canonical
  2.13.1 v3 catalog. Its Git commit and SHA-256 shards are **not** an Ed25519
  signed feed. Never relabel the manifest's scanner or remove its shards.
- The new versioned feed uses a separate `skillspector-cohort-releases`
  branch, `reports/skillspector/cohort/v1/latest.json`, immutable
  `releases/<sha256>.json` and `envelopes/<sha256>.json`.
- The release snapshot embeds the entire nine-source scanner result, content
  findings and independently authenticated current signed Community/Directory
  pin proof. It expires within **24 hours**; the consumer must fall back to
  the old v3 Partial after expiry, missing feed, signature failure or any
  current source ID/revision/tree-digest mismatch.
- The release envelope has its own
  `UAP-SKILLSPECTOR-COHORT-RELEASE-ED25519-V1` signature domain. Neither
  Directory signing authority nor the public CI test-only Ed25519 seed is
  authorized to sign a production cohort.
- CAS publication validates all old v3 shards, current main/report SHA, fresh
  signed Community/Directory pins and the prior cohort's complete signed
  history. It then writes immutable Git blobs, updates the separate branch via
  non-force ref mutation and reads back exact bytes.

## Required production key provisioning

The independently reviewed production **public** Ed25519 key is registered
in `registry/skillspector-cohort/trusted-keys.json` as
`skillspector-cohort-prod-v1`. Its presence does **not** prove that a private
seed has been installed or that any signed cohort is live.

Before the first main-only production workflow dispatch, a repository
administrator must verify that the matching private 32-byte seed is stored
as GitHub Actions secret `SKILLSPECTOR_COHORT_ED25519_PRIVATE_KEY`, and that
repository variable `SKILLSPECTOR_COHORT_SIGNING_KEY_ID` equals
`skillspector-cohort-prod-v1`. The signer derives the public key from this
seed and fails closed if it differs from the registered key. For future key
rotation, generate an independent Ed25519 key outside the repository and
register only its reviewed public 32-byte key and new unique ID. Never put
the private seed in an issue, PR, artifact, source file, CI log, environment
variable visible to untrusted Skill code, or chat message.

The signer must be a **main-only**, read/write-isolated GitHub Actions job:
untrusted Skill content is acquired as inert Git blobs, all scanner jobs run
without the private secret and without contents-write permissions, and only
the final publication job receives protected signing and write credentials.
No production job may sign only the boolean claim
`source_pins_verified_against_fresh_signed_feeds=true`; it must independently
re-fetch the current Directory and Community Ed25519 feeds and exact-match
the entire nine-source signed pin evidence immediately before signing.

## End-to-end release acceptance (all mandatory)

1. Qualify the exact main source revision: verify all published old v3 shards,
   nine existing current Partial witnesses, the pinned 2.13.3 scanner version
   and full no-LLM CLI results. Preserve security findings even when CLI exits
   1 for content risk.
2. Fetch and verify the two current signed Community/Directory snapshots,
   including expiry, package identity, full source SHA and source content
   digest. Reject changed pins and mismatched Directory precedence.
3. Create a bounded release and confirm separate Ed25519 signing, exact
   bytes/digest, nontruncated finding groups and the public trust key. Prior
   release history and source/report/main CAS leases must hold.
4. Publish on the isolated cohort branch, independently read its immutable
   Git commit/blob identities, and verify signed release bytes after publish.
   Never publish to the old v3 branch.
5. In UAP, authenticate the release key and match **each record** to the
   *current* old-v3 source ID/revision/path/content digest. Display signed
   Complete coverage while retaining the same risk findings; do not equate
   Complete with no security findings. All unrelated Partial remain Partial.
6. Run production Chromium desktop/mobile EN/RU and public Skills API E2E
   against the published commit, including invalid signature, expired release,
   renamed source, stale report and missing-feed fallback. Only then report
   visible improvement.

The protocol and CAS classes can be unit- and fake-transport-tested without
production secrets, but this is **not a substitute** for steps 1–6 in the
deployed environment.
