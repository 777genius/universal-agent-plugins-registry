# Directory v1: one wire protocol, isolated signed feed lineages

Owner decisions: 2026-11-06 (original legacy-only publication) and
2026-11-10 (narrow modern-client-only exception). A design decision is
**not** permission to sign or publish an unqualified release.

## Currently published: legacy v1

The existing Ed25519-signed Directory at `registry/schemas/1/` remains
the **only active production feed** until separately approved modern
publication completes. Its immutable snapshots, trust key, publication
ledger/sequence, protected promotion, revocations, expiry, rollback floor
and historical installation state must remain valid and unmodified.

**Never add `pi` to the shared legacy feed.** The released UAP CLI
0.1.89 does not recognize that client ID and would reject an entire
snapshot, including otherwise compatible packages. A minimum-version
field on a release does not solve snapshot-wide parsing. Do not require
old clients to understand Pi, do not revoke their feed, and do not
reinterpret historical signed policies or evidence.

## Approved direction, but NOT approved for publication: modern v1

The 2026-11-10 owner clarification supersedes the 2026-11-06 blanket
ban on a second feed, **only for a separate modern-client signed v1
lineage**. Both feeds retain the same audited `schema_version: 1` wire
contract and Ed25519 message/signature format. There is no Directory v2,
second installer engine or feature flag.

The modern feed must have its own explicitly trusted HTTPS origin,
reviewed public key and signed bootstrap, protected editor-controlled
signer and publication ledger, monotonic sequence/CAS and rollback
floor, revocation chain, cache namespace and feed identity. Never
configure a modern feed by pointing a legacy key, ledger, `latest.json`,
cache or production workflow at another URL. Old signatures must not
authenticate modern data, and modern signatures must not authenticate
legacy data. Tests must reject wrong-key, cross-feed, replay, rollback,
equivocation and tampering, including via restored caches and saved
dependency locks.

The existing schema-1 client policy has signed `scopes: ["user"]`.
Native **project** placement is a separate capability/authorization
decision of the installer; do not invent a signed Project scope that
the v1 reader rejects.

## Activation gates

1. Review exact immutable package sources, compatible mandatory Skills
   and MCP transports, and client-specific authentication. Preserve
   source, license and application-auth policy; unknown auth cannot be
   relabeled `not_required`.
2. Prove **72/72 real saved dependency eligibility** for all 36 active
   releases × user/project on Linux/macOS/Windows, including Marketing
   Kit → signed HubSpot CRM. Keep two suspended scope cases excluded,
   not passed. Direct `--no-save` and `--dry-run` are not substitutes
   for a managed signed dependency installation.
3. Validate positive Pi materialization evidence independently from
   source planning; fail closed for absent reviews, stale source HEADs,
   unresolved dependencies, incorrect receipts or unsupported clients.
4. Qualify a dedicated protected modern signer and bootstrap, separate
   origin/key/ledger/cache/rollback and signed-v1 parity with the
   legacy protocol. Key issuance, signature and promotion require the
   existing editor-controlled approval process; test keys are never
   production trust anchors.
5. Release a new UAP CLI with trusted automatic modern routing before
   advertising modern signed short-name installation. Public **0.1.102**
   supports Pi direct-source workflows, but **does not automatically
   route to a production modern feed**. Test user/project
   add/info/update/repair/remove and immutable source pins on all three
   OS, plus old CLI 0.1.89 warm-cache/live-legacy compatibility.
6. Verify exact signed snapshot, envelope, ledger, CDN/Pages and real
   production UI against the published sequence. No positive Pi
   catalog claim before this completes and post-merge E2E passes.

The legacy publisher `.github/workflows/directory-publication.yml`
and `registry/directory.json` must stay Pi-free. A separate protected
modern-feed implementation can reuse audited v1 serializer/validation
primitives, but must never silently repurpose legacy signing identity
or weaken anti-rollback. This document is a contract, not a claim that
the modern feed has been created, authorized or released.
