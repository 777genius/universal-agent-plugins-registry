# Modern schema-1 publication mechanics

## Purpose and authorization boundary

Continue the reviewed agent-support foundation in Registry PR #480, based on
`ab62dcb893418ec478c6e0c297290bc1037f1fa7`, in a separate branch. The canonical
cross-repository plan remains
[agent support synchronization](https://github.com/777genius/universal-agent-plugins/blob/15ee08c04905b68cf0598fd5ed050f03cbd26383/docs/plans/2026-11-14-agent-support-synchronization.md).

Complete reviewable, non-production publication mechanics after prepare/sign.
Reuse the existing CAS, composition and verification authorities. This change
does not provision a key, public issuer, protected ref, publisher App, environment
or production workflow. It neither publishes evidence nor creates eligibility.
The historical schema-1 feed and all existing production defaults stay intact.

## Fixed contracts and transitions

Extend the existing code-owned `DirectoryFeedContract` with production,
launch-approval and promotion-intent namespaces and the fixed reviewed deployment
contract location. The two singleton profiles remain the only accepted values;
candidate JSON, environment variables and public CLI flags cannot select one.
Modern commands require their reviewed public configuration at the fixed source
path. Missing configuration fails before remote mutation or network observation.

Thread the profile through existing CAS operations: atomic publication,
materialization, deterministic reassembly, immutable intent, monotonic production
marker and their exact readbacks. Preserve the existing source/main lease,
one-parent signed/materialized pair, bounded retries, lost-response recovery,
create-only sequence/intent tags and immutable prepared bytes.

Legacy reassembly continues to admit only its authenticated Discovery/Security
interleaving. The modern ledger does not own those feeds. It rejects their
appends, an unrelated Directory lineage and a moved modern publication head;
the caller must prepare again after a conflicting publication. It never reparents
an already selected sequence over a competing modern Directory publication.

## Composition and first publication

Thread the fixed profile through existing composition selection and freshness
rechecks. Modern production configuration pins its initial ledger seed. Before
the first deployment there is no production marker: selection requires an
approved immutable intent descended from that seed. A seed, prepared snapshot,
or signed sequence is not a production receipt.

The modern ledger is not a complete authoritative Pages tree. Deploying it
wholesale could roll back the legacy Directory, Discovery or Security feed.
Add a narrow composition operation that overlays only the fixed modern feed
subtree onto the existing approved legacy composition. Bind the two selected
plans and require both to remain current before a deployment handoff. Preserve
every other byte and path from the existing composition. Do not add a generic
multi-feed workflow framework or duplicate the production workflow.

Modern materialization is an exact same-tree, single-parent child of its signed
commit. Static site bytes remain under the legacy composition authority. The
combined private plan binds both selected plans, the exact composed Git tree
and a digest of both lineages' refs; selection checks refs before and after
composition. The observer takes its ledger identity from this rechecked plan.

The existing external Pages deployment receipt/checkpoint authority stays shared.
Actual protected workflow integration and modern marker advancement after a
successful deployment are a separately reviewed activation change.

## Verification and observation

Reuse current pointer/envelope/snapshot verification with the fixed profile and
current evidence from modern sequence 1. Modern verification and observation
entrypoints load the public key and origin from the fixed reviewed source paths;
they accept neither arbitrary key files nor arbitrary origins. Public issuer
configuration is deliberately absent from this change.

An exact observation compares the expected sequence, publication ID, source
commit and signed snapshot digest and binds the caller's selected ledger commit
in its receipt. Redirect refusal, byte bounds, canonical JSON, signature checks,
expiry, sequence floor and lineage checks remain mandatory. Observations prove
publication transport, not client installation, activation, OAuth or runtime.

## Files and verification

Implementation belongs in the existing feed contract, CAS, compositor,
verification and observer modules, with small fixed modern entrypoints. Keep
new deployment-contract validation separate only if needed to share the fixed
public authority across those existing consumers. No production workflow is
activated or copied.

Use disposable local repositories/remotes and existing test-only Ed25519 keys
for the complete prepare -> sign -> signed/materialized commits -> atomic CAS
-> exact readback -> immutable intent -> composition -> verified observation
receipt. Test the first publication and a subsequent monotonic publication.
The test issuer and transport fixtures must never enter production trust files.

Adversarial cases cover lost acknowledgments, exact reruns, conflicting refs,
wrong namespaces, rollback, divergent intent, foreign feed appends, changed
materialization bytes, stale composition, cross-key trust, missing fixed public
configuration and receipt identity mismatch. Verify both package and direct
script imports retain the same profile and error identities.

Run focused new tests and the existing CAS, compositor, publication and sequence
boundary suites unchanged. Then run the actual Python discovery command and
contract generation check required by repository CI. Record environment blocks
separately; do not substitute fake platform guards or treat queued CI as PASS.
Independent review and hosted checks must cover the final commit.

## Estimated size and remaining activation work

| Area | Estimated added/changed lines |
| --- | ---: |
| Production mechanics and fixed entrypoints | 650-750 |
| Disposable integration and adversarial tests | 650-900 |
| Plan and operational contract documentation | 100-150 |

Estimated complexity: 6/10. Target reliability after verification: 9/10.
Implementation confidence before review: 8/10. These are planning estimates.
The production estimate increased after accounting for first-publication
approval, preserving both authorities in one composed tree, atomic ref-state
comparison and the fixed-source observer. None introduces a public signed wire
contract. Deploying a whole modern ledger would omit independently advanced
legacy/Discovery/Security bytes, so a constant-only ref substitution is unsafe.

After this mechanics change, activation still requires the real independently
approved issuer/public key/origin, reviewed source and evidence pins, protected
modern refs and publisher credentials, environment approvals, and wiring into
the existing serialized Pages workflow and downstream readers. Genuine native
evidence must authorize actual published targets; support metadata never creates
those grants. The first live publication and readback need their own evidence.

## Corrections from implementation review

An additional review found two publication boundaries that the initial focused
suite did not cover. Before the modern split publication performs any remote
read or push, derive the publication identity from the already validated signed
append and reuse the existing deterministic marker validator. A valid append
cannot authorize an unrelated commit to replace main.

Modern composition must inspect the complete ledger from the reviewed bootstrap,
including intervals between approved targets. Starting at the newest selected
target could miss an earlier foreign append that changed historical snapshot
bytes. Keep the legacy traversal boundary and permitted interleaving unchanged.

Add regressions for a changed-tree marker, a marker for the wrong publication,
and a foreign historical-snapshot replacement between two approved targets whose
latest signed/materialized pair remains valid. Existing clean publication and
both-direction composition cases remain positive controls. Renew independent
review and execute the final focused/full hosted gates before merge; prior green
checks do not close these newly identified gaps.

## Final portable gate correction

Final head `031ee717` passed the focused publication suite and full Pages gate,
including the two review regressions above. Its required portable-catalog job
`132493871456` failed in one existing SkillSpector normalization assertion:
the fixture sampled wall time twice and compared adjacent seconds. The other
nine applicable jobs completed successfully; the portable observer step was
not reached and is not counted as passing.

Reproducing the original test with `reports.now` returning 16:17:39Z and then
16:17:40Z produces the same assertion failure. The test now creates one input
record and captures its timestamp before the real normalizer mutates that
record. It checks that this actual input timestamp is preserved, alongside all
existing coverage, finding-count, truncation and no-safety-claim assertions.
No production logic, clock tolerance, retry or cleanup suppression is added.
The same deterministic probe changes from one failure/two clock samples to
one pass/one sample; the affected module passes all 15 tests. Independent
review approved the exact test-only diff. The final corrected head must pass
all applicable hosted gates, including portable observation, before merge.
