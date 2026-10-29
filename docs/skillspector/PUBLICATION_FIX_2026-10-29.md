# SkillSpector report publication repair — 2026-10-29

Run [40829961888](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/40829961888)
completed preparation, all eight scan partitions, and assembly, then failed in
publication with `uploaded publication tree identity differs`. The published
report remained at `a0e74bc1ba3eccc928b4a313a5f7900356ef44c2`, generated
`2026-10-28T17:23:39Z`.

## Finding and correction

The error came from a compound check on the `POST git/trees` response: expected
SHA, `truncated: false`, and listing shape. It did not establish a SHA mismatch.
The exact failed artifact has 788 shards and four controls. Combining it with
the supported retained files produces 1,764 files, including 1,087 v3 shards.
The eighth bounded shard-tree write reaches a prefix of 1,024 immediate files.

Native Git independently computes that prefix as
`d4c2926c2ed7aa9334b6cae9da5fd2c14418cdab`. A public, nonrecursive GitHub
[read of this existing object](https://api.github.com/repos/777genius/universal-agent-plugins-registry/git/trees/d4c2926c2ed7aa9334b6cae9da5fd2c14418cdab)
returned that exact SHA, `truncated: false`, and all 1,024 expected entries.
Every path, mode, type, and blob SHA matched the artifact-derived prefix.
The correct large prefix was therefore stored; a complete verification listing
is available through the nonrecursive read endpoint.

The original failed POST response was not recorded. Simulating a create-response
listing capped at 1,000 entries reproduces the exact reported error at this
1,024-entry prefix despite a correct native-Git SHA. This is consistent with
create-response truncation, but is not a captured production POST payload.
GitHub's [tree API documentation](https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28)
also permits a truncated create response and describes nonrecursive tree reads.

The transport now checks the POST SHA first, reads that tree by its exact SHA
without `recursive`, then checks the read SHA, an explicit `truncated: false`,
entry shape, and the exact expected entry set and count. Only a fully verified
prefix can become the next `base_tree`. Distinct diagnostics identify identity,
incomplete-listing, malformed-entry, and differing-entry failures.

Upload cardinality and byte limits, total transport deadline, known-tree reuse,
legacy retention, source revision checks, and the final non-force ref update
remain enforced. Inline staging is unchanged: it has at most 128 flat entries
per temporary tree and uses no incremental base.

## Verification

The focused transport, v3 coverage, and workflow suites passed **46 tests**.
The exact 12-module suite from `.github/workflows/skillspector-reports.yml`
passed **192 tests** in 15.129 seconds, using Python 3.12 with the workflow's
pinned `cryptography==46.0.3`, `jsonschema==4.26.0`, and `PyYAML==6.0.3`.

```sh
python3 -m unittest \
  tests.test_skillspector_acquisition tests.test_skillspector_contract \
  tests.test_skillspector_coverage tests.test_skillspector_coverage_v3 \
  tests.test_skillspector_discovery tests.test_skillspector_exceptions \
  tests.test_skillspector_profile_measurement tests.test_skillspector_publication \
  tests.test_skillspector_publication_transport tests.test_skillspector_records_v3 \
  tests.test_skillspector_reports tests.test_skillspector_workflow_v3
```

Regression tests use native `git mktree` and `git ls-tree` as the tree oracle.
They cover 1,087 immediate children with a truncated create response, independent
verification when the create listing is absent, forged/malformed POST identities,
bad GET identities, missing/true/nonboolean truncation flags, malformed entries,
wrong modes, missing entries, and duplicates. Rejected identities/listings stop
before another tree write. The prior 1,297-file retention fixture also passes.

The downloaded failed artifact, ID `12878984700`, ZIP SHA-256
`2102fe01526e94ae45ee4360aceb94ade8a66d0bc79939aab0ffad6aef2aa03d`, passed
the real publisher `check` command against source
`4c62a514b3802b51635b1803f058c93eea12002b`.
An offline replay then ran the complete real publisher against the exact artifact
and prior report tree, replacing only the GitHub boundary with native Git.
`git hash-object` independently checked all 792 artifact blob identities;
`git mktree`/`git ls-tree` verified the complete final tree. The replay retained
all 673 supported legacy files and all 720 prior v3 shards, checked main twice,
and reached a simulated single non-force ref update. No remote ref was changed.

The resulting root was `49ab122f1dc89faeb4f06cc965aa5d556c96b473`. Thirteen
bounded assembly writes had at most 128 request entries and 20,546 request
bytes; thirteen nonrecursive reads verified them. Eleven inline stages stayed
below the existing 8 MiB limit (maximum 8,380,014 bytes). Full replay took
50.286 seconds. Machine-readable input identities, code hashes, and results are
in [the replay evidence](publication-transport-rehearsal-2026-10-29.json).

Hosted CI and a fresh catalog publication after merging remain the deployment
verification. A fresh workflow must bind the report artifact to the then-current
main commit; the old artifact is retained as reproduction evidence.
