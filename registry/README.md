# Public plugin registry

The public directory is Git-native: there is no account database and every
addition or update is reviewed as a pull request. Built-ins remain the existing
26 local packages and keep their CLI short names. Every accepted product,
including an external product, has at least one globally unique short-name
alias for installation. An alias identifies the product; it does not identify
who packaged a distribution or grant official upstream status.

## Released client contract

`client-capabilities.json` is an exact copy of the UAP generator output from
the release pinned in `client-capabilities.lock.json`. It supplies client IDs
and canonical order to the Directory validators; it does not grant package
eligibility. Historical publication keeps its frozen client subset, including
for evidence records. No signed source or release is changed by synchronization.

Check the pin and generated schema enums offline:

```bash
python3 scripts/sync_client_contract.py --check
```

To update after reviewing a published CLI release, use its local UAP Git
checkout, exact release tag and independently verified full release commit.
The command refuses a moved local tag and reads the committed artifact from
that tag, updates the immutable pin and regenerates the enums; it never reads
the checkout's working copy or fetches mutable upstream content.

```bash
python3 scripts/sync_client_contract.py --from-uap ../universal-agent-plugins --release agentplugins-v0.1.108 --revision 8c3cfa28e332c533b0cc0845739c0275730a4285
```

The offline digest check proves integrity against the reviewed pin; it does
not authenticate a local repository or prove GitHub publication. Verify the
release and commit through the canonical UAP release before updating the pin.
Review the pin and generated diff together. `--write` regenerates schemas from
the already checked-in pin. Production rollout remains governed by the
[agent support synchronization plan](https://github.com/777genius/universal-agent-plugins/blob/15ee08c04905b68cf0598fd5ed050f03cbd26383/docs/plans/2026-11-14-agent-support-synchronization.md).

## Submit an external package

The review source is `registry/directory.json`. Before editing it, confirm that
the package at the proposed revision contains:

- a valid Agent Plugins 1.0 `plugin.json` with author and license metadata;
- a package `README.md`;
- at least one declared component: root `mcp.json` or `skills/*/SKILL.md`;
- no client-specific `.mcp.json` or generated `.codex-plugin` output.

Test the same immutable source users will install:

```bash
npx universal-agent-plugins add owner/repository@FULL_40_CHARACTER_SHA//path/to/plugin-name --target cursor --dry-run
```

Use a public GitHub repository and the exact lowercase 40-character commit SHA,
never a branch or tag. Then edit `registry/directory.json` in one focused PR:

1. Add a product with its stable identity, at least one unique short-name
   alias, categories, minimum capabilities, default distribution, and sorted
   distribution IDs.
2. Add a namespaced distribution such as `owner/plugin-name` and list that ID
   on the product. Its `kind`, `status`, and `packager` are reviewed claims.
3. Add an immutable release whose `package_source` is the exact
   `owner/repository`, full SHA, and normalized package path. Record its package
   version, components, manifest digest, and `agentplugins-tree-sha256-v1` tree
   digest.
4. Add the one-for-one entry in `release_policies` for that release sequence,
   including status, minimum installer version, supported targets, delivery,
   authentication requirement, and only evidence IDs already present in the
   Directory source. Every target must set `authentication` to `required`,
   `not_required`, or `unknown`. This describes whether normal use of that
   package/client binding requires the user to authenticate: use `unknown`
   unless reviewed documentation affirmatively supports another value, and
   never infer `not_required` from missing or failed OAuth evidence. Consumers
   treat `required` as `auth_pending` until the client or user attests that
   authentication completed. Manual ChatGPT UI activation alone is not OAuth.

For an update, append a new monotonically increasing release and matching
policy. Do not rewrite an existing release tuple or its package bytes; policy
status and current evidence may change through review.

Product identity, distribution provenance, and default selection are separate:

- The CLI resolves a product alias, then installs that product's reviewed
  `default_distribution`. Distribution IDs remain publisher-qualified.
- `kind: upstream` means official upstream provenance and is accepted only when
  `plugin.json` physically exists at the submitted path in the upstream owner's
  repository. Otherwise use `community_bridge` for a package built from pinned
  upstream source, or `community` for an independently packaged alternative.
  Directory acceptance does not make either one official upstream software.
- Active and historical product aliases stay reserved. A proposal that collides
  with or reassigns an alias owned by an official or community product is
  rejected; adding a distribution to that product grants no new product alias.
- Accepting an external distribution does not make it the default. A
  `default_distribution` change requires an explicit, separately reviewed
  promotion, so a new distribution cannot silently replace the current source.

Generate and verify the deterministic review files:

```bash
python3 scripts/build_registry.py
python3 scripts/build_registry.py --check
python3 -m unittest tests.test_build_registry
```

Commit `registry/directory.json` and any changed `registry/review-preview.json`
or `registry/review-search.json`. The legacy catalogs and flat index are frozen
and must not change.

## Pi compatibility rollout

Pi's native UAP adapter now handles Skills, stdio/HTTP MCP and Pi extensions
in both user and project scope, but the **current signed Directory policies
do not yet include Pi**. Support for a client in the CLI is different from
release-specific installation permission in the Directory. The
[Pi rollout plan](../docs/plans/2026-11-09-pi-directory-global-qualification.md)
covers 37 active policies, direct-source lifecycle evidence, and safe migration
from older pinned CLIs which would reject an unknown `pi` target. Do not
enable Pi in the signed catalog or label packages Pi-installable before
publication readiness and actual signed promotion.

## What validation means

Static schema and package checks at the pinned revision are not endorsement,
ownership verification, a malware verdict, or proof of safe runtime behavior.
Do not add or promote evidence claims from the direct-package preflight:
`current_evidence` may reference only exact, reviewable observations already in
`registry/directory.json`, bound to that distribution, release sequence, tree
digest, client, and outcome. The builder does not run plugin code, install
dependencies, start containers, contact an agent runtime, or prove OAuth and
tool behavior. Evidence level and outcome remain separate from the target's
authentication requirement; neither a pass nor a failure rewrites that field.
