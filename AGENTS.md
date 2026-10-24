# Repository instructions

Before changing the package loader, client adapters, Directory, compatibility
claims, or release pipeline, read and follow
`docs/ECOSYSTEM_GUARDRAILS.md`.

In particular:

- treat published Agent Plugins schemas and specification text as the only
  normative portable contract;
- do not add UAP-only requirements or vendor-specific portable semantics;
- keep validation, installation, activation, OAuth, and runtime evidence
  separate;
- keep direct local and immutable Git installation independent of the Directory;
- run the exact pinned conformance corpus for loader changes;
- do not claim official status, endorsement, or certification;
- do not post to external discussions or contact maintainers without explicit
  project-owner approval.

## Where things live

- This repo: plugin and Skill directory data (`catalog/`, `registry/`) and the
  registry site (`site/`, Nuxt), published at
  https://777genius.github.io/universal-agent-plugins-registry/.
- Product CLI, landing and public docs: `777genius/universal-agent-plugins`.
  Landing: https://universal-agent-plugins.com/. Docs:
  https://universal-agent-plugins.com/docs/en/. The landing builds from this
  repo's signed feeds.
- Install buttons here must match the source kinds the released CLI accepts.
  Check `agentplugins skills add --help` or the release notes first. Today the
  released CLI accepts GitHub sources for Skills only.
