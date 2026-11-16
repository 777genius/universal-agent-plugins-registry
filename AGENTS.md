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

- This repo: signed directory feeds (`catalog/`, `registry/`). Its old site
  (`site/`) is retired. https://777genius.github.io/universal-agent-plugins-registry/
  shows a "has moved" notice.
- The Directory (plugin list and install buttons) is `landing/pages/plugins/` in
  `777genius/universal-agent-plugins`, published at
  https://777genius.github.io/universal-agent-plugins/plugins/. Landing:
  https://universal-agent-plugins.com/. Docs: https://universal-agent-plugins.com/docs/en/.
  The landing build consumes this repo's signed feeds.
- Install buttons in the Directory must match the source kinds the released CLI
  accepts. Check `agentplugins skills add --help` or the release notes first.
  As of `agentplugins` 0.1.91, `skills add` accepts GitHub repositories and
  HTTPS publishers that serve a complete `.well-known` Skills index (publisher
  installs take exact Skill names; repeat `--skill` for several Skills, and
  `*` is not supported). Verify against that release's help before relying on
  it for a newer version.

## Keep the Directory simple (owner, 2026-11-16)

The owner wants every plugin and Skill to work with every supported agent,
easily, for users and for maintainers. Do not over-engineer the Directory: one
feed, one signer and one implementation; no extra rules, flags, modes,
per-package gates or client-specific paths without a clear user benefit. Treat
a new client like the existing ones, derive its support from the client's
capabilities, and let the installer refuse clearly at install time. Keep at
most a tiny data list for known exclusions. Propose the simplest option first.
