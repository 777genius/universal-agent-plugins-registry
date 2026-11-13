# Context7 locked npm security closure — 2026-11-13

Registry PR #451 platform audit found genuine moderate vulnerabilities on all three OS: `@hono/node-server 2.1.3` and `hono 4.13.12`. Firebase and HubSpot Developer passed; Pi's separate signed dependency refusal must not be hidden.

## Scoped change
- Pin reviewed `@hono/node-server 2.1.8` and transitive `hono 4.13.18` with npm SHA-512 integrities from already-reviewed UAP #895 and Registry Dependabot #477.
- Preserve `@upstash/context7-mcp 4.4.4`, exact `qs 6.16.1`, no new scripts or floating dependency. Keep canonical `plugins/context7` and generated `compat/openai` in byte-for-byte parity, and update the runtime lock's SHA-256 binding.
- Add the new exact lock digest to the source allowlist; keep historical reviewed closure for old signed immutable releases. No signing, live Directory or release policy changes.

## Review and E2E
1. Supply chain: verify package integrities and only the two targeted npm dependency updates; do not waive npm audit.
2. Architecture: preserve existing digest-bound allowlist/launcher and immutable historical policy; no new abstraction.
3. Runtime: require build_registry, OpenAI compat parity, Python tests, CodeQL and zero-advisory npm cold installs on Linux/macOS/Windows with original CI reports. A queued/skipped job does not count.
4. Release: stage a new immutable Context7 package release with source evidence, use protected signer/approval and independently verify production CDN. Source-only patch is not published acceptance.

This PR supersedes Dependabot #477, whose compat-only lock change fails canonical mirror validation and leaves Node server vulnerable.

## Immutable release migration for failing Registry validation

The first source-only patch intentionally failed two Registry unit tests with
`777genius/context7@6: reacquired tree digest differs from submitted metadata`.
That was the **correct** immutable-release safety gate, not a flaky test.

The actual signed sequence-47 snapshot contains Context7 release 6 (0.2.4)
bound to immutable source commit `d9c8d778200d51ae941d86bb69af23534cd1c8f7`, tree `sha256:f24e91e8635bf0ab455e5e0fa7504292621e6e9c8815cf3c84b009272b1724f8`.
The source Directory now preserves those exact historical bytes by resolving
release 6 to the already signed revision, marking it superseded, and **appending
new release 7** (0.2.5) with an unresolved current source until post-merge
review and protected signer binding. Sequence 7 uses:
- New package tree `sha256:635e673ec3aa8440a2826dc3a677ebe652b63e542db2e861b61d2df7f55e48b3`, independently recomputed using the
  canonical Go-compatible directory tree framing and validated by first
  reproducing release 6's exact prepatch digest.
- New manifest `sha256:1c1b8633e99d8ae10ed804b2c98532c4e08049b95f6229a6dd0b3746bdaea496` (`plugin.json` 0.2.5).
- New runtime lock `sha256:ba45adff6a9762c0cc75b450eeba6491b5f82b7e140f21d108974cf6521d68ee`, `@upstash/context7-mcp`
  remains fixed at 4.4.4.
- Canonical and OpenAI compat plugin version metadata 0.2.5, no floating
  tags or retroactive historical rewrite.

The source-only audit fixture selects candidate release 7 and uses the real
current locked bytes for 3-OS zero-advisory qualification. **This is not
production publication or proof of a signed release**; all release/promotion
gates still apply.
