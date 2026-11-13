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
