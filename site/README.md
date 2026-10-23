# Universal Agent Plugins site

Static Nuxt 4 frontend for the Universal Agent Plugins Directory.

Requirements: Node.js 22.13 or newer. The typed build adapter accepts the current
`../registry/index.json`, a deterministic review preview, or an exact published
signed snapshot without changing Vue components.

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm test:contracts
NUXT_APP_BASE_URL=/universal-agent-plugins-registry/ pnpm generate
NUXT_APP_BASE_URL=/universal-agent-plugins-registry/ pnpm check:links
pnpm test:browser
```

For site-only development and verification while the generated index is not
available, point Nuxt at the deliberately tiny fixture:

```bash
UAP_REGISTRY_PATH=tests/fixtures/registry.valid.json pnpm dev
```

Production publication passes `UAP_SIGNED_SNAPSHOT_PATH`. Pull-request review
deployments pass `UAP_DIRECTORY_PREVIEW_PATH`; the rendered site then carries a
prominent preview label and never presents unresolved data as production.

Production generation and build finalize every prerendered HTML page with CSP
SHA-256 hashes for its exact inline scripts and style blocks. The server-only
`server/plugins/csp.ts` emits the policy so client head hydration cannot reset
the finalized hashes. The policy is
delivered in HTML because GitHub Pages cannot configure response headers;
directives unsupported in CSP meta elements are intentionally omitted.
`check:generated` verifies the final policy and fails if inline content is
unauthorized or an unsafe source is present. A narrowly scoped
`style-src-attr` exception permits only the runtime CSS positioning used by the
accessible Reka UI popovers; inline scripts and style elements remain
hash-authorized.

`test:browser` serves that finalized output and exercises it in desktop and mobile
Chromium. `test:contracts` remains a fast source-level accessibility contract; it
does not claim screen-reader or other assistive-technology E2E.

The site emits no analytics or tracking requests. See `NOTICE.md` and the icon
README files under `public/` for copied/adapted code and mark attribution.

Security dependency overrides live in `package.json` alongside the existing
patched dependencies. pnpm 10 takes `pnpm.overrides` there in preference to the
workspace override map; keep one authoritative map so security pins take effect.
Nuxt 4.6.2 replaces the unsupported Nuxt 3 security baseline while `srcDir: '.'`
preserves this site's existing directory layout. Vue Router 5 matches Nuxt's
dependency, and ESLint 10 matches the current Nuxt ESLint module's peer range.
The dependency audit remains enabled without exceptions.
