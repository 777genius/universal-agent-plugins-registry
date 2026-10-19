# Site-local listhen TLS adapter

`listhen@1.10.1.patch` replaces only the certificate adapter in the pinned
published listhen package. Both Nuxt CLI and Nitro resolve this exact version.
The pnpm package extension adds pinned `selfsigned@5.5.0`; the dependency
override removes node-forge after its imports and certificate code have been
replaced. The dependency audit remains enabled without exceptions.

This addresses GHSA-86w9-cpqp-85rv while upstream node-forge has no patched
release. Certificate generation/signing uses maintained selfsigned/X509 and
Node crypto. Supplied PEM retains its shape. PFX is passed to native Node TLS,
and the actual Nuxt CLI, Vite, and Nitro consumers preserve those TLS options.
Generated PEM includes its issuer chain so a supplied CA can trust the listener.

This is a repository-local adapter, not a replacement listhen distribution or
a claim of full compatibility with arbitrary external listhen consumers.
`Listener.https` for PFX contains `pfx` and `passphrase` rather than extracted
`key` and `cert`. Modern AES PFX, empty passwords, and legacy 3DES PFX are tested.
Legacy RC2 PFX is not supported by the default Node TLS provider. Re-export it
with modern AES encryption; the adapter reports that action with the native
error. No legacy-provider flags or bespoke cryptographic implementations are
added. This site does not configure HTTPS or PFX inputs.

The behavior tests generate disposable certificates and PFX using OpenSSL.
They exercise HTTP, native HTTPS, encrypted PEM, SANs, CA chain trust, PFX,
ESM/CommonJS, and Vite's actual HTTPS consumer. Their artifacts are cleaned up.
Static generation/browser validation remains the existing Pages CI workflow.

Remove this patch only after a maintained upstream release removes the
vulnerability and passes the same TLS/site gates. Do not merely remove the
dependency override while retaining the adapter or ignore the audit advisory.

## Site-local Nitro glob adapter

`nitropack@2.13.4.patch` routes Nitro's three glob imports through a small
site-local adapter backed by pinned `tinyglobby@0.2.17`. The package extension
declares that dependency; the version-scoped override removes Nitro's globby
dependency and its fast-glob/micromatch/braces path. GHSA-vfj7-8cjw-p6xm has no
patched braces release. The audit remains enabled without exceptions.

The adapter preserves the nine Nitro callers' `cwd`, `absolute`, `dot` and
`ignore` options, files-only discovery, directory/brace expansion and result
deduplication. Ordered negative input patterns exclude only preceding positive
groups, so later positive patterns can reinclude public assets. Negation-only
input retains globby 16.2.0's catch-all fallback; empty input matches nothing.
Negated `options.ignore` entries remain exclusions, as in fast-glob; they are
distinct from ordered input patterns. This is not a general globby replacement:
no gitignore, custom filesystem, stream or synchronous API is exposed.

`nitro-glob.ts` is the handwritten source. The patch's `uap-glob.mjs` is
generated with pinned TypeScript 5.9.3, ESNext modules and ES2022 target for Node
22 compatibility. Tests compare its installed bytes with source compilation
and exercise actual Nitro route discovery, public copy/compression and Rollup
asset metadata using disposable fixtures. They need no full Nuxt build.

To regenerate after changing the source, run `pnpm patch nitropack@2.13.4`,
then compile with `pnpm exec tsc patches/nitro-glob.ts --module ESNext
--moduleResolution Bundler --target ES2022 --skipLibCheck --outDir <temp-dir>`.
Move the generated `nitro-glob.js` to the edit directory's
`dist/shared/uap-glob.mjs`, then run `pnpm patch-commit <edit-dir>
--patches-dir patches`. Run the focused test and frozen install/audit before
the existing full Pages CI gates. Remove this patch only when a maintained
upstream release removes the vulnerable path and passes the same behavior and
site gates.
