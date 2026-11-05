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

## Native Nitro glob regression gates

Nuxt 4.6.4 upgrades to Nitro 2.13.6. The obsolete, version-scoped
`nitropack@2.13.4.patch` was removed rather than retaining a disconnected
adapter and unused pnpm patch binding. `site/tests/nitro-glob.test.ts`
still exercises actual Nitro server route discovery, public asset copy,
compression, and Cloudflare route metadata against the installed native
implementation. If the newer Nitro regresses these behaviors, the Pages
E2E fails; do not bypass those tests.

## Site-local Rollup defaults clone

`@rollup__plugin-node-resolve@16.0.3.patch` removes deepmerge from the pinned
Rollup resolver's ESM and CommonJS entrypoints. Its only use copies the static
`defaults` object before recursively freezing the exported `DEFAULTS`. That
object contains five arrays of strings and two booleans; Node's
`structuredClone` preserves the values and independent arrays. User-supplied
resolver options are handled separately and keep their existing behavior.

The version-scoped pnpm override removes the unused dependency edge, addressing
[GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4), for
which no patched deepmerge release is available. Node 22, already required by
the site, supplies `structuredClone`. The audit retains its existing low
severity threshold without exceptions.

Tests cover the exact recursively frozen exported defaults and actual Rollup
resolution with default and custom extensions through both entrypoints.
Remove this patch and its override together when an upstream release removes
the vulnerable dependency and passes these tests and the existing Pages gates.
