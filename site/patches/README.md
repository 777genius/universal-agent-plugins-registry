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
