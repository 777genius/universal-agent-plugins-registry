# Signed Directory 47: Project add failure classification (2026-11-11)

## Verified situation

- Public CLI `0.1.104` completed the independent six-client User/Project matrix on UAP post-merge `812cbfc0d77fd7cc6c7fc486fdd230d50403b8da` (run [43061348054](https://github.com/777genius/universal-agent-plugins/actions/runs/43061348054)).
- Registry publisher [43054449223](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/43054449223), workflow SHA `dd5614519738c0f4ded6bd001ce2fb48c0437223`, successfully signed and materialized sequence 47 but failed in catalog readiness at `project:add: ValueError`. Original sanitized failure ZIP `13878641963` contains no finer diagnosis. Its promotion, Pages, and final production observer were **skipped**. Sequence 47 is not certified production.
- The existing error format deliberately excludes raw child output, secrets, paths, and native logs. The original job printed no `managed CLI failure` marker; the exception may be sandbox preflight, response decode, User isolation, or response-contract validation. Do not infer which without a fresh exact-phase result.

## Scope and implementation

1. Add only fixed, predeclared, non-sensitive phases around the existing managed `command()` boundary: isolated child, exit status, JSON decode, foreign-state verification, cross-scope User isolation, response contract. Add `validate_add` for subsequent contract failures.
2. Add offline regression cases for multiple phase checkpoints, including intentionally private child output. Never serialize or print exception messages, native logs, environment values, OAuth tokens, filenames, or secret-bearing responses.
3. Keep production fail-closed: **no** changes to signature verification, trust keys, signed source, install permissions, project admission, foreign-state checks, immutable package pins, native transport checks, or the actual outcome gate.
4. Before promotion, obtain a new readiness result against the exact authenticated **sequence 47** and `0.1.104`. If a genuine mutation is found, fix it without accepting a fake PASS. If current-run execution requires an owner-reviewed protected environment, require that approval.

## Acceptance criteria

- Offline contract/CodeQL/validate CI PASS on the exact PR SHA.
- Independent review of the new error surface and staging/production provenance.
- A signed, integrity-checked normal publisher run or permitted **identity-bound retry** of sequence 47, with fresh credential-free catalog proof, attestation, protected promotion, Pages composition, and observer.
- Compare final production sequence/envelope and all immutable Marketing Kit dependencies to the signed ledger. Keep older successful sequence 46 distinct from the failed sequence 47.
- Never rewrite previously merged PR #775 or call its historical two-parent merge a squash merge.

## Review concerns

- **Security:** Even a failure marker could leak a path if derived from untrusted data. This plan restricts markers to hardcoded constants plus internal operation names; still check the resulting failure artifact.
- **Reliability:** Adding labels does not itself repair the underlying failure. Do not promote or publish on the strength of a diagnostic-only test; the next true readiness result must drive any fix.
