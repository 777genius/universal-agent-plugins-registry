# SkillSpector immutable report read: bounded transient retry (2026-11-04)

## Reproduced production failure

[Run #41773051596](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/41773051596), `prepare` job `126434801659`, failed in **Read the previous immutable report snapshot** with `SkillSpector coverage publication failed: The read operation timed out` at 2026-11-04 06:51 UTC. No scans started. Later runs succeeded, proving transient transport behavior rather than a permanent incompatible report.

The v3 `raw_file()` function in `scripts/publish_skillspector_coverage_v3.py` downloads the immutable public report without API quota or credentials, but does not retry transient `urlopen().read()` exceptions. The neighboring GitHub transport already has a bounded three-attempt transient-classification policy.

## Strictly scoped correction

1. Add up to three bounded read attempts only for verified transient errors (e.g. socket/read timeout, connection reset, incomplete read) and HTTP 429/5xx. Reuse existing `GitHub._transient` classification; no new dependency, service, proxy, queue or feature flag.
2. Keep immutable `commit` URL, allowed-path validation, 30s per-attempt timeout, exact `maximum + 1` bounded bytes, semantic 404 behavior, no credentials, same integrity validation after read. Do not retry a malformed, overlarge, forbidden or other nontransient response. On exhaustion emit a fixed sanitized failure instead of raw exception text.
3. Add hermetic unit/integration-contract tests with an injected URL opener: recover from first timeout, exhausted retries, 503 followed by valid body, terminal 404, over-limit response, nontransient OS errors, and attempt/timeout limits.
4. Hosted exact-head Python validation, CodeQL, controlled pinned SkillSpector canary and two independent review passes. Merge only with SHA guard after current main production publication, then verify post-merge live scan/assemble/publish and public report read-back.

## Acceptance and exclusions

This fixes reliability of **transport** into the existing evidence pipeline. It neither changes scanner versions/profile identities nor creates Complete results from previously Partial references. Do not hide or relabel missing coverage. The unrelated scheduler proposal [#415](https://github.com/777genius/universal-agent-plugins-registry/pull/415) was closed after actual job timing showed its original premise was incorrect. Keep the current hourly cadence.

## Failure guardrails

An immutable URL does not mean safe to accept unvalidated content. Retry only whole idempotent GET reads; discard partial in-memory bytes from failed attempts; no incremental append. Existing SHA/size/JSON/schema checks must still reject altered artifacts. No retries of report publication ref writes.
