# Marketing Kit — signed v1 Copilot client qualification (Draft)

## Owner-visible scope

Prerequisite for [UAP PR #775](https://github.com/777genius/universal-agent-plugins/pull/775).
The immutable root `777genius/marketing-kit` currently has **five** signed v1 User-source target clients; its three mandatory Notion, HubSpot CRM, and Playwright Bridge dependencies already include Copilot. This proposal adds only the Copilot **User source eligibility** entry to the existing immutable root release's reviewed policy, while preserving exact immutable package bytes, release sequence, digests, alias, dependencies, authentication=`required` and all other clients.

**No separate v1 Project grant.** The superseding owner decision [2026-11-05 lean Directory v1](https://github.com/777genius/universal-agent-plugins/blob/main/docs/plans/2026-11-05-lean-directory-v1-user-project.md) and merged [UAP #725](https://github.com/777genius/universal-agent-plugins/pull/725) establish that an explicit `--scope project` reuses signed v1 source identity, but requires separate client/adapter Project capability and ownership checks. This draft does **not** invent project-native E2E evidence, modify v1 schema, or activate v2.

## Fail-closed staging qualification

1. Extend the existing credential-free **real** managed Marketing Kit published-CLI 0.1.91 User evidence matrix from five to six clients, including Copilot. Preserve complete four-package closed dependency graph, all installation IDs, native state/lock and exact User add/locked replay/update/remove/doctor checks. The changed 20-entry cardinality is derived from `len(PINS) * len(CLIENTS)`. A genuine Copilot native refusal must fail, never be counted as PASS.
2. Regenerate review-preview deterministically. Do not mutate any frozen legacy catalog or flat index, and verify unchanged source releases/tree digests.
3. Run exact-head registry static tests, real signed-candidate catalog publication readiness and staged signed feed validation. Inspect original generated evidence, not only workflow success.
4. Only after a reviewable **signed** v1 Copilot root eligibility is successfully published through normal, protected, monotonic Directory/ledger/CAS paths, run [UAP #775](https://github.com/777genius/universal-agent-plugins/pull/775) on its exact new HEAD using the genuine published npm `0.1.102` plus real Copilot `1.0.105`, comparing original six-client Project/User reports, full dependency closure and native discovery, foreign-state guards, and required review outcomes. The published feed must reject missing/revoked child and wrong client/scope; no fake signature/unsigned injection or lenient E2E exception.
5. Existing [UAP #527](https://github.com/777genius/universal-agent-plugins/pull/527) provides previously merged genuine Copilot Project A/B/User and scripted-loopback native MCP initialize/list/call proof, **not** proof of this exact Marketing Kit signed closure or OAuth. Additional native stdio/Streamable HTTP tools/call qualification for the intended signed closure remains independent acceptance evidence.

**Hold this PR as Draft:** no owner-approved production release, signing, cutover or grant publication is performed by merely opening it. An actually green six-client signed Marketing Kit test and full independent review are required before accepting [UAP #775](https://github.com/777genius/universal-agent-plugins/pull/775). If the real User qualification fails at Copilot, fix the actual release/client incompatibility rather than adjusting assertions to pass.
