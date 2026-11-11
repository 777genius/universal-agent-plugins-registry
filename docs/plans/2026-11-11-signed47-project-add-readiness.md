# Signed Directory 47: Project add failure classification (2026-11-11)

## Verified situation

- Public CLI `0.1.104` completed the independent six-client User/Project matrix on UAP post-merge `812cbfc0d77fd7cc6c7fc486fdd230d50403b8da` against production sequence 46 (run [43061348054](https://github.com/777genius/universal-agent-plugins/actions/runs/43061348054)). This remains sequence-46 evidence.
- Registry publisher [43054449223](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/43054449223), workflow SHA `dd5614519738c0f4ded6bd001ce2fb48c0437223`, successfully signed and materialized sequence 47 but failed in catalog readiness at `project:add: ValueError`. Original sanitized failure ZIP `13878641963` contains no finer diagnosis. Its promotion, Pages, and final production observer were **skipped**. Sequence 47 is not certified production.
- **New independent reproduction:** diagnostic-only [run #43076789347](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/43076789347/job/130718583566), exactly based on signed47, explicitly reports `project:add:user-isolation: ValueError` with changed protected User HOME buckets `home:.claude`, `home:claude:.claude.json`, and `home:claude:backups`. This establishes genuine User-profile mutation in the publisher's Project-add environment, not merely an overly coarse failure label. The real native Claude Code CLI may initialize that profile during `plugin list --json` discovery. **Causation by a specific command or native version still requires reproduction.**
- The publisher pins native Claude Code **2.1.251**, whereas UAP's independently successful postmerge six-client E2E used **2.1.263**. This version difference is a testable hypothesis, **not a license to skip the isolation test**.
- The error format deliberately excludes raw child output, secrets, paths, and native logs; the new fixed phase labels remain useful for a follow-up true run but are **not** a fix for the observed mutation.

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

## Established cause and fixture correction (18:41 UTC)

The later read-only diagnostic PR #463 is closed without merging. Run [43076789347](https://github.com/777genius/universal-agent-plugins-registry/actions/runs/43076789347), job `130718583566`, completed with the fixed phase `project:add:user-isolation` and fixed categories `home:.claude`, `home:claude:.claude.json`, `home:claude:backups`. The installer returned success; the unchanged whole-User-state assertion rejected native first-start profile writes. This resolves the earlier uncertainty above.

The released .104 adapter's bounded native probe explicitly selects `CLAUDE_CONFIG_DIR=HOME/.claude`. The fixture's existing `HOME/.claude.json` seed is outside that selected global-config location. Swapping in another profile would change native User precedence and Project suppression semantics, so the correction initializes this fresh disposable fixture before public UAP.

Official npm `@anthropic-ai/claude-code@2.1.251` parent integrity matches the frozen workflow pin:
`sha512-eG+ZPPpW2Dbmnntf1Fz9/T9ewS8I8SKfc1tcU2PqSwmftfjRPP7BXPaCyLuZ8kvgTdiPnJi/2/JnTvTRieneEQ==`.
Its exact Linux-x64 optional dependency has verified archive integrity
`sha512-HJyCY1ynzlsBk+N02IJeBNNZmzyd43lMuff49IXtbUDGHlf2XFHcxwYJEWCwIW51J3Hl4MvrqM6Ye8PGpJRIiA==`;
the extracted executable's SHA-256 is
`fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7`.
Static embedded-source inspection identifies first-start time/version and generated machine ID, plus timestamped config backups (maximum five). This is static evidence, not local native execution or publication qualification.

The fixed preparation protocol is:

1. Preserve every existing User object, the whole Project workspace, shared state/store/cache and other client config. Use the exact bounded native environment and original selected Claude profile.
2. Run one genuine `plugin list --json` through the unchanged process-confinement boundary. Require exact successful exit, no stderr and a unique whole empty JSON array. Admit only new ordinary profile metadata and at most five timestamped backup JSON files; each is bounded before hashing/reading, contains only the three first-start fields, and backup values agree with the resulting profile. No auth, trust, settings, plugin or skill entries may appear.
3. Capture the complete User baseline once. Run one fixed second empty-list control and require the entire initialized profile and all protected state to remain byte/type/mode exact. Any instability fails; there is no retry loop.
4. Return that same baseline to the existing managed Project runner. Every subsequent public UAP operation retains the original whole-User guard without exclusions or restamping.

The isolation environment admits only the three necessary Claude probe settings as a group, with both background-disable flags fixed to `1` and an absolute canonical config path inside the private case. All original namespace, mounts, process cleanup, secret filtering, release pins, signatures and policy checks remain.

Offline regressions exercise actual fixture/snapshot/JSON/command-construction helpers, both control failures, foreign writes, unbounded/substituted objects, post-add mutation and sanitized failure artifacts. Hosted Linux confinement and the full signed47 publisher remain required; this fix's unit tests alone do not certify production.
