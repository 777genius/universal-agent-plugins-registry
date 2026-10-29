# SkillSpector publication repair — 2026-10-29

Scope: repair the bounded v3 report Git-object transport that failed in scheduled
run `40829961888`, without changing report interpretation, retained legacy files,
publication ownership, request limits, or commit/ref safeguards.

1. Reproduce the failing `POST git/trees` response contract with the failed
   assembled report artifact. Use native Git to independently verify tree IDs;
   distinguish response shape, truncation, identity, and entry failures.
2. Make the smallest correction justified by the response evidence. Keep exact
   tree identity and entry verification, bounded immediate-child uploads, and
   fail-closed handling of malformed or truncated responses.
3. Cover the observed API response and rejected corruptions with focused tests.
   Rehearse transport of the real artifact using native Git, then run the
   relevant SkillSpector test suite.
4. Record exact commands/results and remaining deployment verification. Submit
   worktree changes for review; the coordinating agent handles publication.

No changes to package contracts, runtime evidence, installation, or the retired
site are required. No remote writes are performed by this implementation task.
