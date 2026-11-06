# Directory: single signed protocol

Owner decision: 2026-11-06. Research is not an authorization to migrate or republish.

## One Directory protocol (owner decision, 2026-11-06)

The only active Directory wire protocol and publisher is the existing signed
schema 1 at `registry/schemas/1/`. Keep its `schema_version: 1` marker,
Ed25519 signatures, exact immutable source pins, ledger sequence, expiry,
revocations, monotonic rollback floor, read-back and guarded publication.
Do **not** migrate or rewrite published snapshots, replace the trust key, add a
second feed, or implicitly promote User evidence into Project runtime proof.
Explicit Project placement is admitted locally by the UAP installer and native
client capabilities, independently of the signed source authority.

The unpublished experimental schema-2 reader, candidate signer, bootstrap
and JSON schemas were retired from the development tree after dependency review.
Historical plans and merged PRs remain available for research, not as an
active cutover plan. Future incompatible protocol changes require a new
specific owner decision and a separate compatibility/security review.

The production publication configuration and signed data remain unchanged.
