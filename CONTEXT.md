# Teleport data model

- A transfer manifest records the recipient label, expiry, per-file metadata, received chunk indexes, verification state, and receipt state.
- A file record identifies a basename, byte size, SHA-256 digest, chunk count, and received chunk indexes.
- A chunk file stores exactly one bounded byte range. Its digest is checked before storage and the complete file digest is checked before receive.
- The recipient code is stored as a SHA-256 verifier, not as plaintext. The sender sees it once when creating the handoff.
- A receipt records recipient label, receive time, and expected file hashes after the browser reports matching downloaded hashes and the server rechecks stored bytes.
- Cleanup removes only a transfer folder after a valid receipt and another server-side hash check. Expiry blocks access but does not purge data.

## Invariants

- Transfer IDs are random strings; filesystem paths are derived only after strict ID validation.
- The service binds to loopback and validates Host, Origin, and a same-origin in-memory request token on state-changing operations.
- The recipient must provide both the expected name and high-entropy code. A name alone never grants access.
- Files in Teleport's runtime store are never the user's original selected source files.
- SHA-256 proves byte equality only. It does not encrypt data or prove who authored it.
