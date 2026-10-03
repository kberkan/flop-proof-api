# FLOP Protocol Research Report

## Verification Summary

The proof pipeline successfully verified:

- Request authenticity
- Delegation provenance

  > **Note:** Delegation is now enforced: only the proof's creator and DIDs
  > the creator listed in a signed `task.delegated` event may append events,
  > and the verifier checks the same rule. A delegation cannot be revoked, and
  > signed events can still be replayed with a new nonce; see `PARITY.md`,
  > Known Security Gaps, and `docs/design/event-authorization.md`.
- Execution lifecycle
- Result integrity
- Cryptographic signatures

This artifact is cryptographically bound to the FLOP proof.
