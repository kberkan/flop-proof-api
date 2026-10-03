# FLOP Protocol Research Report

## Verification Summary

The proof pipeline successfully verified:

- Request authenticity
- Delegation provenance

  > **Note:** The API does not verify delegation. Any DID with a valid
  > signature can append events, including `task.delegated` and
  > `result.created`, to any proof; see `PARITY.md`, Known Security Gaps.
- Execution lifecycle
- Result integrity
- Cryptographic signatures

This artifact is cryptographically bound to the FLOP proof.
