# Changelog

## [0.4.0] - 2026-10-06

### Changed (breaking)
- `submit_stark_evidence(proofs, *, task_hash, gn_weight, latency_ms,
  model_hash, output_hash)`: the API requires these fields; the old
  `submit_stark_evidence(proofs)` always got 422.
- `accept_validator_attestation(report_data, attestations, *, result)`: the
  API requires `result`; the old call always got 422.

### Added
- `FlopProofClient(..., http_client=...)`: an optional `httpx.Client` used for
  every request (connection reuse, or an in-process test client); its own
  timeout setting applies.

### API
- `POST /proofs` accepts `request.created_at` only as a timezone-aware ISO 8601
  date-time string; numbers, numeric strings, naive date-times and bare dates
  are 422.

## [0.3.0] - 2026-10-04

### Changed
- Proof requests and events are signed as domain-tagged version-3 messages:
  `FLOP/REQUEST/v3|room|nonce|text` and
  `FLOP/EVENT/v3|proof_id|type|payload_hash|nonce`. New proofs are version
  `"3"`; untagged proof requests are rejected (401).
- SDK `create_signed_proof` and `append_signed_event` sign the version-3
  formats; the SDK exports the canonical builders and parsers.
- `GET /proofs/{proof_id}` and `/verify` export each event's `nonce`.
- The offline verifier (`python -m app.verifier`) reads the proof `version`
  field to choose the canonical rules and treats an export without `version`
  (or with an unknown one) as `invalid`. `GET /proofs/{proof_id}` has included
  `version` since 0.1.0, so its exports are unaffected; a proof JSON file
  without `version` (for example one built or edited by hand) must be
  re-exported from `GET /proofs/{proof_id}`.

### Removed
- Root `client.py` (an old copy of the SDK); use `flop_proof_sdk`.

### Security
- Signed events can no longer be replayed with a new nonce (version 3), and
  version 1/2 proofs reject a repeated (canonical, signature) pair.
- The verifier reports `format_valid` and `replay_valid` per event and rejects
  version-3 messages in version 1/2 proofs.

## [0.2.0] - 2026-09-05

### Added
- API key authentication
- Request rate limiting with `429` responses and `Retry-After`
- CORS protection for the dashboard
- Security response headers
- Actor listing endpoint
- Secure Next.js dashboard API proxy
- GitHub Actions CI workflow
- Complete Python dependency manifest
- HTTP-level rate-limit regression tests
- Fresh-environment installation coverage

### Improved
- Proof and actor query performance
- SDK API-key handling
- Verification and security regression coverage
- CI support for API integration tests

### Security
- Protected API endpoints with `X-API-Key`
- Dashboard API credentials kept server-side
- Added browser security headers
- Added configurable request rate limiting
