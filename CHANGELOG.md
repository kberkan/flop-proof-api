# Changelog

## [Unreleased]

### Security
- Small-order Ed25519 keys are refused as actor DIDs. Signatures under such
  keys can verify without a private key; previously a DID with one could
  create a proof and append to it, and `/verify` reported it valid. The API
  answers 422 ("Invalid from_did" / "Invalid actor_did", 400 "Invalid delegate
  DID" in a delegate list), and the verifier marks such events
  `signature_valid: false`, so the proof is invalid.
- The verifier decodes Ed25519 signatures strictly: a non-canonical base64url
  text of a valid signature (non-alphabet characters, non-zero padding bits)
  no longer verifies, matching the API's 422.

### Changed
- `POST /proofs` and `POST /proofs/{proof_id}/events` answer a malformed
  signature or signer DID with 422 ("Invalid signature encoding", "Invalid
  from_did", "Invalid actor_did") instead of 401; a well-formed signature that
  does not verify is still 401.
- The tests and `scripts/e2e_client.py` fall back to the same public test API
  key that CI and `scripts/run_tests.sh` use when `FLOP_API_KEY` is not set.

### Removed
- `research-report.md`, an unreferenced sample report from 0.1.0 whose
  statements no longer matched the API.

### License
- The repository is licensed under the Apache License 2.0 (`LICENSE`), with a
  `NOTICE` file; the dashboard's `package.json` declares
  `"license": "Apache-2.0"`. The upstream wire-format vector values embedded
  in the tests are not covered; see `NOTICE`. The SDK package carries the
  license from 0.4.1.

### Fixed
- `alembic upgrade head` on an empty database now creates the full schema. The
  baseline migration was an empty marker, so `proofs` and `proof_events` were
  never created and the first `POST /proofs` answered 500. A database created
  earlier with `Base.metadata.create_all` (no `alembic_version` table) already
  has every table; adopt it once with `alembic stamp head` (running
  `alembic upgrade head` on it fails with "table already exists", as before).
  `scripts/run_tests.sh` builds its test database with the migrations, and
  `test_migrations.py` checks that they produce the schema of `app/models.py`.

## [0.4.1] - 2026-10-08

This release does not change SDK code: `flop_proof_sdk` is the same as in
0.4.0. It adds license information to the package. The API and server changes
listed under [Unreleased] are not part of the SDK package.

### License
- The SDK is licensed under the Apache License 2.0. The package metadata
  declares `License-Expression: Apache-2.0`, and the wheel and sdist include
  `LICENSE` and `NOTICE`.
- Building the package needs setuptools 77 or later.

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

### Distribution
- The SDK wheel and sdist are published as GitHub Release assets (tag
  `sdk-v0.4.0`, with `SHA256SUMS`) by `.github/workflows/release-sdk.yml`
  instead of being committed under `dist/`.

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
