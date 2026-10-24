# Changelog

## [Unreleased]

### Security
- New proofs are version `"4"` (docs/design/proof-closure.md, D-C1 to D-C12).
  Every event signs the chain head it is appended to,
  `FLOP/EVENT/v4|proof_id|type|payload_hash|nonce|prior_head`, and requests use
  `FLOP/REQUEST/v4|room|nonce|text`. `POST /proofs` accepts only v4 requests
  (401 otherwise, no proof is written), so SDK 0.4.x and older can no longer
  create proofs. Events take `signature.prior_head`: required on version-4
  proofs, refused on version 1–3 proofs (400); a head that is not the current
  one gets 409 "Event prior_head does not match the current chain", checked
  last under the chain lock (403 comes first). `GET /proofs/{id}` and every
  append response include `chain_head`.
- `/verify` and the offline verifier report `prior_head_valid` per event
  (null for `request.created` and for v1–v3 events) and `closed`,
  `chain_head` and `event_count` per proof (`events_checked` is unchanged). In
  version-4 proofs, events removed from or reordered in an export, with the
  links recomputed, now make the proof invalid. In every version, an event
  after a closing event (or a second closing event) makes the proof invalid,
  with a `reason`.
- Not detected, by design: removing the last events of a proof, the closing
  event included (it then verifies as an open proof), including with an event
  the API rejected after checking its signature; and re-linking in version
  1–3 proofs. The offline verifier's new `--expect-head` / `--expect-count`
  compare an export with a head or count kept outside the service (exit 1 on
  a mismatch; the verdict is unchanged).
- Small-order Ed25519 keys are refused as actor DIDs. Signatures under such
  keys can verify without a private key; previously a DID with one could
  create a proof and append to it, and `/verify` reported it valid. The API
  answers 422 ("Invalid from_did" / "Invalid actor_did", 400 "Invalid delegate
  DID" in a delegate list), and the verifier marks such events
  `signature_valid: false`, so the proof is invalid.
- The verifier decodes Ed25519 signatures strictly: a non-canonical base64url
  text of a valid signature (non-alphabet characters, non-zero padding bits)
  no longer verifies, matching the API's 422.

### Documentation
- Corrected the event-chain claim in the README and the dashboard: a change to
  an event's signed content is detected, but events removed from or reordered
  in an export (or the database) with the chain links recomputed are not,
  because the chain hash uses no key and signatures do not cover an event's
  position. Events written to the database after a closing event, around the
  API, are not detected either. Dashboard wording: "Event chain (order and
  links)" is now "Event numbering and links", and the `/verify` evidence
  boundary no longer says it proves the chain's integrity.
- New row in `PARITY.md` (Known Security Gaps): "Export events can be
  removed or reordered and re-linked; events written after a closing event
  are not detected by the verifier". First recorded as open with three
  strict-xfail tests; now fixed for version 4 (see Security), with the
  remaining limits listed in the row.
- Added `docs/design/proof-closure.md`; implemented except the dashboard part
  (§8 C).

### Changed
- `POST /proofs` and `POST /proofs/{proof_id}/events` answer a malformed
  signature or signer DID with 422 ("Invalid signature encoding", "Invalid
  from_did", "Invalid actor_did") instead of 401; a well-formed signature that
  does not verify is still 401.
- The tests and `scripts/e2e_client.py` fall back to the same public test API
  key that CI and `scripts/run_tests.sh` use when `FLOP_API_KEY` is not set.

### Fixed (dashboard)
- Proof times were shown shifted by the viewer's UTC offset and without a time
  zone: the API sends UTC timestamps without an offset (the event `created_at`
  string is part of the event-chain hash, so the API keeps that form), and the
  browser read them as local time. The dashboard now reads them as UTC and
  shows local time with its offset (e.g. `08.10.2026 23:12:32 GMT+3`), with the
  UTC ISO value on hover; an unreadable value shows `—`.
- Browser tab titles: "FLOP Proof Dashboard", with the page name on each page,
  instead of the create-next-app defaults.
- Browser tab icon: an "F" tile matching the sidebar logo
  (`dashboard/src/app/icon.svg`) replaces the create-next-app `favicon.ico`.

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

## [0.5.0] - unreleased

The SDK for version-4 proofs. The API change it follows is listed under
[Unreleased]; SDK 0.4.x cannot create proofs against that API.

### Changed
- `create_signed_proof` signs `FLOP/REQUEST/v4|room|nonce|text`.
- `append_signed_event(..., nonce, prior_head=None, *, retries=0)` signs
  `FLOP/EVENT/v4|proof_id|type|payload_hash|nonce|prior_head` and sends
  `signature.prior_head`. Without `prior_head` it calls the new
  `current_head(proof_id)`, which reads `GET /proofs/{id}`, computes the head
  from the exported events (`created_at` used as exported text) and compares
  it with the export's `chain_head`; on a difference it raises the new
  `FlopProofChainError` and signs nothing.

### Added
- `HeadMismatchError` (a `FlopProofHTTPError`, status 409) with
  `signed_head` and `current_head`. `retries=N` re-signs on the new head up
  to N times, never for `proof.completed` / `proof.failed`.
- `build_request_canonical_v4`, `parse_request_canonical_v4`,
  `build_event_canonical_v4`, `parse_event_canonical_v4`, `chain_head`,
  `REQUEST_TAG_V4`, `EVENT_TAG_V4`; checked against
  `tests/fixtures/canonical_v4_vectors.json` (`test_sdk_canonical_v4.py`).
  The v3 functions stay.

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
