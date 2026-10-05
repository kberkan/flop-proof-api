# FLOP Proof API

FLOP Proof API is an API and Python SDK for accepting and validating agent work and proof evidence as cryptographically verifiable structures, while producing independently auditable proof records.

The project provides a **proof validation and validator-attestation acceptance boundary** aligned with the evidence boundaries defined by the FLOP protocol.

> **Scope:** FLOP Proof API is not the full FLOP runtime or settlement runtime. Canonical FLOP runtime metering, execution infrastructure, and on-chain settlement remain outside this API.

## Guarantee Boundary

Evidence accepted or validated by the FLOP Proof API does not, by itself, provide the following runtime guarantees:

- FLOP runtime execution or model re-execution
- Actual TEE/DCAP quote or event-log verification
- Canonical FLOP `F_eff` / `G_n` runtime accounting
- TOPLOC or execution activation
- On-chain settlement, payout, or runtime credit
- STARK proof execution or verification merely because STARK evidence was accepted
- Runtime settlement or execution verification merely because validator attestations were accepted
- Execution verification, settlement, or credit merely because `accepted=true`
- Event authorship beyond the proof's own delegation rule: the API accepts an event only from the proof's creator or from a DID the creator delegated to in a signed `task.delegated` event, and `/verify` checks the same rule. It does not offer revocation (a delegation cannot be withdrawn) or sub-delegation. Replay of a signed event is rejected within its own proof (version-3 proofs sign the nonce; version 1/2 proofs reject a repeated signature, see `docs/design/event-replay.md`); this is API-side protection, not FLOP runtime ProcessedTasks state

**Test/parity boundary:** `IMPLEMENTED (internal-test-verified)` describes behavior validated by the API's own test suite; it does not mean independently verified byte-level parity with the FLOP runtime. External parity status is classified separately in `PARITY.md`.

## Features

- Ed25519 signatures
- DID-based actor identity
- Canonical signed messages
- SHA-256 payload hashes
- Tamper-evident event chain
- Result hash verification
- Artifact hash verification
- API-side proof verification
- Offline proof verification
- Python SDK
- Signed SDK methods
- HTTP error handling
- Validator-attestation acceptance
- Active-validator and quorum validation
- Persistent replay protection
- STARK evidence intake
- Canonical DecodePolicy v1 encoding and hash derivation
- `gn_weight` / `latency_ms` throughput tripwire
- Report-data binding validation

## STARK evidence boundary

The STARK endpoint is an **evidence intake / acceptance boundary**. It does not claim to implement a universal forward-pass STARK verifier.

Canonical FLOP runtime metering and on-chain settlement remain outside this API.

## API

### Health

GET /health

### List proofs

GET /proofs

### List actors

GET /actors

### Create proof

POST /proofs

### Append event

POST /proofs/{proof_id}/events

### Get proof

GET /proofs/{proof_id}

### Verify proof

GET /proofs/{proof_id}/verify

### Accept proof validator attestations

POST /proofs/{proof_id}/validator-attestations/accept

### Submit STARK batch

POST /stark-batches

### Accept validator attestations

POST /validator-attestations/accept

## Python SDK

Install the wheel:

pip install dist/flop_proof_sdk-0.3.0-py3-none-any.whl

Basic usage:

from flop_proof_sdk import FlopProofClient

client = FlopProofClient("http://127.0.0.1:8000")

print(client.health())

## Signed proof

client.create_signed_proof(...)

The SDK signs the version-3 request message `FLOP/REQUEST/v3|room|nonce|text`.
`POST /proofs` accepts only this format and creates version `"3"` proofs.

## Signed event

client.append_signed_event(...)

The SDK signs the version-3 event message
`FLOP/EVENT/v3|proof_id|type|payload_hash|nonce`, so the nonce is signed.
`room`, `nonce` and `type` must not contain `|` or control characters; `text`
is free. Proofs created before version 3 keep the old formats
(`room|nonce|text`, `proof_id|type|payload_hash`). SDK 0.3.0 signs only the
version-3 formats. See `docs/design/event-replay.md`.

## Verify

verification = client.verify_proof(proof_id)

## Offline verifier

python -m app.verifier /path/to/proof.json

## Tests

scripts/run_tests.sh -q

The script creates a temporary database, starts the API server on
127.0.0.1:8000 against it (`FLOP_DATABASE_URL`), runs pytest with the same
environment, and removes both afterwards; extra arguments go to pytest. It
refuses to start if 127.0.0.1:8000 is already in use. Running `pytest` without
the script uses `./proofs.db` and may write test data to it.

Current regression status: **711 passed**

## Test vectors

Some tests embed hash, preimage and signature values taken unchanged from
[`evidence/wire-format-v1.json`](https://github.com/flop-labs/yellowpaper/blob/3c97bbc8d6ba68cf2ea003ab88bc154aafdf105e/evidence/wire-format-v1.json)
in [flop-labs/yellowpaper](https://github.com/flop-labs/yellowpaper)
(commit `3c97bbc8d6`; Copyright (c) 2026 FLOP Labs). The corpus itself is not copied into this
repository. Its commit, URL, size and sha256 are pinned in
`tests/fixtures/flop-yellowpaper/SOURCE.json`, and
`python scripts/check_wire_vectors.py` downloads it and checks every embedded
value (listed in `_embedded_wire_vectors.py`) against it.

Upstream licenses the Yellow Paper specification text under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); whether that
license covers the `evidence/` data is unclear; asked upstream in
[flop-labs/yellowpaper#99](https://github.com/flop-labs/yellowpaper/issues/99).

## Canonical wire primitives

The API includes internally tested canonical v1 constructions for the following FLOP wire-level identifiers and commitments:

- `task_hash_v1` — canonical `FLOP/POUI/TASK` v1 domain/version construction with fixed-width hashes and `nonce:u64LE`.
- `channel_id_v1` — canonical `FLOP/COMPUTE_CHANNEL/ID` v1 construction with `genesis_hash`, `agent`, `miner`, and `nonce:u64LE`.
- `report_data v1` — SHA-256 commitment over the canonical report-data preimage followed by `00 × 32`, producing a **64-byte / 128-hex-character** value.

These constructions are verified against the available public-canonical wire vectors and covered by the repository regression suite.

This parity is limited to the deterministic wire-level primitives. It does **not** claim implementation of the full FLOP compute-channel runtime lifecycle, including channel opening, streaming `VerifiedTurn` receipts, Merkle/session state, settlement, disputes, or finalization.

The API also does not claim that canonical task/channel identifiers are currently enforced throughout an external FLOP runtime producer/validator pipeline. Those runtime-side bindings remain tracked separately in `PARITY.md`.

## G_n boundary

The API deliberately does **not** implement an independent FLOP counter.

The API accepts externally supplied `gn_weight` evidence, validates its cryptographic bindings and applies the reject-only throughput tripwire.

Canonical `G_n` / `F_eff` computation remains dependent on the external FLOP runtime metering implementation (`hp_poui::flop_meter`).

The API does not substitute a simplified formula such as `2 × P × N` for the canonical meter.

## Project boundary

The following capabilities remain outside this API implementation boundary:

- Canonical FLOP runtime `F_eff` / `G_n` metering
- Hardware TEE/DCAP execution verification
- TOPLOC execution activation
- Independent optimistic re-execution
- Runtime/chain settlement state
- On-chain compute-channel settlement

These boundaries are tracked in `PARITY.md`.

## Package

Version: 0.3.0

Build with: python -m build
