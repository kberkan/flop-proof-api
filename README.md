# FLOP Proof API

A FastAPI service, Python SDK and offline verifier that record AI-agent work as
signed, hash-chained proof records and check validator-attestation evidence
against the FLOP Yellow Paper wire formats.

> **Independent, non-official project.** It is not built, reviewed or endorsed
> by FLOP Labs, and it is not the FLOP runtime. Official FLOP sources: the
> [Yellow Paper](https://flop.finance/intro/yellowpaper/) and
> [flop-labs/yellowpaper](https://github.com/flop-labs/yellowpaper).

[![Tests](https://github.com/kberkan/flop-proof-api/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/kberkan/flop-proof-api/actions/workflows/tests.yml)
· SDK [0.4.0](https://github.com/kberkan/flop-proof-api/releases/tag/sdk-v0.4.0)
· per-feature status and parity: [PARITY.md](PARITY.md)
· [CHANGELOG.md](CHANGELOG.md)

It is for developers who want a record of what an agent was asked, who acted
on it and what it returned, which a third party can re-check from an exported
JSON file without running the service.

### What it verifies

- Each proof request and event is Ed25519-signed by a `did:key` actor over a
  domain-tagged message (`FLOP/REQUEST/v3|…`, `FLOP/EVENT/v3|…`). The API
  rejects bad signatures; `/verify` and the offline verifier re-check them.
- Events form a numbered hash chain with SHA-256 payload hashes, so an edited,
  removed or reordered event in the middle of a proof is detected.
- Only the proof's creator, or a DID the creator delegated to in a signed
  `task.delegated` event, can add events, and a signed event cannot be replayed
  within its proof.
- Validator attestations: the 179-byte signed payload, the 275-byte SCALE
  encoding and the sr25519 signatures match the upstream wire vectors;
  distinct-validator quorum and `report_data` binding are covered by this
  repository's tests. Validators come from a local registry.
- `task_hash` v1, `channel_id` v1 and `report_data` v1 match the upstream
  `wire-format-v1.json` vectors (flop-labs/yellowpaper at `3c97bbc8d6`).

### What it does not verify

- That a model actually ran: there is no model execution or re-execution, and
  no TEE/DCAP quote or event-log verification. `quote_verified` and
  `event_log_verified` are claims signed by validators.
- STARK proofs: `/stark-batches` records the evidence as pending.
  `accepted=true` never means execution was verified.
- FLOP accounting: there is no `G_n` / `F_eff` meter. A supplied `gn_weight`
  only passes a reject-only throughput tripwire.
- Runtime or chain state: no settlement, payout, credit, runtime
  ActiveValidators or runtime ProcessedTasks. Replay protection is API-side.
- Parity with a live FLOP runtime. Items marked UNVERIFIED in
  [PARITY.md](PARITY.md) (for example `model_hash`, `output_hash`,
  DecodePolicy) are checked only by this repository's tests.
- That a proof is complete. The hash chain does not detect events removed
  from the end of a proof, and neither `/verify` nor the offline verifier
  checks for it: a closing `proof.completed` event and the export's `status`
  field are not used (the API only refuses new events after
  `proof.completed`). To detect truncation, compare the number of events
  (`events_checked` from `/verify`, `Events:` from the offline verifier) or
  the last event with a record kept outside the service.

### Quickstart

Python 3.12 or later. Work in an empty directory; the clone goes into
`flop-proof-api/` inside it. Start the API with its own database:

```sh
git clone https://github.com/kberkan/flop-proof-api.git
cd flop-proof-api
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export FLOP_API_KEY=dev-key FLOP_DATABASE_URL=sqlite:///./quickstart.db
.venv/bin/python -c "import app.models; from app.database import Base, engine; Base.metadata.create_all(engine)"
.venv/bin/uvicorn app.main:app      # http://127.0.0.1:8000
```

Open a second terminal in the same directory, the one that contains
`flop-proof-api/` (not inside the clone). `sdk-env/`, `quickstart.py` and
`proof.json` are created there. Install the SDK from the GitHub Release and
save the script below as `quickstart.py`:

```sh
python3 -m venv sdk-env
sdk-env/bin/pip install https://github.com/kberkan/flop-proof-api/releases/download/sdk-v0.4.0/flop_proof_sdk-0.4.0-py3-none-any.whl
```

```python
import json
import os
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flop_proof_sdk import FlopProofClient, public_key_to_test_did

client = FlopProofClient("http://127.0.0.1:8000", api_key=os.environ["FLOP_API_KEY"])

key = Ed25519PrivateKey.generate()
did = public_key_to_test_did(key.public_key())

proof = client.create_signed_proof(
    private_key=key,
    did=did,
    text="summarize the report",
    room="quickstart",
    nonce=uuid.uuid4().hex,
    request_id=uuid.uuid4().hex,
    created_at=datetime.now(timezone.utc).isoformat(),
)
client.append_signed_event(proof["proof_id"], key, did, "result.created", {"summary": "done"}, uuid.uuid4().hex)

print(proof["proof_id"], client.verify_proof(proof["proof_id"])["verdict"])

with open("proof.json", "w") as f:
    json.dump(client.get_proof(proof["proof_id"]), f)
```

```sh
FLOP_API_KEY=dev-key sdk-env/bin/python quickstart.py
# proof_… valid
```

Check the exported file offline. Run this from the same directory; it
enters the clone because the verifier is part of `app/`, not of the SDK:

```sh
cd flop-proof-api && .venv/bin/python -m app.verifier ../proof.json
# … Verdict: VALID
```

### Upstream

Conformance notes from this work were reported upstream:
[flop-labs/yellowpaper#112](https://github.com/flop-labs/yellowpaper/issues/112)
(rejection names and check order for `verify_turn_proof` vectors) and a
follow-up comment on
[flop-labs/yellowpaper#46](https://github.com/flop-labs/yellowpaper/issues/46)
(corpus errata).

---

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

Install the wheel from the GitHub Release:

pip install https://github.com/kberkan/flop-proof-api/releases/download/sdk-v0.4.0/flop_proof_sdk-0.4.0-py3-none-any.whl

Each release (tag `sdk-vX.Y.Z`) also carries the sdist and a `SHA256SUMS`
file. To verify a download, fetch the wheel and `SHA256SUMS` from the same
release into one directory and run `sha256sum -c --ignore-missing SHA256SUMS`.

Install from source instead (only the `flop_proof_sdk` package is installed;
`app/` is not part of it):

pip install "git+https://github.com/kberkan/flop-proof-api.git@sdk-v0.4.0"

or, in a checkout: `pip install .`

Basic usage:

from flop_proof_sdk import FlopProofClient

client = FlopProofClient("http://127.0.0.1:8000")

print(client.health())

## Signed proof

client.create_signed_proof(...)

The SDK signs the version-3 request message `FLOP/REQUEST/v3|room|nonce|text`.
`POST /proofs` accepts only this format and creates version `"3"` proofs.
`created_at` must be a timezone-aware ISO 8601 date-time string, e.g.
`datetime.now(timezone.utc).isoformat()` or `"2026-10-06T12:00:00Z"`.

## Signed event

client.append_signed_event(...)

The SDK signs the version-3 event message
`FLOP/EVENT/v3|proof_id|type|payload_hash|nonce`, so the nonce is signed.
`room`, `nonce` and `type` must not contain `|` or control characters; `text`
is free. Proofs created before version 3 keep the old formats
(`room|nonce|text`, `proof_id|type|payload_hash`). SDK 0.3.0 and later sign only the
version-3 formats. See `docs/design/event-replay.md`.

## Evidence submission

client.submit_stark_evidence(proofs, task_hash=..., gn_weight=..., latency_ms=..., model_hash=..., output_hash=...)

client.accept_validator_attestation(report_data, attestations, result=...)

Both take every field the API requires (SDK 0.4.0; earlier versions omitted
them and always got 422). Hashes are 64-character hex strings and the counts
are integers.

`FlopProofClient(..., http_client=...)` accepts an `httpx.Client` used for
every request; the SDK tests pass the in-process FastAPI `TestClient` this
way, so each public method runs against the application without a server.

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

Current regression status: **846 passed**

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

Version: 0.4.0

Build with: python -m build (local builds go to `dist/`, which is not tracked).
Releases are built and published by `.github/workflows/release-sdk.yml` when a
tag `sdk-vX.Y.Z` matching the `pyproject.toml` version is pushed; the release
notes are the `CHANGELOG.md` entry for that version.
