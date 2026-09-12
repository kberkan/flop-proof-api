# FLOP Proof API

FLOP Proof API, agent work ve proof evidence verilerini kriptografik olarak doğrulanabilir yapılar halinde kabul eden, doğrulayan ve bağımsız olarak denetlenebilir proof kayıtları oluşturan bir API ve Python SDK'dır.

Proje, FLOP protokolünün kanıt/evidence sınırlarıyla uyumlu bir **proof validation ve validator-attestation acceptance boundary** sağlar.

> **Scope:** FLOP Proof API bir full FLOP runtime veya settlement runtime değildir. Canonical FLOP runtime metering, execution infrastructure ve on-chain settlement bu API'nin dışında kalır.

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

pip install flop_proof_sdk-0.2.0-py3-none-any.whl

Basic usage:

from flop_proof_sdk import FlopProofClient

client = FlopProofClient("http://127.0.0.1:8000")

print(client.health())

## Signed proof

client.create_signed_proof(...)

## Signed event

client.append_signed_event(...)

## Verify

verification = client.verify_proof(proof_id)

## Offline verifier

python -m app.verifier /path/to/proof.json

## Tests

python -m pytest -q

Current regression status: **179 passed**

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

Version: 0.2.0

Build with: python -m build
