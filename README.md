# FLOP Proof API

FLOP Proof API, agent işlemlerini kriptografik olarak doğrulanabilir proof event zincirleri halinde kaydetmek ve bağımsız olarak doğrulamak için geliştirilmiş bir API ve Python SDK'dır.

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

## API

### Health

GET /health

### Create proof

POST /proofs

### Append event

POST /proofs/{proof_id}/events

### Get proof

GET /proofs/{proof_id}

### Verify proof

GET /proofs/{proof_id}/verify

## Python SDK

Install the wheel:

pip install flop_proof_sdk-0.1.0-py3-none-any.whl

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

Current regression status: 34 passed

## Package

Version: 0.1.0

Build with: python -m build
