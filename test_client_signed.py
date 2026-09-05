import uuid
import hashlib
import os

from app.crypto import generate_test_keypair, public_key_to_test_did
from client import FlopProofClient


def test_signed_sdk_e2e():
    client = FlopProofClient("http://127.0.0.1:8000", api_key=os.getenv("FLOP_API_KEY", "flop-dev-key-2026"))

    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    nonce = "pytest-signed-sdk-nonce"

    created = client.create_signed_proof(
        private_key=private_key,
        did=did,
        text="pytest signed SDK request",
        room="pytest-signed-sdk",
        nonce=nonce,
        request_id=f"pytest-signed-sdk-{uuid.uuid4().hex}",
        created_at="2026-09-04T20:30:00Z",
    )

    proof_id = created["proof_id"]

    client.append_signed_event(
        proof_id=proof_id,
        private_key=private_key,
        did=did,
        event_type="task.delegated",
        payload={
            "task_id": "pytest-task",
            "delegated_to": did,
        },
        nonce=nonce,
    )

    result_content = "Pytest signed SDK result"
    result_hash = (
        "sha256:"
        + hashlib.sha256(
            result_content.encode("utf-8")
        ).hexdigest()
    )

    client.append_signed_event(
        proof_id=proof_id,
        private_key=private_key,
        did=did,
        event_type="result.created",
        payload={
            "content": result_content,
            "content_hash": result_hash,
        },
        nonce=nonce,
    )

    verification = client.verify_proof(proof_id)

    assert verification["verdict"] == "valid"
    assert verification["events_checked"] == 3
    assert verification["result_hash_valid"] is True

    for check in verification["checks"]:
        assert check["sequence_valid"] is True
        assert check["chain_valid"] is True
        assert check["payload_hash_valid"] is True
        assert check["canonical_valid"] is True
        assert check["signature_valid"] is True
