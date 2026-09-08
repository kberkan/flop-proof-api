import uuid
import hashlib
import os

from app.crypto import (
    compute_task_hash,
    generate_test_keypair,
    public_key_to_test_did,
)
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
        nonce=nonce + "-delegated",
    )

    result_content = "Pytest signed SDK result"
    result_hash = (
        "sha256:"
        + hashlib.sha256(
            result_content.encode("utf-8")
        ).hexdigest()
    )

    task_agent = bytes.fromhex("aa" * 32)
    task_nonce = b"pytest-task-nonce"
    task_model_hash = bytes.fromhex("11" * 32)
    task_payload_hash = bytes.fromhex("22" * 32)
    task_commit_hash = bytes.fromhex("33" * 32)

    task_hash = compute_task_hash(
        agent=task_agent,
        nonce=task_nonce,
        model_hash=task_model_hash,
        payload_hash=task_payload_hash,
        commit_hash=task_commit_hash,
    )

    client.append_signed_event(
        proof_id=proof_id,
        private_key=private_key,
        did=did,
        event_type="result.created",
        payload={
            "content": result_content,
            "content_hash": result_hash,
            "task_hash": task_hash,
            "task_hash_inputs": {
                "agent": task_agent.hex(),
                "nonce": task_nonce.hex(),
                "model_hash": task_model_hash.hex(),
                "payload_hash": task_payload_hash.hex(),
                "commit_hash": task_commit_hash.hex(),
            },
        },
        nonce=nonce + "-result",
    )

    verification = client.verify_proof(proof_id)

    assert verification["verdict"] == "valid"
    assert verification["events_checked"] == 3
    assert verification["result_hash_valid"] is True
    assert verification["task_hash_valid"] is True

    for check in verification["checks"]:
        assert check["sequence_valid"] is True
        assert check["chain_valid"] is True
        assert check["payload_hash_valid"] is True
        assert check["canonical_valid"] is True
        assert check["signature_valid"] is True
