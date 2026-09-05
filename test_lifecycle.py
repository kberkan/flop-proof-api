import uuid
import base64
from datetime import datetime, timezone

from fastapi.testclient import TestClient
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.crypto import (
    public_key_to_test_did,
    sign_message,
    sha256_json,
)
from app.main import app


client = TestClient(app, headers={"X-API-Key": os.getenv("FLOP_API_KEY", "flop-dev-key-2026")})


def make_keypair():
    private_key = Ed25519PrivateKey.generate()
    did = public_key_to_test_did(private_key.public_key())
    return private_key, did


def create_signed_proof():
    private_key, did = make_keypair()

    text = "lifecycle test"
    nonce = "lifecycle-nonce"
    canonical = f"room-1|{nonce}|{text}"

    signature = sign_message(
        private_key,
        canonical.encode("utf-8"),
    )

    response = client.post(
        "/proofs",
        json={
            "request": {
                "request_id": f"lifecycle-{uuid.uuid4().hex}",
                "from_did": did,
                "text": text,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "signature": {
                    "nonce": nonce,
                    "sig": signature,
                    "canonical": canonical,
                },
            }
        },
    )

    assert response.status_code == 201
    return response.json(), private_key, did


def signed_event(
    proof_id,
    private_key,
    did,
    event_type,
    payload,
    nonce,
):
    payload_hash = sha256_json(payload)
    canonical = f"{proof_id}|{event_type}|{payload_hash}"

    signature = sign_message(
        private_key,
        canonical.encode("utf-8"),
    )

    return {
        "type": event_type,
        "actor_did": did,
        "payload": payload,
        "signature": {
            "nonce": nonce,
            "sig": signature,
            "canonical": canonical,
        },
    }


def test_pending_to_active():
    proof, private_key, did = create_signed_proof()

    assert proof["status"] == "pending"

    response = client.post(
        f"/proofs/{proof['proof_id']}/events",
        json=signed_event(
            proof["proof_id"],
            private_key,
            did,
            "agent.started",
            {"message": "started"},
            "nonce-active",
        ),
    )

    assert response.status_code == 201

    proof_response = client.get(
        f"/proofs/{proof['proof_id']}"
    )

    assert proof_response.status_code == 200
    assert proof_response.json()["status"] == "active"


def test_active_to_completed_and_locked():
    proof, private_key, did = create_signed_proof()

    start_response = client.post(
        f"/proofs/{proof['proof_id']}/events",
        json=signed_event(
            proof["proof_id"],
            private_key,
            did,
            "agent.started",
            {"message": "started"},
            "nonce-start",
        ),
    )

    assert start_response.status_code == 201

    completed_response = client.post(
        f"/proofs/{proof['proof_id']}/events",
        json=signed_event(
            proof["proof_id"],
            private_key,
            did,
            "proof.completed",
            {"message": "completed"},
            "nonce-complete",
        ),
    )

    assert completed_response.status_code == 201

    proof_response = client.get(
        f"/proofs/{proof['proof_id']}"
    )

    assert proof_response.status_code == 200
    assert proof_response.json()["status"] == "completed"

    locked_response = client.post(
        f"/proofs/{proof['proof_id']}/events",
        json=signed_event(
            proof["proof_id"],
            private_key,
            did,
            "after.completed",
            {"message": "should fail"},
            "nonce-locked",
        ),
    )

    assert locked_response.status_code == 409


def test_active_to_failed_and_locked():
    proof, private_key, did = create_signed_proof()

    start_response = client.post(
        f"/proofs/{proof['proof_id']}/events",
        json=signed_event(
            proof["proof_id"],
            private_key,
            did,
            "agent.started",
            {"message": "started"},
            "nonce-failed-start",
        ),
    )

    assert start_response.status_code == 201

    failed_response = client.post(
        f"/proofs/{proof['proof_id']}/events",
        json=signed_event(
            proof["proof_id"],
            private_key,
            did,
            "proof.failed",
            {"message": "failed"},
            "nonce-failed",
        ),
    )

    assert failed_response.status_code == 201

    proof_response = client.get(
        f"/proofs/{proof['proof_id']}"
    )

    assert proof_response.status_code == 200
    assert proof_response.json()["status"] == "failed"

    locked_response = client.post(
        f"/proofs/{proof['proof_id']}/events",
        json=signed_event(
            proof["proof_id"],
            private_key,
            did,
            "after.failed",
            {"message": "should fail"},
            "nonce-after-failed",
        ),
    )

    assert locked_response.status_code == 409
