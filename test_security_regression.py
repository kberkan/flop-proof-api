
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.crypto import (
    generate_test_keypair,
    public_key_to_test_did,
    sign_message,
)
from app.main import app


client = TestClient(app)


def make_signed_request(private_key, did, request_id, text="security test"):
    nonce = f"nonce-{uuid.uuid4().hex}"
    room = "security-room"
    canonical = f"{room}|{nonce}|{text}"

    signature = sign_message(
        private_key,
        canonical.encode("utf-8"),
    )

    return {
        "request": {
            "request_id": request_id,
            "from_did": did,
            "text": text,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "signature": {
                "nonce": nonce,
                "sig": signature,
                "canonical": canonical,
            },
        }
    }


def create_proof():
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)
    request_id = f"security-{uuid.uuid4().hex}"

    payload = make_signed_request(
        private_key,
        did,
        request_id,
    )

    response = client.post("/proofs", json=payload)

    assert response.status_code == 201

    return response.json(), private_key, did


def test_invalid_proof_id_returns_404():
    response = client.get(
        f"/proofs/proof-does-not-exist-{uuid.uuid4().hex}"
    )

    assert response.status_code == 404


def test_invalid_proof_id_verify_returns_404():
    response = client.get(
        f"/proofs/proof-does-not-exist-{uuid.uuid4().hex}/verify"
    )

    assert response.status_code == 404


def test_tampered_signature_is_rejected():
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    payload = make_signed_request(
        private_key,
        did,
        f"security-signature-{uuid.uuid4().hex}",
    )

    payload["request"]["signature"]["sig"] += "tampered"

    response = client.post("/proofs", json=payload)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid request signature"


def test_tampered_canonical_is_rejected():
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    payload = make_signed_request(
        private_key,
        did,
        f"security-canonical-{uuid.uuid4().hex}",
    )

    payload["request"]["signature"]["canonical"] = (
        payload["request"]["signature"]["canonical"]
        + "|tampered"
    )

    response = client.post("/proofs", json=payload)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid request signature"


def test_completed_proof_rejects_new_event():
    proof, private_key, did = create_proof()
    proof_id = proof["proof_id"]

    event_data = {
        "result": "success",
    }

    from app.crypto import sha256_json

    payload_hash = sha256_json(event_data)
    canonical = f"{proof_id}|proof.completed|{payload_hash}"
    signature = sign_message(
        private_key,
        canonical.encode("utf-8"),
    )

    event_payload = {
        "type": "proof.completed",
        "actor_did": did,
        "payload": event_data,
        "signature": {
            "nonce": f"event-{uuid.uuid4().hex}",
            "sig": signature,
            "canonical": canonical,
        },
    }

    response = client.post(
        f"/proofs/{proof_id}/events",
        json=event_payload,
    )

    assert response.status_code == 201

    second_data = {
        "result": "second",
    }

    second_payload_hash = sha256_json(second_data)
    second_canonical = (
        f"{proof_id}|proof.completed|{second_payload_hash}"
    )
    second_signature = sign_message(
        private_key,
        second_canonical.encode("utf-8"),
    )

    second_event = {
        "type": "proof.completed",
        "actor_did": did,
        "payload": second_data,
        "signature": {
            "nonce": f"event-{uuid.uuid4().hex}",
            "sig": second_signature,
            "canonical": second_canonical,
        },
    }

    response = client.post(
        f"/proofs/{proof_id}/events",
        json=second_event,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Proof is already completed"


def test_invalid_event_actor_is_rejected():
    proof, _, _ = create_proof()
    proof_id = proof["proof_id"]

    _, other_public_key = generate_test_keypair()
    other_did = public_key_to_test_did(other_public_key)

    event_payload = {
        "type": "test.event",
        "actor_did": other_did,
        "payload": {
            "value": "unauthorized",
        },
        "nonce": f"event-{uuid.uuid4().hex}",
    }

    response = client.post(
        f"/proofs/{proof_id}/events",
        json=event_payload,
    )

    assert response.status_code in (400, 401, 403, 422)


def test_verify_endpoint_returns_verification_result():
    proof, _, _ = create_proof()

    response = client.get(
        f"/proofs/{proof['proof_id']}/verify"
    )

    assert response.status_code == 200

    data = response.json()

    assert "verdict" in data
    assert data["verdict"] == "valid"
