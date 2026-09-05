import json
from pathlib import Path

from fastapi.testclient import TestClient
import os

from app.main import app
from app.crypto import generate_test_keypair, public_key_to_test_did, sign_message


client = TestClient(app, headers={"X-API-Key": os.getenv("FLOP_API_KEY", "flop-dev-key-2026")})


def make_signed_request():
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    nonce = "contract-test-nonce"
    text = "contract test request"
    canonical = f"contract-test|{nonce}|{text}"
    signature = sign_message(private_key, canonical.encode("utf-8"))

    return {
        "request": {
            "request_id": "contract-test-request",
            "from_did": did,
            "text": text,
            "created_at": "2026-09-04T20:30:00Z",
            "signature": {
                "nonce": nonce,
                "sig": signature,
                "canonical": canonical,
            },
        }
    }, private_key, did


def test_health_contract():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "flop-proof-api",
    }


def test_unknown_proof_returns_404():
    response = client.get("/proofs/proof_does_not_exist/verify")

    assert response.status_code == 404
    assert response.json() == {"detail": "Proof not found"}


def test_empty_proof_request_returns_422():
    response = client.post("/proofs", json={})

    assert response.status_code == 422


def test_extra_request_field_returns_422():
    body, _, _ = make_signed_request()
    body["request"]["unexpected"] = "forbidden"

    response = client.post("/proofs", json=body)

    assert response.status_code == 422


def test_empty_request_text_returns_422():
    body, _, _ = make_signed_request()
    body["request"]["text"] = ""

    response = client.post("/proofs", json=body)

    assert response.status_code == 422


def test_invalid_request_signature_returns_401():
    body, _, _ = make_signed_request()
    body["request"]["signature"]["sig"] = "invalid-signature"

    response = client.post("/proofs", json=body)

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid request signature"}


def test_nonexistent_event_proof_returns_404():
    event = {
        "type": "task.delegated",
        "actor_did": "did:test:invalid",
        "payload": {"task_id": "t1"},
        "signature": {
            "nonce": "n1",
            "sig": "invalid",
            "canonical": "invalid",
        },
    }

    response = client.post(
        "/proofs/proof_does_not_exist/events",
        json=event,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Proof not found"}
