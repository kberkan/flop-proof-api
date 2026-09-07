import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.crypto import generate_test_keypair, public_key_to_test_did, sign_message


client = TestClient(app, headers={"X-API-Key": "flop-dev-key-2026"})


def test_exact_event_replay_is_rejected():
    private_key, public_key = generate_test_keypair()
    actor_did = public_key_to_test_did(public_key)

    request_id = f"replay-test-request-{uuid.uuid4().hex}"
    text = "Replay protection test"
    request_nonce = f"replay-request-nonce-{uuid.uuid4().hex}"
    created_at = datetime.now(timezone.utc).isoformat()

    request_canonical = f"{request_id}|{request_nonce}|{text}"
    request_signature = sign_message(
        private_key,
        request_canonical.encode(),
    )

    create_response = client.post(
        "/proofs",
        json={
            "request": {
                "request_id": request_id,
                "from_did": actor_did,
                "text": text,
                "created_at": created_at,
                "signature": {
                    "nonce": request_nonce,
                    "canonical": request_canonical,
                    "sig": request_signature,
                },
            }
        },
    )

    assert create_response.status_code == 201, create_response.text

    proof_id = create_response.json()["proof_id"]

    event_type = "test.event"
    payload = {"message": "replay-test"}
    nonce = f"fixed-event-nonce-{uuid.uuid4().hex}"

    payload_hash = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    canonical = f"{proof_id}|{event_type}|{payload_hash}"

    event_signature = sign_message(
        private_key,
        canonical.encode(),
    )

    event = {
        "type": event_type,
        "actor_did": actor_did,
        "payload": payload,
        "signature": {
            "nonce": nonce,
            "canonical": canonical,
            "sig": event_signature,
        },
    }

    first = client.post(
        f"/proofs/{proof_id}/events",
        json=event,
    )

    assert first.status_code == 201, first.text

    second = client.post(
        f"/proofs/{proof_id}/events",
        json=event,
    )

    assert second.status_code == 409
    assert second.json()["detail"] == "event nonce already used for this proof"

    verify = client.get(
        f"/proofs/{proof_id}/verify"
    )

    assert verify.status_code == 200
    assert verify.json()["verdict"] == "valid"
    assert verify.json()["events_checked"] == 2
