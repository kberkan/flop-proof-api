
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto import (
    generate_test_keypair,
    public_key_to_test_did,
    sha256_json,
    sign_message,
)
from app.main import app


TEST_API_KEY = os.getenv("FLOP_API_KEY", "flop-dev-key-2026")

client = TestClient(app, headers={"X-API-Key": TEST_API_KEY})


@pytest.fixture(autouse=True)
def in_memory_db(monkeypatch):
    """Route every request in this file to a fresh in-memory SQLite database,
    so these tests never touch proofs.db. The dependency override and the
    API key are restored after each test."""
    from app import main, models  # noqa: F401  (models registers the tables)
    from app.database import Base, get_db

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(main, "API_KEY", TEST_API_KEY)
    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestSession
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        engine.dispose()


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


def test_event_with_missing_signature_and_unknown_field_is_rejected():
    """Renamed from test_invalid_event_actor_is_rejected.

    The request has no "signature" block and an unknown top-level "nonce"
    field, so it fails schema validation (422) before any signature or actor
    check runs. It never exercised a validly signed foreign actor; that case is
    covered by the xfail tests at the end of this file.
    """
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

    # Evidence Status Contract v0.1.
    assert data["evidence"]["class"] == "proof_integrity_verified"
    assert data["evidence"]["execution_verified"] is False
    assert data["evidence"]["runtime_settled"] is False


# ---------------------------------------------------------------------------
# Known security gaps (see PARITY.md "Known security gaps"). These tests state
# the intended behavior and are expected to fail until the gaps are fixed.
# raises=AssertionError keeps any other error (setup, import) visible.
# ---------------------------------------------------------------------------

AUTHZ_GAP = "known gap: event append has no actor authorization (see PARITY.md)"
REPLAY_GAP = "known gap: event nonce is not part of the signed message (see PARITY.md)"


def new_actor():
    private_key, public_key = generate_test_keypair()
    return private_key, public_key_to_test_did(public_key)


def signed_event(private_key, did, proof_id, event_type, payload):
    """An event correctly signed by `did` for `proof_id`."""
    canonical = f"{proof_id}|{event_type}|{sha256_json(payload)}"
    return {
        "type": event_type,
        "actor_did": did,
        "payload": payload,
        "signature": {
            "nonce": f"event-{uuid.uuid4().hex}",
            "sig": sign_message(private_key, canonical.encode("utf-8")),
            "canonical": canonical,
        },
    }


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=AUTHZ_GAP)
def test_foreign_actor_cannot_append_result_to_another_actors_proof():
    proof, _, _ = create_proof()
    foreign_key, foreign_did = new_actor()

    response = client.post(
        f"/proofs/{proof['proof_id']}/events",
        json=signed_event(
            foreign_key,
            foreign_did,
            proof["proof_id"],
            "result.created",
            {"content": "written by a foreign actor"},
        ),
    )

    assert 400 <= response.status_code < 500, response.json()


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=AUTHZ_GAP)
def test_foreign_actor_cannot_complete_another_actors_proof():
    proof, _, _ = create_proof()
    foreign_key, foreign_did = new_actor()

    response = client.post(
        f"/proofs/{proof['proof_id']}/events",
        json=signed_event(
            foreign_key,
            foreign_did,
            proof["proof_id"],
            "proof.completed",
            {"result": "closed by a foreign actor"},
        ),
    )
    status = client.get(f"/proofs/{proof['proof_id']}").json()["status"]

    assert 400 <= response.status_code < 500, response.json()
    assert status == "pending"


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=REPLAY_GAP)
def test_signed_event_cannot_be_replayed_with_new_nonce():
    proof, private_key, did = create_proof()
    original = signed_event(
        private_key, did, proof["proof_id"], "task.delegated", {"to": "worker-1"}
    )

    first = client.post(f"/proofs/{proof['proof_id']}/events", json=original)
    assert first.status_code == 201

    replayed = {
        **original,
        "signature": {**original["signature"], "nonce": f"event-{uuid.uuid4().hex}"},
    }
    second = client.post(f"/proofs/{proof['proof_id']}/events", json=replayed)

    assert 400 <= second.status_code < 500, second.json()


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=AUTHZ_GAP)
def test_verify_rejects_proof_with_foreign_actor_result(in_memory_db):
    """The foreign event is written directly to the database, so this test
    checks the verifier on its own and keeps failing for the right reason
    even after the append endpoint starts rejecting foreign actors."""
    from app.events import create_event

    proof, _, _ = create_proof()
    foreign_key, foreign_did = new_actor()
    event = signed_event(
        foreign_key,
        foreign_did,
        proof["proof_id"],
        "result.created",
        {"content": "written by a foreign actor"},
    )

    db = in_memory_db()
    try:
        create_event(
            db=db,
            proof_id=proof["proof_id"],
            event_type=event["type"],
            actor_did=event["actor_did"],
            payload=event["payload"],
            canonical=event["signature"]["canonical"],
            signature=event["signature"]["sig"],
            nonce=event["signature"]["nonce"],
        )
        db.commit()
    finally:
        db.close()

    verification = client.get(f"/proofs/{proof['proof_id']}/verify").json()

    assert verification["verdict"] == "invalid"
