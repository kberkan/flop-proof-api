
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
# Event authorization (docs/design/event-authorization.md) and the remaining
# known gap (see PARITY.md "Known Security Gaps"). The replay test is still
# expected to fail; raises=AssertionError keeps any other error visible.
# ---------------------------------------------------------------------------

NOT_AUTHORIZED = {"detail": "Actor is not authorized for this proof"}
CREATOR_ONLY = {"detail": "Event type requires the proof creator"}

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

    assert response.status_code == 403
    assert response.json() == NOT_AUTHORIZED


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

    assert response.status_code == 403
    assert response.json() == NOT_AUTHORIZED
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


def test_verify_rejects_proof_with_foreign_actor_result(in_memory_db):
    """The foreign event is written directly to the database, bypassing the
    append endpoint, so this test checks the verifier on its own (D-A10)."""
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
    foreign = verification["checks"][-1]

    assert verification["verdict"] == "invalid"
    assert foreign["actor_did"] == foreign_did
    assert foreign["role"] == "unauthorized"
    assert foreign["actor_authorized"] is False
    assert foreign["authorization_reason"] == "not_delegated"
    # The event itself is correctly signed; only authorization fails.
    assert foreign["signature_valid"] is True


# ---------------------------------------------------------------------------
# Delegation end to end (docs/design/event-authorization.md, D1-D8, D-A1-D-A10)
# ---------------------------------------------------------------------------


def append(private_key, did, proof_id, event_type, payload):
    return client.post(
        f"/proofs/{proof_id}/events",
        json=signed_event(private_key, did, proof_id, event_type, payload),
    )


def delegate_to(private_key, did, proof_id, *delegates):
    response = append(
        private_key, did, proof_id, "task.delegated", {"delegates": list(delegates)}
    )
    assert response.status_code == 201, response.json()
    return response


def test_delegation_end_to_end_with_verifier_roles():
    proof, creator_key, creator_did = create_proof()
    proof_id = proof["proof_id"]
    delegate_key, delegate_did = new_actor()

    delegate_to(creator_key, creator_did, proof_id, delegate_did)

    result = append(delegate_key, delegate_did, proof_id, "result.created", {"content": "by delegate"})
    assert result.status_code == 201

    delegate_close = append(delegate_key, delegate_did, proof_id, "proof.completed", {"result": "x"})
    assert delegate_close.status_code == 403
    assert delegate_close.json() == CREATOR_ONLY

    creator_close = append(creator_key, creator_did, proof_id, "proof.completed", {"result": "done"})
    assert creator_close.status_code == 201

    verification = client.get(f"/proofs/{proof_id}/verify").json()

    assert verification["verdict"] == "valid"
    assert [(check["type"], check["role"], check["actor_authorized"]) for check in verification["checks"]] == [
        ("request.created", "creator", True),
        ("task.delegated", "creator", True),
        ("result.created", "delegate", True),
        ("proof.completed", "creator", True),
    ]
    assert all(check["authorization_reason"] is None for check in verification["checks"])


@pytest.mark.parametrize("who", ["creator", "delegate", "stranger"])
def test_request_created_cannot_be_appended_through_events_endpoint(who):
    proof, creator_key, creator_did = create_proof()
    proof_id = proof["proof_id"]
    delegate_key, delegate_did = new_actor()
    delegate_to(creator_key, creator_did, proof_id, delegate_did)
    actors = {
        "creator": (creator_key, creator_did),
        "delegate": (delegate_key, delegate_did),
        "stranger": new_actor(),
    }

    response = append(*actors[who], proof_id, "request.created", {"text": "second request"})

    assert response.status_code == 403
    assert response.json() == {"detail": "request.created can only be written by POST /proofs"}


@pytest.mark.parametrize("second_by", ["creator", "delegate"])
def test_second_result_created_is_rejected_with_409(second_by):
    proof, creator_key, creator_did = create_proof()
    proof_id = proof["proof_id"]
    delegate_key, delegate_did = new_actor()
    delegate_to(creator_key, creator_did, proof_id, delegate_did)
    assert append(creator_key, creator_did, proof_id, "result.created", {"content": "first"}).status_code == 201

    key, did = (creator_key, creator_did) if second_by == "creator" else (delegate_key, delegate_did)
    response = append(key, did, proof_id, "result.created", {"content": "second"})

    assert response.status_code == 409
    assert response.json() == {"detail": "result.created already exists for this proof"}


@pytest.mark.parametrize(
    ("delegates", "detail"),
    [
        ("33", "Invalid delegate list"),
        ("bad-did", "Invalid delegate DID"),
    ],
)
def test_malformed_delegates_are_rejected_with_400(delegates, detail):
    proof, creator_key, creator_did = create_proof()
    if delegates == "33":
        value = [new_actor()[1] for _ in range(33)]
    else:
        value = ["did:key:not-a-key"]

    response = append(creator_key, creator_did, proof["proof_id"], "task.delegated", {"delegates": value})

    assert response.status_code == 400
    assert response.json() == {"detail": detail}


def test_delegate_cannot_append_before_the_delegation():
    proof, creator_key, creator_did = create_proof()
    proof_id = proof["proof_id"]
    delegate_key, delegate_did = new_actor()

    early = append(delegate_key, delegate_did, proof_id, "agent.started", {})
    delegate_to(creator_key, creator_did, proof_id, delegate_did)
    late = append(delegate_key, delegate_did, proof_id, "agent.started", {})

    assert early.status_code == 403
    assert early.json() == NOT_AUTHORIZED
    assert late.status_code == 201


def test_offline_verifier_matches_api_verification(in_memory_db):
    """D-A10: the exported proof gives the same verdict and authorization
    fields offline as through GET /verify, including for an event written
    around the API."""
    from app.events import create_event
    from app.verifier import verify_proof_data

    proof, creator_key, creator_did = create_proof()
    proof_id = proof["proof_id"]
    delegate_key, delegate_did = new_actor()
    stranger_key, stranger_did = new_actor()
    delegate_to(creator_key, creator_did, proof_id, delegate_did)
    assert append(delegate_key, delegate_did, proof_id, "result.created", {"content": "ok"}).status_code == 201

    stranger_event = signed_event(stranger_key, stranger_did, proof_id, "agent.started", {})
    db = in_memory_db()
    try:
        create_event(
            db=db,
            proof_id=proof_id,
            event_type=stranger_event["type"],
            actor_did=stranger_did,
            payload=stranger_event["payload"],
            canonical=stranger_event["signature"]["canonical"],
            signature=stranger_event["signature"]["sig"],
            nonce=stranger_event["signature"]["nonce"],
        )
        db.commit()
    finally:
        db.close()

    api = client.get(f"/proofs/{proof_id}/verify").json()
    offline = verify_proof_data(client.get(f"/proofs/{proof_id}").json())

    fields = ("sequence", "type", "actor_did", "role", "actor_authorized", "authorization_reason")
    assert offline["verdict"] == api["verdict"] == "invalid"
    assert [{k: c[k] for k in fields} for c in offline["checks"]] == [
        {k: c[k] for k in fields} for c in api["checks"]
    ]
    assert [c["role"] for c in api["checks"]] == ["creator", "creator", "delegate", "unauthorized"]


@pytest.fixture
def file_db(in_memory_db, tmp_path):
    """A temporary file database for the concurrency test: the in-memory
    StaticPool shares one connection between threads, so it cannot show
    whether the write lock serializes concurrent requests."""
    from app import models  # noqa: F401
    from app.database import Base, get_db

    engine = create_engine(
        f"sqlite:///{tmp_path / 'race.db'}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    Base.metadata.create_all(engine)
    FileSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = FileSession()
        try:
            yield db
        finally:
            db.close()

    from app.main import app as fastapi_app

    previous = fastapi_app.dependency_overrides[get_db]
    fastapi_app.dependency_overrides[get_db] = override_get_db
    try:
        yield FileSession
    finally:
        fastapi_app.dependency_overrides[get_db] = previous
        engine.dispose()


def test_concurrent_result_created_admits_exactly_one(file_db):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from app.models import ProofEvent

    for _ in range(5):
        proof, creator_key, creator_did = create_proof()
        proof_id = proof["proof_id"]
        bodies = [
            signed_event(creator_key, creator_did, proof_id, "result.created", {"content": f"result {index}"})
            for index in range(2)
        ]
        barrier = threading.Barrier(2)

        def post(body):
            barrier.wait()
            return client.post(f"/proofs/{proof_id}/events", json=body).status_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = sorted(executor.map(post, bodies))

        db = file_db()
        try:
            results = (
                db.query(ProofEvent)
                .filter(ProofEvent.proof_id == proof_id, ProofEvent.event_type == "result.created")
                .count()
            )
            sequences = [
                row.sequence
                for row in db.query(ProofEvent).filter(ProofEvent.proof_id == proof_id).order_by(ProofEvent.sequence)
            ]
        finally:
            db.close()

        assert statuses == [201, 409]
        assert results == 1
        assert sequences == [1, 2]
