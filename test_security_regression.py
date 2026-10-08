
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.canonical import build_event_canonical_v3, build_request_canonical_v3
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
    canonical = build_request_canonical_v3(room, nonce, text)

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
    """Appending text makes the signature 94 characters, which is not 64 bytes
    of base64url: malformed input, 422 (it was 401 before malformed and
    non-verifying signatures were told apart). A bit-flipped signature of the
    right length is still 401 (test_signature_error_classification.py)."""
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    payload = make_signed_request(
        private_key,
        did,
        f"security-signature-{uuid.uuid4().hex}",
    )

    payload["request"]["signature"]["sig"] += "tampered"

    response = client.post("/proofs", json=payload)

    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid signature encoding"


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
    nonce = f"event-{uuid.uuid4().hex}"
    canonical = build_event_canonical_v3(proof_id, "proof.completed", payload_hash, nonce)
    signature = sign_message(
        private_key,
        canonical.encode("utf-8"),
    )

    event_payload = {
        "type": "proof.completed",
        "actor_did": did,
        "payload": event_data,
        "signature": {
            "nonce": nonce,
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
    second_nonce = f"event-{uuid.uuid4().hex}"
    second_canonical = build_event_canonical_v3(
        proof_id, "proof.completed", second_payload_hash, second_nonce
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
            "nonce": second_nonce,
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
# Event authorization (docs/design/event-authorization.md) and event replay
# (docs/design/event-replay.md).
# ---------------------------------------------------------------------------

NOT_AUTHORIZED = {"detail": "Actor is not authorized for this proof"}
CREATOR_ONLY = {"detail": "Event type requires the proof creator"}

def new_actor():
    private_key, public_key = generate_test_keypair()
    return private_key, public_key_to_test_did(public_key)


def signed_event(private_key, did, proof_id, event_type, payload):
    """An event correctly signed by `did` for the version-3 proof `proof_id`."""
    nonce = f"event-{uuid.uuid4().hex}"
    canonical = build_event_canonical_v3(proof_id, event_type, sha256_json(payload), nonce)
    return {
        "type": event_type,
        "actor_did": did,
        "payload": payload,
        "signature": {
            "nonce": nonce,
            "sig": sign_message(private_key, canonical.encode("utf-8")),
            "canonical": canonical,
        },
    }


def legacy_signed_event(private_key, did, proof_id, event_type, payload):
    """An event in the v1/v2 format proof_id|type|payload_hash, unsigned nonce.
    Used on purpose by the tests of the v1/v2 path (Option B, D-R11)."""
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


def test_signed_event_cannot_be_replayed_with_new_nonce():
    """Was xfail (REPLAY_GAP) until the nonce became part of the signed
    message (version 3, docs/design/event-replay.md D-R2)."""
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


# ---------------------------------------------------------------------------
# Event signatures must not work as proof request signatures
# (docs/design/event-replay.md §1.2). In version 3 the domain tags keep the two
# message kinds apart (D-R2); the v1/v2 verifier path keeps the minimal fix.
# ---------------------------------------------------------------------------

UNTAGGED_REQUEST = (
    "Invalid request canonical, expected FLOP/REQUEST/v3|room|nonce|text "
    "(canonical: tag must be FLOP/REQUEST/v3)"
)


def legacy_signed_request(private_key, did, request_id, text="security test"):
    """A request in the v1/v2 format room|nonce|text. Used on purpose where a
    test needs the old format (POST /proofs no longer accepts it, D-R4)."""
    nonce = f"nonce-{uuid.uuid4().hex}"
    canonical = f"security-room|{nonce}|{text}"
    return {
        "request_id": request_id,
        "from_did": did,
        "text": text,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "signature": {
            "nonce": nonce,
            "sig": sign_message(private_key, canonical.encode("utf-8")),
            "canonical": canonical,
        },
    }


def _victim_event_signature(event_format):
    """A victim's correctly signed event: version 3 (appended through the API)
    or v1/v2 (signed directly, since the API only creates version-3 proofs)."""
    payload = {"step": 1}
    if event_format == "v3":
        proof, victim_key, victim_did = create_proof()
        event = signed_event(victim_key, victim_did, proof["proof_id"], "agent.started", payload)
        assert client.post(f"/proofs/{proof['proof_id']}/events", json=event).status_code == 201
    else:
        victim_key, victim_did = new_actor()
        event = legacy_signed_event(
            victim_key, victim_did, f"proof_{uuid.uuid4().hex}", "agent.started", payload
        )
    return victim_did, event, sha256_json(payload)


def _request_from_event_signature(victim_did, event, payload_hash):
    """The attacker's POST /proofs body reusing the event's canonical and
    signature (for the v1/v2 format, proof_id|type|payload_hash parsed as
    room|nonce|text)."""
    return {
        "request": {
            "request_id": f"attacker-{uuid.uuid4().hex}",
            "from_did": victim_did,
            "text": payload_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "signature": {
                "nonce": event["type"],
                "sig": event["signature"]["sig"],
                "canonical": event["signature"]["canonical"],
            },
        }
    }


def _write_proof(in_memory_db, version, request, actor_did, nonce=""):
    """Write a proof and its request.created directly, bypassing POST /proofs."""
    from app.events import create_event
    from app.models import Proof

    proof_id = f"proof_{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    db = in_memory_db()
    try:
        db.add(
            Proof(
                proof_id=proof_id,
                request_id=request["request_id"],
                version=version,
                status="pending",
                created_at=now,
                updated_at=now,
            )
        )
        create_event(
            db=db,
            proof_id=proof_id,
            event_type="request.created",
            actor_did=actor_did,
            payload=request,
            canonical=request["signature"]["canonical"],
            signature=request["signature"]["sig"],
            nonce=nonce,
        )
        db.commit()
    finally:
        db.close()
    return proof_id


def _write_event(in_memory_db, proof_id, event, nonce=None):
    """Append a signed event directly, bypassing POST /proofs/{id}/events."""
    from app.events import create_event

    db = in_memory_db()
    try:
        create_event(
            db=db,
            proof_id=proof_id,
            event_type=event["type"],
            actor_did=event["actor_did"],
            payload=event["payload"],
            canonical=event["signature"]["canonical"],
            signature=event["signature"]["sig"],
            nonce=event["signature"]["nonce"] if nonce is None else nonce,
        )
        db.commit()
    finally:
        db.close()


@pytest.mark.parametrize("event_format", ["v3", "legacy"])
def test_event_signature_cannot_create_proof(event_format):
    """Expectation changed from 401 "Invalid request signature": the request
    is now rejected earlier, by the version-3 tag check (D-R4), still 401."""
    victim_did, event, payload_hash = _victim_event_signature(event_format)
    forged = _request_from_event_signature(victim_did, event, payload_hash)

    response = client.post("/proofs", json=forged)

    assert response.status_code == 401
    assert response.json() == {"detail": UNTAGGED_REQUEST}
    listing = client.get("/proofs", params={"limit": 100}).json()["items"]
    assert all(item["request_id"] != forged["request"]["request_id"] for item in listing)


def test_verify_rejects_v2_proof_created_from_event_signature(in_memory_db):
    """v1/v2 path, kept on the old formats on purpose: a forged version-2
    proof whose request is a victim's v1/v2 event signature."""
    victim_did, event, payload_hash = _victim_event_signature("legacy")
    request = _request_from_event_signature(victim_did, event, payload_hash)["request"]
    proof_id = _write_proof(in_memory_db, "2", request, victim_did)

    verification = client.get(f"/proofs/{proof_id}/verify").json()

    assert verification["verdict"] == "invalid"
    assert verification["checks"][0]["request_binding_valid"] is False


def test_verify_rejects_v3_proof_created_from_event_signature(in_memory_db):
    victim_did, event, payload_hash = _victim_event_signature("v3")
    request = _request_from_event_signature(victim_did, event, payload_hash)["request"]
    proof_id = _write_proof(in_memory_db, "3", request, victim_did, nonce=event["signature"]["nonce"])

    verification = client.get(f"/proofs/{proof_id}/verify").json()
    check = verification["checks"][0]

    assert verification["verdict"] == "invalid"
    assert check["signature_valid"] is True
    assert check["request_binding_valid"] is False
    assert check["format_valid"] is False


def test_request_with_ordinary_room_is_still_accepted():
    proof, _, _ = create_proof()

    verification = client.get(f"/proofs/{proof['proof_id']}/verify").json()

    assert verification["verdict"] == "valid"
    assert verification["proof_version"] == "3"
    assert verification["checks"][0]["request_binding_valid"] is True
    assert verification["checks"][0]["format_valid"] is True


@pytest.mark.parametrize("version", ["3", "2"])
def test_verify_rejects_request_whose_stored_text_differs_from_signed_text(in_memory_db, version):
    """Every other check passes; only the request binding fails. The "2" case
    keeps the v1/v2 request format on purpose."""
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)
    request_id = f"security-{uuid.uuid4().hex}"
    if version == "3":
        request = make_signed_request(private_key, did, request_id, text="signed text")["request"]
        nonce = request["signature"]["nonce"]
    else:
        request = legacy_signed_request(private_key, did, request_id, text="signed text")
        nonce = ""
    request["text"] = "different stored text"
    proof_id = _write_proof(in_memory_db, version, request, did, nonce=nonce)

    verification = client.get(f"/proofs/{proof_id}/verify").json()
    check = verification["checks"][0]

    assert (
        check["payload_hash_valid"],
        check["canonical_valid"],
        check["signature_valid"],
        check["format_valid"],
        check["replay_valid"],
    ) == (True, True, True, True, True)
    assert check["request_binding_valid"] is False
    assert verification["verdict"] == "invalid"


PROOF_ID_BEHAVIOR_CASES = [
    "proof_0123456789abcdef0123456789abcdef",
    "proof_0123456789abcdef0123456789abcdef\n",
    "proof_0123456789abcdef0123456789abcdef\r\n",
    "proof_0123456789abcdef0123456789abcdef\r",
    "proof_0123456789abcdef0123456789abcdef ",
    " proof_0123456789abcdef0123456789abcdef",
    "\nproof_0123456789abcdef0123456789abcdef",
    "proof_0123456789abcdef0123456789abcdef\u2028",
    "proof_0123456789ABCDEF0123456789abcdef",
    "proof_0123456789abcdef0123456789abcde",
    "proof_0123456789abcdef0123456789abcdef0",
    "proof_0123456789abcdef0123456789abcdef/verify",
    "proof_",
    "",
    "security-room",
]


def test_proof_id_pattern_matches_generated_ids_and_dashboard_proxy():
    """D-R9: Python's is_proof_id and the dashboard proxy's PROOF_ID give the
    same answer for every case, including trailing newlines and spaces (the
    patterns' text alone did not show that Python's "$" accepts a trailing
    newline). Node evaluates the regex literal read from the proxy source."""
    import json as json_module
    import re
    import shutil
    import subprocess
    from pathlib import Path

    from app.crypto import is_proof_id

    proof, _, _ = create_proof()
    assert is_proof_id(proof["proof_id"])
    assert is_proof_id(f"proof_{uuid.uuid4().hex}")

    proxy = (Path(__file__).parent / "dashboard/src/lib/proxy-policy.ts").read_text()
    regex_literal = re.search(r"const PROOF_ID = (/.+/);", proxy).group(1)

    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            pytest.fail("node is required in CI to compare the proof_id patterns")
        pytest.skip("node is not installed")

    script = (
        f"const pattern = {regex_literal};"
        "const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
        "process.stdout.write(JSON.stringify(cases.map((c) => pattern.test(c))));"
    )
    completed = subprocess.run(
        [node, "-e", script],
        input=json_module.dumps(PROOF_ID_BEHAVIOR_CASES),
        capture_output=True,
        text=True,
        check=True,
    )
    javascript = json_module.loads(completed.stdout)
    python = [is_proof_id(case) for case in PROOF_ID_BEHAVIOR_CASES]

    assert python == javascript
    assert python[:2] == [True, False]
    assert sum(python) == 1


# ---------------------------------------------------------------------------
# Event replay (docs/design/event-replay.md, D-R1-D-R12)
# ---------------------------------------------------------------------------

REPLAYED_EVENT = {"detail": "event already recorded in this proof"}
NONCE_USED = {"detail": "event nonce already used for this proof"}
CANONICAL_MISMATCH = {"detail": "Event canonical message mismatch"}


def _with_nonce(event, nonce):
    return {**event, "signature": {**event["signature"], "nonce": nonce}}


def _event_types(proof_id):
    return [event["type"] for event in client.get(f"/proofs/{proof_id}").json()["events"]]


def test_new_proofs_are_version_3_and_export_the_nonce():
    proof, key, did = create_proof()
    event = signed_event(key, did, proof["proof_id"], "agent.started", {})
    assert client.post(f"/proofs/{proof['proof_id']}/events", json=event).status_code == 201

    exported = client.get(f"/proofs/{proof['proof_id']}").json()
    verify_events = client.get(f"/proofs/{proof['proof_id']}/verify").json()

    assert proof["version"] == exported["version"] == "3"
    assert [e["nonce"] for e in exported["events"]] == [
        exported["events"][0]["payload"]["signature"]["nonce"],
        event["signature"]["nonce"],
    ]
    assert verify_events["verdict"] == "valid"


def test_v3_replay_with_new_nonce_is_rejected_with_401():
    proof, key, did = create_proof()
    proof_id = proof["proof_id"]
    original = signed_event(key, did, proof_id, "agent.started", {"step": 1})
    assert client.post(f"/proofs/{proof_id}/events", json=original).status_code == 201

    replayed = client.post(
        f"/proofs/{proof_id}/events", json=_with_nonce(original, f"event-{uuid.uuid4().hex}")
    )

    assert replayed.status_code == 401
    assert replayed.json() == CANONICAL_MISMATCH
    assert _event_types(proof_id) == ["request.created", "agent.started"]


def test_v3_replay_with_same_nonce_is_rejected_with_409():
    proof, key, did = create_proof()
    proof_id = proof["proof_id"]
    original = signed_event(key, did, proof_id, "agent.started", {"step": 1})
    assert client.post(f"/proofs/{proof_id}/events", json=original).status_code == 201

    replayed = client.post(f"/proofs/{proof_id}/events", json=original)

    assert replayed.status_code == 409
    assert replayed.json() == NONCE_USED
    assert _event_types(proof_id) == ["request.created", "agent.started"]


def test_v3_event_cannot_reuse_the_request_nonce():
    """The request.created row stores the request's signed nonce, so it takes
    part in the per-proof nonce check."""
    proof, key, did = create_proof()
    proof_id = proof["proof_id"]
    request_nonce = client.get(f"/proofs/{proof_id}").json()["events"][0]["nonce"]
    nonce = request_nonce
    canonical = build_event_canonical_v3(proof_id, "agent.started", sha256_json({}), nonce)
    event = {
        "type": "agent.started",
        "actor_did": did,
        "payload": {},
        "signature": {
            "nonce": nonce,
            "sig": sign_message(key, canonical.encode("utf-8")),
            "canonical": canonical,
        },
    }

    response = client.post(f"/proofs/{proof_id}/events", json=event)

    assert response.status_code == 409
    assert response.json() == NONCE_USED


def test_v3_proof_rejects_legacy_event_format():
    """D-R12: no format mixing in a version-3 chain."""
    proof, key, did = create_proof()
    event = legacy_signed_event(key, did, proof["proof_id"], "agent.started", {})

    response = client.post(f"/proofs/{proof['proof_id']}/events", json=event)

    assert response.status_code == 401
    assert response.json() == CANONICAL_MISMATCH


@pytest.mark.parametrize(
    ("event_type", "nonce", "detail"),
    [
        ("agent|started", "n-1", "Invalid event field (event_type: must not contain '|')"),
        ("agent.started", "n|1", "Invalid event field (nonce: must not contain '|')"),
        ("agent.started", "n\n1", "Invalid event field (nonce: must not contain control characters)"),
        ("agent\x00started", "n-1", "Invalid event field (event_type: must not contain control characters)"),
    ],
)
def test_v3_event_with_invalid_field_is_rejected_with_400(event_type, nonce, detail):
    proof, key, did = create_proof()
    event = {
        "type": event_type,
        "actor_did": did,
        "payload": {},
        "signature": {"nonce": nonce, "sig": "unused", "canonical": "unused"},
    }

    response = client.post(f"/proofs/{proof['proof_id']}/events", json=event)

    assert response.status_code == 400
    assert response.json() == {"detail": detail}


def _legacy_proof(in_memory_db):
    """A version-2 proof with a v1/v2 request, written directly (the API only
    creates version-3 proofs). Kept on the old formats on purpose."""
    key, did = new_actor()
    request = legacy_signed_request(key, did, f"legacy-{uuid.uuid4().hex}")
    return _write_proof(in_memory_db, "2", request, did), key, did


def test_v2_proof_rejects_repeated_signature_with_409(in_memory_db):
    """Option B (D-R5): the nonce is not signed in v1/v2, so a replay with a
    new nonce is caught as a repeated (canonical, signature) pair."""
    proof_id, key, did = _legacy_proof(in_memory_db)
    original = legacy_signed_event(key, did, proof_id, "agent.started", {"step": 1})
    assert client.post(f"/proofs/{proof_id}/events", json=original).status_code == 201

    new_nonce = client.post(
        f"/proofs/{proof_id}/events", json=_with_nonce(original, f"event-{uuid.uuid4().hex}")
    )
    same_nonce = client.post(f"/proofs/{proof_id}/events", json=original)

    assert new_nonce.status_code == 409
    assert new_nonce.json() == REPLAYED_EVENT
    assert same_nonce.status_code == 409
    assert same_nonce.json() == NONCE_USED
    assert _event_types(proof_id) == ["request.created", "agent.started"]
    # v1/v2 proofs stay verifiable (D-R5).
    assert client.get(f"/proofs/{proof_id}/verify").json()["verdict"] == "valid"


def test_v2_proof_rejects_tagged_event(in_memory_db):
    """D-R11/D-R12: a version-3 event never enters a v1/v2 chain."""
    proof_id, key, did = _legacy_proof(in_memory_db)
    event = signed_event(key, did, proof_id, "agent.started", {})

    response = client.post(f"/proofs/{proof_id}/events", json=event)

    assert response.status_code == 401
    assert response.json() == CANONICAL_MISMATCH


@pytest.mark.parametrize("replay_nonce", ["same", "new"])
def test_verify_detects_v3_replay_written_around_the_api(in_memory_db, replay_nonce):
    proof, key, did = create_proof()
    proof_id = proof["proof_id"]
    original = signed_event(key, did, proof_id, "agent.started", {"step": 1})
    assert client.post(f"/proofs/{proof_id}/events", json=original).status_code == 201
    nonce = original["signature"]["nonce"] if replay_nonce == "same" else f"event-{uuid.uuid4().hex}"
    _write_event(in_memory_db, proof_id, original, nonce=nonce)

    verification = client.get(f"/proofs/{proof_id}/verify").json()
    first, copy = verification["checks"][1:]

    assert verification["verdict"] == "invalid"
    assert first["replay_valid"] is True and first["format_valid"] is True
    assert copy["signature_valid"] is True
    assert copy["replay_valid"] is False
    # With a new stored nonce the copy also no longer matches its signed nonce.
    assert copy["format_valid"] is (replay_nonce == "same")
    assert copy["canonical_valid"] is (replay_nonce == "same")


def test_verify_detects_v2_replay_written_around_the_api(in_memory_db):
    proof_id, key, did = _legacy_proof(in_memory_db)
    original = legacy_signed_event(key, did, proof_id, "agent.started", {"step": 1})
    assert client.post(f"/proofs/{proof_id}/events", json=original).status_code == 201
    _write_event(in_memory_db, proof_id, original, nonce=f"event-{uuid.uuid4().hex}")

    verification = client.get(f"/proofs/{proof_id}/verify").json()
    first, copy = verification["checks"][1:]

    assert verification["verdict"] == "invalid"
    assert verification["proof_version"] == "2"
    assert first["replay_valid"] is True
    assert (copy["signature_valid"], copy["canonical_valid"], copy["replay_valid"]) == (True, True, False)


def test_untagged_request_is_rejected_and_creates_no_proof():
    key, did = new_actor()
    request = legacy_signed_request(key, did, f"untagged-{uuid.uuid4().hex}")
    before = client.get("/proofs", params={"limit": 100}).json()["count"]

    response = client.post("/proofs", json={"request": request})

    assert response.status_code == 401
    assert response.json() == {"detail": UNTAGGED_REQUEST}
    assert client.get("/proofs", params={"limit": 100}).json()["count"] == before


def test_v3_export_relabelled_as_v2_is_invalid():
    """D-R11: version-3 signatures in an export whose version was changed to
    "2" do not pass the v1/v2 rules; a missing or unknown version is not
    guessed."""
    from app.verifier import verify_proof_data

    proof, key, did = create_proof()
    proof_id = proof["proof_id"]
    event = signed_event(key, did, proof_id, "agent.started", {})
    assert client.post(f"/proofs/{proof_id}/events", json=event).status_code == 201
    exported = client.get(f"/proofs/{proof_id}").json()

    assert verify_proof_data(exported)["verdict"] == "valid"

    relabelled = verify_proof_data({**exported, "version": "2"})
    assert relabelled["verdict"] == "invalid"
    assert [check["format_valid"] for check in relabelled["checks"]] == [False, False]

    for version in (None, "4", 3):
        broken = {key: value for key, value in exported.items() if key != "version"}
        if version is not None:
            broken["version"] = version
        result = verify_proof_data(broken)
        assert result["verdict"] == "invalid"
        assert result["reason"] == "Missing or unsupported proof version."


def test_sdk_end_to_end_v3_flow(monkeypatch):
    """The SDK against the API in-process: create, delegate, result, replay
    rejected, verified online and offline."""
    from flop_proof_sdk import FlopProofClient, FlopProofHTTPError
    from flop_proof_sdk import client as sdk_client_module

    from app.verifier import verify_proof_data

    def request_through_testclient(method, url, timeout=None, headers=None, **kwargs):
        return client.request(method, url.removeprefix("http://sdk.test"), headers=headers, **kwargs)

    monkeypatch.setattr(sdk_client_module.httpx, "request", request_through_testclient)
    sdk = FlopProofClient("http://sdk.test", api_key=TEST_API_KEY)
    key, did = new_actor()
    worker_key, worker_did = new_actor()

    created = sdk.create_signed_proof(
        private_key=key,
        did=did,
        text="sdk | end to end",
        room="sdk-room",
        nonce=f"sdk-request-{uuid.uuid4().hex}",
        request_id=f"sdk-e2e-{uuid.uuid4().hex}",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    proof_id = created["proof_id"]
    sdk.append_signed_event(proof_id, key, did, "task.delegated", {"delegates": [worker_did]}, "sdk-n1")
    sdk.append_signed_event(proof_id, worker_key, worker_did, "result.created", {"content": "done"}, "sdk-n2")

    with pytest.raises(FlopProofHTTPError) as replay:
        sdk.append_signed_event(proof_id, worker_key, worker_did, "result.created", {"content": "done"}, "sdk-n2")
    with pytest.raises(ValueError, match="nonce: must not contain '|'"):
        sdk.append_signed_event(proof_id, key, did, "agent.started", {}, "bad|nonce")

    exported = sdk.get_proof(proof_id)
    online = sdk.verify_proof(proof_id)

    assert created["version"] == "3"
    assert replay.value.status_code == 409
    assert exported["events"][0]["canonical"].startswith("FLOP/REQUEST/v3|sdk-room|")
    assert all(e["canonical"].startswith("FLOP/EVENT/v3|") for e in exported["events"][1:])
    assert [e["nonce"] for e in exported["events"][1:]] == ["sdk-n1", "sdk-n2"]
    assert online["verdict"] == verify_proof_data(exported)["verdict"] == "valid"
