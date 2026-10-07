"""Every public FlopProofClient method, end to end against the application.

The SDK's HTTP layer is the in-process TestClient (`http_client=`), backed by
an in-memory database: real request validation, handlers and responses, with
no live server and no proofs.db.
"""

import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.canonical import build_event_canonical_v3, build_request_canonical_v3
from app.crypto import generate_test_keypair, public_key_to_test_did, sha256_json, sign_message
from app.main import app
from flop_proof_sdk import FlopProofClient, FlopProofHTTPError
from test_validator_result_validation import _matching_result, _signed_bundle

API_KEY = "sdk-against-app-key"


@pytest.fixture
def sdk(monkeypatch):
    from app import main, models  # noqa: F401  (models registers the tables)
    from app.database import Base, get_db

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(main, "API_KEY", API_KEY)
    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield FlopProofClient("http://testserver", api_key=API_KEY, http_client=test_client)
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        engine.dispose()


@pytest.fixture
def validator_registry(monkeypatch):
    from app import main

    attestation, report_data, validator_id = _signed_bundle()
    monkeypatch.setattr(main, "validator_registry", main.MockValidatorRegistry([validator_id]))
    monkeypatch.setattr(main, "processed_validator_tasks", main.ProcessedTasks())
    return attestation, report_data


def _actor():
    private_key, public_key = generate_test_keypair()
    return private_key, public_key_to_test_did(public_key)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _signed_proof(sdk, private_key, did):
    return sdk.create_signed_proof(
        private_key=private_key,
        did=did,
        text="sdk against app",
        room="sdk-room",
        nonce=f"sdk-{uuid.uuid4().hex}",
        request_id=f"sdk-{uuid.uuid4().hex}",
        created_at=_now(),
    )


def test_health(sdk):
    assert sdk.health() == {"status": "ok", "service": "flop-proof-api"}


def test_create_proof_with_a_prebuilt_signed_request(sdk):
    private_key, did = _actor()
    nonce = f"raw-{uuid.uuid4().hex}"
    canonical = build_request_canonical_v3("raw-room", nonce, "raw request")

    created = sdk.create_proof(
        {
            "request_id": f"raw-{uuid.uuid4().hex}",
            "from_did": did,
            "text": "raw request",
            "created_at": _now(),
            "signature": {"nonce": nonce, "sig": sign_message(private_key, canonical.encode()), "canonical": canonical},
        }
    )

    assert created["version"] == "3"
    assert created["status"] == "pending"


def test_signed_proof_events_get_and_verify(sdk):
    """create_signed_proof, append_signed_event, append_event, get_proof, verify_proof."""
    private_key, did = _actor()
    proof_id = _signed_proof(sdk, private_key, did)["proof_id"]

    sdk.append_signed_event(proof_id, private_key, did, "agent.started", {"step": 1}, f"n-{uuid.uuid4().hex}")
    nonce = f"n-{uuid.uuid4().hex}"
    canonical = build_event_canonical_v3(proof_id, "agent.finished", sha256_json({}), nonce)
    appended = sdk.append_event(
        proof_id,
        {
            "type": "agent.finished",
            "actor_did": did,
            "payload": {},
            "signature": {"nonce": nonce, "sig": sign_message(private_key, canonical.encode()), "canonical": canonical},
        },
    )

    proof = sdk.get_proof(proof_id)
    verification = sdk.verify_proof(proof_id)

    assert appended["sequence"] == 3
    assert [event["type"] for event in proof["events"]] == ["request.created", "agent.started", "agent.finished"]
    assert verification["verdict"] == "valid"


def test_api_errors_raise_flop_proof_http_error(sdk):
    with pytest.raises(FlopProofHTTPError) as error:
        sdk.get_proof(f"proof_{uuid.uuid4().hex}")

    assert error.value.status_code == 404


def test_accept_proof_validator_attestations(sdk, validator_registry):
    attestation, report_data = validator_registry
    private_key, did = _actor()
    proof_id = _signed_proof(sdk, private_key, did)["proof_id"]
    sdk.append_signed_event(proof_id, private_key, did, "result.created", _matching_result(), f"r-{uuid.uuid4().hex}")

    accepted = sdk.accept_proof_validator_attestations(proof_id, report_data, [attestation])

    assert accepted["accepted"] is True
    assert accepted["proof_id"] == proof_id
    assert accepted["evidence"]["execution_verified"] is False


def test_accept_validator_attestation(sdk, validator_registry):
    attestation, report_data = validator_registry

    accepted = sdk.accept_validator_attestation(report_data, [attestation], result=_matching_result())

    assert accepted["accepted"] is True
    assert accepted["validators"] == 1


def test_submit_stark_evidence(sdk):
    task_hash = uuid.uuid4().hex * 2

    accepted = sdk.submit_stark_evidence(
        [{"proof": "opaque"}],
        task_hash=task_hash,
        gn_weight=5,
        latency_ms=5,
        model_hash="22" * 32,
        output_hash="33" * 32,
    )

    assert accepted == {
        "accepted": True,
        "proof_verified": False,
        "verification_status": "pending",
        "task_hash": task_hash,
        "evidence": {"class": "stark_evidence_pending", "execution_verified": False, "runtime_settled": False},
    }
