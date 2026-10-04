import hashlib
import json
import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.canonical import build_event_canonical_v3, build_request_canonical_v3
from app.verifier import verify_proof_file, verify_proof_data


TEST_API_KEY = os.getenv("FLOP_API_KEY", "flop-dev-key-2026")


@pytest.fixture
def proof_file(tmp_path, monkeypatch):
    """Export a fresh four-event proof (request.created, task.delegated,
    result.created, artifact.created) to tmp_path and return its path.

    Same flow as the test_client.py script, but in-process against an
    in-memory database, so the tests never read a proof or artifact left
    in /tmp by an earlier run and never touch proofs.db.
    """
    from app import main, models  # noqa: F401  (models registers the tables)
    from app.crypto import (
        generate_test_keypair,
        public_key_to_test_did,
        sha256_json,
        sign_message,
    )
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
    previous = main.app.dependency_overrides.get(get_db)
    main.app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(main.app, headers={"X-API-Key": TEST_API_KEY})

        private_key, public_key = generate_test_keypair()
        did = public_key_to_test_did(public_key)

        nonce = f"verifier-nonce-{uuid.uuid4().hex}"
        text = "proof created for test_verifier"
        canonical = build_request_canonical_v3("verifier-room", nonce, text)
        created = client.post(
            "/proofs",
            json={
                "request": {
                    "request_id": f"verifier-request-{uuid.uuid4().hex}",
                    "from_did": did,
                    "text": text,
                    "created_at": "2026-09-04T20:30:00Z",
                    "signature": {
                        "nonce": nonce,
                        "sig": sign_message(private_key, canonical.encode("utf-8")),
                        "canonical": canonical,
                    },
                }
            },
        )
        assert created.status_code == 201, created.text
        proof_id = created.json()["proof_id"]

        def append_event(event_type, payload):
            event_nonce = f"verifier-event-{uuid.uuid4().hex}"
            event_canonical = build_event_canonical_v3(
                proof_id, event_type, sha256_json(payload), event_nonce
            )
            response = client.post(
                f"/proofs/{proof_id}/events",
                json={
                    "type": event_type,
                    "actor_did": did,
                    "payload": payload,
                    "signature": {
                        "nonce": event_nonce,
                        "sig": sign_message(private_key, event_canonical.encode("utf-8")),
                        "canonical": event_canonical,
                    },
                },
            )
            assert response.status_code == 201, response.text

        append_event(
            "task.delegated",
            {
                "task_id": "verifier-task-001",
                "instruction": "Execute for test_verifier",
                "delegated_to": did,
            },
        )

        result_content = "test_verifier generated result"
        append_event(
            "result.created",
            {
                "content": result_content,
                "content_hash": "sha256:"
                + hashlib.sha256(result_content.encode("utf-8")).hexdigest(),
            },
        )

        artifact_path = tmp_path / "flop-artifact.txt"
        artifact_content = b"FLOP test_verifier artifact\n"
        artifact_path.write_bytes(artifact_content)
        append_event(
            "artifact.created",
            {
                "path": str(artifact_path),
                "sha256": "sha256:" + hashlib.sha256(artifact_content).hexdigest(),
            },
        )

        response = client.get(f"/proofs/{proof_id}")
        assert response.status_code == 200, response.text
        proof = response.json()
        assert len(proof["events"]) == 4
    finally:
        if previous is None:
            main.app.dependency_overrides.pop(get_db, None)
        else:
            main.app.dependency_overrides[get_db] = previous
        engine.dispose()

    path = tmp_path / "flop-proof.json"
    path.write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_proof(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_valid_proof(proof_file):
    result = verify_proof_file(proof_file)

    assert result["verdict"] == "valid"
    assert result["events_checked"] == 4
    assert result["result_hash_valid"] is True
    assert result["artifact_hash_valid"] is True

    for check in result["checks"]:
        assert check["sequence_valid"] is True
        assert check["chain_valid"] is True
        assert check["payload_hash_valid"] is True
        assert check["canonical_valid"] is True
        assert check["signature_valid"] is True


def test_payload_tampering(proof_file):
    proof = load_proof(proof_file)

    for event in proof["events"]:
        if event["type"] == "task.delegated":
            event["payload"]["instruction"] = "TAMPERED TASK"
            break

    result = verify_proof_data(proof)

    assert result["verdict"] == "invalid"

    delegated = next(
        check
        for check in result["checks"]
        if check["type"] == "task.delegated"
    )

    assert delegated["payload_hash_valid"] is False


def test_chain_tampering(proof_file):
    proof = load_proof(proof_file)

    for event in proof["events"]:
        if event["type"] == "result.created":
            event["previous_event_hash"] = "0" * 64
            break

    result = verify_proof_data(proof)

    assert result["verdict"] == "invalid"

    result_event = next(
        check
        for check in result["checks"]
        if check["type"] == "result.created"
    )

    assert result_event["chain_valid"] is False


def test_event_reordering(proof_file):
    proof = load_proof(proof_file)

    proof["events"][1]["sequence"] = 3
    proof["events"][2]["sequence"] = 2

    result = verify_proof_data(proof)

    assert result["verdict"] == "invalid"

    assert any(
        check["chain_valid"] is False
        for check in result["checks"]
    )


def test_missing_proof_id(proof_file):
    proof = load_proof(proof_file)
    proof.pop("proof_id")

    result = verify_proof_data(proof)

    assert result["verdict"] == "invalid"
    assert result["error"] == "Missing proof_id"


def test_invalid_events_structure(proof_file):
    proof = load_proof(proof_file)
    proof["events"] = "invalid"

    result = verify_proof_data(proof)

    assert result["verdict"] == "invalid"
    assert result["error"] == "Invalid events"

# A version-3 proof id (app/canonical.py requires the proof_id pattern).
TASK_HASH_PROOF_ID = "proof_" + "ab" * 16


def _build_signed_result_event(payload):
    """A valid two-event chain: the creator's request.created (sequence 1)
    and its result.created (sequence 2) carrying `payload`.

    Event authorization (docs/design/event-authorization.md, D-A7/D-A10)
    makes a chain without a sequence-1 request.created invalid, so the
    result alone is no longer a complete proof.
    """
    from app.crypto import (
        generate_test_keypair,
        hash_event_record,
        public_key_to_test_did,
        sha256_json,
        sign_message,
    )

    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)
    proof_id = TASK_HASH_PROOF_ID

    request_canonical = build_request_canonical_v3(
        "task-hash-room", "request-nonce", "task hash test"
    )
    request_signature = sign_message(private_key, request_canonical.encode("utf-8"))
    request_payload = {
        "request_id": "request-task-hash-test",
        "from_did": did,
        "text": "task hash test",
        "signature": {
            "nonce": "request-nonce",
            "sig": request_signature,
            "canonical": request_canonical,
        },
    }
    request_event = {
        "event_id": "evt_task_hash_request",
        "type": "request.created",
        "actor_did": did,
        "payload": request_payload,
        "payload_hash": sha256_json(request_payload),
        "canonical": request_canonical,
        "signature": request_signature,
        "nonce": "request-nonce",
        "created_at": "2026-09-08T00:00:00+00:00",
        "sequence": 1,
        "previous_event_hash": None,
    }

    event_type = "result.created"
    payload_hash = sha256_json(payload)
    canonical = build_event_canonical_v3(proof_id, event_type, payload_hash, "result-nonce")
    result_event = {
        "event_id": "evt_task_hash_test",
        "type": event_type,
        "actor_did": did,
        "payload": payload,
        "payload_hash": payload_hash,
        "canonical": canonical,
        "signature": sign_message(
            private_key,
            canonical.encode("utf-8"),
        ),
        "nonce": "result-nonce",
        "created_at": "2026-09-08T00:00:01+00:00",
        "sequence": 2,
        "previous_event_hash": hash_event_record(
            event_id=request_event["event_id"],
            proof_id=proof_id,
            event_type=request_event["type"],
            actor_did=request_event["actor_did"],
            payload_hash=request_event["payload_hash"],
            canonical=request_event["canonical"],
            signature=request_event["signature"],
            created_at=request_event["created_at"],
            sequence=request_event["sequence"],
        ),
    }

    return [request_event, result_event]


def _task_hash_test_inputs():
    from app.crypto import compute_task_hash

    agent = bytes.fromhex("aa" * 32)
    nonce = b"test-nonce"
    model_hash = bytes.fromhex("11" * 32)
    payload_hash = bytes.fromhex("22" * 32)
    commit_hash = bytes.fromhex("33" * 32)

    task_hash = compute_task_hash(
        agent=agent,
        nonce=nonce,
        model_hash=model_hash,
        payload_hash=payload_hash,
        commit_hash=commit_hash,
    )

    return task_hash, {
        "agent": agent.hex(),
        "nonce": nonce.hex(),
        "model_hash": model_hash.hex(),
        "payload_hash": payload_hash.hex(),
        "commit_hash": commit_hash.hex(),
    }


def test_legacy_result_has_no_task_hash_requirement():
    from app.verification_core import verify_proof_events

    payload = {
        "content": "model output",
    }

    events = _build_signed_result_event(payload)

    result = verify_proof_events(
        proof_id=TASK_HASH_PROOF_ID,
        events=events,
        version="3",
    )

    assert result["verdict"] == "valid"
    assert result["task_hash_valid"] is None


def test_result_with_consistent_task_hash_is_valid():
    from app.verification_core import verify_proof_events

    task_hash, inputs = _task_hash_test_inputs()

    payload = {
        "content": "model output",
        "task_hash": task_hash,
        "task_hash_inputs": inputs,
    }

    events = _build_signed_result_event(payload)

    result = verify_proof_events(
        proof_id=TASK_HASH_PROOF_ID,
        events=events,
        version="3",
    )

    assert result["verdict"] == "valid"
    assert result["task_hash_valid"] is True


def test_result_with_invalid_task_hash_is_invalid():
    from app.verification_core import verify_proof_events

    _, inputs = _task_hash_test_inputs()

    payload = {
        "content": "model output",
        "task_hash": "00" * 32,
        "task_hash_inputs": inputs,
    }

    events = _build_signed_result_event(payload)

    result = verify_proof_events(
        proof_id=TASK_HASH_PROOF_ID,
        events=events,
        version="3",
    )

    assert result["verdict"] == "invalid"
    assert result["task_hash_valid"] is False

def test_report_data_is_optional_metadata_on_result():
    payload = {
        "content": "model output",
        "report_data": "55" * 32,
    }

    assert payload["report_data"] == "55" * 32
    assert len(bytes.fromhex(payload["report_data"])) == 32


def test_report_data_does_not_imply_validator_attestation():
    payload = {
        "content": "model output",
        "report_data": "55" * 32,
    }

    assert "validator_attestation" not in payload
    assert "quote_verified" not in payload
    assert "event_log_verified" not in payload
