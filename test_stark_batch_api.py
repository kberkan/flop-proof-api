import hashlib
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import PendingVerification


client = TestClient(app)


def _batch_payload():
    return {
        "proofs": [
            {
                "proof": "test-proof",
                "index": 0,
            }
        ],
        "gn_weight": 123,
        "task_hash": hashlib.blake2b(
            uuid.uuid4().bytes,
            digest_size=32,
        ).hexdigest(),
        "latency_ms": 42,
        "model_hash": "11" * 32,
        "output_hash": "22" * 32,
    }


def test_submit_stark_batch_accepts_valid_batch():
    payload = _batch_payload()

    response = client.post(
        "/stark-batches",
        json=payload,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["accepted"] is True
    assert body["proof_verified"] is False
    assert body["verification_status"] == "pending"
    assert body["task_hash"] == payload["task_hash"]

    # Evidence Status Contract v0.1.
    assert body["evidence"]["class"] == "stark_evidence_pending"
    assert body["evidence"]["execution_verified"] is False
    assert body["evidence"]["runtime_settled"] is False

    # Contract lock: pending intake must never claim settlement.
    assert "settled" not in body
    assert "credited" not in body
    assert body.get("verified") is not True


def test_submit_stark_batch_persists_pending_verification():
    payload = _batch_payload()

    response = client.post(
        "/stark-batches",
        json=payload,
    )

    assert response.status_code == 200

    db = SessionLocal()
    try:
        row = db.get(
            PendingVerification,
            payload["task_hash"],
        )

        assert row is not None
        assert row.task_hash == payload["task_hash"]
        assert row.gn_weight == payload["gn_weight"]
        assert row.latency_ms == payload["latency_ms"]
        assert row.model_hash == payload["model_hash"]
        assert row.output_hash == payload["output_hash"]
    finally:
        db.close()


def test_submit_stark_batch_rejects_replay():
    payload = _batch_payload()

    first = client.post(
        "/stark-batches",
        json=payload,
    )

    second = client.post(
        "/stark-batches",
        json=payload,
    )

    assert first.status_code == 200
    assert second.status_code == 409


def test_submit_stark_batch_rejects_invalid_hex_hashes():
    payload = _batch_payload()

    payload["task_hash"] = "zz" * 32

    response = client.post(
        "/stark-batches",
        json=payload,
    )

    assert response.status_code == 422


def test_submit_stark_batch_rejects_missing_required_metadata():
    payload = _batch_payload()
    del payload["output_hash"]

    response = client.post(
        "/stark-batches",
        json=payload,
    )

    assert response.status_code == 422


def test_submit_stark_batch_concurrent_replay():
    import threading

    payload = _batch_payload()

    responses = []
    errors = []

    def submit():
        try:
            responses.append(
                client.post(
                    "/stark-batches",
                    json=payload,
                )
            )
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=submit)
        for _ in range(2)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert not errors
    assert sorted(response.status_code for response in responses) == [200, 409]
