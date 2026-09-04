import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.crypto import generate_test_keypair, public_key_to_test_did, sign_message

client = TestClient(app)


def make_request(private_key, did, request_id, text="idempotency test"):
    nonce = f"nonce-{uuid.uuid4().hex}"
    room = "idempotency-room"
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


def test_same_request_id_returns_same_proof():
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)
    request_id = f"idem-same-{uuid.uuid4().hex}"

    payload = make_request(
        private_key,
        did,
        request_id,
    )

    first = client.post("/proofs", json=payload)
    second = client.post("/proofs", json=payload)

    assert first.status_code == 201
    assert second.status_code == 201

    first_data = first.json()
    second_data = second.json()

    assert first_data["proof_id"] == second_data["proof_id"]
    assert first_data["request_id"] == request_id
    assert second_data["request_id"] == request_id


def test_same_request_id_different_actor_returns_409():
    private_key_1, public_key_1 = generate_test_keypair()
    did_1 = public_key_to_test_did(public_key_1)

    private_key_2, public_key_2 = generate_test_keypair()
    did_2 = public_key_to_test_did(public_key_2)

    request_id = f"idem-actor-{uuid.uuid4().hex}"

    first_payload = make_request(
        private_key_1,
        did_1,
        request_id,
    )

    second_payload = make_request(
        private_key_2,
        did_2,
        request_id,
    )

    first = client.post("/proofs", json=first_payload)
    second = client.post("/proofs", json=second_payload)

    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json()["detail"] == "request_id already belongs to another actor"


def test_different_request_id_creates_new_proof():
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    request_id_1 = f"idem-different-1-{uuid.uuid4().hex}"
    request_id_2 = f"idem-different-2-{uuid.uuid4().hex}"

    first = client.post(
        "/proofs",
        json=make_request(private_key, did, request_id_1),
    )

    second = client.post(
        "/proofs",
        json=make_request(private_key, did, request_id_2),
    )

    assert first.status_code == 201
    assert second.status_code == 201

    assert first.json()["proof_id"] != second.json()["proof_id"]
    assert first.json()["request_id"] == request_id_1
    assert second.json()["request_id"] == request_id_2


def test_same_request_id_same_actor_different_payload_returns_409():
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)
    request_id = f"idem-payload-{uuid.uuid4().hex}"

    first_payload = make_request(
        private_key,
        did,
        request_id,
        text="original request",
    )

    second_payload = make_request(
        private_key,
        did,
        request_id,
        text="different request",
    )

    first = client.post("/proofs", json=first_payload)
    second = client.post("/proofs", json=second_payload)

    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json()["detail"] == (
        "request_id already belongs to a different request"
    )


def test_concurrent_same_request_id_creates_single_proof():
    from concurrent.futures import ThreadPoolExecutor

    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)
    request_id = f"idem-concurrent-{uuid.uuid4().hex}"

    payload = make_request(
        private_key,
        did,
        request_id,
        text="concurrent request",
    )

    def send_request():
        response = client.post("/proofs", json=payload)
        return response.status_code, response.json()

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda _: send_request(), range(5)))

    statuses = [status for status, _ in results]

    assert all(status == 201 for status in statuses), results

    proof_ids = {
        data["proof_id"]
        for _, data in results
    }

    assert len(proof_ids) == 1, results

    returned_request_ids = {
        data["request_id"]
        for _, data in results
    }

    assert returned_request_ids == {request_id}
