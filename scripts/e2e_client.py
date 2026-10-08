"""End-to-end check of the SDK against a running API (not a pytest test).

    FLOP_API_KEY=... python scripts/e2e_client.py

Talks to http://127.0.0.1:8000, creates a signed proof, appends events, writes
the exported proof to /tmp/flop-proof.json and an artifact under /tmp, and
verifies it. Run it against a disposable server: it writes to that server's
database.
"""

import hashlib
import json
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.crypto import (  # noqa: E402
    generate_test_keypair,
    public_key_to_test_did,
    sign_message,
)
from flop_proof_sdk import (  # noqa: E402
    FlopProofClient,
    build_event_canonical_v3,
    build_request_canonical_v3,
)


BASE_URL = "http://127.0.0.1:8000"
ARTIFACT_PATH = "/tmp/flop-client-sdk-artifact.txt"


def payload_hash(payload):
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def main():
    client = FlopProofClient(BASE_URL, api_key=os.getenv("FLOP_API_KEY", "flop-test-key-2026"))

    print("1. HEALTH")
    assert client.health()["status"] == "ok"

    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    nonce = f"client-sdk-nonce-{uuid.uuid4().hex}"
    text = "proof created through Python SDK"
    canonical = build_request_canonical_v3("client-sdk", nonce, text)
    signature = sign_message(
        private_key,
        canonical.encode("utf-8"),
    )

    request = {
        "request_id": f"client-sdk-request-{uuid.uuid4().hex}",
        "from_did": did,
        "text": text,
        "created_at": "2026-09-04T20:30:00Z",
        "signature": {
            "nonce": nonce,
            "sig": signature,
            "canonical": canonical,
        },
    }

    print("2. CREATE PROOF")
    created = client.create_proof(request)
    proof_id = created["proof_id"]
    print(f"   Proof: {proof_id}")

    def append_event(event_type, payload):
        event_nonce = f"client-sdk-event-{uuid.uuid4().hex}"
        event_canonical = build_event_canonical_v3(
            proof_id, event_type, payload_hash(payload), event_nonce
        )
        event_signature = sign_message(
            private_key,
            event_canonical.encode("utf-8"),
        )

        event = {
            "type": event_type,
            "actor_did": did,
            "payload": payload,
            "signature": {
                "nonce": event_nonce,
                "sig": event_signature,
                "canonical": event_canonical,
            },
        }

        result = client.append_event(proof_id, event)
        print(f"   {event_type}: {result['event_id']}")

    print("3. APPEND EVENTS")

    append_event(
        "task.delegated",
        {
            "task_id": "sdk-task-001",
            "instruction": "Execute through SDK",
            "delegated_to": did,
        },
    )

    result_content = "SDK generated result"
    result_hash = (
        "sha256:"
        + hashlib.sha256(
            result_content.encode("utf-8")
        ).hexdigest()
    )

    append_event(
        "result.created",
        {
            "content": result_content,
            "content_hash": result_hash,
        },
    )

    artifact_content = b"FLOP SDK artifact\n"
    with open(ARTIFACT_PATH, "wb") as f:
        f.write(artifact_content)

    artifact_hash = (
        "sha256:"
        + hashlib.sha256(artifact_content).hexdigest()
    )

    append_event(
        "artifact.created",
        {
            "path": ARTIFACT_PATH,
            "sha256": artifact_hash,
        },
    )

    print("4. GET PROOF")
    proof = client.get_proof(proof_id)

    assert proof["proof_id"] == proof_id
    assert len(proof["events"]) == 4

    with open("/tmp/flop-proof.json", "w", encoding="utf-8") as f:
        json.dump(proof, f, ensure_ascii=False, indent=2)

    print(f"   Events: {len(proof['events'])}")

    print("5. VERIFY")
    verification = client.verify_proof(proof_id)

    print(f"   Verdict: {verification['verdict']}")
    print(f"   Events checked: {verification['events_checked']}")

    assert verification["verdict"] == "valid"
    assert verification["events_checked"] == 4
    assert verification["result_hash_valid"] is True
    assert verification["artifact_hash_valid"] is True

    for check in verification["checks"]:
        assert check["sequence_valid"] is True
        assert check["chain_valid"] is True
        assert check["payload_hash_valid"] is True
        assert check["canonical_valid"] is True
        assert check["signature_valid"] is True

    print()
    print("PYTHON CLIENT SDK E2E: PASS")


if __name__ == "__main__":
    main()
