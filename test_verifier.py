import copy
import json
import os
import subprocess

from app.verifier import verify_proof_file, verify_proof_data


PROOF_FILE = "/tmp/flop-proof.json"


def ensure_proof_file():
    if os.path.exists(PROOF_FILE):
        return

    subprocess.run(
        ["python", "test_client.py"],
        check=True,
        stdout=subprocess.DEVNULL,
    )



def load_proof():
    ensure_proof_file()
    with open(PROOF_FILE, encoding="utf-8") as f:
        return json.load(f)


def test_valid_proof():
    ensure_proof_file()
    result = verify_proof_file(PROOF_FILE)

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


def test_payload_tampering():
    proof = load_proof()

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


def test_chain_tampering():
    proof = load_proof()

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


def test_event_reordering():
    proof = load_proof()

    proof["events"][1]["sequence"] = 3
    proof["events"][2]["sequence"] = 2

    result = verify_proof_data(proof)

    assert result["verdict"] == "invalid"

    assert any(
        check["chain_valid"] is False
        for check in result["checks"]
    )


def test_missing_proof_id():
    proof = load_proof()
    proof.pop("proof_id")

    result = verify_proof_data(proof)

    assert result["verdict"] == "invalid"
    assert result["error"] == "Missing proof_id"


def test_invalid_events_structure():
    proof = load_proof()
    proof["events"] = "invalid"

    result = verify_proof_data(proof)

    assert result["verdict"] == "invalid"
    assert result["error"] == "Invalid events"

def _build_signed_result_event(payload):
    from app.crypto import (
        generate_test_keypair,
        public_key_to_test_did,
        sha256_json,
        sign_message,
    )

    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    proof_id = "proof_task_hash_test"
    event_type = "result.created"
    payload_hash = sha256_json(payload)
    canonical = f"{proof_id}|{event_type}|{payload_hash}"

    return {
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
        "created_at": "2026-09-08T00:00:00+00:00",
        "sequence": 1,
        "previous_event_hash": None,
    }


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

    event = _build_signed_result_event(payload)

    result = verify_proof_events(
        proof_id="proof_task_hash_test",
        events=[event],
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

    event = _build_signed_result_event(payload)

    result = verify_proof_events(
        proof_id="proof_task_hash_test",
        events=[event],
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

    event = _build_signed_result_event(payload)

    result = verify_proof_events(
        proof_id="proof_task_hash_test",
        events=[event],
    )

    assert result["verdict"] == "invalid"
    assert result["task_hash_valid"] is False
