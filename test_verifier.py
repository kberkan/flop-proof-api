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
