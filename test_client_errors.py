import pytest
import os

from client import (
    FlopProofClient,
    FlopProofError,
    FlopProofHTTPError,
)


client = FlopProofClient("http://127.0.0.1:8000", api_key=os.getenv("FLOP_API_KEY", "flop-dev-key-2026"))


def test_get_unknown_proof_raises_404():
    with pytest.raises(FlopProofHTTPError) as exc_info:
        client.get_proof("proof_does_not_exist")

    error = exc_info.value

    assert error.status_code == 404
    assert error.detail == "Proof not found"
    assert "404" in str(error)


def test_verify_unknown_proof_raises_404():
    with pytest.raises(FlopProofHTTPError) as exc_info:
        client.verify_proof("proof_does_not_exist")

    error = exc_info.value

    assert error.status_code == 404
    assert error.detail == "Proof not found"


def test_invalid_create_proof_raises_422():
    with pytest.raises(FlopProofHTTPError) as exc_info:
        client.create_proof({})

    error = exc_info.value

    assert error.status_code == 422
    assert isinstance(error.detail, list)


def test_invalid_event_proof_raises_404():
    event = {
        "type": "task.delegated",
        "actor_did": "did:test:invalid",
        "payload": {},
        "signature": {
            "nonce": "test",
            "sig": "invalid",
            "canonical": "invalid",
        },
    }

    with pytest.raises(FlopProofHTTPError) as exc_info:
        client.append_event(
            "proof_does_not_exist",
            event,
        )

    error = exc_info.value

    assert error.status_code == 404
    assert error.detail == "Proof not found"


def test_connection_error_raises_sdk_error():
    broken_client = FlopProofClient(
        "http://127.0.0.1:1",
        timeout=0.5,
    )

    with pytest.raises(FlopProofError) as exc_info:
        broken_client.health()

    assert "connection error" in str(exc_info.value).lower()
