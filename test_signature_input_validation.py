"""Malformed input to the sr25519 verifiers is a ValueError, not False.

verify_verified_turn_leaf_signature, verify_agent_receipt_v1 and
verify_validator_attestation_signature follow verify_turn_ack: input checks
raise ValueError, and only sr25519.verify is wrapped, turning its ValueError
(a key that is not a Ristretto point, a signature without the schnorrkel
marker) into False. Those sr25519 cases stay locked in
test_sr25519_edge_cases.py; the API's handling of malformed attestations is
checked at the end of this file.
"""

import base64
import os

import pytest
from fastapi.testclient import TestClient

from app.crypto import (
    verify_agent_receipt_v1,
    verify_validator_attestation_signature,
    verify_verified_turn_leaf_signature,
)

KEY = bytes(range(32))
SIG = bytes(range(64))
HASH = bytes(range(32, 64))


# --- verify_verified_turn_leaf_signature ------------------------------------------

LEAF_ARGS = {"public_key": KEY, "signature": SIG, "leaf_hash": HASH}


@pytest.mark.parametrize(
    "override",
    [
        pytest.param({"public_key": KEY[:31]}, id="public_key-31-bytes"),
        pytest.param({"public_key": "k" * 32}, id="public_key-str"),
        pytest.param({"public_key": None}, id="public_key-None"),
        pytest.param({"signature": SIG[:63]}, id="signature-63-bytes"),
        pytest.param({"signature": bytearray(SIG)}, id="signature-bytearray"),
        pytest.param({"leaf_hash": HASH + b"x"}, id="leaf_hash-33-bytes"),
    ],
)
def test_leaf_signature_rejects_malformed_input_with_value_error(override):
    with pytest.raises(ValueError):
        verify_verified_turn_leaf_signature(**{**LEAF_ARGS, **override})


# --- verify_agent_receipt_v1 ------------------------------------------------------

RECEIPT_ARGS = {
    "public_key": KEY,
    "signature": SIG,
    "channel_id": HASH,
    "final_root": HASH,
    "aggregate_gn": 1,
    "payable": 1,
}


@pytest.mark.parametrize(
    "override",
    [
        pytest.param({"public_key": KEY[:31]}, id="public_key-31-bytes"),
        pytest.param({"signature": SIG[:63]}, id="signature-63-bytes"),
        pytest.param({"signature": "s" * 64}, id="signature-str"),
        pytest.param({"channel_id": HASH[:31]}, id="channel_id-31-bytes"),
        pytest.param({"final_root": HASH + b"x"}, id="final_root-33-bytes"),
        pytest.param({"aggregate_gn": 2**128}, id="aggregate_gn-above-u128"),
        pytest.param({"payable": -1}, id="payable-negative"),
        pytest.param({"aggregate_gn": "1"}, id="aggregate_gn-str"),
        pytest.param({"payable": True}, id="payable-bool"),
    ],
)
def test_agent_receipt_rejects_malformed_input_with_value_error(override):
    with pytest.raises(ValueError):
        verify_agent_receipt_v1(**{**RECEIPT_ARGS, **override})


def test_receipt_payload_builder_keeps_its_type_error_contract():
    from app.crypto import compute_agent_receipt_v1_signable_payload

    with pytest.raises(TypeError):
        compute_agent_receipt_v1_signable_payload(HASH, HASH, "1", 1)


# --- verify_validator_attestation_signature ----------------------------------------

VALIDATOR_ARGS = {
    "public_key": KEY,
    "signature": SIG,
    "task_hash": HASH,
    "gn_weight": 1,
    "latency_ms": 1,
    "model_hash": HASH,
    "output_hash": HASH,
    "decode_policy_hash": HASH,
    "tee_type": 1,
    "quote_verified": True,
    "event_log_verified": True,
    "hardware_id_hash": HASH,
}


@pytest.mark.parametrize(
    "override",
    [
        pytest.param({"public_key": KEY[:31]}, id="public_key-31-bytes"),
        pytest.param({"public_key": "k" * 32}, id="public_key-str"),
        pytest.param({"signature": SIG[:63]}, id="signature-63-bytes"),
        pytest.param({"signature": bytearray(SIG)}, id="signature-bytearray"),
        # Field encoding errors already raised ValueError before this change.
        pytest.param({"task_hash": HASH[:31]}, id="task_hash-31-bytes"),
        pytest.param({"gn_weight": 2**64}, id="gn_weight-above-u64"),
    ],
)
def test_validator_signature_rejects_malformed_input_with_value_error(override):
    with pytest.raises(ValueError):
        verify_validator_attestation_signature(**{**VALIDATOR_ARGS, **override})


# --- well-formed input with a bad signature is still False ---------------------------

def test_well_formed_input_with_wrong_signature_is_false():
    assert verify_verified_turn_leaf_signature(**LEAF_ARGS) is False
    assert verify_agent_receipt_v1(**RECEIPT_ARGS) is False
    assert verify_validator_attestation_signature(**VALIDATOR_ARGS) is False


# --- API: malformed attestation encoding is 422, never 500 ----------------------------

client = TestClient(
    __import__("app.main", fromlist=["app"]).app,
    headers={"X-API-Key": os.getenv("FLOP_API_KEY", "flop-dev-key-2026")},
    raise_server_exceptions=False,
)


def _attestation(**override):
    attestation = {
        "task_hash": "11" * 32,
        "gn_weight": 1,
        "latency_ms": 1,
        "model_hash": "22" * 32,
        "output_hash": "33" * 32,
        "decode_policy_hash": "44" * 32,
        "tee_type": 1,
        "quote_verified": True,
        "event_log_verified": True,
        "hardware_id_hash": "55" * 32,
        "validator_id": "66" * 32,
        "signature": base64.urlsafe_b64encode(SIG).decode().rstrip("="),
    }
    attestation.update(override)
    return attestation


@pytest.mark.parametrize(
    "override",
    [
        pytest.param({"validator_id": "zz" * 32}, id="validator_id-not-hex"),
        pytest.param({"task_hash": "1g" * 32}, id="task_hash-not-hex"),
        pytest.param({"signature": "!" * 86}, id="signature-not-base64"),
        pytest.param(
            {"signature": base64.urlsafe_b64encode(bytes(66)).decode()},
            id="signature-decodes-to-66-bytes",
        ),
    ],
)
def test_malformed_attestation_encoding_is_422_never_500(override):
    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": {},
            "report_data": "00" * 64,
            "attestations": [_attestation(**override)],
        },
    )

    assert response.status_code == 422, response.text
    assert response.json() == {"detail": "Invalid validator attestation encoding"}
