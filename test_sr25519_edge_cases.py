"""sr25519.verify raises ValueError (not False) for a public key that is not a
Ristretto point and for a signature without the schnorrkel marker bit. These
tests lock how every sr25519 verification path handles both cases.

verify_turn_ack is covered in test_compute_channel.py
(test_verify_turn_ack_returns_false_for_unusable_public_key and
test_verify_turn_ack_returns_false_for_unmarked_signature).

All hex values below are upstream wire-format-v1 values already registered in
_embedded_wire_vectors.py.
"""

import base64
from dataclasses import replace
from fractions import Fraction

import pytest

EDGE_CASES = ["non_point_key", "unmarked_signature"]

NON_POINT_KEY = b"\xff" * 32

# compute_channel_v1: V3 leaf, enclave key/signature, Merkle root/path.
CHANNEL_ID = bytes.fromhex(
    "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
)
V3_LEAF_HASH = bytes.fromhex(
    "8ca5d489cec0a255a48a2e3c2149d8028597e03ea78628d9a3672ddb80df2869"
)
ENCLAVE_PUBLIC_KEY = bytes.fromhex(
    "207b3ee770b7213b7e76bdb32702e2e166a8fea8a125613d6e98c765f5a06d40"
)
ENCLAVE_SIGNATURE = bytes.fromhex(
    "2e60e88466a203e1c106a6dfca39276cf97556c3af971f48c4da8845cc23e068"
    "cbbcaf63aa20672cd21a6f64b9513d086f2ade15c90979e870fc2162c07d2f8d"
)
MERKLE_ROOT = bytes.fromhex(
    "1020281304e2677e48c1093e7f5069fc8fbff1ea82daf2ac5b2b49d7cef756ed"
)
MERKLE_PATH = (
    (
        bytes.fromhex(
            "8ca5d489cec0a255a48a2e3c2149d8028597e03ea78628d9a3672ddb80df2869"
        ),
        False,
    ),
    (
        bytes.fromhex(
            "482735fe0838313af87270c7fa678a8fb6c3cf9d9e3af35b8c73ea39f279a92a"
        ),
        True,
    ),
)

# compute_channel_v1.receipt
AGENT_PUBLIC_KEY = bytes.fromhex(
    "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a"
)
RECEIPT_SIGNATURE = bytes.fromhex(
    "7803f98d0297c23f5df90f4bce093492de9658045d3d2296717a1e718e8bc40d"
    "891e60e517fdc459f59140b289d9fcba90809493875b5d8e77325b0ec9572683"
)

# direct_rail_v1
VALIDATOR_ID = bytes.fromhex(
    "28cc07a97ff218ae057724f5d860f1ac5bcb9a1e907d141b2d6c06116a7ecf5c"
)
VALIDATOR_SIGNATURE = bytes.fromhex(
    "729d579cd385954df683730ce83bc81f18c30838d434b890ef05efb29b3ebf42"
    "1a93d4e01f57e0ecb4036b23b55c2c5b23bd84eaa912fbd724ceb3dde8533682"
)
TASK_HASH = bytes.fromhex(
    "8d06cbf826718cda29c2ec2aa363ea13cebc118947eed5fa5d4dbb364357920d"
)
DECODE_POLICY_HASH = bytes.fromhex(
    "be572af01bd68df9c660da094b7796244dd29435d532c63c9f42efe6bdabd796"
)


def _unmark(signature: bytes) -> bytes:
    """Clear the schnorrkel marker bit (high bit of the last byte)."""
    return signature[:63] + bytes([signature[63] & 0x7F])


def _edge(case: str, public_key: bytes, signature: bytes) -> tuple[bytes, bytes]:
    if case == "non_point_key":
        return NON_POINT_KEY, signature
    return public_key, _unmark(signature)


def _attestation_fields() -> dict:
    return {
        "task_hash": TASK_HASH,
        "gn_weight": 42,
        "latency_ms": 500,
        "model_hash": bytes.fromhex("02" * 32),
        "output_hash": bytes.fromhex("03" * 32),
        "decode_policy_hash": DECODE_POLICY_HASH,
        "tee_type": 0,
        "quote_verified": True,
        "event_log_verified": True,
        "hardware_id_hash": bytes.fromhex("04" * 32),
    }


def _receipt_fields() -> dict:
    return {
        "channel_id": bytes.fromhex("11" * 32),
        "final_root": bytes.fromhex("22" * 32),
        "aggregate_gn": 42,
        "payable": 1000,
    }


def _turn_proof_kwargs(enclave_public_key: bytes, enclave_sig: bytes) -> dict:
    from app.compute_channel import VerifiedTurnRecord

    return {
        "channel_id": CHANNEL_ID,
        "turn": VerifiedTurnRecord(
            leaf_version=3,
            turn_index=2**32 - 1,
            h_in=bytes.fromhex("33" * 32),
            h_out=bytes.fromhex("44" * 32),
            g_n=2**128 - 1,
            decode_policy_hash=bytes.fromhex("66" * 32),
            h_ids=bytes.fromhex(
                "368e6eca01b76a510619dc2778d46860a9070c4a6ad73ef52e81c31dab5a404f"
            ),
            toploc_commitment_hash=bytes.fromhex("77" * 32),
            miner_recv_ms=2**64 - 3,
            miner_done_ms=2**64 - 2,
            latency_ms=1,
            enclave_sig=enclave_sig,
            agent_ack=None,
        ),
        "merkle_index": 2,
        "merkle_path": MERKLE_PATH,
        "expected_root": MERKLE_ROOT,
        "enclave_public_key": enclave_public_key,
        "expected_decode_policy_hash": bytes.fromhex("66" * 32),
    }


# a) verify_verified_turn_leaf_signature


def test_leaf_signature_control():
    from app.crypto import verify_verified_turn_leaf_signature

    assert verify_verified_turn_leaf_signature(
        ENCLAVE_PUBLIC_KEY, ENCLAVE_SIGNATURE, V3_LEAF_HASH
    ) is True


@pytest.mark.parametrize("case", EDGE_CASES)
def test_leaf_signature_edge_case_returns_false(case):
    from app.crypto import verify_verified_turn_leaf_signature

    public_key, signature = _edge(case, ENCLAVE_PUBLIC_KEY, ENCLAVE_SIGNATURE)

    assert verify_verified_turn_leaf_signature(
        public_key, signature, V3_LEAF_HASH
    ) is False


# b) verify_turn_proof


def test_turn_proof_control():
    from app.compute_channel import verify_turn_proof

    assert verify_turn_proof(
        **_turn_proof_kwargs(ENCLAVE_PUBLIC_KEY, ENCLAVE_SIGNATURE)
    ) == V3_LEAF_HASH


@pytest.mark.parametrize("case", EDGE_CASES)
def test_turn_proof_edge_case_raises_invalid_enclave_signature(case):
    from app.compute_channel import verify_turn_proof

    public_key, signature = _edge(case, ENCLAVE_PUBLIC_KEY, ENCLAVE_SIGNATURE)

    with pytest.raises(ValueError, match="^InvalidEnclaveSignature$"):
        verify_turn_proof(**_turn_proof_kwargs(public_key, signature))


# c) verify_agent_receipt_v1


def test_agent_receipt_control():
    from app.crypto import verify_agent_receipt_v1

    assert verify_agent_receipt_v1(
        AGENT_PUBLIC_KEY, RECEIPT_SIGNATURE, **_receipt_fields()
    ) is True


@pytest.mark.parametrize("case", EDGE_CASES)
def test_agent_receipt_edge_case_returns_false(case):
    from app.crypto import verify_agent_receipt_v1

    public_key, signature = _edge(case, AGENT_PUBLIC_KEY, RECEIPT_SIGNATURE)

    assert verify_agent_receipt_v1(
        public_key, signature, **_receipt_fields()
    ) is False


# d) verify_receipt


def _verify_receipt(monkeypatch, public_key: bytes, signature: bytes) -> int:
    import app.compute_channel as cc

    # The receipt signature is checked before turn collection; the stub only
    # makes the control reach a result without turn proofs.
    monkeypatch.setattr(cc, "verified_work_from_turns", lambda **kwargs: 42)

    return cc.verify_receipt(
        **_receipt_fields(),
        agent_public_key=public_key,
        agent_receipt_sig=signature,
        turn_proofs=(),
        enclave_public_key=ENCLAVE_PUBLIC_KEY,
    )


def test_verify_receipt_control(monkeypatch):
    assert _verify_receipt(monkeypatch, AGENT_PUBLIC_KEY, RECEIPT_SIGNATURE) == 42


@pytest.mark.parametrize("case", EDGE_CASES)
def test_verify_receipt_edge_case_raises_bad_receipt_signature(case, monkeypatch):
    public_key, signature = _edge(case, AGENT_PUBLIC_KEY, RECEIPT_SIGNATURE)

    with pytest.raises(ValueError, match="^BadReceiptSignature$"):
        _verify_receipt(monkeypatch, public_key, signature)


# e) verify_validator_attestation_signature


def test_validator_signature_control():
    from app.crypto import verify_validator_attestation_signature

    assert verify_validator_attestation_signature(
        VALIDATOR_ID, VALIDATOR_SIGNATURE, **_attestation_fields()
    ) is True


@pytest.mark.parametrize("case", EDGE_CASES)
def test_validator_signature_edge_case_returns_false(case):
    from app.crypto import verify_validator_attestation_signature

    public_key, signature = _edge(case, VALIDATOR_ID, VALIDATOR_SIGNATURE)

    assert verify_validator_attestation_signature(
        public_key, signature, **_attestation_fields()
    ) is False


# g) POST /validator-attestations/accept


API_KEY = "sr25519-edge-case-key"


@pytest.fixture
def attestation_endpoint(monkeypatch):
    """TestClient against the in-memory endpoint (no database).

    Every global the endpoint reads is monkeypatched, so it is restored after
    the test. The returned function sets a one-key registry (quorum 1) per
    request, so a rejection can only come from the signature check.
    """
    from fastapi.testclient import TestClient

    from app import main

    monkeypatch.setattr(main, "API_KEY", API_KEY)
    monkeypatch.setattr(main, "RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(main, "VALIDATOR_ATTESTATION_THRESHOLD", Fraction(2, 3))
    monkeypatch.setattr(main, "processed_validator_tasks", main.ProcessedTasks())
    monkeypatch.setattr(main, "validator_registry", main.MockValidatorRegistry([]))

    client = TestClient(main.app, headers={"X-API-Key": API_KEY})
    fields = _attestation_fields()
    report_data = main.compute_report_data(
        task_hash=fields["task_hash"],
        gn_weight=fields["gn_weight"].to_bytes(8, "little"),
        latency_ms=fields["latency_ms"].to_bytes(8, "little"),
        model_hash=fields["model_hash"],
        output_hash=fields["output_hash"],
        decode_policy_hash=fields["decode_policy_hash"],
        tee_type=fields["tee_type"].to_bytes(1, "little"),
    )
    result = {
        "task_hash": fields["task_hash"].hex(),
        "gn_weight": fields["gn_weight"],
        "latency_ms": fields["latency_ms"],
        "model_hash": fields["model_hash"].hex(),
        "output_hash": fields["output_hash"].hex(),
        "decode_policy_hash": fields["decode_policy_hash"].hex(),
        "tee_type": fields["tee_type"],
    }

    def post(validator_id: bytes, signature: bytes):
        monkeypatch.setattr(
            main, "validator_registry", main.MockValidatorRegistry([validator_id])
        )
        attestation = {
            key: value.hex() if isinstance(value, bytes) else value
            for key, value in fields.items()
        }
        attestation["validator_id"] = validator_id.hex()
        attestation["signature"] = (
            base64.urlsafe_b64encode(signature).decode().rstrip("=")
        )
        return client.post(
            "/validator-attestations/accept",
            json={
                "result": result,
                "report_data": report_data,
                "attestations": [attestation],
            },
        )

    return post


def test_attestation_endpoint_rejects_sr25519_edge_cases_then_accepts_control(
    attestation_endpoint,
):
    for case in EDGE_CASES:
        validator_id, signature = _edge(case, VALIDATOR_ID, VALIDATOR_SIGNATURE)
        response = attestation_endpoint(validator_id, signature)

        assert response.status_code == 409, case
        assert response.json() == {"detail": "Validator attestation bundle rejected"}

    # Control last: acceptance consumes the task hash.
    response = attestation_endpoint(VALIDATOR_ID, VALIDATOR_SIGNATURE)

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["task_hash"] == TASK_HASH.hex()


def test_attestation_endpoint_globals_are_restored():
    """Runs after the endpoint test in file order; the monkeypatched globals
    must be back to their module values."""
    from app import main

    assert main.API_KEY != API_KEY
    assert not main.processed_validator_tasks.is_processed(TASK_HASH)
    assert not main.validator_registry.is_active(VALIDATOR_ID)
