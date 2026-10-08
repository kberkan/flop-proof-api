"""Validator-attestation `result` handling: missing or boolean gn_weight /
latency_ms are rejected (422 locally, 409 on the proof-bound endpoint), never
500, and the result-binding helper never raises, which is what allows the
`except Exception` around it to be removed.

Everything runs in-process; the proof-bound case uses an in-memory database.
"""

import base64
import os
import random
import uuid

import pytest
import sr25519
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.canonical import build_event_canonical_v3, build_request_canonical_v3
from app.crypto import (
    ValidatorAttestation,
    compute_report_data,
    generate_test_keypair,
    public_key_to_test_did,
    sha256_json,
    sign_message,
    sign_validator_attestation,
    validator_attestation_matches_result,
)
from app.main import app

API_KEY = os.getenv("FLOP_API_KEY", "flop-test-key-2026")
client = TestClient(app, headers={"X-API-Key": API_KEY}, raise_server_exceptions=False)

TASK_HASH = bytes.fromhex("11" * 32)
MODEL_HASH = bytes.fromhex("22" * 32)
OUTPUT_HASH = bytes.fromhex("33" * 32)
POLICY_HASH = bytes.fromhex("44" * 32)
HARDWARE_HASH = bytes.fromhex("55" * 32)
GN_WEIGHT, LATENCY_MS, TEE_TYPE = 1, 1, 1


def _signed_bundle():
    """One correctly signed attestation, its report_data, and the validator id."""
    validator_id, private_key = sr25519.pair_from_seed(bytes([7]) * 32)
    fields = dict(
        task_hash=TASK_HASH,
        gn_weight=GN_WEIGHT,
        latency_ms=LATENCY_MS,
        model_hash=MODEL_HASH,
        output_hash=OUTPUT_HASH,
        decode_policy_hash=POLICY_HASH,
        tee_type=TEE_TYPE,
        quote_verified=True,
        event_log_verified=True,
        hardware_id_hash=HARDWARE_HASH,
    )
    signature = sign_validator_attestation(keypair=(validator_id, private_key), **fields)
    attestation = {
        **{key: (value.hex() if isinstance(value, bytes) else value) for key, value in fields.items()},
        "validator_id": validator_id.hex(),
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    }
    report_data = compute_report_data(
        task_hash=TASK_HASH,
        gn_weight=GN_WEIGHT.to_bytes(8, "little"),
        latency_ms=LATENCY_MS.to_bytes(8, "little"),
        model_hash=MODEL_HASH,
        output_hash=OUTPUT_HASH,
        decode_policy_hash=POLICY_HASH,
        tee_type=TEE_TYPE.to_bytes(1, "little"),
    )
    return attestation, report_data, validator_id


def _matching_result(**override):
    result = {
        "task_hash": TASK_HASH.hex(),
        "model_hash": MODEL_HASH.hex(),
        "output_hash": OUTPUT_HASH.hex(),
        "decode_policy_hash": POLICY_HASH.hex(),
        "gn_weight": GN_WEIGHT,
        "latency_ms": LATENCY_MS,
        "tee_type": TEE_TYPE,
    }
    result.update(override)
    return {key: value for key, value in result.items() if value is not _MISSING}


_MISSING = object()


@pytest.fixture
def registry(monkeypatch):
    from app import main

    attestation, report_data, validator_id = _signed_bundle()
    monkeypatch.setattr(main, "validator_registry", main.MockValidatorRegistry([validator_id]))
    monkeypatch.setattr(main, "processed_validator_tasks", main.ProcessedTasks())
    return attestation, report_data


# --- a) local endpoint: missing fields are 422, not 500 -------------------------------

INVALID_RESULT = {"detail": "Invalid validator result encoding"}


@pytest.mark.parametrize(
    "result",
    [
        pytest.param({}, id="empty-result"),
        pytest.param(_matching_result(gn_weight=_MISSING), id="gn_weight-missing"),
        pytest.param(_matching_result(latency_ms=_MISSING), id="latency_ms-missing"),
    ],
)
def test_local_endpoint_rejects_missing_fields_with_422(registry, result):
    attestation, report_data = registry

    response = client.post(
        "/validator-attestations/accept",
        json={"result": result, "report_data": report_data, "attestations": [attestation]},
    )

    assert response.status_code == 422, response.text
    assert response.json() == INVALID_RESULT


def test_local_endpoint_accepts_the_matching_bundle(registry):
    """Control: the same bundle with integer fields is accepted."""
    attestation, report_data = registry

    response = client.post(
        "/validator-attestations/accept",
        json={"result": _matching_result(), "report_data": report_data, "attestations": [attestation]},
    )

    assert response.status_code == 200, response.text


# --- b) booleans are not integers -------------------------------------------------------

@pytest.mark.parametrize(
    "override",
    [
        pytest.param({"gn_weight": True}, id="gn_weight-true"),
        pytest.param({"latency_ms": True}, id="latency_ms-true"),
    ],
)
def test_local_endpoint_rejects_boolean_fields_with_422(registry, override):
    attestation, report_data = registry

    response = client.post(
        "/validator-attestations/accept",
        json={"result": _matching_result(**override), "report_data": report_data, "attestations": [attestation]},
    )

    assert response.status_code == 422, response.text
    assert response.json() == INVALID_RESULT


@pytest.fixture
def in_memory_db():
    from app import models  # noqa: F401  (registers the tables)
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

    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    try:
        yield
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        engine.dispose()


def _proof_with_result(result_payload):
    """A version-3 proof whose result.created carries `result_payload`."""
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)
    nonce = f"result-validation-{uuid.uuid4().hex}"
    canonical = build_request_canonical_v3("result-validation", nonce, "validator result")
    created = client.post(
        "/proofs",
        json={
            "request": {
                "request_id": f"result-validation-{uuid.uuid4().hex}",
                "from_did": did,
                "text": "validator result",
                "created_at": "2026-10-06T00:00:00Z",
                "signature": {
                    "nonce": nonce,
                    "sig": sign_message(private_key, canonical.encode()),
                    "canonical": canonical,
                },
            }
        },
    )
    assert created.status_code == 201, created.text
    proof_id = created.json()["proof_id"]
    event_nonce = f"{nonce}-result"
    event_canonical = build_event_canonical_v3(
        proof_id, "result.created", sha256_json(result_payload), event_nonce
    )
    appended = client.post(
        f"/proofs/{proof_id}/events",
        json={
            "type": "result.created",
            "actor_did": did,
            "payload": result_payload,
            "signature": {
                "nonce": event_nonce,
                "sig": sign_message(private_key, event_canonical.encode()),
                "canonical": event_canonical,
            },
        },
    )
    assert appended.status_code == 201, appended.text
    return proof_id


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        pytest.param({}, 200, id="integer-fields-control"),
        pytest.param({"gn_weight": True}, 409, id="gn_weight-true"),
        pytest.param({"latency_ms": True}, 409, id="latency_ms-true"),
    ],
)
def test_proof_bound_endpoint_rejects_boolean_stored_fields_with_409(
    in_memory_db, registry, override, expected
):
    attestation, report_data = registry
    proof_id = _proof_with_result(_matching_result(**override))

    response = client.post(
        f"/proofs/{proof_id}/validator-attestations/accept",
        json={"report_data": report_data, "attestations": [attestation]},
    )

    assert response.status_code == expected, response.text
    if expected == 409:
        assert response.json() == {"detail": "Validator attestation bundle rejected"}


# --- c) the binding helper never raises ----------------------------------------------

FUZZ_VALUES = [
    None, True, False, 0, 1, -1, 10**40, 1.5, float("nan"), "", "00" * 32, "zz" * 32,
    "0" * 63, [], [1], {}, {"a": {"b": [None]}}, "é" * 64,
]
FUZZ_FIELDS = [
    "task_hash", "model_hash", "output_hash", "decode_policy_hash", "gn_weight", "latency_ms", "tee_type",
]


def test_result_binding_never_raises_on_json_shaped_or_non_dict_results():
    """Seeded fuzz over JSON-shaped results (fields present with p=0.8) and
    non-dict inputs. validator_attestation_matches_result must return a bool
    for all of them; the bundle verifiers call it without a try block."""
    attestation = ValidatorAttestation(
        task_hash=TASK_HASH, gn_weight=1, latency_ms=1, model_hash=MODEL_HASH, output_hash=OUTPUT_HASH,
        decode_policy_hash=POLICY_HASH, tee_type=1, quote_verified=True, event_log_verified=True,
        hardware_id_hash=HARDWARE_HASH, validator_id=bytes(32), signature=bytes(64),
    )
    rng = random.Random(7)
    results = [
        {field: rng.choice(FUZZ_VALUES) for field in FUZZ_FIELDS if rng.random() < 0.8}
        for _ in range(20000)
    ]
    results += [None, [], "x", 5, 1.5, (), _matching_result()]

    outcomes = [validator_attestation_matches_result(attestation=attestation, result=r) for r in results]

    assert all(isinstance(outcome, bool) for outcome in outcomes)
    assert outcomes[-1] is True


# --- 2a) attestation integer fields are strict: no bool, string or float -------------

# Each value equals the signed integer 1 after Pydantic's lax coercion, so
# before strict typing the bundle was accepted (200).
LOOSE_ONE = [
    pytest.param(True, id="true"),
    pytest.param("1", id="string-1"),
    pytest.param("1.0", id="string-1.0"),
    pytest.param(1.0, id="float-1.0"),
]


@pytest.mark.parametrize("field", ["gn_weight", "latency_ms", "tee_type"])
@pytest.mark.parametrize("value", LOOSE_ONE)
def test_attestation_integer_fields_reject_non_integers_with_422(registry, field, value):
    attestation, report_data = registry

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": _matching_result(),
            "report_data": report_data,
            "attestations": [{**attestation, field: value}],
        },
    )

    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["loc"][-1] == field


# --- 2b / 3) result.tee_type follows gn_weight and latency_ms --------------------------

@pytest.mark.parametrize(
    "override",
    [
        pytest.param({"tee_type": True}, id="tee_type-true"),
        pytest.param({"tee_type": _MISSING}, id="tee_type-missing"),
        pytest.param({"tee_type": "1"}, id="tee_type-string"),
    ],
)
def test_local_endpoint_rejects_invalid_result_tee_type_with_422(registry, override):
    attestation, report_data = registry

    response = client.post(
        "/validator-attestations/accept",
        json={"result": _matching_result(**override), "report_data": report_data, "attestations": [attestation]},
    )

    assert response.status_code == 422, response.text
    assert response.json() == INVALID_RESULT


def test_proof_bound_endpoint_rejects_boolean_stored_tee_type_with_409(in_memory_db, registry):
    attestation, report_data = registry
    proof_id = _proof_with_result(_matching_result(tee_type=True))

    response = client.post(
        f"/proofs/{proof_id}/validator-attestations/accept",
        json={"report_data": report_data, "attestations": [attestation]},
    )

    assert response.status_code == 409, response.text
    assert response.json() == {"detail": "Validator attestation bundle rejected"}
