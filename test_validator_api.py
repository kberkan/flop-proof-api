import os

import sr25519
from fastapi.testclient import TestClient

from app.crypto import (
    DecodePolicy,
    DecodePolicyClass,
    OutputTransform,
    SamplingParams,
    compute_decode_policy_hash,
    encode_decode_policy,
    sign_validator_attestation,
    verify_validator_attestation_signature,
)
from app.main import app


client = TestClient(
    app,
    headers={
        "X-API-Key": os.getenv(
            "FLOP_API_KEY",
            "flop-dev-key-2026",
        )
    },
)


def make_valid_attestation():
    seed = bytes([7]) * 32
    validator_id, private_key = sr25519.pair_from_seed(seed)

    task_hash = bytes.fromhex("11" * 32)
    model_hash = bytes.fromhex("22" * 32)
    output_hash = bytes.fromhex("33" * 32)
    decode_policy_hash = bytes.fromhex("44" * 32)
    hardware_id_hash = bytes.fromhex("55" * 32)

    gn_weight = 1
    latency_ms = 123
    tee_type = 1
    quote_verified = True
    event_log_verified = True

    signature = sign_validator_attestation(
        keypair=(validator_id, private_key),
        task_hash=task_hash,
        gn_weight=gn_weight,
        latency_ms=latency_ms,
        model_hash=model_hash,
        output_hash=output_hash,
        decode_policy_hash=decode_policy_hash,
        tee_type=tee_type,
        quote_verified=quote_verified,
        event_log_verified=event_log_verified,
        hardware_id_hash=hardware_id_hash,
    )

    return {
        "validator_id": validator_id,
        "private_key": private_key,
        "task_hash": task_hash,
        "model_hash": model_hash,
        "output_hash": output_hash,
        "decode_policy_hash": decode_policy_hash,
        "hardware_id_hash": hardware_id_hash,
        "gn_weight": gn_weight,
        "latency_ms": latency_ms,
        "tee_type": tee_type,
        "quote_verified": quote_verified,
        "event_log_verified": event_log_verified,
        "signature": signature,
    }


def make_validator_bundle():
    validators = []

    for i in (7, 8, 9):
        seed = bytes([i]) * 32
        validator_id, private_key = sr25519.pair_from_seed(seed)

        validators.append(
            {
                "validator_id": validator_id,
                "private_key": private_key,
            }
        )

    common = {
        "task_hash": bytes.fromhex("11" * 32),
        "model_hash": bytes.fromhex("22" * 32),
        "output_hash": bytes.fromhex("33" * 32),
        "decode_policy_hash": bytes.fromhex("44" * 32),
        "hardware_id_hash": bytes.fromhex("55" * 32),
        "gn_weight": 1,
        "latency_ms": 123,
        "tee_type": 1,
        "quote_verified": True,
        "event_log_verified": True,
    }

    attestations = []

    for validator in validators[:2]:
        signature = sign_validator_attestation(
            keypair=(validator["validator_id"], validator["private_key"]),
            **common,
        )

        attestations.append(
            {
                **common,
                "validator_id": validator["validator_id"],
                "signature": signature,
            }
        )

    return validators, common, attestations


def test_validator_fixture_signature_is_valid():
    fixture = make_valid_attestation()

    assert len(fixture["validator_id"]) == 32
    assert len(fixture["signature"]) == 64

    assert verify_validator_attestation_signature(
        public_key=fixture["validator_id"],
        signature=fixture["signature"],
        task_hash=fixture["task_hash"],
        gn_weight=fixture["gn_weight"],
        latency_ms=fixture["latency_ms"],
        model_hash=fixture["model_hash"],
        output_hash=fixture["output_hash"],
        decode_policy_hash=fixture["decode_policy_hash"],
        tee_type=fixture["tee_type"],
        quote_verified=fixture["quote_verified"],
        event_log_verified=fixture["event_log_verified"],
        hardware_id_hash=fixture["hardware_id_hash"],
    )


def test_validator_attestation_endpoint_rejects_empty_attestations():
    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": {},
            "report_data": "00" * 32,
            "attestations": [],
        },
    )

    assert response.status_code == 422



def test_validator_attestation_endpoint_accepts_two_of_three_validators(monkeypatch):
    from app import main

    validators, common, attestations = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    report_data = main.sha256_bytes(
        (
            common["task_hash"]
            + common["gn_weight"].to_bytes(8, "little")
            + common["latency_ms"].to_bytes(8, "little")
            + common["model_hash"]
            + common["output_hash"]
            + common["decode_policy_hash"]
            + common["tee_type"].to_bytes(1, "little")
        )
    )

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": common["gn_weight"],
        "latency_ms": common["latency_ms"],
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": report_data,
            "attestations": [
                {
                    **{
                        key: value.hex()
                        if isinstance(value, bytes)
                        else value
                        for key, value in attestation.items()
                        if key != "private_key"
                    },
                    "signature": __import__("base64").urlsafe_b64encode(
                        attestation["signature"]
                    ).rstrip(b"=").decode(),
                }
                for attestation in attestations
            ],
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["accepted"] is True
    assert body["validators"] == 2

    # Evidence Status Contract v0.1.
    assert body["evidence"]["class"] == "validator_attestation_binding"
    assert body["evidence"]["execution_verified"] is False
    assert body["evidence"]["runtime_settled"] is False

    # Contract lock:
    # attestation acceptance is not protocol settlement/crediting.
    assert "settled" not in body
    assert "credited" not in body
    assert body.get("verified") is not True


def test_validator_attestation_endpoint_rejects_result_binding_mismatch(monkeypatch):
    from app import main

    validators, common, attestations = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    report_data = main.sha256_bytes(
        (
            common["task_hash"]
            + common["gn_weight"].to_bytes(8, "little")
            + common["latency_ms"].to_bytes(8, "little")
            + common["model_hash"]
            + common["output_hash"]
            + common["decode_policy_hash"]
            + common["tee_type"].to_bytes(1, "little")
        )
    )

    result = {
        "task_hash": "ff" * 32,
        "gn_weight": common["gn_weight"],
        "latency_ms": common["latency_ms"],
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": report_data,
            "attestations": [
                {
                    **{
                        key: value.hex()
                        if isinstance(value, bytes)
                        else value
                        for key, value in attestation.items()
                        if key != "private_key"
                    },
                    "signature": __import__("base64").urlsafe_b64encode(
                        attestation["signature"]
                    ).rstrip(b"=").decode(),
                }
                for attestation in attestations
            ],
        },
    )

    assert response.status_code == 409


def test_validator_attestation_endpoint_rejects_report_data_mismatch(monkeypatch):
    from app import main

    validators, common, attestations = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    valid_report_data = main.sha256_bytes(
        (
            common["task_hash"]
            + common["gn_weight"].to_bytes(8, "little")
            + common["latency_ms"].to_bytes(8, "little")
            + common["model_hash"]
            + common["output_hash"]
            + common["decode_policy_hash"]
            + common["tee_type"].to_bytes(1, "little")
        )
    )

    invalid_report_data = (
        ("00" if valid_report_data[:2] != "00" else "ff")
        + valid_report_data[2:]
    )

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": common["gn_weight"],
        "latency_ms": common["latency_ms"],
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": invalid_report_data,
            "attestations": [
                {
                    **{
                        key: value.hex()
                        if isinstance(value, bytes)
                        else value
                        for key, value in attestation.items()
                        if key != "private_key"
                    },
                    "signature": __import__("base64").urlsafe_b64encode(
                        attestation["signature"]
                    ).rstrip(b"=").decode(),
                }
                for attestation in attestations
            ],
        },
    )

    assert response.status_code == 409


def test_validator_attestation_endpoint_rejects_below_quorum_without_consuming_task(
    monkeypatch,
):
    from app import main

    validators, common, attestations = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    report_data = main.sha256_bytes(
        (
            common["task_hash"]
            + common["gn_weight"].to_bytes(8, "little")
            + common["latency_ms"].to_bytes(8, "little")
            + common["model_hash"]
            + common["output_hash"]
            + common["decode_policy_hash"]
            + common["tee_type"].to_bytes(1, "little")
        )
    )

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": common["gn_weight"],
        "latency_ms": common["latency_ms"],
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    def encode_attestation(attestation):
        import base64

        return {
            **{
                key: value.hex()
                if isinstance(value, bytes)
                else value
                for key, value in attestation.items()
                if key != "private_key"
            },
            "signature": base64.urlsafe_b64encode(
                attestation["signature"]
            ).rstrip(b"=").decode(),
        }

    one_validator_response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": report_data,
            "attestations": [encode_attestation(attestations[0])],
        },
    )

    assert one_validator_response.status_code == 409

    two_validator_response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": report_data,
            "attestations": [
                encode_attestation(attestations[0]),
                encode_attestation(attestations[1]),
            ],
        },
    )

    assert two_validator_response.status_code == 200
    assert two_validator_response.json()["accepted"] is True


def test_validator_attestation_endpoint_rejects_injected_validator(monkeypatch):
    from app import main

    validators, common, attestations = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    import base64

    attacker_id, attacker_private_key = sr25519.pair_from_seed(
        bytes([99]) * 32
    )

    attacker_signature = sign_validator_attestation(
        keypair=(attacker_id, attacker_private_key),
        task_hash=common["task_hash"],
        gn_weight=common["gn_weight"],
        latency_ms=common["latency_ms"],
        model_hash=common["model_hash"],
        output_hash=common["output_hash"],
        decode_policy_hash=common["decode_policy_hash"],
        tee_type=common["tee_type"],
        quote_verified=common["quote_verified"],
        event_log_verified=common["event_log_verified"],
        hardware_id_hash=common["hardware_id_hash"],
    )

    report_data = main.sha256_bytes(
        (
            common["task_hash"]
            + common["gn_weight"].to_bytes(8, "little")
            + common["latency_ms"].to_bytes(8, "little")
            + common["model_hash"]
            + common["output_hash"]
            + common["decode_policy_hash"]
            + common["tee_type"].to_bytes(1, "little")
        )
    )

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": common["gn_weight"],
        "latency_ms": common["latency_ms"],
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    def encode_attestation(attestation):
        return {
            **{
                key: value.hex()
                if isinstance(value, bytes)
                else value
                for key, value in attestation.items()
                if key != "private_key"
            },
            "signature": base64.urlsafe_b64encode(
                attestation["signature"]
            ).rstrip(b"=").decode(),
        }

    injected = {
        **{
            key: value.hex()
            if isinstance(value, bytes)
            else value
            for key, value in common.items()
        },
        "validator_id": attacker_id.hex(),
        "signature": base64.urlsafe_b64encode(
            attacker_signature
        ).rstrip(b"=").decode(),
    }

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": report_data,
            "attestations": [
                encode_attestation(attestations[0]),
                injected,
            ],
        },
    )

    assert response.status_code == 409


def test_validator_attestation_endpoint_rejects_replay(monkeypatch):
    from app import main

    validators, common, attestations = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    import base64

    report_data = main.sha256_bytes(
        (
            common["task_hash"]
            + common["gn_weight"].to_bytes(8, "little")
            + common["latency_ms"].to_bytes(8, "little")
            + common["model_hash"]
            + common["output_hash"]
            + common["decode_policy_hash"]
            + common["tee_type"].to_bytes(1, "little")
        )
    )

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": common["gn_weight"],
        "latency_ms": common["latency_ms"],
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    def encode_attestation(attestation):
        return {
            **{
                key: value.hex()
                if isinstance(value, bytes)
                else value
                for key, value in attestation.items()
                if key != "private_key"
            },
            "signature": base64.urlsafe_b64encode(
                attestation["signature"]
            ).rstrip(b"=").decode(),
        }

    payload = {
        "result": result,
        "report_data": report_data,
        "attestations": [
            encode_attestation(attestations[0]),
            encode_attestation(attestations[1]),
        ],
    }

    first_response = client.post(
        "/validator-attestations/accept",
        json=payload,
    )

    assert first_response.status_code == 200
    assert first_response.json()["accepted"] is True

    replay_response = client.post(
        "/validator-attestations/accept",
        json=payload,
    )

    assert replay_response.status_code == 409


def test_validator_attestation_endpoint_is_single_winner_under_concurrency(
    monkeypatch,
):
    from concurrent.futures import ThreadPoolExecutor
    import base64
    from app import main

    validators, common, attestations = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    report_data = main.sha256_bytes(
        (
            common["task_hash"]
            + common["gn_weight"].to_bytes(8, "little")
            + common["latency_ms"].to_bytes(8, "little")
            + common["model_hash"]
            + common["output_hash"]
            + common["decode_policy_hash"]
            + common["tee_type"].to_bytes(1, "little")
        )
    )

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": common["gn_weight"],
        "latency_ms": common["latency_ms"],
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    def encode_attestation(attestation):
        return {
            **{
                key: value.hex()
                if isinstance(value, bytes)
                else value
                for key, value in attestation.items()
                if key != "private_key"
            },
            "signature": base64.urlsafe_b64encode(
                attestation["signature"]
            ).rstrip(b"=").decode(),
        }

    payload = {
        "result": result,
        "report_data": report_data,
        "attestations": [
            encode_attestation(attestations[0]),
            encode_attestation(attestations[1]),
        ],
    }

    def send_request():
        local_client = TestClient(
            main.app,
            headers={
                "X-API-Key": os.getenv(
                    "FLOP_API_KEY",
                    "flop-dev-key-2026",
                )
            },
        )
        return local_client.post(
            "/validator-attestations/accept",
            json=payload,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        responses = list(executor.map(lambda _: send_request(), range(8)))

    statuses = [response.status_code for response in responses]

    assert statuses.count(200) == 1
    assert statuses.count(409) == 7


def test_proof_validator_attestation_throughput_tripwire_rejects_bound_result(monkeypatch):
    import base64
    import hashlib
    import uuid
    import sr25519

    from app import main
    from app.crypto import (
        compute_task_hash,
        compute_report_data,
        generate_test_keypair,
        public_key_to_test_did,
        sign_validator_attestation,
    )
    from client import FlopProofClient

    api_client = FlopProofClient(
        "http://127.0.0.1:8000",
        api_key=os.getenv("FLOP_API_KEY", "flop-dev-key-2026"),
    )

    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    nonce = f"validator-proof-tripwire-{uuid.uuid4().hex}"

    created = api_client.create_signed_proof(
        private_key=private_key,
        did=did,
        text="validator proof tripwire",
        room="validator-proof-tripwire-room",
        nonce=nonce,
        request_id=f"validator-proof-tripwire-{uuid.uuid4().hex}",
        created_at="2026-09-08T20:00:00Z",
    )

    proof_id = created["proof_id"]

    task_agent = bytes.fromhex("aa" * 32)
    task_nonce = f"validator-proof-tripwire-task-{uuid.uuid4().hex}".encode()
    model_hash = bytes.fromhex("11" * 32)
    task_payload_hash = bytes.fromhex("22" * 32)
    commit_hash = bytes.fromhex("33" * 32)

    task_hash = compute_task_hash(
        agent=task_agent,
        nonce=task_nonce,
        model_hash=model_hash,
        payload_hash=task_payload_hash,
        commit_hash=commit_hash,
    )

    content = "validator-bound tripwire result"
    content_hash = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    gn_weight = 2_000_001
    latency_ms = 1000
    decode_policy_hash = bytes.fromhex("44" * 32)
    output_hash = bytes.fromhex("55" * 32)
    hardware_id_hash = bytes.fromhex("66" * 32)

    result_payload = {
        "content": content,
        "content_hash": content_hash,
        "task_hash": task_hash,
        "task_hash_inputs": {
            "agent": task_agent.hex(),
            "nonce": task_nonce.hex(),
            "model_hash": model_hash.hex(),
            "payload_hash": task_payload_hash.hex(),
            "commit_hash": commit_hash.hex(),
        },
        "model_hash": model_hash.hex(),
        "gn_weight": gn_weight,
        "latency_ms": latency_ms,
        "decode_policy_hash": decode_policy_hash.hex(),
        "tee_type": 1,
        "output_hash": output_hash.hex(),
    }

    api_client.append_signed_event(
        proof_id=proof_id,
        private_key=private_key,
        did=did,
        event_type="result.created",
        payload=result_payload,
        nonce=nonce + "-result",
    )

    validator_keys = [
        sr25519.pair_from_seed(bytes([7]) * 32),
        sr25519.pair_from_seed(bytes([8]) * 32),
        sr25519.pair_from_seed(bytes([9]) * 32),
    ]

    task_hash_bytes = bytes.fromhex(task_hash)
    attestations = []

    for validator_id, validator_private in validator_keys[:2]:
        signature = sign_validator_attestation(
            keypair=(validator_id, validator_private),
            task_hash=task_hash_bytes,
            gn_weight=gn_weight,
            latency_ms=latency_ms,
            model_hash=model_hash,
            output_hash=output_hash,
            decode_policy_hash=decode_policy_hash,
            tee_type=1,
            quote_verified=True,
            event_log_verified=True,
            hardware_id_hash=hardware_id_hash,
        )

        attestations.append(
            {
                "task_hash": task_hash,
                "gn_weight": gn_weight,
                "latency_ms": latency_ms,
                "model_hash": model_hash.hex(),
                "output_hash": output_hash.hex(),
                "decode_policy_hash": decode_policy_hash.hex(),
                "tee_type": 1,
                "quote_verified": True,
                "event_log_verified": True,
                "hardware_id_hash": hardware_id_hash.hex(),
                "validator_id": validator_id.hex(),
                "signature": base64.urlsafe_b64encode(signature)
                .rstrip(b"=")
                .decode(),
            }
        )

    report_data = compute_report_data(
        task_hash=task_hash_bytes,
        gn_weight=gn_weight.to_bytes(8, "little"),
        latency_ms=latency_ms.to_bytes(8, "little"),
        model_hash=model_hash,
        output_hash=output_hash,
        decode_policy_hash=decode_policy_hash,
        tee_type=(1).to_bytes(1, "little"),
    )

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator_id for validator_id, _ in validator_keys]
        ),
    )
    processed = main.ProcessedTasks()
    monkeypatch.setattr(main, "processed_validator_tasks", processed)

    response = client.post(
        f"/proofs/{proof_id}/validator-attestations/accept",
        json={
            "report_data": report_data,
            "attestations": attestations,
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Validator attestation bundle rejected"
    assert processed.is_processed(task_hash_bytes) is False


def test_proof_validator_attestation_requires_result_created(monkeypatch):
    from app import main

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry([]),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    response = client.post(
        "/proofs/proof-that-does-not-exist/validator-attestations/accept",
        json={
            "report_data": "00" * 32,
            "attestations": [],
        },
    )

    assert response.status_code == 404


def test_proof_validator_attestation_accepts_bound_result(monkeypatch):
    import base64
    import hashlib
    import uuid
    import sr25519

    from app import main
    from app.crypto import compute_task_hash, compute_report_data, generate_test_keypair, public_key_to_test_did, sign_validator_attestation
    from client import FlopProofClient

    api_client = FlopProofClient(
        "http://127.0.0.1:8000",
        api_key=os.getenv("FLOP_API_KEY", "flop-dev-key-2026"),
    )

    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    nonce = f"validator-proof-{uuid.uuid4().hex}"

    created = api_client.create_signed_proof(
        private_key=private_key,
        did=did,
        text="validator proof integration",
        room="validator-proof-room",
        nonce=nonce,
        request_id=f"validator-proof-{uuid.uuid4().hex}",
        created_at="2026-09-08T20:00:00Z",
    )

    assert created["proof_id"]

    proof_id = created["proof_id"]

    task_agent = bytes.fromhex("aa" * 32)
    task_nonce = f"validator-proof-task-{uuid.uuid4().hex}".encode()
    model_hash = bytes.fromhex("11" * 32)
    task_payload_hash = bytes.fromhex("22" * 32)
    commit_hash = bytes.fromhex("33" * 32)

    task_hash = compute_task_hash(
        agent=task_agent,
        nonce=task_nonce,
        model_hash=model_hash,
        payload_hash=task_payload_hash,
        commit_hash=commit_hash,
    )

    content = "validator-bound result"
    content_hash = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    result_payload = {
        "content": content,
        "content_hash": content_hash,
        "task_hash": task_hash,
        "task_hash_inputs": {
            "agent": task_agent.hex(),
            "nonce": task_nonce.hex(),
            "model_hash": model_hash.hex(),
            "payload_hash": task_payload_hash.hex(),
            "commit_hash": commit_hash.hex(),
        },
        "model_hash": model_hash.hex(),
        "gn_weight": 1,
        "latency_ms": 123,
        "decode_policy_hash": "44" * 32,
        "tee_type": 1,
        "output_hash": "55" * 32,
    }

    api_client.append_signed_event(
        proof_id=proof_id,
        private_key=private_key,
        did=did,
        event_type="result.created",
        payload=result_payload,
        nonce=nonce + "-result",
    )

    validator_keys = [
        sr25519.pair_from_seed(bytes([7]) * 32),
        sr25519.pair_from_seed(bytes([8]) * 32),
        sr25519.pair_from_seed(bytes([9]) * 32),
    ]

    task_hash_bytes = bytes.fromhex(task_hash)
    output_hash = bytes.fromhex("55" * 32)
    decode_policy_hash = bytes.fromhex("44" * 32)
    hardware_id_hash = bytes.fromhex("55" * 32)

    attestations = []

    for validator_id, validator_private in validator_keys[:2]:
        signature = sign_validator_attestation(
            keypair=(validator_id, validator_private),
            task_hash=task_hash_bytes,
            gn_weight=1,
            latency_ms=123,
            model_hash=model_hash,
            output_hash=output_hash,
            decode_policy_hash=decode_policy_hash,
            tee_type=1,
            quote_verified=True,
            event_log_verified=True,
            hardware_id_hash=hardware_id_hash,
        )

        attestations.append(
            {
                "task_hash": task_hash,
                "gn_weight": 1,
                "latency_ms": 123,
                "model_hash": model_hash.hex(),
                "output_hash": output_hash.hex(),
                "decode_policy_hash": decode_policy_hash.hex(),
                "tee_type": 1,
                "quote_verified": True,
                "event_log_verified": True,
                "hardware_id_hash": hardware_id_hash.hex(),
                "validator_id": validator_id.hex(),
                "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
            }
        )

    report_data = compute_report_data(
        task_hash=task_hash_bytes,
        gn_weight=(1).to_bytes(8, "little"),
        latency_ms=(123).to_bytes(8, "little"),
        model_hash=model_hash,
        output_hash=output_hash,
        decode_policy_hash=decode_policy_hash,
        tee_type=(1).to_bytes(1, "little"),
    )

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator_id for validator_id, _ in validator_keys]
        ),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    response = client.post(
        f"/proofs/{proof_id}/validator-attestations/accept",
        json={
            "report_data": report_data,
            "attestations": attestations,
        },
    )

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["proof_id"] == proof_id
    assert response.json()["validators"] == 2

def test_proof_validator_attestation_rejects_missing_result_created(monkeypatch):
    from app import main
    import uuid

    api_client = __import__("client", fromlist=["FlopProofClient"]).FlopProofClient(
        "http://127.0.0.1:8000",
        api_key=os.getenv("FLOP_API_KEY", "flop-dev-key-2026"),
    )

    from app.crypto import generate_test_keypair, public_key_to_test_did
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    created = api_client.create_signed_proof(
        private_key=private_key,
        did=did,
        text="no result event",
        room="validator-negative",
        nonce=f"negative-{uuid.uuid4().hex}",
        request_id=f"negative-{uuid.uuid4().hex}",
        created_at="2026-09-08T20:00:00Z",
    )

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry([]),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    response = client.post(
        f"/proofs/{created['proof_id']}/validator-attestations/accept",
        json={
            "report_data": "00" * 32,
            "attestations": [],
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "result.created event not found"


def test_proof_validator_attestation_rejects_incomplete_result(monkeypatch):
    from app import main
    import uuid

    api_client = __import__("client", fromlist=["FlopProofClient"]).FlopProofClient(
        "http://127.0.0.1:8000",
        api_key=os.getenv("FLOP_API_KEY", "flop-dev-key-2026"),
    )

    from app.crypto import generate_test_keypair, public_key_to_test_did
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    nonce = f"incomplete-{uuid.uuid4().hex}"

    created = api_client.create_signed_proof(
        private_key=private_key,
        did=did,
        text="incomplete result",
        room="validator-negative",
        nonce=nonce,
        request_id=f"incomplete-{uuid.uuid4().hex}",
        created_at="2026-09-08T20:00:00Z",
    )

    api_client.append_signed_event(
        proof_id=created["proof_id"],
        private_key=private_key,
        did=did,
        event_type="result.created",
        payload={
            "task_hash": "11" * 32,
            "model_hash": "22" * 32,
            "gn_weight": 1,
            "latency_ms": 123,
            "decode_policy_hash": "33" * 32,
            "tee_type": 1,
        },
        nonce=nonce + "-result",
    )

    response = client.post(
        f"/proofs/{created['proof_id']}/validator-attestations/accept",
        json={
            "report_data": "00" * 32,
            "attestations": [],
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "result.created is not validator-ready"


def test_proof_validator_attestation_rejects_result_attestation_mismatch(monkeypatch):
    import base64
    import uuid
    import sr25519

    from app import main
    from app.crypto import (
        compute_report_data,
        compute_task_hash,
        sign_validator_attestation,
    )

    api_client = __import__("client", fromlist=["FlopProofClient"]).FlopProofClient(
        "http://127.0.0.1:8000",
        api_key=os.getenv("FLOP_API_KEY", "flop-dev-key-2026"),
    )

    from app.crypto import generate_test_keypair, public_key_to_test_did
    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)

    nonce = f"mismatch-{uuid.uuid4().hex}"

    created = api_client.create_signed_proof(
        private_key=private_key,
        did=did,
        text="mismatch result",
        room="validator-negative",
        nonce=nonce,
        request_id=f"mismatch-{uuid.uuid4().hex}",
        created_at="2026-09-08T20:00:00Z",
    )

    task_agent = bytes.fromhex("aa" * 32)
    task_nonce = b"mismatch-task"
    model_hash = bytes.fromhex("11" * 32)
    task_payload_hash = bytes.fromhex("22" * 32)
    commit_hash = bytes.fromhex("33" * 32)

    task_hash = compute_task_hash(
        agent=task_agent,
        nonce=task_nonce,
        model_hash=model_hash,
        payload_hash=task_payload_hash,
        commit_hash=commit_hash,
    )

    result_payload = {
        "content": "bound result",
        "content_hash": "sha256:" + ("44" * 32),
        "task_hash": task_hash,
        "task_hash_inputs": {
            "agent": task_agent.hex(),
            "nonce": task_nonce.hex(),
            "model_hash": model_hash.hex(),
            "payload_hash": task_payload_hash.hex(),
            "commit_hash": commit_hash.hex(),
        },
        "model_hash": model_hash.hex(),
        "gn_weight": 1,
        "latency_ms": 123,
        "decode_policy_hash": "55" * 32,
        "tee_type": 1,
        "output_hash": "66" * 32,
    }

    api_client.append_signed_event(
        proof_id=created["proof_id"],
        private_key=private_key,
        did=did,
        event_type="result.created",
        payload=result_payload,
        nonce=nonce + "-result",
    )

    validator_id, validator_private = sr25519.pair_from_seed(bytes([7]) * 32)

    # Sign an attestation whose output_hash deliberately differs
    # from the stored result.created output_hash.
    attestation_output_hash = bytes.fromhex("77" * 32)

    signature = sign_validator_attestation(
        keypair=(validator_id, validator_private),
        task_hash=bytes.fromhex(task_hash),
        gn_weight=1,
        latency_ms=123,
        model_hash=model_hash,
        output_hash=attestation_output_hash,
        decode_policy_hash=bytes.fromhex("55" * 32),
        tee_type=1,
        quote_verified=True,
        event_log_verified=True,
        hardware_id_hash=bytes.fromhex("88" * 32),
    )

    attestations = [
        {
            "task_hash": task_hash,
            "gn_weight": 1,
            "latency_ms": 123,
            "model_hash": model_hash.hex(),
            "output_hash": attestation_output_hash.hex(),
            "decode_policy_hash": "55" * 32,
            "tee_type": 1,
            "quote_verified": True,
            "event_log_verified": True,
            "hardware_id_hash": "88" * 32,
            "validator_id": validator_id.hex(),
            "signature": base64.urlsafe_b64encode(signature)
            .rstrip(b"=")
            .decode(),
        }
    ]

    report_data = compute_report_data(
        task_hash=bytes.fromhex(task_hash),
        gn_weight=(1).to_bytes(8, "little"),
        latency_ms=(123).to_bytes(8, "little"),
        model_hash=model_hash,
        output_hash=attestation_output_hash,
        decode_policy_hash=bytes.fromhex("55" * 32),
        tee_type=(1).to_bytes(1, "little"),
    )

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry([validator_id]),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    response = client.post(
        f"/proofs/{created['proof_id']}/validator-attestations/accept",
        json={
            "report_data": report_data,
            "attestations": attestations,
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Validator attestation bundle rejected"


def test_proof_validator_attestation_replay_survives_memory_reset(monkeypatch):
    import base64
    import hashlib
    import uuid
    import sr25519

    from app import main
    from app.crypto import (
        compute_report_data,
        compute_task_hash,
        generate_test_keypair,
        public_key_to_test_did,
        sign_validator_attestation,
    )
    from client import FlopProofClient

    api_client = FlopProofClient(
        "http://127.0.0.1:8000",
        api_key=os.getenv("FLOP_API_KEY", "flop-dev-key-2026"),
    )

    private_key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)
    nonce = f"persistent-replay-{uuid.uuid4().hex}"

    created = api_client.create_signed_proof(
        private_key=private_key,
        did=did,
        text="persistent replay test",
        room="validator-persistent-replay",
        nonce=nonce,
        request_id=f"persistent-replay-{uuid.uuid4().hex}",
        created_at="2026-09-08T20:00:00Z",
    )

    proof_id = created["proof_id"]

    task_hash = compute_task_hash(
        agent=bytes.fromhex("aa" * 32),
        nonce=f"persistent-replay-task-{uuid.uuid4().hex}".encode(),
        model_hash=bytes.fromhex("11" * 32),
        payload_hash=bytes.fromhex("22" * 32),
        commit_hash=bytes.fromhex("33" * 32),
    )

    result_payload = {
        "content": "persistent replay result",
        "content_hash": "sha256:" + hashlib.sha256(
            b"persistent replay result"
        ).hexdigest(),
        "task_hash": task_hash,
        "task_hash_inputs": {
            "agent": "aa" * 32,
            "nonce": b"persistent-replay-task".hex(),
            "model_hash": "11" * 32,
            "payload_hash": "22" * 32,
            "commit_hash": "33" * 32,
        },
        "model_hash": "11" * 32,
        "gn_weight": 1,
        "latency_ms": 123,
        "decode_policy_hash": "44" * 32,
        "tee_type": 1,
        "output_hash": "55" * 32,
    }

    api_client.append_signed_event(
        proof_id=proof_id,
        private_key=private_key,
        did=did,
        event_type="result.created",
        payload=result_payload,
        nonce=nonce + "-result",
    )

    validator_keys = [
        sr25519.pair_from_seed(bytes([7]) * 32),
        sr25519.pair_from_seed(bytes([8]) * 32),
        sr25519.pair_from_seed(bytes([9]) * 32),
    ]

    validator_ids = [validator_id for validator_id, _ in validator_keys]
    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(validator_ids),
    )
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    attestations = []

    for validator_id, validator_private in validator_keys[:2]:
        signature = sign_validator_attestation(
            keypair=(validator_id, validator_private),
            task_hash=bytes.fromhex(task_hash),
            gn_weight=1,
            latency_ms=123,
            model_hash=bytes.fromhex("11" * 32),
            output_hash=bytes.fromhex("55" * 32),
            decode_policy_hash=bytes.fromhex("44" * 32),
            tee_type=1,
            quote_verified=True,
            event_log_verified=True,
            hardware_id_hash=bytes.fromhex("66" * 32),
        )

        attestations.append(
            {
                "task_hash": task_hash,
                "gn_weight": 1,
                "latency_ms": 123,
                "model_hash": "11" * 32,
                "output_hash": "55" * 32,
                "decode_policy_hash": "44" * 32,
                "tee_type": 1,
                "quote_verified": True,
                "event_log_verified": True,
                "hardware_id_hash": "66" * 32,
                "validator_id": validator_id.hex(),
                "signature": base64.urlsafe_b64encode(signature)
                .rstrip(b"=")
                .decode(),
            }
        )

    report_data = compute_report_data(
        task_hash=bytes.fromhex(task_hash),
        gn_weight=(1).to_bytes(8, "little"),
        latency_ms=(123).to_bytes(8, "little"),
        model_hash=bytes.fromhex("11" * 32),
        output_hash=bytes.fromhex("55" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=(1).to_bytes(1, "little"),
    )

    payload = {
        "report_data": report_data,
        "attestations": attestations,
    }

    first_response = client.post(
        f"/proofs/{proof_id}/validator-attestations/accept",
        json=payload,
    )

    assert first_response.status_code == 200

    body = first_response.json()

    assert body["accepted"] is True
    assert body["proof_id"] == proof_id
    assert body["task_hash"] == task_hash
    assert body["validators"] == 2
    assert body["result_event_id"]

    # Evidence Status Contract v0.1.
    assert body["evidence"]["class"] == "validator_attestation_binding"
    assert body["evidence"]["execution_verified"] is False
    assert body["evidence"]["runtime_settled"] is False

    # Contract lock:
    # stored-proof attestation acceptance is not protocol settlement/crediting.
    assert "settled" not in body
    assert "credited" not in body
    assert body.get("verified") is not True

    # Simulate a fresh application process: the in-memory replay store is gone.
    monkeypatch.setattr(
        main,
        "processed_validator_tasks",
        main.ProcessedTasks(),
    )

    replay_response = client.post(
        f"/proofs/{proof_id}/validator-attestations/accept",
        json=payload,
    )

    assert replay_response.status_code == 409
    assert replay_response.json()["detail"] == (
        "Validator attestation bundle rejected"
    )

# Phase 5 throughput tripwire tests

def test_validator_attestation_throughput_tripwire_accepts_exact_boundary(monkeypatch):
    from app import main

    validators, common, _ = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(main, "processed_validator_tasks", main.ProcessedTasks())

    gn_weight = 2_000_000
    latency_ms = 1000

    attestations = []
    for validator in validators[:2]:
        signature = sign_validator_attestation(
            keypair=(validator["validator_id"], validator["private_key"]),
            task_hash=common["task_hash"],
            gn_weight=gn_weight,
            latency_ms=latency_ms,
            model_hash=common["model_hash"],
            output_hash=common["output_hash"],
            decode_policy_hash=common["decode_policy_hash"],
            tee_type=common["tee_type"],
            quote_verified=True,
            event_log_verified=True,
            hardware_id_hash=common["hardware_id_hash"],
        )
        attestations.append({
            **common,
            "gn_weight": gn_weight,
            "latency_ms": latency_ms,
            "validator_id": validator["validator_id"],
            "signature": signature,
        })

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": gn_weight,
        "latency_ms": latency_ms,
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    import base64

    encoded = []
    for attestation in attestations:
        item = {
            key: value.hex() if isinstance(value, bytes) else value
            for key, value in attestation.items()
            if key != "private_key"
        }
        item["signature"] = (
            base64.urlsafe_b64encode(attestation["signature"])
            .rstrip(b"=")
            .decode()
        )
        encoded.append(item)

    report_data = main.sha256_bytes(
        common["task_hash"]
        + gn_weight.to_bytes(8, "little")
        + latency_ms.to_bytes(8, "little")
        + common["model_hash"]
        + common["output_hash"]
        + common["decode_policy_hash"]
        + common["tee_type"].to_bytes(1, "little")
    )

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": report_data,
            "attestations": encoded,
        },
    )

    assert response.status_code == 200


def test_validator_attestation_throughput_tripwire_rejects_above_boundary(monkeypatch):
    from app import main

    validators, common, _ = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(main, "processed_validator_tasks", main.ProcessedTasks())

    gn_weight = 2_000_001
    latency_ms = 1000

    attestations = []
    for validator in validators[:2]:
        signature = sign_validator_attestation(
            keypair=(validator["validator_id"], validator["private_key"]),
            task_hash=common["task_hash"],
            gn_weight=gn_weight,
            latency_ms=latency_ms,
            model_hash=common["model_hash"],
            output_hash=common["output_hash"],
            decode_policy_hash=common["decode_policy_hash"],
            tee_type=common["tee_type"],
            quote_verified=True,
            event_log_verified=True,
            hardware_id_hash=common["hardware_id_hash"],
        )
        attestations.append({
            **common,
            "gn_weight": gn_weight,
            "latency_ms": latency_ms,
            "validator_id": validator["validator_id"],
            "signature": signature,
        })

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": gn_weight,
        "latency_ms": latency_ms,
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    import base64

    encoded = []
    for attestation in attestations:
        item = {
            key: value.hex() if isinstance(value, bytes) else value
            for key, value in attestation.items()
            if key != "private_key"
        }
        item["signature"] = (
            base64.urlsafe_b64encode(attestation["signature"])
            .rstrip(b"=")
            .decode()
        )
        encoded.append(item)

    report_data = main.sha256_bytes(
        common["task_hash"]
        + gn_weight.to_bytes(8, "little")
        + latency_ms.to_bytes(8, "little")
        + common["model_hash"]
        + common["output_hash"]
        + common["decode_policy_hash"]
        + common["tee_type"].to_bytes(1, "little")
    )

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": report_data,
            "attestations": encoded,
        },
    )

    assert response.status_code == 409


def test_validator_attestation_throughput_tripwire_rejects_zero_latency(monkeypatch):
    from app import main

    validators, common, _ = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )
    monkeypatch.setattr(main, "processed_validator_tasks", main.ProcessedTasks())

    gn_weight = 1
    latency_ms = 0

    attestations = []
    for validator in validators[:2]:
        signature = sign_validator_attestation(
            keypair=(validator["validator_id"], validator["private_key"]),
            task_hash=common["task_hash"],
            gn_weight=gn_weight,
            latency_ms=latency_ms,
            model_hash=common["model_hash"],
            output_hash=common["output_hash"],
            decode_policy_hash=common["decode_policy_hash"],
            tee_type=common["tee_type"],
            quote_verified=True,
            event_log_verified=True,
            hardware_id_hash=common["hardware_id_hash"],
        )
        attestations.append({
            **common,
            "gn_weight": gn_weight,
            "latency_ms": latency_ms,
            "validator_id": validator["validator_id"],
            "signature": signature,
        })

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": gn_weight,
        "latency_ms": latency_ms,
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    import base64

    encoded = []
    for attestation in attestations:
        item = {
            key: value.hex() if isinstance(value, bytes) else value
            for key, value in attestation.items()
            if key != "private_key"
        }
        item["signature"] = (
            base64.urlsafe_b64encode(attestation["signature"])
            .rstrip(b"=")
            .decode()
        )
        encoded.append(item)

    report_data = main.sha256_bytes(
        common["task_hash"]
        + gn_weight.to_bytes(8, "little")
        + latency_ms.to_bytes(8, "little")
        + common["model_hash"]
        + common["output_hash"]
        + common["decode_policy_hash"]
        + common["tee_type"].to_bytes(1, "little")
    )

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": report_data,
            "attestations": encoded,
        },
    )

    assert response.status_code == 409


def test_validator_attestation_tripwire_rejection_does_not_consume_task(monkeypatch):
    from app import main

    validators, common, _ = make_validator_bundle()

    monkeypatch.setattr(
        main,
        "validator_registry",
        main.MockValidatorRegistry(
            [validator["validator_id"] for validator in validators]
        ),
    )

    processed = main.ProcessedTasks()
    monkeypatch.setattr(main, "processed_validator_tasks", processed)

    gn_weight = 2_000_001
    latency_ms = 1000

    attestations = []
    for validator in validators[:2]:
        signature = sign_validator_attestation(
            keypair=(validator["validator_id"], validator["private_key"]),
            task_hash=common["task_hash"],
            gn_weight=gn_weight,
            latency_ms=latency_ms,
            model_hash=common["model_hash"],
            output_hash=common["output_hash"],
            decode_policy_hash=common["decode_policy_hash"],
            tee_type=common["tee_type"],
            quote_verified=True,
            event_log_verified=True,
            hardware_id_hash=common["hardware_id_hash"],
        )
        attestations.append({
            **common,
            "gn_weight": gn_weight,
            "latency_ms": latency_ms,
            "validator_id": validator["validator_id"],
            "signature": signature,
        })

    result = {
        "task_hash": common["task_hash"].hex(),
        "gn_weight": gn_weight,
        "latency_ms": latency_ms,
        "model_hash": common["model_hash"].hex(),
        "output_hash": common["output_hash"].hex(),
        "decode_policy_hash": common["decode_policy_hash"].hex(),
        "tee_type": common["tee_type"],
    }

    import base64

    encoded = []
    for attestation in attestations:
        item = {
            key: value.hex() if isinstance(value, bytes) else value
            for key, value in attestation.items()
            if key != "private_key"
        }
        item["signature"] = (
            base64.urlsafe_b64encode(attestation["signature"])
            .rstrip(b"=")
            .decode()
        )
        encoded.append(item)

    report_data = main.sha256_bytes(
        common["task_hash"]
        + gn_weight.to_bytes(8, "little")
        + latency_ms.to_bytes(8, "little")
        + common["model_hash"]
        + common["output_hash"]
        + common["decode_policy_hash"]
        + common["tee_type"].to_bytes(1, "little")
    )

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": result,
            "report_data": report_data,
            "attestations": encoded,
        },
    )

    assert response.status_code == 409
    assert not processed.is_processed(common["task_hash"])



def test_decode_policy_v1_canonical_encoding_and_hash():
    policy = DecodePolicy(
        version=1,
        class_tag=DecodePolicyClass.TEXT_GENERATION,
        tokenizer_hash=bytes.fromhex("11" * 32),
        sampling_params=SamplingParams(
            temperature_milli=700,
            top_p_ppm=950000,
            top_k=40,
            repetition_penalty_ppm=1100000,
            beam_width=1,
            seed=42,
        ),
        stop_conditions_hash=bytes.fromhex("22" * 32),
        output_transform=OutputTransform.IDENTITY,
        transform_id=None,
        class_policy_hash=bytes.fromhex("33" * 32),
    )

    encoded = encode_decode_policy(policy)

    assert encoded[:2] == b"\x01\x00"
    assert encoded[2] == DecodePolicyClass.TEXT_GENERATION
    assert len(encoded) == 2 + 1 + 32 + 4 + 4 + 4 + 4 + 2 + 8 + 32 + 1 + 32

    digest_1 = compute_decode_policy_hash(policy)
    digest_2 = compute_decode_policy_hash(policy)

    assert len(digest_1) == 32
    assert digest_1 == digest_2

    import hashlib

    expected = hashlib.sha256(
        b"FLOP_DECODE_POLICY_HASH_V1" + encoded
    ).digest()

    assert digest_1 == expected


def test_decode_policy_v1_transform_id_encoding():
    policy = DecodePolicy(
        version=1,
        class_tag=DecodePolicyClass.IMAGE_DENOISE,
        tokenizer_hash=bytes.fromhex("11" * 32),
        sampling_params=SamplingParams(
            temperature_milli=1000,
            top_p_ppm=1000000,
            top_k=0,
            repetition_penalty_ppm=1000000,
            beam_width=1,
            seed=0,
        ),
        stop_conditions_hash=bytes.fromhex("22" * 32),
        output_transform=OutputTransform.TRANSFORM_ID,
        transform_id=bytes.fromhex("44" * 32),
        class_policy_hash=bytes.fromhex("33" * 32),
    )

    encoded = encode_decode_policy(policy)

    # Layout ends with:
    #   output_transform(1) | transform_id(32) | class_policy_hash(32)
    assert encoded[-65] == OutputTransform.TRANSFORM_ID
    assert encoded[-64:-32] == bytes.fromhex("44" * 32)
    assert encoded[-32:] == bytes.fromhex("33" * 32)


def test_decode_policy_v1_other_class_requires_u16():
    policy = DecodePolicy(
        version=1,
        class_tag=DecodePolicyClass.OTHER,
        tokenizer_hash=bytes.fromhex("11" * 32),
        sampling_params=SamplingParams(
            temperature_milli=1,
            top_p_ppm=2,
            top_k=3,
            repetition_penalty_ppm=4,
            beam_width=5,
            seed=6,
        ),
        stop_conditions_hash=bytes.fromhex("22" * 32),
        output_transform=OutputTransform.IDENTITY,
        transform_id=None,
        class_policy_hash=bytes.fromhex("33" * 32),
    )

    import pytest

    with pytest.raises(ValueError, match="other_class"):
        encode_decode_policy(policy)

    policy = DecodePolicy(
        version=1,
        class_tag=DecodePolicyClass.OTHER,
        tokenizer_hash=bytes.fromhex("11" * 32),
        sampling_params=SamplingParams(
            temperature_milli=1,
            top_p_ppm=2,
            top_k=3,
            repetition_penalty_ppm=4,
            beam_width=5,
            seed=6,
        ),
        stop_conditions_hash=bytes.fromhex("22" * 32),
        output_transform=OutputTransform.IDENTITY,
        transform_id=None,
        class_policy_hash=bytes.fromhex("33" * 32),
        other_class=0x1234,
    )

    encoded = encode_decode_policy(policy)

    assert encoded[2] == DecodePolicyClass.OTHER
    assert encoded[3:5] == b"\x34\x12"


def test_decode_policy_v1_rejects_invalid_hash_width():
    policy = DecodePolicy(
        version=1,
        class_tag=DecodePolicyClass.TEXT_GENERATION,
        tokenizer_hash=b"\x11" * 31,
        sampling_params=SamplingParams(
            temperature_milli=1,
            top_p_ppm=2,
            top_k=3,
            repetition_penalty_ppm=4,
            beam_width=5,
            seed=6,
        ),
        stop_conditions_hash=b"\x22" * 32,
        output_transform=OutputTransform.IDENTITY,
        transform_id=None,
        class_policy_hash=b"\x33" * 32,
    )

    import pytest

    with pytest.raises(ValueError, match="tokenizer_hash"):
        encode_decode_policy(policy)
