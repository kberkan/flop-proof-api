import os

import sr25519
from fastapi.testclient import TestClient

from app.crypto import (
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
    assert response.json()["accepted"] is True
    assert response.json()["validators"] == 2


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
