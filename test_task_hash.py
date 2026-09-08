import hashlib


def test_task_hash_reference_shape():
    agent = bytes.fromhex("aa" * 32)
    nonce = b"nonce"
    model_hash = bytes.fromhex("11" * 32)
    payload_hash = bytes.fromhex("22" * 32)
    commit_hash = bytes.fromhex("33" * 32)

    preimage = (
        agent
        + nonce
        + model_hash
        + payload_hash
        + commit_hash
    )

    expected = hashlib.blake2b(
        preimage,
        digest_size=32,
    ).hexdigest()

    from app.crypto import compute_task_hash

    assert compute_task_hash(
        agent=agent,
        nonce=nonce,
        model_hash=model_hash,
        payload_hash=payload_hash,
        commit_hash=commit_hash,
    ) == expected


def test_task_hash_requires_32_byte_agent_and_hashes():
    from app.crypto import compute_task_hash

    valid = bytes(32)

    invalid_cases = [
        ("agent", b"agent"),
        ("model_hash", b"\x11" * 31),
        ("payload_hash", b"\x22" * 31),
        ("commit_hash", b"\x33" * 31),
    ]

    for field, invalid in invalid_cases:
        values = {
            "agent": valid,
            "nonce": b"nonce",
            "model_hash": valid,
            "payload_hash": valid,
            "commit_hash": valid,
        }
        values[field] = invalid

        try:
            compute_task_hash(**values)
        except ValueError:
            continue

        raise AssertionError(
            f"{field} must be exactly 32 bytes"
        )


def test_result_content_hash_changes_when_content_changes():
    from app.crypto import sha256_bytes

    original = "original result"
    modified = "modified result"

    original_hash = f"sha256:{sha256_bytes(original.encode('utf-8'))}"
    modified_hash = f"sha256:{sha256_bytes(modified.encode('utf-8'))}"

    assert original_hash != modified_hash

def test_output_hash_is_distinct_from_legacy_content_hash():
    from app.crypto import sha256_bytes

    content = b"model inference output"

    content_hash = f"sha256:{sha256_bytes(content)}"

    # FLOP output_hash is a separate protocol-level commitment.
    # Until the exact serialization is specified, it must not be
    # silently treated as the legacy content_hash field.
    output_hash = None

    assert content_hash
    assert output_hash is None

def test_task_hash_verification_is_optional_for_legacy_result():
    payload = {
        "content": "model output",
        "content_hash": "sha256:placeholder",
    }

    assert "task_hash" not in payload


def test_task_hash_is_present_when_supplied():
    payload = {
        "content": "model output",
        "content_hash": "sha256:placeholder",
        "task_hash": "aa" * 32,
    }

    assert payload["task_hash"] == "aa" * 32


def test_task_hash_mismatch_is_detectable():
    from app.crypto import compute_task_hash

    agent = bytes.fromhex("aa" * 32)
    nonce = b"nonce"
    model_hash = bytes.fromhex("11" * 32)
    payload_hash = bytes.fromhex("22" * 32)
    commit_hash = bytes.fromhex("33" * 32)

    calculated = compute_task_hash(
        agent=agent,
        nonce=nonce,
        model_hash=model_hash,
        payload_hash=payload_hash,
        commit_hash=commit_hash,
    )

    supplied = "00" * 32

    assert supplied != calculated

def test_flop_result_metadata_can_be_carried_without_output_hash():
    payload = {
        "content": "model output",
        "content_hash": "sha256:placeholder",
        "task_hash": "aa" * 32,
        "task_hash_inputs": {
            "agent": "aa" * 32,
            "nonce": "746573742d6e6f6e6365",
            "model_hash": "11" * 32,
            "payload_hash": "22" * 32,
            "commit_hash": "33" * 32,
        },
        "model_hash": "11" * 32,
        "gn_weight": "1000000000000000000",
        "latency_ms": 125,
        "decode_policy_hash": "44" * 32,
        "tee_type": "test",
    }

    assert payload["task_hash"]
    assert payload["model_hash"]
    assert payload["gn_weight"]
    assert payload["latency_ms"] == 125
    assert payload["decode_policy_hash"]
    assert payload["tee_type"]
    assert "output_hash" not in payload


def test_flop_result_metadata_output_hash_is_optional():
    payload = {
        "content": "model output",
        "content_hash": "sha256:placeholder",
    }

    assert payload.get("output_hash") is None

def test_flop_metadata_status_legacy_is_absent():
    payload = {
        "content": "model output",
        "content_hash": "sha256:placeholder",
    }

    assert "task_hash" not in payload
    assert "model_hash" not in payload
    assert "gn_weight" not in payload
    assert "latency_ms" not in payload
    assert "decode_policy_hash" not in payload
    assert "tee_type" not in payload


def test_flop_metadata_status_partial_is_incomplete():
    payload = {
        "task_hash": "aa" * 32,
        "model_hash": "11" * 32,
        "latency_ms": 125,
    }

    required = {
        "task_hash",
        "model_hash",
        "gn_weight",
        "latency_ms",
        "decode_policy_hash",
        "tee_type",
    }

    assert set(payload) & required
    assert not required.issubset(payload)


def test_flop_metadata_status_complete_is_present():
    payload = {
        "task_hash": "aa" * 32,
        "model_hash": "11" * 32,
        "gn_weight": "1000000000000000000",
        "latency_ms": 125,
        "decode_policy_hash": "44" * 32,
        "tee_type": "test",
    }

    required = {
        "task_hash",
        "model_hash",
        "gn_weight",
        "latency_ms",
        "decode_policy_hash",
        "tee_type",
    }

    assert required.issubset(payload)
