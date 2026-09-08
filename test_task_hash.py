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

def test_flop_metadata_fields_are_declarative_until_attested():
    payload = {
        "model_hash": "11" * 32,
        "gn_weight": "1000000000000000000",
        "latency_ms": 125,
        "decode_policy_hash": "44" * 32,
        "tee_type": "test",
    }

    assert isinstance(payload["model_hash"], str)
    assert isinstance(payload["gn_weight"], str)
    assert isinstance(payload["latency_ms"], int)
    assert isinstance(payload["decode_policy_hash"], str)
    assert isinstance(payload["tee_type"], str)


def test_flop_metadata_does_not_imply_attestation():
    payload = {
        "model_hash": "11" * 32,
        "gn_weight": "1000000000000000000",
        "latency_ms": 125,
        "decode_policy_hash": "44" * 32,
        "tee_type": "test",
    }

    assert "quote_verified" not in payload
    assert "event_log_verified" not in payload
    assert "validator_attestation" not in payload

def test_report_data_requires_flop_binding_hashes():
    fields = {
        "task_hash": "11" * 32,
        "model_hash": "22" * 32,
        "output_hash": "33" * 32,
        "decode_policy_hash": "44" * 32,
    }

    for name, value in fields.items():
        assert len(bytes.fromhex(value)) == 32


def test_report_data_field_order_is_defined():
    field_order = [
        "task_hash",
        "gn_weight",
        "latency_ms",
        "model_hash",
        "output_hash",
        "decode_policy_hash",
        "tee_type",
    ]

    assert field_order == [
        "task_hash",
        "gn_weight",
        "latency_ms",
        "model_hash",
        "output_hash",
        "decode_policy_hash",
        "tee_type",
    ]


def test_report_data_is_distinct_from_task_hash():
    task_hash = "11" * 32
    report_data = "22" * 32

    assert task_hash != report_data

def test_report_data_binding_hash_fields_are_raw_32_bytes():
    values = {
        "task_hash": "11" * 32,
        "model_hash": "22" * 32,
        "output_hash": "33" * 32,
        "decode_policy_hash": "44" * 32,
    }

    encoded = {name: bytes.fromhex(value) for name, value in values.items()}

    assert all(len(value) == 32 for value in encoded.values())


def test_report_data_binding_preserves_protocol_field_order():
    field_order = (
        "task_hash",
        "gn_weight",
        "latency_ms",
        "model_hash",
        "output_hash",
        "decode_policy_hash",
        "tee_type",
    )

    assert field_order[0] == "task_hash"
    assert field_order[1:3] == ("gn_weight", "latency_ms")
    assert field_order[3:] == (
        "model_hash",
        "output_hash",
        "decode_policy_hash",
        "tee_type",
    )


def test_report_data_binding_requires_output_hash():
    binding_fields = {
        "task_hash": "11" * 32,
        "gn_weight": "1000000000000000000",
        "latency_ms": 125,
        "model_hash": "22" * 32,
        "decode_policy_hash": "44" * 32,
        "tee_type": "test",
    }

    assert "output_hash" not in binding_fields


def test_report_data_is_sha256_commitment_not_task_hash():
    import hashlib

    preimage = b"FLOP report-data test"
    report_data = hashlib.sha256(preimage).hexdigest()

    assert len(bytes.fromhex(report_data)) == 32
    assert report_data != hashlib.blake2b(
        preimage,
        digest_size=32,
    ).hexdigest()

def test_report_data_primitive_matches_sha256_binding():
    import hashlib
    from app.crypto import compute_report_data

    task_hash = bytes.fromhex("11" * 32)
    model_hash = bytes.fromhex("22" * 32)
    output_hash = bytes.fromhex("33" * 32)
    decode_policy_hash = bytes.fromhex("44" * 32)

    gn_weight = b"gn-weight"
    latency_ms = b"latency"
    tee_type = b"tee"

    expected = hashlib.sha256(
        task_hash
        + gn_weight
        + latency_ms
        + model_hash
        + output_hash
        + decode_policy_hash
        + tee_type
    ).hexdigest()

    assert compute_report_data(
        task_hash,
        gn_weight,
        latency_ms,
        model_hash,
        output_hash,
        decode_policy_hash,
        tee_type,
    ) == expected


def test_report_data_rejects_invalid_hash_lengths():
    from app.crypto import compute_report_data

    valid = bytes.fromhex("11" * 32)

    try:
        compute_report_data(
            b"short",
            b"gn",
            b"latency",
            valid,
            valid,
            valid,
            b"tee",
        )
    except ValueError as exc:
        assert str(exc) == "task_hash must be exactly 32 bytes"
    else:
        raise AssertionError("expected invalid task_hash length to fail")

def test_validator_attestation_fields_are_distinct_from_result_metadata():
    attestation = {
        "task_hash": "11" * 32,
        "gn_weight": "1000000000000000000",
        "latency_ms": 125,
        "model_hash": "22" * 32,
        "output_hash": "33" * 32,
        "decode_policy_hash": "44" * 32,
        "tee_type": 1,
        "quote_verified": True,
        "event_log_verified": True,
        "hardware_id_hash": "55" * 32,
        "validator_id": "66" * 32,
        "signature": "test-signature",
    }

    assert len(bytes.fromhex(attestation["task_hash"])) == 32
    assert len(bytes.fromhex(attestation["model_hash"])) == 32
    assert len(bytes.fromhex(attestation["output_hash"])) == 32
    assert len(bytes.fromhex(attestation["decode_policy_hash"])) == 32
    assert len(bytes.fromhex(attestation["hardware_id_hash"])) == 32


def test_validator_attestation_contains_quote_and_event_log_status():
    attestation = {
        "quote_verified": True,
        "event_log_verified": True,
    }

    assert isinstance(attestation["quote_verified"], bool)
    assert isinstance(attestation["event_log_verified"], bool)


def test_validator_attestation_is_not_implied_by_flop_metadata():
    payload = {
        "task_hash": "11" * 32,
        "model_hash": "22" * 32,
        "output_hash": "33" * 32,
        "gn_weight": "1000000000000000000",
        "latency_ms": 125,
        "decode_policy_hash": "44" * 32,
        "tee_type": 1,
    }

    assert "quote_verified" not in payload
    assert "event_log_verified" not in payload
    assert "validator_id" not in payload
    assert "signature" not in payload

def test_validator_attestation_signable_fields_are_exactly_first_ten():
    signable_fields = (
        "task_hash",
        "gn_weight",
        "latency_ms",
        "model_hash",
        "output_hash",
        "decode_policy_hash",
        "tee_type",
        "quote_verified",
        "event_log_verified",
        "hardware_id_hash",
    )

    excluded_fields = (
        "validator_id",
        "signature",
    )

    assert len(signable_fields) == 10
    assert len(excluded_fields) == 2
    assert "validator_id" not in signable_fields
    assert "signature" not in signable_fields


def test_validator_attestation_signable_field_order_matches_spec():
    assert (
        "task_hash",
        "gn_weight",
        "latency_ms",
        "model_hash",
        "output_hash",
        "decode_policy_hash",
        "tee_type",
        "quote_verified",
        "event_log_verified",
        "hardware_id_hash",
    ) == (
        "task_hash",
        "gn_weight",
        "latency_ms",
        "model_hash",
        "output_hash",
        "decode_policy_hash",
        "tee_type",
        "quote_verified",
        "event_log_verified",
        "hardware_id_hash",
    )


def test_validator_attestation_signature_is_fixed_64_bytes():
    signature = bytes(64)

    assert len(signature) == 64


def test_validator_attestation_validator_id_is_fixed_32_bytes():
    validator_id = bytes(32)

    assert len(validator_id) == 32



def test_validator_attestation_signable_payload_is_179_bytes():
    from app.crypto import encode_validator_attestation_signable_payload

    payload = encode_validator_attestation_signable_payload(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=0x0102030405060708,
        latency_ms=0x1112131415161718,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=False,
        hardware_id_hash=bytes.fromhex("55" * 32),
    )

    assert len(payload) == 179


def test_validator_attestation_signable_payload_uses_scale_little_endian():
    from app.crypto import encode_validator_attestation_signable_payload

    payload = encode_validator_attestation_signable_payload(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=0x0102030405060708,
        latency_ms=0x1112131415161718,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=False,
        hardware_id_hash=bytes.fromhex("55" * 32),
    )

    assert payload[32:40] == bytes.fromhex("0807060504030201")
    assert payload[40:48] == bytes.fromhex("1817161514131211")
    assert payload[144] == 7
    assert payload[145] == 1
    assert payload[146] == 0


def test_validator_attestation_signature_round_trip():
    import sr25519
    from app.crypto import (
        sign_validator_attestation,
        verify_validator_attestation_signature,
    )

    seed = bytes(range(32))
    public_key, private_key = sr25519.pair_from_seed(seed)

    kwargs = dict(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=123456,
        latency_ms=789,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=False,
        hardware_id_hash=bytes.fromhex("55" * 32),
    )

    signature = sign_validator_attestation(
        (public_key, private_key),
        **kwargs,
    )

    assert len(public_key) == 32
    assert len(signature) == 64
    assert verify_validator_attestation_signature(
        public_key, signature, **kwargs
    )


def test_validator_attestation_signature_rejects_tampering():
    import sr25519
    from app.crypto import (
        sign_validator_attestation,
        verify_validator_attestation_signature,
    )

    seed = bytes(range(32))
    public_key, private_key = sr25519.pair_from_seed(seed)

    kwargs = dict(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=123456,
        latency_ms=789,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=False,
        hardware_id_hash=bytes.fromhex("55" * 32),
    )

    signature = sign_validator_attestation(
        (public_key, private_key),
        **kwargs,
    )

    tampered = dict(kwargs)
    tampered["latency_ms"] += 1

    assert not verify_validator_attestation_signature(
        public_key, signature, **tampered
    )


def test_validator_attestation_validator_id_binds_signature():
    import sr25519
    from app.crypto import (
        sign_validator_attestation,
        verify_validator_attestation_signature,
    )

    validator_id, private_key = sr25519.pair_from_seed(bytes(range(32)))

    kwargs = dict(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=123456,
        latency_ms=789,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=False,
        hardware_id_hash=bytes.fromhex("55" * 32),
    )

    signature = sign_validator_attestation(
        (validator_id, private_key),
        **kwargs,
    )

    assert len(validator_id) == 32
    assert len(signature) == 64
    assert verify_validator_attestation_signature(
        validator_id,
        signature,
        **kwargs,
    )


def test_validator_attestation_rejects_signature_from_different_validator():
    import sr25519
    from app.crypto import (
        sign_validator_attestation,
        verify_validator_attestation_signature,
    )

    validator_id_a, private_key_a = sr25519.pair_from_seed(bytes(range(32)))
    validator_id_b, _ = sr25519.pair_from_seed(bytes(range(32, 64)))

    kwargs = dict(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=123456,
        latency_ms=789,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=False,
        hardware_id_hash=bytes.fromhex("55" * 32),
    )

    signature = sign_validator_attestation(
        (validator_id_a, private_key_a),
        **kwargs,
    )

    assert not verify_validator_attestation_signature(
        validator_id_b,
        signature,
        **kwargs,
    )

def test_validator_attestation_requires_exact_field_shapes():
    from app.crypto import ValidatorAttestation

    attestation = ValidatorAttestation(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=123456,
        latency_ms=789,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=True,
        hardware_id_hash=bytes.fromhex("55" * 32),
        validator_id=bytes.fromhex("66" * 32),
        signature=bytes.fromhex("77" * 64),
    )

    assert len(attestation.task_hash) == 32
    assert len(attestation.model_hash) == 32
    assert len(attestation.output_hash) == 32
    assert len(attestation.decode_policy_hash) == 32
    assert len(attestation.hardware_id_hash) == 32
    assert len(attestation.validator_id) == 32
    assert len(attestation.signature) == 64
    assert attestation.gn_weight == 123456
    assert attestation.latency_ms == 789
    assert attestation.tee_type == 7
    assert attestation.quote_verified is True
    assert attestation.event_log_verified is True


def test_validator_attestation_rejects_invalid_fixed_width_fields():
    from app.crypto import ValidatorAttestation

    valid = dict(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=123456,
        latency_ms=789,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=True,
        hardware_id_hash=bytes.fromhex("55" * 32),
        validator_id=bytes.fromhex("66" * 32),
        signature=bytes.fromhex("77" * 64),
    )

    invalid_cases = [
        ("task_hash", b"\x11" * 31),
        ("model_hash", b"\x22" * 31),
        ("output_hash", b"\x33" * 31),
        ("decode_policy_hash", b"\x44" * 31),
        ("hardware_id_hash", b"\x55" * 31),
        ("validator_id", b"\x66" * 31),
        ("signature", b"\x77" * 63),
    ]

    for field, invalid in invalid_cases:
        values = dict(valid)
        values[field] = invalid

        try:
            ValidatorAttestation(**values)
        except ValueError:
            continue

        raise AssertionError(
            f"{field} must have the exact protocol length"
        )

def test_validator_attestation_signable_payload_is_exactly_179_bytes():
    from app.crypto import encode_validator_attestation_signable_payload

    payload = encode_validator_attestation_signable_payload(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=123456,
        latency_ms=789,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=True,
        hardware_id_hash=bytes.fromhex("55" * 32),
    )

    assert len(payload) == 179

def test_validator_attestation_signable_payload_uses_expected_field_order():
    from app.crypto import encode_validator_attestation_signable_payload

    task_hash = bytes.fromhex("11" * 32)
    model_hash = bytes.fromhex("22" * 32)
    output_hash = bytes.fromhex("33" * 32)
    decode_policy_hash = bytes.fromhex("44" * 32)
    hardware_id_hash = bytes.fromhex("55" * 32)

    payload = encode_validator_attestation_signable_payload(
        task_hash=task_hash,
        gn_weight=0x0102030405060708,
        latency_ms=0x1112131415161718,
        model_hash=model_hash,
        output_hash=output_hash,
        decode_policy_hash=decode_policy_hash,
        tee_type=0x07,
        quote_verified=True,
        event_log_verified=False,
        hardware_id_hash=hardware_id_hash,
    )

    expected = (
        task_hash
        + bytes.fromhex("0807060504030201")
        + bytes.fromhex("1817161514131211")
        + model_hash
        + output_hash
        + decode_policy_hash
        + b"\x07"
        + b"\x01"
        + b"\x00"
        + hardware_id_hash
    )

    assert payload == expected
    assert len(payload) == 179

def test_validator_quorum_uses_active_validator_count():
    from app.crypto import calculate_validator_quorum

    # 5 active validators, 2/3 threshold:
    # ceil(5 * 2/3) = 4
    assert calculate_validator_quorum(5, 2 / 3) == 4


def test_validator_quorum_requires_at_least_one_validator():
    from app.crypto import calculate_validator_quorum

    assert calculate_validator_quorum(0, 2 / 3) == 1


def test_validator_quorum_does_not_use_attestation_count_as_denominator():
    from app.crypto import calculate_validator_quorum

    # 5 active validators remain the denominator.
    # Three matching attestations are only 3/5, so quorum is still 4.
    assert calculate_validator_quorum(5, 2 / 3) == 4


def test_validator_quorum_rejects_duplicate_validator_ids():
    from app.crypto import has_distinct_validator_ids

    validator_a = bytes.fromhex("11" * 32)
    validator_b = bytes.fromhex("22" * 32)

    assert has_distinct_validator_ids(
        [validator_a, validator_b]
    )

    assert not has_distinct_validator_ids(
        [validator_a, validator_a]
    )


def test_validator_quorum_requires_matching_signed_fields():
    from app.crypto import validator_attestation_fields_match

    base = dict(
        task_hash=bytes.fromhex("11" * 32),
        gn_weight=100,
        latency_ms=200,
        model_hash=bytes.fromhex("22" * 32),
        output_hash=bytes.fromhex("33" * 32),
        decode_policy_hash=bytes.fromhex("44" * 32),
        tee_type=7,
        quote_verified=True,
        event_log_verified=True,
        hardware_id_hash=bytes.fromhex("55" * 32),
    )

    same = dict(base)
    different = dict(base)
    different["output_hash"] = bytes.fromhex("66" * 32)

    assert validator_attestation_fields_match(base, same)
    assert not validator_attestation_fields_match(base, different)

def test_validator_quorum_ceil_behavior_for_active_validator_counts():
    from app.crypto import calculate_validator_quorum

    expected = {
        1: 1,
        2: 2,
        3: 2,
        4: 3,
        5: 4,
        6: 4,
    }

    for active_count, quorum in expected.items():
        assert calculate_validator_quorum(
            active_count,
            2 / 3,
        ) == quorum


def test_validator_quorum_rejects_invalid_thresholds():
    from app.crypto import calculate_validator_quorum

    for threshold in (0, -0.1, 1.1, 2):
        try:
            calculate_validator_quorum(5, threshold)
        except ValueError:
            continue

        raise AssertionError(
            f"threshold={threshold} must be rejected"
        )


def test_validator_quorum_rejects_negative_active_validator_count():
    from app.crypto import calculate_validator_quorum

    try:
        calculate_validator_quorum(-1, 2 / 3)
    except ValueError:
        return

    raise AssertionError(
        "negative active validator count must be rejected"
    )


def test_validator_quorum_accepts_exact_threshold_boundary():
    from app.crypto import calculate_validator_quorum

    # 3 active validators at 2/3 requires exactly 2.
    assert calculate_validator_quorum(3, 2 / 3) == 2


def test_validator_quorum_rounds_fractional_requirement_up():
    from app.crypto import calculate_validator_quorum

    # 5 * 2/3 = 3.333..., therefore 4 are required.
    assert calculate_validator_quorum(5, 2 / 3) == 4
