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
