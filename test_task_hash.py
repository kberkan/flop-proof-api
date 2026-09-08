import hashlib


def test_task_hash_reference_shape():
    agent = b"agent"
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
