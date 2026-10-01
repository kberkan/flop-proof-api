import pytest

from app.compute_channel import decode_fcc4_transcript


def test_compute_channel_module_imports():
    from app.compute_channel import FCC4_MAGIC, VerifiedTurnRecord

    assert FCC4_MAGIC == b"FCC4"
    assert VerifiedTurnRecord.__dataclass_fields__


def test_fcc4_rejects_unknown_magic():
    with pytest.raises(ValueError, match="UnknownFCCVersion"):
        decode_fcc4_transcript(b"FCC9")


def test_fcc4_rejects_truncated_header():
    with pytest.raises(ValueError, match="truncated FCC4 transcript"):
        decode_fcc4_transcript(b"FCC4")


def test_fcc4_rejects_trailing_bytes():
    with pytest.raises(ValueError, match="truncated FCC4 transcript|TrailingBytes"):
        decode_fcc4_transcript(
            b"FCC4"
            + bytes(32)
            + (0).to_bytes(4, "little")
            + b"\x00"
        )


def test_fcc4_rejects_unknown_leaf_version():
    data = (
        b"FCC4"
        + bytes(32)
        + (1).to_bytes(4, "little")
        + b"\x04"
    )

    with pytest.raises(ValueError, match="UnsupportedLeafVersion|truncated"):
        decode_fcc4_transcript(data)



def test_fcc4_canonical_public_vector_decodes_exactly():
    blob = bytes.fromhex(
        "464343343655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
        "0100000003ffffffff"
        "3333333333333333333333333333333333333333333333333333333333333333"
        "4444444444444444444444444444444444444444444444444444444444444444"
        "ffffffffffffffffffffffffffffffff"
        "01"
        "6666666666666666666666666666666666666666666666666666666666666666"
        "368e6eca01b76a510619dc2778d46860a9070c4a6ad73ef52e81c31dab5a404f"
        "7777777777777777777777777777777777777777777777777777777777777777"
        "fdffffffffffffff"
        "feffffffffffffff"
        "0100000000000000"
        "94f2f8b99c2080051b431786b410153a928c37eff5054d6e2ab5a109f4a69148"
        "d9113049764e517c2f9a1a8122a606a8366370f59440d3aabbfc289aeea72086"
        "00"
    )

    assert len(blob) == 311

    transcript = decode_fcc4_transcript(blob)

    assert transcript.channel_id == bytes.fromhex(
        "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
    )
    assert len(transcript.turns) == 1

    turn = transcript.turns[0]
    assert turn.leaf_version == 3
    assert turn.turn_index == 2**32 - 1
    assert turn.h_in == bytes.fromhex("33" * 32)
    assert turn.h_out == bytes.fromhex("44" * 32)
    assert turn.g_n == 2**128 - 1
    assert turn.decode_policy_hash == bytes.fromhex("66" * 32)
    assert turn.h_ids == bytes.fromhex(
        "368e6eca01b76a510619dc2778d46860a9070c4a6ad73ef52e81c31dab5a404f"
    )
    assert turn.toploc_commitment_hash == bytes.fromhex("77" * 32)
    assert turn.miner_recv_ms == 2**64 - 3
    assert turn.miner_done_ms == 2**64 - 2
    assert turn.latency_ms == 1
    assert turn.enclave_sig == bytes.fromhex(
        "94f2f8b99c2080051b431786b410153a928c37eff5054d6e2ab5a109f4a69148"
        "d9113049764e517c2f9a1a8122a606a8366370f59440d3aabbfc289aeea72086"
    )
    assert turn.agent_ack is None



def _canonical_fcc4_blob() -> bytes:
    return bytes.fromhex(
        "464343343655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
        "0100000003ffffffff"
        "3333333333333333333333333333333333333333333333333333333333333333"
        "4444444444444444444444444444444444444444444444444444444444444444"
        "ffffffffffffffffffffffffffffffff"
        "01"
        "6666666666666666666666666666666666666666666666666666666666666666"
        "368e6eca01b76a510619dc2778d46860a9070c4a6ad73ef52e81c31dab5a404f"
        "7777777777777777777777777777777777777777777777777777777777777777"
        "fdffffffffffffff"
        "feffffffffffffff"
        "0100000000000000"
        "94f2f8b99c2080051b431786b410153a928c37eff5054d6e2ab5a109f4a69148"
        "d9113049764e517c2f9a1a8122a606a8366370f59440d3aabbfc289aeea72086"
        "00"
    )


def test_fcc4_rejects_truncated_canonical_vector():
    from app.compute_channel import decode_fcc4_transcript

    blob = _canonical_fcc4_blob()
    with pytest.raises(ValueError, match="truncated"):
        decode_fcc4_transcript(blob[:-1])


def test_fcc4_rejects_trailing_bytes_on_canonical_vector():
    from app.compute_channel import decode_fcc4_transcript

    blob = _canonical_fcc4_blob()
    with pytest.raises(ValueError, match="TrailingBytes"):
        decode_fcc4_transcript(blob + b"\x00")


def test_fcc4_rejects_invalid_optional_flag():
    from app.compute_channel import decode_fcc4_transcript

    blob = bytearray(_canonical_fcc4_blob())
    # V3 has policy flag immediately after g_n.
    policy_flag_offset = 4 + 32 + 4 + 1 + 4 + 32 + 32 + 16
    blob[policy_flag_offset] = 2

    with pytest.raises(ValueError, match="has_policy"):
        decode_fcc4_transcript(bytes(blob))


def test_fcc4_rejects_v3_zero_h_ids():
    from app.compute_channel import decode_fcc4_transcript

    blob = bytearray(_canonical_fcc4_blob())

    # Locate h_ids after:
    # header + leaf_version + turn_index + h_in + h_out + g_n
    # + has_policy + policy_hash.
    h_ids_offset = (
        4 + 32 + 4 + 1 + 4 + 32 + 32 + 16 + 1 + 32
    )
    blob[h_ids_offset:h_ids_offset + 32] = b"\x00" * 32

    with pytest.raises(ValueError, match="LeafFieldsInconsistent"):
        decode_fcc4_transcript(bytes(blob))


def test_fcc4_rejects_v3_inconsistent_policy_flag():
    from app.compute_channel import decode_fcc4_transcript

    blob = bytearray(_canonical_fcc4_blob())
    policy_flag_offset = 4 + 32 + 4 + 1 + 4 + 32 + 32 + 16

    # Remove policy flag but leave the V3 payload otherwise intact.
    blob[policy_flag_offset] = 0

    with pytest.raises(ValueError):
        decode_fcc4_transcript(bytes(blob))


def test_fcc4_rejects_unknown_leaf_version_before_decoding_fields():
    from app.compute_channel import decode_fcc4_transcript

    blob = bytearray(_canonical_fcc4_blob())
    leaf_version_offset = 4 + 32 + 4
    blob[leaf_version_offset] = 9

    with pytest.raises(ValueError, match="UnsupportedLeafVersion"):
        decode_fcc4_transcript(bytes(blob))


def test_fcc4_rejects_unknown_container_magic():
    from app.compute_channel import decode_fcc4_transcript

    blob = bytearray(_canonical_fcc4_blob())
    blob[0:4] = b"FCC5"

    with pytest.raises(ValueError, match="UnknownFCCVersion"):
        decode_fcc4_transcript(bytes(blob))


def test_verify_turn_proof_matches_public_canonical_v3_vector():
    from app.compute_channel import VerifiedTurnRecord, verify_turn_proof

    channel_id = bytes.fromhex(
        "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
    )

    turn = VerifiedTurnRecord(
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
        enclave_sig=bytes.fromhex(
            "94f2f8b99c2080051b431786b410153a928c37eff5054d6e2ab5a109f4a69148"
            "d9113049764e517c2f9a1a8122a606a8366370f59440d3aabbfc289aeea72086"
        ),
        agent_ack=None,
    )

    merkle_path = (
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

    root = bytes.fromhex(
        "1020281304e2677e48c1093e7f5069fc8fbff1ea82daf2ac5b2b49d7cef756ed"
    )

    public_key = bytes.fromhex(
        "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a"
    )

    leaf_hash = verify_turn_proof(
        channel_id=channel_id,
        turn=turn,
        merkle_index=2,
        merkle_path=merkle_path,
        expected_root=root,
        enclave_public_key=public_key,
        expected_decode_policy_hash=bytes.fromhex("66" * 32),
    )

    assert leaf_hash.hex() == (
        "8ca5d489cec0a255a48a2e3c2149d8028597e03ea78628d9a3672ddb80df2869"
    )

def _collection_test_turn(turn_index: int, g_n: int):
    from app.compute_channel import VerifiedTurnRecord

    return VerifiedTurnRecord(
        leaf_version=3,
        turn_index=turn_index,
        h_in=b"\x33" * 32,
        h_out=b"\x44" * 32,
        g_n=g_n,
        decode_policy_hash=b"\x66" * 32,
        h_ids=b"\x36" * 32,
        toploc_commitment_hash=b"\x77" * 32,
        miner_recv_ms=1,
        miner_done_ms=2,
        latency_ms=1,
        enclave_sig=b"\x94" * 64,
        agent_ack=None,
    )


def test_verified_work_from_turns_checks_and_returns_aggregate(monkeypatch):
    import app.compute_channel as cc

    calls = []

    def fake_verify_turn_proof(**kwargs):
        calls.append(kwargs)
        return b"\xaa" * 32

    monkeypatch.setattr(cc, "verify_turn_proof", fake_verify_turn_proof)

    turn_a = _collection_test_turn(10, 40)
    turn_b = _collection_test_turn(11, 2)

    result = cc.verified_work_from_turns(
        channel_id=b"\x01" * 32,
        turn_proofs=(
            (0, turn_a, ()),
            (1, turn_b, ()),
        ),
        expected_root=b"\x02" * 32,
        aggregate_gn=42,
        enclave_public_key=b"\x03" * 32,
    )

    assert result == 42
    assert len(calls) == 2
    assert calls[0]["merkle_index"] == 0
    assert calls[1]["merkle_index"] == 1


def test_verified_work_from_turns_rejects_duplicate_turn_index(monkeypatch):
    import app.compute_channel as cc

    monkeypatch.setattr(cc, "verify_turn_proof", lambda **kwargs: b"\xaa" * 32)

    turn_a = _collection_test_turn(10, 1)
    turn_b = _collection_test_turn(10, 2)

    with pytest.raises(ValueError, match="DuplicateVerifiedTurn"):
        cc.verified_work_from_turns(
            channel_id=b"\x01" * 32,
            turn_proofs=(
                (0, turn_a, ()),
                (1, turn_b, ()),
            ),
            expected_root=b"\x02" * 32,
            aggregate_gn=3,
            enclave_public_key=b"\x03" * 32,
        )


def test_verified_work_from_turns_rejects_out_of_range_merkle_index(monkeypatch):
    import app.compute_channel as cc

    monkeypatch.setattr(cc, "verify_turn_proof", lambda **kwargs: b"\xaa" * 32)

    turn = _collection_test_turn(10, 1)

    with pytest.raises(ValueError, match="OutOfRangeMerkleIndex"):
        cc.verified_work_from_turns(
            channel_id=b"\x01" * 32,
            turn_proofs=((1024, turn, ()),),
            expected_root=b"\x02" * 32,
            aggregate_gn=1,
            enclave_public_key=b"\x03" * 32,
        )


def test_verified_work_from_turns_rejects_duplicate_merkle_index(monkeypatch):
    import app.compute_channel as cc

    monkeypatch.setattr(cc, "verify_turn_proof", lambda **kwargs: b"\xaa" * 32)

    turn_a = _collection_test_turn(10, 1)
    turn_b = _collection_test_turn(11, 2)

    with pytest.raises(ValueError, match="DuplicateMerkleIndex"):
        cc.verified_work_from_turns(
            channel_id=b"\x01" * 32,
            turn_proofs=(
                (5, turn_a, ()),
                (5, turn_b, ()),
            ),
            expected_root=b"\x02" * 32,
            aggregate_gn=3,
            enclave_public_key=b"\x03" * 32,
        )


def test_verified_work_from_turns_rejects_aggregate_mismatch(monkeypatch):
    import app.compute_channel as cc

    monkeypatch.setattr(cc, "verify_turn_proof", lambda **kwargs: b"\xaa" * 32)

    turn = _collection_test_turn(10, 42)

    with pytest.raises(ValueError, match="AggregateGnMismatch"):
        cc.verified_work_from_turns(
            channel_id=b"\x01" * 32,
            turn_proofs=((0, turn, ()),),
            expected_root=b"\x02" * 32,
            aggregate_gn=41,
            enclave_public_key=b"\x03" * 32,
        )


def test_verified_work_from_turns_rejects_checked_sum_overflow(monkeypatch):
    import app.compute_channel as cc

    monkeypatch.setattr(cc, "verify_turn_proof", lambda **kwargs: b"\xaa" * 32)

    max_u128 = 2**128 - 1
    turn_a = _collection_test_turn(10, max_u128)
    turn_b = _collection_test_turn(11, 1)

    with pytest.raises(ValueError, match="AggregateGnOverflow"):
        cc.verified_work_from_turns(
            channel_id=b"\x01" * 32,
            turn_proofs=(
                (0, turn_a, ()),
                (1, turn_b, ()),
            ),
            expected_root=b"\x02" * 32,
            aggregate_gn=max_u128,
            enclave_public_key=b"\x03" * 32,
        )


def test_verify_receipt_canonical_agent_receipt_then_turn_collection(monkeypatch):
    import app.compute_channel as cc

    calls = []

    def fake_verified_work_from_turns(**kwargs):
        calls.append(kwargs)
        return 42

    monkeypatch.setattr(cc, "verified_work_from_turns", fake_verified_work_from_turns)

    result = cc.verify_receipt(
        channel_id=bytes.fromhex("11" * 32),
        final_root=bytes.fromhex("22" * 32),
        aggregate_gn=42,
        payable=1000,
        agent_public_key=bytes.fromhex(
            "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a"
        ),
        agent_receipt_sig=bytes.fromhex(
            "7803f98d0297c23f5df90f4bce093492de9658045d3d2296717a1e718e8bc40d"
            "891e60e517fdc459f59140b289d9fcba90809493875b5d8e77325b0ec9572683"
        ),
        turn_proofs=(),
        enclave_public_key=bytes.fromhex("33" * 32),
    )

    assert result == 42
    assert len(calls) == 1
    assert calls[0]["expected_root"] == bytes.fromhex("22" * 32)
    assert calls[0]["aggregate_gn"] == 42


def test_verify_receipt_rejects_invalid_agent_receipt_before_turns(monkeypatch):
    import app.compute_channel as cc

    called = False

    def fake_verified_work_from_turns(**kwargs):
        nonlocal called
        called = True
        return 42

    monkeypatch.setattr(cc, "verified_work_from_turns", fake_verified_work_from_turns)

    with pytest.raises(ValueError, match="BadReceiptSignature"):
        cc.verify_receipt(
            channel_id=bytes.fromhex("11" * 32),
            final_root=bytes.fromhex("22" * 32),
            aggregate_gn=42,
            payable=1000,
            agent_public_key=bytes.fromhex(
                "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a"
            ),
            agent_receipt_sig=bytes.fromhex(
                "7903f98d0297c23f5df90f4bce093492de9658045d3d2296717a1e718e8bc40d"
                "891e60e517fdc459f59140b289d9fcba90809493875b5d8e77325b0ec9572683"
            ),
            turn_proofs=(),
            enclave_public_key=bytes.fromhex("33" * 32),
        )

    assert called is False


def test_verify_receipt_rejects_receipt_field_binding(monkeypatch):
    import app.compute_channel as cc

    monkeypatch.setattr(
        cc,
        "verified_work_from_turns",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("turns must not run")
        ),
    )

    with pytest.raises(ValueError, match="BadReceiptSignature"):
        cc.verify_receipt(
            channel_id=bytes.fromhex("11" * 32),
            final_root=bytes.fromhex("22" * 32),
            aggregate_gn=43,
            payable=1000,
            agent_public_key=bytes.fromhex(
                "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a"
            ),
            agent_receipt_sig=bytes.fromhex(
                "7803f98d0297c23f5df90f4bce093492de9658045d3d2296717a1e718e8bc40d"
                "891e60e517fdc459f59140b289d9fcba90809493875b5d8e77325b0ec9572683"
            ),
            turn_proofs=(),
            enclave_public_key=bytes.fromhex("33" * 32),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("channel_id", bytes.fromhex("12" * 32)),
        ("final_root", bytes.fromhex("23" * 32)),
        ("aggregate_gn", 43),
        ("payable", 1001),
    ],
)
def test_verify_receipt_rejects_receipt_binding_mutation(field, value, monkeypatch):
    import app.compute_channel as cc

    monkeypatch.setattr(
        cc,
        "verified_work_from_turns",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("turn collection must not run")
        ),
    )

    kwargs = {
        "channel_id": bytes.fromhex("11" * 32),
        "final_root": bytes.fromhex("22" * 32),
        "aggregate_gn": 42,
        "payable": 1000,
        "agent_public_key": bytes.fromhex(
            "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a"
        ),
        "agent_receipt_sig": bytes.fromhex(
            "7803f98d0297c23f5df90f4bce093492de9658045d3d2296717a1e718e8bc40d"
            "891e60e517fdc459f59140b289d9fcba90809493875b5d8e77325b0ec9572683"
        ),
        "turn_proofs": (),
        "enclave_public_key": bytes.fromhex("33" * 32),
    }

    kwargs[field] = value

    with pytest.raises(ValueError, match="BadReceiptSignature"):
        cc.verify_receipt(**kwargs)


def test_verify_receipt_rejects_wrong_agent_signature(monkeypatch):
    import app.compute_channel as cc

    monkeypatch.setattr(
        cc,
        "verified_work_from_turns",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("turn collection must not run")
        ),
    )

    with pytest.raises(ValueError, match="BadReceiptSignature"):
        cc.verify_receipt(
            channel_id=bytes.fromhex("11" * 32),
            final_root=bytes.fromhex("22" * 32),
            aggregate_gn=42,
            payable=1000,
            agent_public_key=bytes.fromhex(
                "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a"
            ),
            agent_receipt_sig=bytes.fromhex(
                "7903f98d0297c23f5df90f4bce093492de9658045d3d2296717a1e718e8bc40d"
                "891e60e517fdc459f59140b289d9fcba90809493875b5d8e77325b0ec9572683"
            ),
            turn_proofs=(),
            enclave_public_key=bytes.fromhex("33" * 32),
        )


# wire-format-v1 negative case `legacy_leaf_current_channel`, copied verbatim
# from flop-labs/yellowpaper@3c97bbc8d6 evidence/wire-format-v1.json.
LEGACY_LEAF_CURRENT_CHANNEL_HEX = (
    "01ffffffff333333333333333333333333333333333333333333333333333333"
    "3333333333444444444444444444444444444444444444444444444444444444"
    "4444444444ffffffffffffffffffffffffffffffff0000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000fdfffffffffffffffeffff"
    "ffffffffff01000000000000001454f6cf53b85cd7a0665ef54785cb037bb046"
    "4270b42fc0760ba28482eee44eaa482284b51d7e23558bf5e844eca10b3c2b62"
    "f95504fccf2c4d57e86b910180084a3632de6913f0502c6313499b29d0976b08"
    "5a4612e14e017c5eaf065b1c6c2d005f0ff24a5b34ae51d68c9e76052c5aabc0"
    "b6715d0cf78b18383d56da2a6ff85200"
)


def _decode_verified_turn_scale(data: bytes):
    """Decode the SCALE VerifiedTurn layout used by the wire-format vectors."""
    from app.compute_channel import VerifiedTurnRecord

    offset = 0

    def take(size: int) -> bytes:
        nonlocal offset
        chunk = data[offset:offset + size]
        assert len(chunk) == size
        offset += size
        return chunk

    def u(size: int) -> int:
        return int.from_bytes(take(size), "little")

    leaf_version = u(1)
    turn_index = u(4)
    h_in = take(32)
    h_out = take(32)
    g_n = u(16)
    decode_policy_hash = take(32)
    h_ids = take(32)
    toploc_commitment_hash = take(32)
    miner_recv_ms = u(8)
    miner_done_ms = u(8)
    latency_ms = u(8)
    enclave_sig = take(64)

    # Single-byte compact length mode only (path length < 64).
    path_len_byte = u(1)
    assert path_len_byte & 0b11 == 0
    path = []
    for _ in range(path_len_byte >> 2):
        sibling = take(32)
        flag = u(1)
        assert flag in (0, 1)
        path.append((sibling, bool(flag)))
    assert offset == len(data)

    turn = VerifiedTurnRecord(
        leaf_version=leaf_version,
        turn_index=turn_index,
        h_in=h_in,
        h_out=h_out,
        g_n=g_n,
        decode_policy_hash=decode_policy_hash,
        h_ids=h_ids,
        toploc_commitment_hash=toploc_commitment_hash,
        miner_recv_ms=miner_recv_ms,
        miner_done_ms=miner_done_ms,
        latency_ms=latency_ms,
        enclave_sig=enclave_sig,
        agent_ack=None,
    )
    return turn, tuple(path)


def test_verify_turn_proof_rejects_legacy_leaf_on_pinned_policy_channel():
    """V1 leaf on a channel with a pinned decode policy -> UnsupportedLeafVersion.

    Context from the upstream generator: canonical channel_id, Merkle tree
    [V1, V2, V3] with the legacy turn at index 0, and the pinned policy
    0x66 * 32 used by every current-channel vector.
    """
    from app.compute_channel import verify_turn_proof

    blob = bytes.fromhex(LEGACY_LEAF_CURRENT_CHANNEL_HEX)
    assert len(blob) == 336

    turn, merkle_path = _decode_verified_turn_scale(blob)
    assert turn.leaf_version == 1

    with pytest.raises(ValueError, match="UnsupportedLeafVersion"):
        verify_turn_proof(
            channel_id=bytes.fromhex(
                "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
            ),
            turn=turn,
            merkle_index=0,
            merkle_path=merkle_path,
            expected_root=bytes.fromhex(
                "1020281304e2677e48c1093e7f5069fc8fbff1ea82daf2ac5b2b49d7cef756ed"
            ),
            enclave_public_key=bytes.fromhex(
                "207b3ee770b7213b7e76bdb32702e2e166a8fea8a125613d6e98c765f5a06d40"
            ),
            expected_decode_policy_hash=bytes.fromhex("66" * 32),
        )


def _canonical_v3_turn_proof_kwargs() -> dict:
    from app.compute_channel import VerifiedTurnRecord

    return {
        "channel_id": bytes.fromhex(
            "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
        ),
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
            enclave_sig=bytes.fromhex(
                "94f2f8b99c2080051b431786b410153a928c37eff5054d6e2ab5a109f4a69148"
                "d9113049764e517c2f9a1a8122a606a8366370f59440d3aabbfc289aeea72086"
            ),
            agent_ack=None,
        ),
        "merkle_index": 2,
        "merkle_path": (
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
        ),
        "expected_root": bytes.fromhex(
            "1020281304e2677e48c1093e7f5069fc8fbff1ea82daf2ac5b2b49d7cef756ed"
        ),
        "enclave_public_key": bytes.fromhex(
            "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a"
        ),
        "expected_decode_policy_hash": bytes.fromhex("66" * 32),
    }


def test_verify_turn_proof_rejects_flipped_enclave_signature():
    from dataclasses import replace

    from app.compute_channel import verify_turn_proof

    kwargs = _canonical_v3_turn_proof_kwargs()
    sig = kwargs["turn"].enclave_sig
    kwargs["turn"] = replace(
        kwargs["turn"],
        enclave_sig=bytes([sig[0] ^ 1]) + sig[1:],
    )

    with pytest.raises(ValueError, match="InvalidEnclaveSignature"):
        verify_turn_proof(**kwargs)


def test_verify_turn_proof_rejects_wrong_path_orientation():
    """Wrong orientation -> LeafNotInRoot (wire-format-v1 negative vector)."""
    from app.compute_channel import verify_turn_proof

    kwargs = _canonical_v3_turn_proof_kwargs()
    first, (sibling, sibling_is_left) = kwargs["merkle_path"]
    kwargs["merkle_path"] = (first, (sibling, not sibling_is_left))

    with pytest.raises(ValueError, match="LeafNotInRoot"):
        verify_turn_proof(**kwargs)


# wire-format-v1 negative case `wrong_path_orientation`, copied verbatim
# from flop-labs/yellowpaper@3c97bbc8d6 evidence/wire-format-v1.json.
WRONG_PATH_ORIENTATION_HEX = (
    "03ffffffff333333333333333333333333333333333333333333333333333333"
    "3333333333444444444444444444444444444444444444444444444444444444"
    "4444444444ffffffffffffffffffffffffffffffff6666666666666666666666"
    "666666666666666666666666666666666666666666368e6eca01b76a510619dc"
    "2778d46860a9070c4a6ad73ef52e81c31dab5a404f7777777777777777777777"
    "777777777777777777777777777777777777777777fdfffffffffffffffeffff"
    "ffffffffff01000000000000002e60e88466a203e1c106a6dfca39276cf97556"
    "c3af971f48c4da8845cc23e068cbbcaf63aa20672cd21a6f64b9513d086f2ade"
    "15c90979e870fc2162c07d2f8d088ca5d489cec0a255a48a2e3c2149d8028597"
    "e03ea78628d9a3672ddb80df286900482735fe0838313af87270c7fa678a8fb6"
    "c3cf9d9e3af35b8c73ea39f279a92a00"
)

# Upstream channel_max_merkle_path_len (params/flop-protocol-params.yaml).
CHANNEL_MAX_MERKLE_PATH_LEN = 64


def _canonical_path_of_length(length: int) -> tuple:
    """Well-formed path for merkle_index 2 with orientation bits respected.

    The first two items are the canonical siblings; the rest are filler
    right-hand siblings, so only the length (and therefore the root) differs.
    """
    canonical = _canonical_v3_turn_proof_kwargs()["merkle_path"]
    filler = (bytes.fromhex("5a" * 32), False)
    return canonical + (filler,) * (length - len(canonical))


def test_verify_turn_proof_rejects_path_longer_than_max():
    from app.compute_channel import verify_turn_proof

    kwargs = _canonical_v3_turn_proof_kwargs()
    kwargs["merkle_path"] = _canonical_path_of_length(
        CHANNEL_MAX_MERKLE_PATH_LEN + 1
    )

    with pytest.raises(ValueError, match="MerklePathTooLong"):
        verify_turn_proof(**kwargs)


def test_verify_turn_proof_max_length_path_is_not_too_long():
    """A 64-item path is within the bound; it fails only because the root
    no longer matches, so the expected error is LeafNotInRoot."""
    from app.compute_channel import verify_turn_proof

    kwargs = _canonical_v3_turn_proof_kwargs()
    kwargs["merkle_path"] = _canonical_path_of_length(CHANNEL_MAX_MERKLE_PATH_LEN)

    with pytest.raises(ValueError, match="LeafNotInRoot"):
        verify_turn_proof(**kwargs)


def test_verify_turn_proof_wrong_path_orientation_matches_negative_vector():
    """Context from the upstream generator: canonical channel_id, Merkle tree
    [V1, V2, V3] with the V3 turn at index 2, enclave key 207b..., and the
    turn's own decode policy 0x66 * 32 as the channel policy.
    """
    from app.compute_channel import verify_turn_proof

    blob = bytes.fromhex(WRONG_PATH_ORIENTATION_HEX)
    assert len(blob) == 336

    turn, merkle_path = _decode_verified_turn_scale(blob)
    assert turn.leaf_version == 3

    with pytest.raises(ValueError, match="LeafNotInRoot"):
        verify_turn_proof(
            channel_id=bytes.fromhex(
                "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
            ),
            turn=turn,
            merkle_index=2,
            merkle_path=merkle_path,
            expected_root=bytes.fromhex(
                "1020281304e2677e48c1093e7f5069fc8fbff1ea82daf2ac5b2b49d7cef756ed"
            ),
            enclave_public_key=bytes.fromhex(
                "207b3ee770b7213b7e76bdb32702e2e166a8fea8a125613d6e98c765f5a06d40"
            ),
            expected_decode_policy_hash=bytes.fromhex("66" * 32),
        )


def test_verify_turn_proof_rejects_wrong_root():
    from app.compute_channel import verify_turn_proof

    kwargs = _canonical_v3_turn_proof_kwargs()
    kwargs["expected_root"] = bytes.fromhex("ab" * 32)

    with pytest.raises(ValueError, match="LeafNotInRoot"):
        verify_turn_proof(**kwargs)


def test_verify_turn_proof_rejects_malformed_path_item():
    """Locks remaining InvalidMerkleProof meaning: malformed path item."""
    from app.compute_channel import verify_turn_proof

    kwargs = _canonical_v3_turn_proof_kwargs()
    (sibling, sibling_is_left), second = kwargs["merkle_path"]
    kwargs["merkle_path"] = ((sibling[:31], sibling_is_left), second)

    with pytest.raises(ValueError, match="InvalidMerkleProof"):
        verify_turn_proof(**kwargs)


def test_verify_turn_proof_rejects_u32_overflow_merkle_index():
    """Locks remaining InvalidMerkleProof meaning: index beyond u32.

    The u32 range check lives in verify_merkle_path, which receives
    merkle_index (not turn.turn_index) as its turn index.
    """
    from app.compute_channel import verify_turn_proof

    kwargs = _canonical_v3_turn_proof_kwargs()
    kwargs["merkle_index"] = 2**32

    with pytest.raises(ValueError, match="InvalidMerkleProof"):
        verify_turn_proof(**kwargs)


def _signed_single_leaf_turn_proof_kwargs(leaf_version: int, **overrides) -> dict:
    """V0/V1 turn signed with a local sr25519 key in a single-leaf tree.

    The V0/V1 leaf preimage omits decode_policy_hash, h_ids and the TOPLOC
    commitment, so overriding those fields keeps signature and Merkle valid.
    """
    import sr25519

    from app.compute_channel import VerifiedTurnRecord
    from app.crypto import compute_verified_turn_leaf_v0_v1_v2_v3

    channel_id = bytes.fromhex(
        "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
    )
    fields = {
        "leaf_version": leaf_version,
        "turn_index": 0,
        "h_in": bytes.fromhex("33" * 32),
        "h_out": bytes.fromhex("44" * 32),
        "g_n": 42,
        "decode_policy_hash": bytes(32),
        "h_ids": bytes(32),
        "toploc_commitment_hash": bytes(32),
        "miner_recv_ms": 1 if leaf_version == 1 else 0,
        "miner_done_ms": 2 if leaf_version == 1 else 0,
        "latency_ms": 1 if leaf_version == 1 else 0,
    }
    leaf_hash = bytes.fromhex(
        compute_verified_turn_leaf_v0_v1_v2_v3(channel_id=channel_id, **fields)
    )
    public_key, private_key = sr25519.pair_from_seed(bytes(range(32)))
    enclave_sig = sr25519.sign((public_key, private_key), leaf_hash)

    fields.update(overrides)
    return {
        "channel_id": channel_id,
        "turn": VerifiedTurnRecord(enclave_sig=enclave_sig, agent_ack=None, **fields),
        "merkle_index": 0,
        "merkle_path": (),
        "expected_root": leaf_hash,
        "enclave_public_key": public_key,
        "expected_decode_policy_hash": None,
    }


@pytest.mark.parametrize("leaf_version", [0, 1])
def test_verify_turn_proof_accepts_consistent_legacy_leaf_control(leaf_version):
    """Control: the signed V0/V1 fixture is valid when its V3 fields are zero."""
    from app.compute_channel import verify_turn_proof

    kwargs = _signed_single_leaf_turn_proof_kwargs(leaf_version)

    assert verify_turn_proof(**kwargs) == kwargs["expected_root"]


@pytest.mark.parametrize(
    ("leaf_version", "field"),
    [
        (1, "h_ids"),
        (1, "toploc_commitment_hash"),
        (0, "h_ids"),
    ],
)
def test_verify_turn_proof_rejects_legacy_leaf_with_nonzero_v3_field(
    leaf_version, field
):
    from app.compute_channel import verify_turn_proof

    kwargs = _signed_single_leaf_turn_proof_kwargs(
        leaf_version, **{field: bytes.fromhex("99" * 32)}
    )

    with pytest.raises(ValueError, match="LeafFieldsInconsistent"):
        verify_turn_proof(**kwargs)


def test_verify_turn_proof_rejects_u32_overflow_turn_index():
    """turn.turn_index beyond u32 fails during leaf hash computation."""
    from dataclasses import replace

    from app.compute_channel import verify_turn_proof

    kwargs = _canonical_v3_turn_proof_kwargs()
    kwargs["turn"] = replace(kwargs["turn"], turn_index=2**32)

    with pytest.raises(ValueError, match="turn_index must fit in u32"):
        verify_turn_proof(**kwargs)


# wire-format-v1 `compute_channel_v1.receipt` and negative case
# `legacy_receipt_current_channel`, copied verbatim from
# flop-labs/yellowpaper@3c97bbc8d6 evidence/wire-format-v1.json.
RECEIPT_V1_SIGNATURE_HEX = (
    "7803f98d0297c23f5df90f4bce093492de9658045d3d2296717a1e718e8bc40d"
    "891e60e517fdc459f59140b289d9fcba90809493875b5d8e77325b0ec9572683"
)

LEGACY_RECEIPT_CURRENT_CHANNEL_HEX = (
    "1111111111111111111111111111111111111111111111111111111111111111"
    "2222222222222222222222222222222222222222222222222222222222222222"
    "2a000000000000000000000000000000e8030000000000000000000000000000"
    "a0f54ce7f97e6e8e76a4ddf6b8785ec5efd243b4a335b7954504a5c19faee620"
    "e881741ae3cfbb56cd503d17e91cd5406ffc1a8d7478108854cd781aade52687"
)

RECEIPT_PUBLIC_KEY = bytes.fromhex(
    "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a"
)


def _vector_receipt_kwargs(agent_receipt_sig: bytes) -> dict:
    return {
        "channel_id": bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111"),
        "final_root": bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222"),
        "aggregate_gn": 42,
        "payable": 1000,
        "agent_public_key": RECEIPT_PUBLIC_KEY,
        "agent_receipt_sig": agent_receipt_sig,
        "turn_proofs": (),
        "enclave_public_key": bytes.fromhex("33" * 32),
    }


def _split_legacy_receipt_vector() -> tuple[bytes, bytes]:
    """Vector bytes are the unprefixed 96 B receipt preimage || 64 B signature."""
    blob = bytes.fromhex(LEGACY_RECEIPT_CURRENT_CHANNEL_HEX)
    assert len(blob) == 160
    return blob[:96], blob[96:]


def test_verify_receipt_rejects_legacy_receipt_on_current_channel(monkeypatch):
    """Negative case `legacy_receipt_current_channel`: a signature over the
    receipt preimage without the "FLOP/COMPUTE_CHANNEL/RECEIPT" || 01 prefix."""
    import app.compute_channel as cc

    monkeypatch.setattr(
        cc,
        "verified_work_from_turns",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("turn collection must not run")
        ),
    )

    _, legacy_sig = _split_legacy_receipt_vector()

    with pytest.raises(ValueError, match="BadReceiptSignature"):
        cc.verify_receipt(**_vector_receipt_kwargs(legacy_sig))


def test_legacy_receipt_vector_differs_from_v1_only_by_prefix_control():
    """Control: the legacy signature is a genuine signature by the same key over
    the same inputs; only the receipt domain/version prefix is missing."""
    import sr25519

    from app.crypto import compute_agent_receipt_v1_signable_payload

    legacy_preimage, legacy_sig = _split_legacy_receipt_vector()
    kwargs = _vector_receipt_kwargs(legacy_sig)
    v1_payload = compute_agent_receipt_v1_signable_payload(
        channel_id=kwargs["channel_id"],
        final_root=kwargs["final_root"],
        aggregate_gn=kwargs["aggregate_gn"],
        payable=kwargs["payable"],
    )

    assert v1_payload == b"FLOP/COMPUTE_CHANNEL/RECEIPT\x01" + legacy_preimage
    assert sr25519.verify(legacy_sig, legacy_preimage, RECEIPT_PUBLIC_KEY)


def test_verify_receipt_accepts_v1_receipt_vector_control(monkeypatch):
    """Control: same key and inputs with the prefixed v1 receipt are accepted."""
    import app.compute_channel as cc

    monkeypatch.setattr(cc, "verified_work_from_turns", lambda **kwargs: 42)

    assert cc.verify_receipt(
        **_vector_receipt_kwargs(bytes.fromhex(RECEIPT_V1_SIGNATURE_HEX))
    ) == 42
