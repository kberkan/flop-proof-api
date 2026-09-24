import pytest

from app.compute_channel import decode_fcc4_transcript


def _canonical_fcc4_blob() -> bytes:
    return bytes.fromhex(
        "46434334"
        "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
        "01000000"
        "03"
        "ffffffff"
        "33" * 32
    )


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

    with pytest.raises(ValueError, match="DuplicateTurnIndex"):
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
