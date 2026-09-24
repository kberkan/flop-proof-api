from __future__ import annotations

from dataclasses import dataclass


from app.crypto import (
    compute_verified_turn_leaf_v0_v1_v2_v3,
    verify_agent_receipt_v1,
    verify_verified_turn_leaf_signature,
    verify_merkle_path,
)
FCC4_MAGIC = b"FCC4"
H256_SIZE = 32
SR25519_SIGNATURE_SIZE = 64
MAX_TURNS = 1024


@dataclass(frozen=True)
class VerifiedTurnRecord:
    leaf_version: int
    turn_index: int
    h_in: bytes
    h_out: bytes
    g_n: int
    decode_policy_hash: bytes
    h_ids: bytes
    toploc_commitment_hash: bytes
    miner_recv_ms: int
    miner_done_ms: int
    latency_ms: int
    enclave_sig: bytes
    agent_ack: tuple[int, int, bytes] | None = None


@dataclass(frozen=True)
class FCC4Transcript:
    channel_id: bytes
    turns: tuple[VerifiedTurnRecord, ...]


def _read_exact(data: bytes, offset: int, size: int) -> tuple[bytes, int]:
    end = offset + size
    if end > len(data):
        raise ValueError("truncated FCC4 transcript")
    return data[offset:end], end


def _read_u8(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 1)
    return raw[0], offset


def _read_u32_le(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 4)
    return int.from_bytes(raw, "little"), offset


def _read_u64_le(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 8)
    return int.from_bytes(raw, "little"), offset


def _read_u128_le(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 16)
    return int.from_bytes(raw, "little"), offset


def _read_h256(data: bytes, offset: int) -> tuple[bytes, int]:
    return _read_exact(data, offset, H256_SIZE)


def _require_flag(value: int, name: str) -> None:
    if value not in (0, 1):
        raise ValueError(f"{name} must be exactly 0 or 1")


def _validate_leaf_fields(
    leaf_version: int,
    decode_policy_hash: bytes,
    h_ids: bytes,
    toploc_commitment_hash: bytes,
    has_policy: int,
) -> None:
    zero = b"\x00" * 32

    if leaf_version not in (0, 1, 2, 3):
        raise ValueError("UnsupportedLeafVersion")

    _require_flag(has_policy, "has_policy")

    if leaf_version in (0, 1):
        if has_policy != 0 or decode_policy_hash != zero:
            raise ValueError("LeafFieldsInconsistent")
        if h_ids != zero or toploc_commitment_hash != zero:
            raise ValueError("LeafFieldsInconsistent")
    elif leaf_version == 2:
        if has_policy != 1 or decode_policy_hash == zero:
            raise ValueError("LeafFieldsInconsistent")
        if h_ids != zero or toploc_commitment_hash != zero:
            raise ValueError("LeafFieldsInconsistent")
    else:
        if has_policy != 1 or decode_policy_hash == zero:
            raise ValueError("LeafFieldsInconsistent")
        if h_ids == zero or toploc_commitment_hash == zero:
            raise ValueError("LeafFieldsInconsistent")


def decode_fcc4_transcript(data: bytes) -> FCC4Transcript:
    if not isinstance(data, bytes):
        raise TypeError("FCC4 transcript must be bytes")

    offset = 0

    magic, offset = _read_exact(data, offset, 4)
    if magic != FCC4_MAGIC:
        raise ValueError("UnknownFCCVersion")

    channel_id, offset = _read_h256(data, offset)
    turn_count, offset = _read_u32_le(data, offset)

    if turn_count > MAX_TURNS:
        raise ValueError("TooManyTurns")

    turns: list[VerifiedTurnRecord] = []

    for _ in range(turn_count):
        leaf_version, offset = _read_u8(data, offset)
        turn_index, offset = _read_u32_le(data, offset)
        h_in, offset = _read_h256(data, offset)
        h_out, offset = _read_h256(data, offset)
        g_n, offset = _read_u128_le(data, offset)

        has_policy, offset = _read_u8(data, offset)
        _require_flag(has_policy, "has_policy")

        if has_policy:
            decode_policy_hash, offset = _read_h256(data, offset)
        else:
            decode_policy_hash = b"\x00" * 32

        h_ids, offset = _read_h256(data, offset)
        toploc_commitment_hash, offset = _read_h256(data, offset)
        miner_recv_ms, offset = _read_u64_le(data, offset)
        miner_done_ms, offset = _read_u64_le(data, offset)
        latency_ms, offset = _read_u64_le(data, offset)
        enclave_sig, offset = _read_exact(
            data, offset, SR25519_SIGNATURE_SIZE
        )

        _validate_leaf_fields(
            leaf_version=leaf_version,
            decode_policy_hash=decode_policy_hash,
            h_ids=h_ids,
            toploc_commitment_hash=toploc_commitment_hash,
            has_policy=has_policy,
        )

        has_ack, offset = _read_u8(data, offset)
        _require_flag(has_ack, "has_ack")

        agent_ack = None
        if has_ack:
            send_ms, offset = _read_u64_le(data, offset)
            receive_ms, offset = _read_u64_le(data, offset)
            agent_sig, offset = _read_exact(
                data, offset, SR25519_SIGNATURE_SIZE
            )
            agent_ack = (send_ms, receive_ms, agent_sig)

        turns.append(
            VerifiedTurnRecord(
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
                agent_ack=agent_ack,
            )
        )

    if offset != len(data):
        raise ValueError("TrailingBytes")

    return FCC4Transcript(
        channel_id=channel_id,
        turns=tuple(turns),
    )


def verify_turn_proof(
    *,
    channel_id: bytes,
    turn: VerifiedTurnRecord,
    merkle_index: int,
    merkle_path: tuple[tuple[bytes, bool], ...],
    expected_root: bytes,
    enclave_public_key: bytes,
    expected_decode_policy_hash: bytes | None = None,
) -> bytes:
    """Verify one explicitly versioned VerifiedTurn against a Merkle root.

    The caller supplies the exact leaf version encoded by the turn.
    No alternate leaf version is attempted on failure.
    """
    if not isinstance(channel_id, bytes) or len(channel_id) != H256_SIZE:
        raise ValueError("InvalidChannelID")

    if not isinstance(merkle_index, int) or isinstance(merkle_index, bool):
        raise ValueError("InvalidMerkleIndex")

    if merkle_index < 0:
        raise ValueError("InvalidMerkleIndex")

    if not isinstance(expected_root, bytes) or len(expected_root) != H256_SIZE:
        raise ValueError("InvalidRoot")

    if not isinstance(enclave_public_key, bytes) or len(enclave_public_key) != H256_SIZE:
        raise ValueError("InvalidEnclavePublicKey")

    if expected_decode_policy_hash is not None:
        if (
            not isinstance(expected_decode_policy_hash, bytes)
            or len(expected_decode_policy_hash) != H256_SIZE
        ):
            raise ValueError("InvalidDecodePolicyHash")

    if turn.leaf_version not in (0, 1, 2, 3):
        raise ValueError("UnsupportedLeafVersion")

    zero = b"\x00" * H256_SIZE

    if turn.leaf_version in (0, 1):
        if turn.decode_policy_hash != zero:
            raise ValueError("LeafFieldsInconsistent")
        if expected_decode_policy_hash is not None:
            raise ValueError("PolicyRequiredForCurrentChannel")
    else:
        if turn.decode_policy_hash == zero:
            raise ValueError("LeafFieldsInconsistent")
        if (
            expected_decode_policy_hash is not None
            and turn.decode_policy_hash != expected_decode_policy_hash
        ):
            raise ValueError("DecodePolicyMismatch")

    if turn.leaf_version == 3 and turn.h_ids == zero:
        raise ValueError("LeafFieldsInconsistent")

    leaf_hex = compute_verified_turn_leaf_v0_v1_v2_v3(
        leaf_version=turn.leaf_version,
        channel_id=channel_id,
        turn_index=turn.turn_index,
        h_in=turn.h_in,
        h_out=turn.h_out,
        g_n=turn.g_n,
        decode_policy_hash=turn.decode_policy_hash,
        h_ids=turn.h_ids,
        toploc_commitment_hash=turn.toploc_commitment_hash,
        miner_recv_ms=turn.miner_recv_ms,
        miner_done_ms=turn.miner_done_ms,
        latency_ms=turn.latency_ms,
    )
    leaf_hash = bytes.fromhex(leaf_hex)

    if not verify_verified_turn_leaf_signature(
        enclave_public_key,
        turn.enclave_sig,
        leaf_hash,
    ):
        raise ValueError("InvalidValidatorSignature")

    if not verify_merkle_path(
        leaf_hash,
        merkle_index,
        list(merkle_path),
        expected_root,
    ):
        raise ValueError("InvalidMerkleProof")

    return leaf_hash


def verified_work_from_turns(
    *,
    channel_id: bytes,
    turn_proofs: tuple[
        tuple[int, VerifiedTurnRecord, tuple[tuple[bytes, bool], ...]], ...
    ],
    expected_root: bytes,
    aggregate_gn: int,
    enclave_public_key: bytes,
    expected_decode_policy_hash: bytes | None = None,
) -> int:
    """Verify a submitted turn collection and its checked G_n aggregate.

    Each item is:
        (merkle_index, VerifiedTurnRecord, merkle_path)

    `turn.turn_index` is the canonical u32 value bound into the leaf hash.
    `merkle_index` is the leaf position used only for Merkle-path verification.
    """
    if not isinstance(channel_id, bytes) or len(channel_id) != H256_SIZE:
        raise ValueError("InvalidChannelID")

    if not isinstance(expected_root, bytes) or len(expected_root) != H256_SIZE:
        raise ValueError("InvalidRoot")

    if (
        not isinstance(aggregate_gn, int)
        or isinstance(aggregate_gn, bool)
        or not 0 <= aggregate_gn <= (2**128 - 1)
    ):
        raise ValueError("InvalidAggregateGn")

    if not isinstance(turn_proofs, tuple):
        raise TypeError("turn_proofs must be a tuple")

    if len(turn_proofs) > MAX_TURNS:
        raise ValueError("TooManySettlementTurns")

    seen_turn_indices: set[int] = set()
    seen_merkle_indices: set[int] = set()
    total_gn = 0
    max_u128 = 2**128 - 1

    for item in turn_proofs:
        if not isinstance(item, tuple) or len(item) != 3:
            raise ValueError("InvalidTurnProof")

        merkle_index, turn, merkle_path = item

        if (
            not isinstance(merkle_index, int)
            or isinstance(merkle_index, bool)
            or not 0 <= merkle_index < MAX_TURNS
        ):
            raise ValueError("OutOfRangeMerkleIndex")

        if merkle_index in seen_merkle_indices:
            raise ValueError("DuplicateMerkleIndex")
        seen_merkle_indices.add(merkle_index)

        if not isinstance(turn.turn_index, int) or isinstance(turn.turn_index, bool):
            raise ValueError("InvalidTurnIndex")

        if not 0 <= turn.turn_index <= 2**32 - 1:
            raise ValueError("OutOfRangeTurnIndex")

        if turn.turn_index in seen_turn_indices:
            raise ValueError("DuplicateTurnIndex")
        seen_turn_indices.add(turn.turn_index)

        if (
            not isinstance(turn.g_n, int)
            or isinstance(turn.g_n, bool)
            or not 0 <= turn.g_n <= max_u128
        ):
            raise ValueError("InvalidGn")

        if not isinstance(merkle_path, tuple):
            raise TypeError("MerklePathMustBeTuple")

        verify_turn_proof(
            channel_id=channel_id,
            turn=turn,
            merkle_index=merkle_index,
            merkle_path=merkle_path,
            expected_root=expected_root,
            enclave_public_key=enclave_public_key,
            expected_decode_policy_hash=expected_decode_policy_hash,
        )

        if total_gn > max_u128 - turn.g_n:
            raise ValueError("AggregateGnOverflow")

        total_gn += turn.g_n

    if total_gn != aggregate_gn:
        raise ValueError("AggregateGnMismatch")

    return total_gn


def verify_receipt(
    *,
    channel_id: bytes,
    final_root: bytes,
    aggregate_gn: int,
    payable: int,
    agent_public_key: bytes,
    agent_receipt_sig: bytes,
    turn_proofs: tuple[
        tuple[int, VerifiedTurnRecord, tuple[tuple[bytes, bool], ...]], ...
    ],
    enclave_public_key: bytes,
    expected_decode_policy_hash: bytes | None = None,
) -> int:
    """Verify the canonical agent receipt and submitted turn collection."""
    if not isinstance(channel_id, bytes) or len(channel_id) != H256_SIZE:
        raise ValueError("InvalidChannelID")

    if not isinstance(final_root, bytes) or len(final_root) != H256_SIZE:
        raise ValueError("InvalidRoot")

    if (
        not isinstance(aggregate_gn, int)
        or isinstance(aggregate_gn, bool)
        or not 0 <= aggregate_gn <= 2**128 - 1
    ):
        raise ValueError("InvalidAggregateGn")

    if (
        not isinstance(payable, int)
        or isinstance(payable, bool)
        or not 0 <= payable <= 2**128 - 1
    ):
        raise ValueError("InvalidPayable")

    if not isinstance(agent_public_key, bytes) or len(agent_public_key) != H256_SIZE:
        raise ValueError("InvalidAgentPublicKey")

    if (
        not isinstance(agent_receipt_sig, bytes)
        or len(agent_receipt_sig) != SR25519_SIGNATURE_SIZE
    ):
        raise ValueError("InvalidReceiptSignature")

    if not verify_agent_receipt_v1(
        public_key=agent_public_key,
        signature=agent_receipt_sig,
        channel_id=channel_id,
        final_root=final_root,
        aggregate_gn=aggregate_gn,
        payable=payable,
    ):
        raise ValueError("BadReceiptSignature")

    return verified_work_from_turns(
        channel_id=channel_id,
        turn_proofs=turn_proofs,
        expected_root=final_root,
        aggregate_gn=aggregate_gn,
        enclave_public_key=enclave_public_key,
        expected_decode_policy_hash=expected_decode_policy_hash,
    )
