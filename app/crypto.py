import base64
import hashlib
from dataclasses import dataclass
from fractions import Fraction
from typing import Protocol

import json
import re

import base58
import sr25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ED25519_PUB_MULTICODEC = bytes([0xED, 0x01])


class DecodePolicyClass:
    TEXT_GENERATION = 0
    IMAGE_DENOISE = 1
    ROLLOUT = 2
    CONTROL_LOOP = 3
    OTHER = 4


class OutputTransform:
    IDENTITY = 0
    TRANSFORM_ID = 1


@dataclass(frozen=True)
class SamplingParams:
    temperature_milli: int
    top_p_ppm: int
    top_k: int
    repetition_penalty_ppm: int
    beam_width: int
    seed: int


@dataclass(frozen=True)
class DecodePolicy:
    version: int
    class_tag: int
    tokenizer_hash: bytes
    sampling_params: SamplingParams
    stop_conditions_hash: bytes
    output_transform: int
    transform_id: bytes | None
    class_policy_hash: bytes
    other_class: int | None = None


def _u16_le(value: int, name: str) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= 2**16 - 1:
        raise ValueError(f"{name} must be a u16")
    return value.to_bytes(2, "little")


def _u32_le(value: int, name: str) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= 2**32 - 1:
        raise ValueError(f"{name} must be a u32")
    return value.to_bytes(4, "little")


def _u64_le(value: int, name: str) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= 2**64 - 1:
        raise ValueError(f"{name} must be a u64")
    return value.to_bytes(8, "little")


def _h256(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")
    return value


def _sr25519_signature(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 64:
        raise ValueError(f"{name} must be exactly 64 bytes")
    return value


def encode_sampling_params(params: SamplingParams) -> bytes:
    """Canonical SCALE encoding of SamplingParams v1."""
    return (
        _u32_le(params.temperature_milli, "temperature_milli")
        + _u32_le(params.top_p_ppm, "top_p_ppm")
        + _u32_le(params.top_k, "top_k")
        + _u32_le(params.repetition_penalty_ppm, "repetition_penalty_ppm")
        + _u16_le(params.beam_width, "beam_width")
        + _u64_le(params.seed, "seed")
    )


def encode_decode_policy(policy: DecodePolicy) -> bytes:
    """Canonical SCALE encoding of DecodePolicy v1."""
    if policy.version != 1:
        raise ValueError("DecodePolicy version must be 1")

    if not isinstance(policy.class_tag, int) or not 0 <= policy.class_tag <= 4:
        raise ValueError("class_tag must be in the range 0..4")

    encoded = _u16_le(policy.version, "version")

    if policy.class_tag == DecodePolicyClass.OTHER:
        encoded += bytes([DecodePolicyClass.OTHER])
        other_value = policy.other_class
        if other_value is None:
            raise ValueError("Other class requires other_class u16")
        encoded += _u16_le(other_value, "other_class")
    else:
        encoded += bytes([policy.class_tag])

    encoded += _h256(policy.tokenizer_hash, "tokenizer_hash")
    encoded += encode_sampling_params(policy.sampling_params)
    encoded += _h256(policy.stop_conditions_hash, "stop_conditions_hash")

    if policy.output_transform == OutputTransform.IDENTITY:
        encoded += bytes([OutputTransform.IDENTITY])
    elif policy.output_transform == OutputTransform.TRANSFORM_ID:
        encoded += bytes([OutputTransform.TRANSFORM_ID])
        encoded += _h256(policy.transform_id, "transform_id")
    else:
        raise ValueError("output_transform must be Identity(0) or TransformId(1)")

    encoded += _h256(policy.class_policy_hash, "class_policy_hash")
    return encoded


def compute_decode_policy_hash(policy: DecodePolicy) -> bytes:
    """Compute canonical FLOP DecodePolicy v1 SHA-256 digest."""
    return hashlib.sha256(
        b"FLOP_DECODE_POLICY_HASH_V1" + encode_decode_policy(policy)
    ).digest()


@dataclass(frozen=True)
class ValidatorAttestation:
    task_hash: bytes
    gn_weight: int
    latency_ms: int
    model_hash: bytes
    output_hash: bytes
    decode_policy_hash: bytes
    tee_type: int
    quote_verified: bool
    event_log_verified: bool
    hardware_id_hash: bytes
    validator_id: bytes
    signature: bytes

    def __post_init__(self) -> None:
        hash_fields = (
            ("task_hash", self.task_hash),
            ("model_hash", self.model_hash),
            ("output_hash", self.output_hash),
            ("decode_policy_hash", self.decode_policy_hash),
            ("hardware_id_hash", self.hardware_id_hash),
            ("validator_id", self.validator_id),
        )

        for name, value in hash_fields:
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError(f"{name} must be exactly 32 bytes")

        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValueError("signature must be exactly 64 bytes")

        if not isinstance(self.gn_weight, int) or not 0 <= self.gn_weight <= 2**64 - 1:
            raise ValueError("gn_weight must be a u64")

        if not isinstance(self.latency_ms, int) or not 0 <= self.latency_ms <= 2**64 - 1:
            raise ValueError("latency_ms must be a u64")

        if not isinstance(self.tee_type, int) or not 0 <= self.tee_type <= 255:
            raise ValueError("tee_type must be a u8")

        if not isinstance(self.quote_verified, bool):
            raise ValueError("quote_verified must be a bool")

        if not isinstance(self.event_log_verified, bool):
            raise ValueError("event_log_verified must be a bool")


class ValidatorRegistry(Protocol):
    """Source of the currently active validator set."""

    def active_validator_ids(self) -> tuple[bytes, ...]:
        ...

    def active_validator_count(self) -> int:
        ...

    def is_active(self, validator_id: bytes) -> bool:
        ...


@dataclass(frozen=True)
class MockValidatorRegistry:
    """Local/test-only source of active validator membership."""

    _active_validator_ids: tuple[bytes, ...]

    def __init__(self, active_validator_ids: list[bytes]) -> None:
        normalized = tuple(active_validator_ids)

        for validator_id in normalized:
            if not isinstance(validator_id, bytes) or len(validator_id) != 32:
                raise ValueError(
                    "validator IDs must be exactly 32 bytes"
                )

        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate validator IDs are not allowed")

        object.__setattr__(
            self,
            "_active_validator_ids",
            normalized,
        )

    def active_validator_ids(self) -> tuple[bytes, ...]:
        return self._active_validator_ids

    def active_validator_count(self) -> int:
        return len(self._active_validator_ids)

    def is_active(self, validator_id: bytes) -> bool:
        return validator_id in self._active_validator_ids


class ProcessedTasks:
    """Local/in-memory replay guard for creditable task hashes."""

    def __init__(self) -> None:
        self._processed: set[bytes] = set()

    @staticmethod
    def _validate_task_hash(task_hash: bytes) -> None:
        if not isinstance(task_hash, bytes) or len(task_hash) != 32:
            raise ValueError("task_hash must be exactly 32 bytes")

    def is_processed(self, task_hash: bytes) -> bool:
        self._validate_task_hash(task_hash)
        return task_hash in self._processed

    def claim(self, task_hash: bytes) -> bool:
        self._validate_task_hash(task_hash)
        if task_hash in self._processed:
            return False
        self._processed.add(task_hash)
        return True

    def mark_processed(self, task_hash: bytes) -> bool:
        self._validate_task_hash(task_hash)

        if task_hash in self._processed:
            return False

        self._processed.add(task_hash)
        return True


def calculate_validator_quorum(
    active_validator_count: int,
    threshold: float | Fraction,
) -> int:
    """Calculate the minimum attestation quorum from active validators."""
    if not isinstance(active_validator_count, int):
        raise ValueError("active_validator_count must be an integer")
    if active_validator_count < 0:
        raise ValueError("active_validator_count cannot be negative")

    try:
        threshold = Fraction(threshold)
    except (TypeError, ValueError, ZeroDivisionError):
        raise ValueError("threshold must be numeric") from None

    if not 0 < threshold <= 1:
        raise ValueError("threshold must be greater than 0 and at most 1")

    required = (
        active_validator_count * threshold.numerator
        + threshold.denominator
        - 1
    ) // threshold.denominator

    return max(1, required)


def has_distinct_validator_ids(validator_ids: list[bytes]) -> bool:
    """Return whether every validator ID in a bundle is unique."""
    return len(validator_ids) == len(set(validator_ids))


_VALIDATOR_ATTESTATION_SIGNED_FIELDS = (
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


def validator_attestation_fields_match(
    left: dict,
    right: dict,
) -> bool:
    """Compare the named signed ValidatorAttestation fields only."""
    return all(
        left.get(field) == right.get(field)
        for field in _VALIDATOR_ATTESTATION_SIGNED_FIELDS
    )


THROUGHPUT_TRIPWIRE_GFLOPS_PER_SEC = 2_000_000

# Longest accepted compute-channel Merkle path: channel_max_merkle_path_len in
# params/flop-protocol-params.yaml (flop-labs/yellowpaper@3c97bbc8d6). The one
# definition; app.compute_channel imports it.
CHANNEL_MAX_MERKLE_PATH_LEN = 64


def validate_gn_latency_throughput_tripwire(
    gn_weight: int,
    latency_ms: int,
) -> bool:
    """Reject implausible G_n/latency claims using the protocol tripwire.

    This validates an externally supplied claim; it does not compute G_n.
    A bool is not a count, although Python treats True as 1.
    """
    if not isinstance(gn_weight, int) or isinstance(gn_weight, bool) or gn_weight < 0:
        return False

    if not isinstance(latency_ms, int) or isinstance(latency_ms, bool) or latency_ms <= 0:
        return False

    return (
        gn_weight * 1000
        <= THROUGHPUT_TRIPWIRE_GFLOPS_PER_SEC * latency_ms
    )

def verify_validator_attestation_quorum(
    attestations: list[ValidatorAttestation],
    registry: ValidatorRegistry,
    threshold: float | Fraction,
) -> bool:
    """Verify a ValidatorAttestation bundle against an active validator registry."""
    if not attestations:
        return False

    required = calculate_validator_quorum(
        registry.active_validator_count(),
        threshold,
    )

    if len(attestations) < required:
        return False

    validator_ids = [attestation.validator_id for attestation in attestations]

    if not has_distinct_validator_ids(validator_ids):
        return False

    if not all(registry.is_active(validator_id) for validator_id in validator_ids):
        return False

    reference = attestations[0]

    for attestation in attestations:
        if not attestation.quote_verified:
            return False

        if not attestation.event_log_verified:
            return False

        if (
            attestation.task_hash != reference.task_hash
            or attestation.gn_weight != reference.gn_weight
            or attestation.latency_ms != reference.latency_ms
            or attestation.model_hash != reference.model_hash
            or attestation.output_hash != reference.output_hash
            or attestation.decode_policy_hash != reference.decode_policy_hash
            or attestation.tee_type != reference.tee_type
            or attestation.quote_verified != reference.quote_verified
            or attestation.event_log_verified != reference.event_log_verified
            or attestation.hardware_id_hash != reference.hardware_id_hash
        ):
            return False

        if not verify_validator_attestation_signature(
            public_key=attestation.validator_id,
            signature=attestation.signature,
            task_hash=attestation.task_hash,
            gn_weight=attestation.gn_weight,
            latency_ms=attestation.latency_ms,
            model_hash=attestation.model_hash,
            output_hash=attestation.output_hash,
            decode_policy_hash=attestation.decode_policy_hash,
            tee_type=attestation.tee_type,
            quote_verified=attestation.quote_verified,
            event_log_verified=attestation.event_log_verified,
            hardware_id_hash=attestation.hardware_id_hash,
        ):
            return False

    return True


def compute_task_hash(
    agent: bytes,
    nonce: bytes,
    model_hash: bytes,
    payload_hash: bytes,
    commit_hash: bytes,
) -> str:
    """Compute the draft FLOP task hash from its byte components."""
    for name, value in (
        ("agent", agent),
        ("model_hash", model_hash),
        ("payload_hash", payload_hash),
        ("commit_hash", commit_hash),
    ):
        if len(value) != 32:
            raise ValueError(f"{name} must be exactly 32 bytes")

    preimage = (
        agent
        + nonce
        + model_hash
        + payload_hash
        + commit_hash
    )

    return hashlib.blake2b(
        preimage,
        digest_size=32,
    ).hexdigest()


def compute_channel_id_v1(
    genesis_hash: bytes,
    agent: bytes,
    miner: bytes,
    nonce: int,
) -> str:
    """Compute the canonical FLOP compute-channel ID v1."""
    for name, value in (
        ("genesis_hash", genesis_hash),
        ("agent", agent),
        ("miner", miner),
    ):
        if len(value) != 32:
            raise ValueError(f"{name} must be exactly 32 bytes")

    if not isinstance(nonce, int) or isinstance(nonce, bool):
        raise TypeError("nonce must be an integer")
    if nonce < 0 or nonce > 2**64 - 1:
        raise ValueError("nonce must fit in u64")

    preimage = (
        b"FLOP/COMPUTE_CHANNEL/ID"
        + b"\x01"
        + genesis_hash
        + agent
        + miner
        + nonce.to_bytes(8, byteorder="little", signed=False)
    )
    return hashlib.blake2b(preimage, digest_size=32).hexdigest()


def compute_verified_turn_leaf_v0_v1_v2_v3(
    leaf_version: int,
    channel_id: bytes,
    turn_index: int,
    h_in: bytes,
    h_out: bytes,
    g_n: int,
    decode_policy_hash: bytes = b"\x00" * 32,
    h_ids: bytes = b"\x00" * 32,
    toploc_commitment_hash: bytes = b"\x00" * 32,
    miner_recv_ms: int = 0,
    miner_done_ms: int = 0,
    latency_ms: int = 0,
) -> str:
    """Compute the canonical FLOP VerifiedTurn leaf hash for V0..V3.

    NOTE: no domain prefix here. The deployment/session-bound channel_id
    is the leading field, unlike task_hash/channel_id/receipt.

    The version determines exactly one preimage. Fields belonging to a
    newer version must remain zero when computing an older version so a
    caller cannot silently hash a V3-shaped turn as V0/V1/V2.
    """
    if leaf_version not in (0, 1, 2, 3):
        raise ValueError("unsupported leaf_version")

    for name, value in (
        ("channel_id", channel_id),
        ("h_in", h_in),
        ("h_out", h_out),
        ("decode_policy_hash", decode_policy_hash),
        ("h_ids", h_ids),
        ("toploc_commitment_hash", toploc_commitment_hash),
    ):
        if len(value) != 32:
            raise ValueError(f"{name} must be exactly 32 bytes")

    if not isinstance(turn_index, int) or isinstance(turn_index, bool):
        raise TypeError("turn_index must be an integer")
    if not 0 <= turn_index <= 2**32 - 1:
        raise ValueError("turn_index must fit in u32")

    if not isinstance(g_n, int) or isinstance(g_n, bool):
        raise TypeError("g_n must be an integer")
    if not 0 <= g_n <= 2**128 - 1:
        raise ValueError("g_n must fit in u128")

    for name, value in (
        ("miner_recv_ms", miner_recv_ms),
        ("miner_done_ms", miner_done_ms),
        ("latency_ms", latency_ms),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{name} must be an integer")
        if not 0 <= value <= 2**64 - 1:
            raise ValueError(f"{name} must fit in u64")

    zero32 = b"\x00" * 32

    # SCALE enum/version field consistency is fail-closed:
    # V0/V1 have no decode-policy binding.
    if leaf_version in (0, 1) and decode_policy_hash != zero32:
        raise ValueError("LeafFieldsInconsistent: decode_policy_hash")
    # V0/V1/V2 do not carry the V3 token-ID/TOPLOC fields.
    if leaf_version in (0, 1, 2) and (
        h_ids != zero32 or toploc_commitment_hash != zero32
    ):
        raise ValueError("LeafFieldsInconsistent: V3 fields")
    # V0 does not carry timing fields.
    if leaf_version == 0 and any(
        value != 0 for value in (miner_recv_ms, miner_done_ms, latency_ms)
    ):
        raise ValueError("LeafFieldsInconsistent: timing fields")
    # V3 explicitly binds both h_ids and TOPLOC.
    if leaf_version == 3 and (
        decode_policy_hash == zero32
        or h_ids == zero32
        or toploc_commitment_hash == zero32
    ):
        raise ValueError("LeafFieldsInconsistent: V3 bindings")

    preimage = (
        channel_id
        + turn_index.to_bytes(4, byteorder="little", signed=False)
        + h_in
        + h_out
        + g_n.to_bytes(16, byteorder="little", signed=False)
    )

    if leaf_version >= 2:
        preimage += decode_policy_hash

    if leaf_version == 3:
        preimage += h_ids + toploc_commitment_hash

    if leaf_version >= 1:
        preimage += (
            miner_recv_ms.to_bytes(8, byteorder="little", signed=False)
            + miner_done_ms.to_bytes(8, byteorder="little", signed=False)
            + latency_ms.to_bytes(8, byteorder="little", signed=False)
        )

    # NOTE: no domain prefix here; leaf preimage starts directly with channel_id.
    return hashlib.blake2b(preimage, digest_size=32).hexdigest()


def verify_verified_turn_leaf_signature(
    public_key: bytes,
    signature: bytes,
    leaf_hash: bytes,
) -> bool:
    """Verify the sr25519 signature over a 32-byte VerifiedTurn leaf hash.

    Malformed input (wrong type or length) raises ValueError. An invalid
    signature returns False, including a key that is not a valid sr25519 point.
    """
    _h256(public_key, "public_key")
    _sr25519_signature(signature, "signature")
    _h256(leaf_hash, "leaf_hash")
    try:
        return sr25519.verify(signature, leaf_hash, public_key)
    except ValueError:
        # sr25519 raises for a key that is not a Ristretto point or a
        # signature without the schnorrkel marker; both are invalid signatures.
        return False


def compute_merkle_node(left: bytes, right: bytes) -> str:
    """Compute a canonical compute-channel Merkle node.

    NOTE: no domain prefix here. The preimage is exactly left_32 || right_32.
    """
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle node inputs must be exactly 32 bytes")
    # NOTE: no domain prefix; exactly 64 bytes left_32 || right_32.
    return hashlib.blake2b(left + right, digest_size=32).hexdigest()


def compute_merkle_root(leaves: list[bytes]) -> str:
    """Compute the canonical ordered Merkle root for turn leaf hashes."""
    if any(len(leaf) != 32 for leaf in leaves):
        raise ValueError("every Merkle leaf must be exactly 32 bytes")

    if not leaves:
        return (b"\x00" * 32).hex()

    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])

        level = [
            bytes.fromhex(compute_merkle_node(level[i], level[i + 1]))
            for i in range(0, len(level), 2)
        ]

    return level[0].hex()


def verify_merkle_path(
    leaf_hash: bytes,
    turn_index: int,
    merkle_path: list[tuple[bytes, bool]],
    root: bytes,
) -> bool:
    """Verify one ordered Merkle path against the canonical root."""
    if len(leaf_hash) != 32 or len(root) != 32:
        return False
    if not isinstance(turn_index, int) or isinstance(turn_index, bool):
        return False
    if not 0 <= turn_index <= 2**32 - 1:
        return False
    if len(merkle_path) > CHANNEL_MAX_MERKLE_PATH_LEN:
        return False

    current = leaf_hash

    for level, item in enumerate(merkle_path):
        if not isinstance(item, tuple) or len(item) != 2:
            return False

        sibling, sibling_is_left = item

        if len(sibling) != 32 or not isinstance(sibling_is_left, bool):
            return False

        # Canonical path orientation is determined by the turn index bit.
        expected_sibling_is_left = bool((turn_index >> level) & 1)
        if sibling_is_left != expected_sibling_is_left:
            return False

        if sibling_is_left:
            current = bytes.fromhex(compute_merkle_node(sibling, current))
        else:
            current = bytes.fromhex(compute_merkle_node(current, sibling))

    return current == root


def compute_agent_receipt_v1_signable_payload(
    channel_id: bytes,
    final_root: bytes,
    aggregate_gn: int,
    payable: int,
) -> bytes:
    """Build the canonical agent receipt v1 signing payload.

    NOTE: the domain prefix is present here, unlike leaf/Merkle primitives.
    """
    for name, value in (
        ("channel_id", channel_id),
        ("final_root", final_root),
    ):
        if len(value) != 32:
            raise ValueError(f"{name} must be exactly 32 bytes")

    for name, value in (
        ("aggregate_gn", aggregate_gn),
        ("payable", payable),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{name} must be an integer")
        if not 0 <= value <= 2**128 - 1:
            raise ValueError(f"{name} must fit in u128")

    return (
        b"FLOP/COMPUTE_CHANNEL/RECEIPT"
        + b"\x01"
        + channel_id
        + final_root
        + aggregate_gn.to_bytes(16, byteorder="little", signed=False)
        + payable.to_bytes(16, byteorder="little", signed=False)
    )


def verify_agent_receipt_v1(
    public_key: bytes,
    signature: bytes,
    channel_id: bytes,
    final_root: bytes,
    aggregate_gn: int,
    payable: int,
) -> bool:
    """Verify the single agent co-signature over receipt v1.

    Malformed input (wrong type, length or integer range) raises ValueError.
    An invalid signature returns False, including a key that is not a valid
    sr25519 point.
    """
    _h256(public_key, "public_key")
    _sr25519_signature(signature, "signature")
    _h256(channel_id, "channel_id")
    _h256(final_root, "final_root")
    for name, value in (("aggregate_gn", aggregate_gn), ("payable", payable)):
        # Checked here so a wrong type is a ValueError; the payload builder
        # keeps its own TypeError for non-integers.
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{name} must be an integer")

    payload = compute_agent_receipt_v1_signable_payload(
        channel_id=channel_id,
        final_root=final_root,
        aggregate_gn=aggregate_gn,
        payable=payable,
    )
    try:
        return sr25519.verify(signature, payload, public_key)
    except ValueError:
        # Not a Ristretto point / no schnorrkel marker: an invalid signature.
        return False


def turn_ack_message(
    channel_id: bytes,
    turn_index: int,
    leaf_hash: bytes,
    agent_send_ms: int,
    agent_recv_ms: int,
) -> bytes:
    """Build the 84-byte per-turn agent ack message (Appendix F.0, F.3).

    channel_id(32) ‖ turn_index:u32LE ‖ leaf_hash(32) ‖ agent_send_ms:u64LE ‖
    agent_recv_ms:u64LE. NOTE: no domain tag or version byte; the spec keeps
    the shipped preimage as is (Rationale, yellowpaper L1946-1948).

    leaf_hash must be computed by the caller from the turn under its own
    explicit leaf version. Upstream publishes an ack vector for V3 only.
    """
    for name, value in (
        ("turn_index", turn_index),
        ("agent_send_ms", agent_send_ms),
        ("agent_recv_ms", agent_recv_ms),
    ):
        if isinstance(value, bool):
            raise ValueError(f"{name} must be an integer")

    return (
        _h256(channel_id, "channel_id")
        + _u32_le(turn_index, "turn_index")
        + _h256(leaf_hash, "leaf_hash")
        + _u64_le(agent_send_ms, "agent_send_ms")
        + _u64_le(agent_recv_ms, "agent_recv_ms")
    )


def verify_turn_ack(
    agent_public_key: bytes,
    channel_id: bytes,
    turn_index: int,
    leaf_hash: bytes,
    agent_send_ms: int,
    agent_recv_ms: int,
    agent_sig: bytes,
) -> bool:
    """Verify a per-turn agent ack (Appendix F.0, F.3): sr25519 under the
    channel's agent key over turn_ack_message(...).

    Off-chain / SDK verification (F.6: DA fetch/audit/evidence builders,
    miner record_ack); no extrinsic in Appendix G.1 takes an ack. The spec
    names no rejection error, so an invalid signature returns False, including
    a key that is not a valid sr25519 point. Malformed inputs (wrong type,
    length or integer range) raise ValueError.

    leaf_hash must be computed by the caller from the turn under its own
    explicit leaf version. Upstream publishes an ack vector for V3 only.
    """
    _h256(agent_public_key, "agent_public_key")
    if not isinstance(agent_sig, bytes) or len(agent_sig) != 64:
        raise ValueError("agent_sig must be exactly 64 bytes")

    message = turn_ack_message(
        channel_id=channel_id,
        turn_index=turn_index,
        leaf_hash=leaf_hash,
        agent_send_ms=agent_send_ms,
        agent_recv_ms=agent_recv_ms,
    )
    try:
        return sr25519.verify(agent_sig, message, agent_public_key)
    except ValueError:
        # sr25519 raises for a key that is not a Ristretto point or a
        # signature without the schnorrkel marker; both are invalid signatures.
        return False


def compute_task_hash_v1(
    genesis_hash: bytes,
    agent: bytes,
    nonce: int,
    model_hash: bytes,
    payload_hash: bytes,
    commit_hash: bytes,
) -> str:
    """Compute the canonical FLOP/POUI task hash v1."""
    for name, value in (
        ("genesis_hash", genesis_hash),
        ("agent", agent),
        ("model_hash", model_hash),
        ("payload_hash", payload_hash),
        ("commit_hash", commit_hash),
    ):
        if len(value) != 32:
            raise ValueError(f"{name} must be exactly 32 bytes")

    if not isinstance(nonce, int) or isinstance(nonce, bool):
        raise TypeError("nonce must be an integer")
    if nonce < 0 or nonce > 2**64 - 1:
        raise ValueError("nonce must fit in u64")

    preimage = (
        b"FLOP/POUI/TASK"
        + b"\x01"
        + genesis_hash
        + agent
        + nonce.to_bytes(8, byteorder="little", signed=False)
        + model_hash
        + payload_hash
        + commit_hash
    )

    return hashlib.blake2b(
        preimage,
        digest_size=32,
    ).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(payload: dict) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return sha256_bytes(canonical)


def hash_event_record(
    event_id: str,
    proof_id: str,
    event_type: str,
    actor_did: str,
    payload_hash: str,
    canonical: str,
    signature: str,
    created_at: str,
    sequence: int,
) -> str:
    return sha256_json(
        {
            "event_id": event_id,
            "proof_id": proof_id,
            "event_type": event_type,
            "actor_did": actor_did,
            "payload_hash": payload_hash,
            "canonical": canonical,
            "signature": signature,
            "created_at": created_at,
            "sequence": sequence,
        }
    )


def canonical_signed_message(
    room: str,
    nonce: str,
    text: str,
) -> bytes:
    return f"{room}|{nonce}|{text}".encode("utf-8")


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def did_key_to_public_key(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError("Unsupported DID format")

    encoded = did[len("did:key:z"):]
    decoded = base58.b58decode(encoded)

    if not decoded.startswith(ED25519_PUB_MULTICODEC):
        raise ValueError("DID does not contain an Ed25519 public key")

    public_key_bytes = decoded[len(ED25519_PUB_MULTICODEC):]

    if len(public_key_bytes) != 32:
        raise ValueError("Invalid Ed25519 public key length")

    # Every signature check (API and verifier) resolves the key here, so the
    # verifier refuses the same keys as the API's 422 pre-check: bytes that do
    # not decode as a point, and small-order points, under which signatures
    # can verify without any private key.
    if not is_ed25519_point_encoding(public_key_bytes):
        raise ValueError("Ed25519 public key is not a valid point encoding")
    if public_key_bytes in SMALL_ORDER_ED25519_KEYS:
        raise ValueError("Ed25519 public key has small order")

    return Ed25519PublicKey.from_public_bytes(public_key_bytes)


# RFC 8032 Ed25519 constants for point decoding (§5.1.3).
_ED25519_P = 2**255 - 19
_ED25519_D = (-121665 * pow(121666, -1, _ED25519_P)) % _ED25519_P
_ED25519_SQRT_M1 = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)

# The 8 points of order dividing 8 (the torsion subgroup), as the only
# encodings of them that pass is_ed25519_point_encoding. A key among them
# admits forged signatures: with the identity point, R = identity and S = 0
# verify for every message, in cryptography/OpenSSL as well.
SMALL_ORDER_ED25519_KEYS = frozenset(
    bytes.fromhex(key)
    for key in (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    )
)

# 64 bytes in base64url: 86 characters, optionally padded with "==".
_ED25519_SIGNATURE_BASE64URL = re.compile(r"[A-Za-z0-9_-]{86}(?:==)?")


def is_ed25519_point_encoding(public_key: bytes) -> bool:
    """True if `public_key` decodes as an Ed25519 point (RFC 8032 §5.1.3).

    cryptography's Ed25519PublicKey.from_public_bytes accepts any 32 bytes, so
    a key that is not a point would only fail later, as a bad signature.
    Small-order points are valid encodings and decode.
    """
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        return False
    p = _ED25519_P
    y = int.from_bytes(public_key, "little") & ((1 << 255) - 1)
    x_sign = public_key[31] >> 7
    if y >= p:
        return False
    u = (y * y - 1) % p
    v = (_ED25519_D * y * y + 1) % p
    x = (u * pow(v, 3, p) * pow(u * pow(v, 7, p), (p - 5) // 8, p)) % p
    vx2 = (v * x * x) % p
    if vx2 == (-u) % p and vx2 != u:
        x = (x * _ED25519_SQRT_M1) % p
    elif vx2 != u:
        return False
    return not (x == 0 and x_sign == 1)


def decode_ed25519_signature(signature: str) -> bytes:
    """The 64 bytes of a base64url Ed25519 signature (unpadded or "=="-padded,
    canonical trailing bits). Raises ValueError for anything else."""
    if not isinstance(signature, str) or not _ED25519_SIGNATURE_BASE64URL.fullmatch(signature):
        raise ValueError("signature must be 64 bytes of base64url")
    raw = base64.urlsafe_b64decode(signature[:86] + "==")
    if len(raw) != 64 or encode_base64url(raw) != signature[:86]:
        raise ValueError("signature must be 64 bytes of canonical base64url")
    return raw


def ed25519_public_key_from_did(did: str) -> bytes:
    """The 32-byte Ed25519 key of a did:key, checked to decode as a point of
    large order. Raises ValueError for any other DID."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ValueError("Unsupported DID format")
    decoded = base58.b58decode(did[len("did:key:z"):])
    if not decoded.startswith(ED25519_PUB_MULTICODEC):
        raise ValueError("DID does not contain an Ed25519 public key")
    public_key = decoded[len(ED25519_PUB_MULTICODEC):]
    if len(public_key) != 32:
        raise ValueError("Invalid Ed25519 public key length")
    if not is_ed25519_point_encoding(public_key):
        raise ValueError("Ed25519 public key is not a valid point encoding")
    if public_key in SMALL_ORDER_ED25519_KEYS:
        raise ValueError("Ed25519 public key has small order")
    return public_key


def generate_test_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_test_did(public_key: Ed25519PublicKey) -> str:
    public_key_bytes = public_key.public_bytes_raw()

    multicodec_key = ED25519_PUB_MULTICODEC + public_key_bytes

    return "did:key:z" + base58.b58encode(multicodec_key).decode("ascii")


def sign_message(
    private_key: Ed25519PrivateKey,
    message: bytes,
) -> str:
    signature = private_key.sign(message)
    return encode_base64url(signature)


def verify_signature(
    public_key: Ed25519PublicKey,
    message: bytes,
    signature: str,
) -> bool:
    # Strict: only the canonical base64url text of 64 bytes is a signature.
    # A lax decoder would drop non-alphabet characters and ignore the padding
    # bits, so several texts would verify as the same signature.
    try:
        public_key.verify(
            decode_ed25519_signature(signature),
            message,
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_did_signature(
    did: str,
    message: bytes,
    signature: str,
) -> bool:
    public_key = did_key_to_public_key(did)

    return verify_signature(
        public_key,
        message,
        signature,
    )


def verify_canonical_signature(
    did: str,
    canonical: str,
    signature: str,
) -> bool:
    return verify_did_signature(
        did=did,
        message=canonical.encode("utf-8"),
        signature=signature,
    )


# proof_id as issued by POST /proofs: "proof_" + uuid4().hex. The dashboard
# proxy uses the same pattern (dashboard/src/lib/proxy-policy.ts); a test
# checks that the two stay identical.
PROOF_ID_PATTERN = re.compile(r"^proof_[0-9a-f]{32}$")


def is_proof_id(value: str) -> bool:
    # fullmatch: with match, "$" also accepts a trailing newline (D-R9).
    return isinstance(value, str) and PROOF_ID_PATTERN.fullmatch(value) is not None


def verify_floop_signature(
    did: str,
    nonce: str,
    text: str,
    canonical: str,
    signature: str,
) -> bool:
    """v1/v2 request signature (room|nonce|text). POST /proofs accepts only
    version-3 requests (app/canonical.py, D-R4); this is the legacy format."""
    # D-R11: a tagged (version-3) message is never a v1/v2 request.
    # Same value as app/canonical.py TAG_PREFIX (that module imports this one).
    if canonical.startswith("FLOP/"):
        return False

    expected_parts = canonical.split("|", 2)

    if len(expected_parts) != 3:
        return False

    room, canonical_nonce, canonical_text = expected_parts

    if not room:
        return False

    # An event canonical is proof_id|type|payload_hash, which also splits
    # into room|nonce|text. Refuse it as a request so an event signature
    # cannot create a proof (docs/design/event-replay.md §1.2). Minimal fix;
    # domain-tagged messages are the planned replacement.
    if is_proof_id(room):
        return False

    if canonical_nonce != nonce:
        return False

    if canonical_text != text:
        return False

    message = canonical_signed_message(
        room,
        nonce,
        text,
    )

    return verify_did_signature(
        did,
        message,
        signature,
    )

def encode_validator_attestation_signable_payload(
    task_hash: bytes,
    gn_weight: int,
    latency_ms: int,
    model_hash: bytes,
    output_hash: bytes,
    decode_policy_hash: bytes,
    tee_type: int,
    quote_verified: bool,
    event_log_verified: bool,
    hardware_id_hash: bytes,
) -> bytes:
    """Encode the 10-field ValidatorAttestation signable subset using SCALE."""
    hash_fields = (
        ("task_hash", task_hash),
        ("model_hash", model_hash),
        ("output_hash", output_hash),
        ("decode_policy_hash", decode_policy_hash),
        ("hardware_id_hash", hardware_id_hash),
    )

    for name, value in hash_fields:
        if len(value) != 32:
            raise ValueError(f"{name} must be exactly 32 bytes")

    if not isinstance(gn_weight, int) or not 0 <= gn_weight <= 2**64 - 1:
        raise ValueError("gn_weight must be a u64")
    if not isinstance(latency_ms, int) or not 0 <= latency_ms <= 2**64 - 1:
        raise ValueError("latency_ms must be a u64")
    if not isinstance(tee_type, int) or not 0 <= tee_type <= 255:
        raise ValueError("tee_type must be a u8")
    if not isinstance(quote_verified, bool):
        raise ValueError("quote_verified must be a bool")
    if not isinstance(event_log_verified, bool):
        raise ValueError("event_log_verified must be a bool")

    return (
        task_hash
        + gn_weight.to_bytes(8, "little")
        + latency_ms.to_bytes(8, "little")
        + model_hash
        + output_hash
        + decode_policy_hash
        + tee_type.to_bytes(1, "little")
        + bytes([quote_verified])
        + bytes([event_log_verified])
        + hardware_id_hash
    )

def sign_validator_attestation(
    keypair: tuple[bytes, bytes],
    task_hash: bytes,
    gn_weight: int,
    latency_ms: int,
    model_hash: bytes,
    output_hash: bytes,
    decode_policy_hash: bytes,
    tee_type: int,
    quote_verified: bool,
    event_log_verified: bool,
    hardware_id_hash: bytes,
) -> bytes:
    payload = encode_validator_attestation_signable_payload(
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
    return sr25519.sign(keypair, payload)


def verify_validator_attestation_signature(
    public_key: bytes,
    signature: bytes,
    task_hash: bytes,
    gn_weight: int,
    latency_ms: int,
    model_hash: bytes,
    output_hash: bytes,
    decode_policy_hash: bytes,
    tee_type: int,
    quote_verified: bool,
    event_log_verified: bool,
    hardware_id_hash: bytes,
) -> bool:
    payload = encode_validator_attestation_signable_payload(
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
    _h256(public_key, "public_key")
    _sr25519_signature(signature, "signature")

    try:
        return sr25519.verify(signature, payload, public_key)
    except ValueError:
        # Not a Ristretto point / no schnorrkel marker: an invalid signature.
        return False


def compute_report_data(
    task_hash: bytes,
    gn_weight: bytes,
    latency_ms: bytes,
    model_hash: bytes,
    output_hash: bytes,
    decode_policy_hash: bytes,
    tee_type: bytes,
) -> str:
    """Compute the FLOP report_data SHA-256 commitment.

    Numeric/protocol fields are accepted in their caller-provided
    canonical byte representation. This avoids inventing an encoding
    rule where the current specification does not explicitly define one.
    """
    hash_fields = (
        ("task_hash", task_hash),
        ("model_hash", model_hash),
        ("output_hash", output_hash),
        ("decode_policy_hash", decode_policy_hash),
    )

    for name, value in hash_fields:
        if len(value) != 32:
            raise ValueError(f"{name} must be exactly 32 bytes")

    preimage = (
        task_hash
        + gn_weight
        + latency_ms
        + model_hash
        + output_hash
        + decode_policy_hash
        + tee_type
    )

    digest = hashlib.sha256(preimage).digest()
    return (digest + b"\x00" * 32).hex()


def verify_and_accept_validator_attestation_quorum(
    attestations: list[ValidatorAttestation],
    registry: ValidatorRegistry,
    threshold: float | Fraction,
    processed_tasks: ProcessedTasks,
) -> bool:
    """Verify an attestation quorum and consume its task hash exactly once."""
    if not attestations:
        return False

    task_hash = attestations[0].task_hash

    if processed_tasks.is_processed(task_hash):
        return False

    if not verify_validator_attestation_quorum(
        attestations=attestations,
        registry=registry,
        threshold=threshold,
    ):
        return False

    return processed_tasks.mark_processed(task_hash)


def verify_validator_attestation_report_data(
    attestation: ValidatorAttestation,
    report_data: str,
) -> bool:
    """Verify that report_data matches the attestation's committed claims."""
    if not isinstance(report_data, str):
        return False

    try:
        expected_report_data = compute_report_data(
            task_hash=attestation.task_hash,
            gn_weight=attestation.gn_weight.to_bytes(8, "little"),
            latency_ms=attestation.latency_ms.to_bytes(8, "little"),
            model_hash=attestation.model_hash,
            output_hash=attestation.output_hash,
            decode_policy_hash=attestation.decode_policy_hash,
            tee_type=attestation.tee_type.to_bytes(1, "little"),
        )
    except (ValueError, OverflowError):
        return False

    return report_data == expected_report_data


def verify_and_accept_validator_attestation(
    attestation: ValidatorAttestation,
    report_data: str,
    registry: ValidatorRegistry,
    threshold: float | Fraction,
    processed_tasks: ProcessedTasks,
) -> bool:
    """Verify one validator attestation and accept its task exactly once."""
    if processed_tasks.is_processed(attestation.task_hash):
        return False

    if not attestation.quote_verified:
        return False

    if not attestation.event_log_verified:
        return False

    if not verify_validator_attestation_report_data(
        attestation=attestation,
        report_data=report_data,
    ):
        return False

    if not verify_validator_attestation_quorum(
        attestations=[attestation],
        registry=registry,
        threshold=threshold,
    ):
        return False

    return processed_tasks.mark_processed(attestation.task_hash)


def encode_validator_attestation_scale(
    attestation: ValidatorAttestation,
) -> bytes:
    """Encode the complete ValidatorAttestation fixed-field SCALE payload."""
    signed_payload = encode_validator_attestation_signable_payload(
        task_hash=attestation.task_hash,
        gn_weight=attestation.gn_weight,
        latency_ms=attestation.latency_ms,
        model_hash=attestation.model_hash,
        output_hash=attestation.output_hash,
        decode_policy_hash=attestation.decode_policy_hash,
        tee_type=attestation.tee_type,
        quote_verified=attestation.quote_verified,
        event_log_verified=attestation.event_log_verified,
        hardware_id_hash=attestation.hardware_id_hash,
    )

    if len(attestation.validator_id) != 32:
        raise ValueError("validator_id must be exactly 32 bytes")

    if len(attestation.signature) != 64:
        raise ValueError("signature must be exactly 64 bytes")

    return signed_payload + attestation.validator_id + attestation.signature


def verify_and_accept_validator_attestation_bundle(
    attestations: list[ValidatorAttestation],
    report_data: str,
    registry: ValidatorRegistry,
    threshold: float | Fraction,
    processed_tasks: ProcessedTasks,
) -> bool:
    """Verify and accept a validator attestation bundle exactly once.

    The bundle must satisfy quorum, validator/signature checks, and
    report_data binding before its task hash is marked as processed.
    """
    if not attestations:
        return False

    task_hash = attestations[0].task_hash

    if processed_tasks.is_processed(task_hash):
        return False

    if not verify_validator_attestation_quorum(
        attestations=attestations,
        registry=registry,
        threshold=threshold,
    ):
        return False

    if not verify_validator_attestation_report_data(
        attestation=attestations[0],
        report_data=report_data,
    ):
        return False

    return processed_tasks.mark_processed(task_hash)


def validator_attestation_matches_result(
    attestation: ValidatorAttestation,
    result: dict,
) -> bool:
    """Check that validator attestation claims match result metadata."""
    if not isinstance(result, dict):
        return False

    hash_fields = (
        "task_hash",
        "model_hash",
        "output_hash",
        "decode_policy_hash",
    )

    for field in hash_fields:
        value = result.get(field)

        if not isinstance(value, str):
            return False

        try:
            if bytes.fromhex(value) != getattr(attestation, field):
                return False
        except ValueError:
            return False

    numeric_fields = (
        "gn_weight",
        "latency_ms",
        "tee_type",
    )

    for field in numeric_fields:
        value = result.get(field)
        # The result is a free-form dict; True == 1 in Python, so without
        # this a boolean would bind to an attestation that signed 1.
        if isinstance(value, bool):
            return False
        if value != getattr(attestation, field):
            return False

    return True



def verify_validator_attestation_bundle_for_result(
    attestations: list[ValidatorAttestation],
    result: dict,
    report_data: str,
    registry: ValidatorRegistry,
    threshold: float | Fraction,
) -> bool:
    """Verify result binding, report_data and validator quorum without mutation."""
    if not attestations:
        return False

    # validator_attestation_matches_result returns False for any malformed
    # result and never raises (locked by
    # test_result_binding_never_raises_on_json_shaped_or_non_dict_results).
    for attestation in attestations:
        if not validator_attestation_matches_result(
            attestation=attestation,
            result=result,
        ):
            return False

    if not verify_validator_attestation_report_data(
        attestation=attestations[0],
        report_data=report_data,
    ):
        return False

    if not verify_validator_attestation_quorum(
        attestations=attestations,
        registry=registry,
        threshold=threshold,
    ):
        return False

    if not validate_gn_latency_throughput_tripwire(
        result["gn_weight"],
        result["latency_ms"],
    ):
        return False

    return True


def verify_and_accept_validator_attestation_bundle_for_result(
    attestations: list[ValidatorAttestation],
    result: dict,
    report_data: str,
    registry: ValidatorRegistry,
    threshold: float | Fraction,
    processed_tasks: ProcessedTasks,
) -> bool:
    """Atomically verify result binding, report_data, quorum and replay.

    No task is marked as processed until every verification step succeeds.
    Any result-binding exception fails closed.
    """
    if not attestations:
        return False

    # 1. Bind every validator attestation to the externally supplied result.
    # The binding helper returns False for any malformed result and never
    # raises (locked by a fuzz test), so no exception handling is needed.
    for attestation in attestations:
        if not validator_attestation_matches_result(
            attestation=attestation,
            result=result,
        ):
            return False

    # 2. Bind the attestation claims to TEE report_data.
    if not verify_validator_attestation_report_data(
        attestation=attestations[0],
        report_data=report_data,
    ):
        return False

    # 3. Verify the complete validator quorum and signatures.
    if not verify_validator_attestation_quorum(
        attestations=attestations,
        registry=registry,
        threshold=threshold,
    ):
        return False

    # 4. Reject implausible G_n/latency claims before replay consumption.
    if not validate_gn_latency_throughput_tripwire(
        result["gn_weight"],
        result["latency_ms"],
    ):
        return False

    # 5. Replay check happens only after all verification has succeeded.
    task_hash = attestations[0].task_hash

    if processed_tasks.is_processed(task_hash):
        return False

    # 6. The only state mutation is the final acceptance operation.
    return processed_tasks.mark_processed(task_hash)
