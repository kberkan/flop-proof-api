import base64
import hashlib
from dataclasses import dataclass
from fractions import Fraction

import json

import base58
import sr25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ED25519_PUB_MULTICODEC = bytes([0xED, 0x01])


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


def decode_base64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


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

    return Ed25519PublicKey.from_public_bytes(public_key_bytes)


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
    try:
        public_key.verify(
            decode_base64url(signature),
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


def verify_floop_signature(
    did: str,
    nonce: str,
    text: str,
    canonical: str,
    signature: str,
) -> bool:
    expected_parts = canonical.split("|", 2)

    if len(expected_parts) != 3:
        return False

    room, canonical_nonce, canonical_text = expected_parts

    if not room:
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

    try:
        return sr25519.verify(signature, payload, public_key)
    except Exception:
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

    return hashlib.sha256(preimage).hexdigest()
