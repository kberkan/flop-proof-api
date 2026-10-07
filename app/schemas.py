import re
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


_ISO_8601_DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")


class SignatureSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(min_length=1)
    sig: str = Field(min_length=1)
    canonical: str = Field(min_length=1)


class RequestSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1)
    from_did: str = Field(min_length=1)
    text: str = Field(min_length=1)
    # A timezone-aware ISO 8601 date-time string only: the validator below
    # rejects numbers, numeric strings (Unix timestamps) and bare dates, and
    # AwareDatetime rejects naive values. (strict=True is not used: after a
    # "before" validator it would reject every string.) Stored in the
    # request.created payload, so its form is part of the hash.
    created_at: AwareDatetime
    signature: SignatureSchema

    @field_validator("created_at", mode="before")
    @classmethod
    def created_at_is_iso_8601(cls, value: Any) -> Any:
        # Strict datetime parsing still reads a numeric string ("1759708800")
        # as a Unix timestamp; require the ISO 8601 date-time shape first.
        if not isinstance(value, str) or not _ISO_8601_DATE_TIME.match(value):
            raise ValueError("created_at must be an ISO 8601 date-time with a timezone")
        return value


class ProofCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request: RequestSchema


class EventSignatureSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(min_length=1)
    sig: str = Field(min_length=1)
    canonical: str = Field(min_length=1)


class EventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1)
    actor_did: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    signature: EventSignatureSchema


class StarkBatchSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proofs: list[dict[str, Any]] = Field(default_factory=list)
    # strict=True: the G_n claim stored with the task_hash for later STARK
    # verification; only a JSON integer is accepted (lax mode would turn
    # true, "5" or 5.0 into an integer).
    gn_weight: int = Field(strict=True, ge=0, le=2**64 - 1)
    task_hash: str = Field(min_length=64, max_length=64)
    latency_ms: int = Field(strict=True, ge=0, le=2**64 - 1)
    model_hash: str = Field(min_length=64, max_length=64)
    output_hash: str = Field(min_length=64, max_length=64)

    @field_validator(
        "task_hash",
        "model_hash",
        "output_hash",
    )
    @classmethod
    def validate_hash_hex(cls, value: str) -> str:
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("hash must be valid hexadecimal") from exc

        if len(value) != 64:
            raise ValueError("hash must represent exactly 32 bytes")

        return value.lower()


class ValidatorAttestationSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_hash: str = Field(min_length=64, max_length=64)
    # strict=True: these are signed integers, so only a JSON integer is
    # accepted; lax mode would turn true, "1", "1.0" or 1.0 into 1.
    gn_weight: int = Field(strict=True, ge=0, le=2**64 - 1)
    latency_ms: int = Field(strict=True, ge=0, le=2**64 - 1)
    model_hash: str = Field(min_length=64, max_length=64)
    output_hash: str = Field(min_length=64, max_length=64)
    decode_policy_hash: str = Field(min_length=64, max_length=64)
    tee_type: int = Field(strict=True, ge=0, le=255)
    # strict=True: signed bits of the attestation; only JSON true/false is
    # accepted (lax mode would turn 1, "true", "yes" or "on" into True).
    quote_verified: bool = Field(strict=True)
    event_log_verified: bool = Field(strict=True)
    hardware_id_hash: str = Field(min_length=64, max_length=64)
    validator_id: str = Field(min_length=64, max_length=64)
    signature: str = Field(min_length=86, max_length=88)


class ValidatorAttestationAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: dict[str, Any]
    report_data: str = Field(min_length=128, max_length=128)
    attestations: list[ValidatorAttestationSchema] = Field(min_length=1)


class ProofValidatorAttestationAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_data: str = Field(min_length=128, max_length=128)
    attestations: list[ValidatorAttestationSchema] = Field(default_factory=list)
