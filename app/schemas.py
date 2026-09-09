from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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
    created_at: datetime
    signature: SignatureSchema


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


class ValidatorAttestationSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_hash: str = Field(min_length=64, max_length=64)
    gn_weight: int = Field(ge=0, le=2**64 - 1)
    latency_ms: int = Field(ge=0, le=2**64 - 1)
    model_hash: str = Field(min_length=64, max_length=64)
    output_hash: str = Field(min_length=64, max_length=64)
    decode_policy_hash: str = Field(min_length=64, max_length=64)
    tee_type: int = Field(ge=0, le=255)
    quote_verified: bool
    event_log_verified: bool
    hardware_id_hash: str = Field(min_length=64, max_length=64)
    validator_id: str = Field(min_length=64, max_length=64)
    signature: str = Field(min_length=86, max_length=88)


class ValidatorAttestationAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: dict[str, Any]
    report_data: str = Field(min_length=64, max_length=64)
    attestations: list[ValidatorAttestationSchema] = Field(min_length=1)


class ProofValidatorAttestationAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_data: str = Field(min_length=64, max_length=64)
    attestations: list[ValidatorAttestationSchema] = Field(default_factory=list)
