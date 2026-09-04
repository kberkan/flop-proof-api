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
