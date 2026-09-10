from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class Proof(Base):
    __tablename__ = "proofs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    proof_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    request_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    version: Mapped[str] = mapped_column(String(10), default="1")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime)
    updated_at: Mapped[datetime] = mapped_column(DateTime)


class ProofEvent(Base):
    __tablename__ = "proof_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    proof_id: Mapped[str] = mapped_column(String(100), index=True)
    event_type: Mapped[str] = mapped_column(String(100))
    actor_did: Mapped[str] = mapped_column(String(500))
    payload_hash: Mapped[str] = mapped_column(String(128))
    payload_json: Mapped[str] = mapped_column(Text)
    canonical: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    sequence: Mapped[int] = mapped_column(Integer)
    previous_event_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    nonce: Mapped[str] = mapped_column(String(255), index=True, default="")


class PendingVerification(Base):
    __tablename__ = "pending_verifications"

    task_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    proofs_json: Mapped[str] = mapped_column(Text, nullable=False)
    gn_weight: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    model_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    output_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class ProcessedTask(Base):
    __tablename__ = "processed_tasks"

    task_hash: Mapped[bytes] = mapped_column(String(64), primary_key=True)
    processed_at: Mapped[datetime] = mapped_column(DateTime)
