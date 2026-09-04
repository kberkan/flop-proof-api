import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .crypto import hash_event_record, sha256_json
from .models import ProofEvent


def create_event(
    db: Session,
    proof_id: str,
    event_type: str,
    actor_did: str,
    payload: dict,
    canonical: str | None = None,
    signature: str | None = None,
) -> ProofEvent:
    payload_hash = sha256_json(payload)

    if canonical is None:
        canonical = f"{proof_id}|{event_type}|{payload_hash}"

    last_event = db.scalar(
        select(ProofEvent)
        .where(ProofEvent.proof_id == proof_id)
        .order_by(ProofEvent.sequence.desc())
    )

    last_sequence = last_event.sequence if last_event else None

    sequence = (last_sequence or 0) + 1

    previous_event_hash = None

    if last_event is not None:
        previous_event_hash = hash_event_record(
            event_id=last_event.event_id,
            proof_id=last_event.proof_id,
            event_type=last_event.event_type,
            actor_did=last_event.actor_did,
            payload_hash=last_event.payload_hash,
            canonical=last_event.canonical,
            signature=last_event.signature,
            created_at=last_event.created_at.isoformat(),
            sequence=last_event.sequence,
        )

    event = ProofEvent(
        event_id=f"evt_{uuid.uuid4().hex}",
        proof_id=proof_id,
        event_type=event_type,
        actor_did=actor_did,
        payload_hash=payload_hash,
        payload_json=json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
        canonical=canonical,
        signature=signature or "",
        created_at=datetime.now(timezone.utc),
        sequence=sequence,
        previous_event_hash=previous_event_hash,
    )

    db.add(event)
    return event
