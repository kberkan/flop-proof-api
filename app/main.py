import json
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .crypto import (
    hash_event_record,
    sha256_bytes,
    sha256_json,
    verify_canonical_signature,
    verify_floop_signature,
)
from .database import Base, engine, get_db
from .events import create_event
from .models import Proof, ProofEvent
from .schemas import EventCreate, ProofCreate

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="FLOP Proof API",
    version="1.0.0",
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "flop-proof-api",
    }



@app.get("/proofs")
def list_proofs(
    limit: int = 20,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    """List recent proofs for the operations dashboard."""
    if limit < 1 or limit > 100:
        raise HTTPException(400, "limit must be between 1 and 100")

    query = select(Proof).order_by(Proof.created_at.desc()).limit(limit)

    if status is not None:
        allowed_statuses = {"pending", "active", "completed", "failed"}
        if status not in allowed_statuses:
            raise HTTPException(400, "Invalid proof status")
        query = (
            select(Proof)
            .where(Proof.status == status)
            .order_by(Proof.created_at.desc())
            .limit(limit)
        )

    proofs = db.execute(query).scalars().all()

    proof_ids = [proof.proof_id for proof in proofs]

    event_counts = {}
    if proof_ids:
        event_rows = db.execute(
            select(ProofEvent.proof_id, func.count(ProofEvent.id))
            .where(ProofEvent.proof_id.in_(proof_ids))
            .group_by(ProofEvent.proof_id)
        ).all()
        event_counts = {
            proof_id: count
            for proof_id, count in event_rows
        }

    items = []
    for proof in proofs:
        items.append(
            {
                "proof_id": proof.proof_id,
                "request_id": proof.request_id,
                "version": proof.version,
                "status": proof.status,
                "created_at": proof.created_at,
                "updated_at": proof.updated_at,
                "events": event_counts.get(proof.proof_id, 0),
            }
        )

    total = db.execute(select(func.count(Proof.id))).scalar_one()

    status_rows = db.execute(
        select(Proof.status, func.count(Proof.id))
        .group_by(Proof.status)
    ).all()

    stats = {
        "total": total,
        "pending": 0,
        "active": 0,
        "completed": 0,
        "failed": 0,
    }

    for proof_status, count in status_rows:
        if proof_status in stats:
            stats[proof_status] = count

    return {
        "items": items,
        "count": len(items),
        "total": total,
        "stats": stats,
    }

@app.get("/actors")
def list_actors(
    db: Session = Depends(get_db),
):
    """List actor identities and their proof activity."""
    rows = db.execute(
        select(ProofEvent.actor_did, ProofEvent.proof_id, ProofEvent.event_type)
        .order_by(ProofEvent.created_at.desc())
    ).all()

    actors = {}

    for actor_did, proof_id, event_type in rows:
        if actor_did not in actors:
            actors[actor_did] = {
                "did": actor_did,
                "proof_ids": set(),
                "active": 0,
                "completed": 0,
                "failed": 0,
            }

        actor = actors[actor_did]
        actor["proof_ids"].add(proof_id)

    for actor in actors.values():
        proof_ids = actor["proof_ids"]

        statuses = db.execute(
            select(Proof.status).where(Proof.proof_id.in_(proof_ids))
        ).scalars().all()

        actor["active"] = statuses.count("active")
        actor["completed"] = statuses.count("completed")
        actor["failed"] = statuses.count("failed")

    items = []
    for actor in actors.values():
        items.append(
            {
                "did": actor["did"],
                "proofs": len(actor["proof_ids"]),
                "active": actor["active"],
                "completed": actor["completed"],
                "failed": actor["failed"],
            }
        )

    items.sort(key=lambda item: item["proofs"], reverse=True)

    return {
        "items": items,
        "count": len(items),
    }


@app.post("/proofs", status_code=201)
def create_proof(
    request: ProofCreate,
    db: Session = Depends(get_db),
):
    signed_request = request.request

    try:
        valid = verify_floop_signature(
            did=signed_request.from_did,
            nonce=signed_request.signature.nonce,
            text=signed_request.text,
            canonical=signed_request.signature.canonical,
            signature=signed_request.signature.sig,
        )
    except ValueError:
        valid = False

    if not valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid request signature",
        )

    existing_proof = db.scalar(
        select(Proof).where(
            Proof.request_id == signed_request.request_id
        )
    )

    if existing_proof is not None:
        existing_event = db.scalar(
            select(ProofEvent).where(
                ProofEvent.proof_id == existing_proof.proof_id,
                ProofEvent.event_type == "request.created",
            )
        )

        if (
            existing_event is not None
            and existing_event.actor_did == signed_request.from_did
        ):
            incoming_payload = signed_request.model_dump(mode="json")
            incoming_payload_hash = sha256_json(incoming_payload)

            if existing_event.payload_hash == incoming_payload_hash:
                return {
                    "proof_id": existing_proof.proof_id,
                    "request_id": existing_proof.request_id,
                    "version": existing_proof.version,
                    "status": existing_proof.status,
                    "created_at": existing_proof.created_at,
                }

            raise HTTPException(
                status_code=409,
                detail="request_id already belongs to a different request",
            )

        raise HTTPException(
            status_code=409,
            detail="request_id already belongs to another actor",
        )

    proof_id = f"proof_{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)

    proof = Proof(
        proof_id=proof_id,
        request_id=signed_request.request_id,
        version="1",
        status="pending",
        created_at=now,
        updated_at=now,
    )

    db.add(proof)

    request_payload = signed_request.model_dump(mode="json")

    create_event(
        db=db,
        proof_id=proof_id,
        event_type="request.created",
        actor_did=signed_request.from_did,
        payload=request_payload,
        canonical=signed_request.signature.canonical,
        signature=signed_request.signature.sig,
    )

    try:
        db.commit()
    except IntegrityError:
        db.rollback()

        raced_proof = db.scalar(
            select(Proof).where(
                Proof.request_id == signed_request.request_id
            )
        )

        if raced_proof is None:
            raise

        raced_event = db.scalar(
            select(ProofEvent).where(
                ProofEvent.proof_id == raced_proof.proof_id,
                ProofEvent.event_type == "request.created",
            )
        )

        incoming_payload_hash = sha256_json(
            signed_request.model_dump(mode="json")
        )

        if raced_event is not None:
            if raced_event.actor_did != signed_request.from_did:
                raise HTTPException(
                    status_code=409,
                    detail="request_id already belongs to another actor",
                )

            if raced_event.payload_hash != incoming_payload_hash:
                raise HTTPException(
                    status_code=409,
                    detail="request_id already belongs to a different request",
                )

            return {
                "proof_id": raced_proof.proof_id,
                "request_id": raced_proof.request_id,
                "version": raced_proof.version,
                "status": raced_proof.status,
                "created_at": raced_proof.created_at,
            }

        raise

    return {
        "proof_id": proof_id,
        "request_id": proof.request_id,
        "version": proof.version,
        "status": proof.status,
        "created_at": proof.created_at,
    }


@app.post("/proofs/{proof_id}/events", status_code=201)
def append_event(
    proof_id: str,
    event: EventCreate,
    db: Session = Depends(get_db),
):
    proof = db.scalar(
        select(Proof).where(Proof.proof_id == proof_id)
    )

    if proof is None:
        raise HTTPException(
            status_code=404,
            detail="Proof not found",
        )

    if proof.status in {"completed", "failed"}:
        raise HTTPException(
            status_code=409,
            detail=f"Proof is already {proof.status}",
        )

    payload_hash = sha256_json(event.payload)

    expected_canonical = (
        f"{proof_id}|{event.type}|{payload_hash}"
    )

    if event.signature.canonical != expected_canonical:
        raise HTTPException(
            status_code=401,
            detail="Event canonical message mismatch",
        )

    try:
        valid = verify_canonical_signature(
            did=event.actor_did,
            canonical=event.signature.canonical,
            signature=event.signature.sig,
        )
    except ValueError:
        valid = False

    if not valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid event signature",
        )

    created = create_event(
        db=db,
        proof_id=proof_id,
        event_type=event.type,
        actor_did=event.actor_did,
        payload=event.payload,
        canonical=event.signature.canonical,
        signature=event.signature.sig,
    )

    if proof.status == "pending":
        proof.status = "active"

    if event.type == "proof.completed":
        proof.status = "completed"
    elif event.type == "proof.failed":
        proof.status = "failed"

    proof.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(created)

    return {
        "event_id": created.event_id,
        "proof_id": created.proof_id,
        "event_type": created.event_type,
        "actor_did": created.actor_did,
        "payload_hash": created.payload_hash,
        "created_at": created.created_at,
        "sequence": created.sequence,
    }


@app.get("/proofs/{proof_id}")
def get_proof(
    proof_id: str,
    db: Session = Depends(get_db),
):
    proof = db.scalar(
        select(Proof).where(Proof.proof_id == proof_id)
    )

    if proof is None:
        raise HTTPException(
            status_code=404,
            detail="Proof not found",
        )

    events = db.scalars(
        select(ProofEvent)
        .where(ProofEvent.proof_id == proof_id)
        .order_by(ProofEvent.sequence)
    ).all()

    return {
        "proof_id": proof.proof_id,
        "request_id": proof.request_id,
        "version": proof.version,
        "status": proof.status,
        "created_at": proof.created_at,
        "updated_at": proof.updated_at,
        "events": [
            {
                "event_id": event.event_id,
                "type": event.event_type,
                "actor_did": event.actor_did,
                "payload_hash": event.payload_hash,
                "payload": json.loads(event.payload_json),
                "canonical": event.canonical,
                "signature": event.signature,
                "created_at": event.created_at,
                "sequence": event.sequence,
                "previous_event_hash": event.previous_event_hash,
            }
            for event in events
        ],
    }


@app.get("/proofs/{proof_id}/verify")
def verify_proof(
    proof_id: str,
    db: Session = Depends(get_db),
):
    from .verification_core import verify_proof_events

    proof = db.scalar(
        select(Proof).where(Proof.proof_id == proof_id)
    )

    if proof is None:
        raise HTTPException(
            status_code=404,
            detail="Proof not found",
        )

    db_events = db.scalars(
        select(ProofEvent)
        .where(ProofEvent.proof_id == proof_id)
        .order_by(ProofEvent.sequence)
    ).all()

    events = [
        {
            "event_id": event.event_id,
            "type": event.event_type,
            "actor_did": event.actor_did,
            "payload": json.loads(event.payload_json),
            "payload_hash": event.payload_hash,
            "canonical": event.canonical,
            "signature": event.signature,
            "created_at": event.created_at.isoformat(),
            "sequence": event.sequence,
            "previous_event_hash": event.previous_event_hash,
        }
        for event in db_events
    ]

    return verify_proof_events(
        proof_id=proof_id,
        events=events,
    )
