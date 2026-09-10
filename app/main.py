import base64
import json
import os
import uuid
from datetime import datetime, timezone
from fractions import Fraction

from fastapi import Depends, FastAPI, HTTPException, Header, Request
from dotenv import load_dotenv
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .crypto import (
    MockValidatorRegistry,
    ProcessedTasks,
    ValidatorAttestation,
    hash_event_record,
    sha256_bytes,
    sha256_json,
    verify_canonical_signature,
    verify_floop_signature,
    verify_and_accept_validator_attestation_bundle_for_result,
    verify_validator_attestation_bundle_for_result,
    validate_gn_latency_throughput_tripwire,
)
from .replay import claim_processed_task
from .database import Base, engine, get_db
from .events import create_event
from .schemas import (
    ProofValidatorAttestationAcceptRequest,
    ValidatorAttestationAcceptRequest,
    StarkBatchSubmitRequest,
)
from .models import PendingVerification, Proof, ProofEvent
from .schemas import EventCreate, ProofCreate
from .rate_limit import RateLimiter

load_dotenv()


app = FastAPI(
    title="FLOP Proof API",
    version="1.0.0",
)

    
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)


API_KEY = os.getenv("FLOP_API_KEY")

RATE_LIMIT_ENABLED = os.getenv("FLOP_RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("FLOP_RATE_LIMIT", "100"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("FLOP_RATE_WINDOW", "60"))

rate_limiter = RateLimiter(
    max_requests=RATE_LIMIT_MAX_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)

    
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if not RATE_LIMIT_ENABLED or request.url.path == "/health":
        return await call_next(request)

    api_key = request.headers.get("X-API-Key")
    client_ip = request.client.host if request.client else "unknown"

    # API key varsa onu, yoksa IP adresini limiter anahtarı olarak kullan.
    rate_limit_key = f"api:{api_key}" if api_key else f"ip:{client_ip}"

    allowed, retry_after = rate_limiter.check(rate_limit_key)

    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
            headers={"Retry-After": str(retry_after)},
        )

    return await call_next(request)


def require_api_key(x_api_key: str | None = Header(default=None)):
    if not API_KEY:
        raise HTTPException(
            status_code=500,
            detail="API authentication is not configured",
        )

    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    return True


LOCAL_VALIDATOR_IDS = tuple(
    bytes.fromhex(value.strip())
    for value in os.getenv("FLOP_LOCAL_VALIDATOR_IDS", "").split(",")
    if value.strip()
)

validator_registry = MockValidatorRegistry(list(LOCAL_VALIDATOR_IDS))
processed_validator_tasks = ProcessedTasks()
VALIDATOR_ATTESTATION_THRESHOLD = Fraction(
    os.getenv("FLOP_VALIDATOR_THRESHOLD", "2/3")
)


@app.post("/proofs/{proof_id}/validator-attestations/accept")
def accept_proof_validator_attestations(
    proof_id: str,
    request: ProofValidatorAttestationAcceptRequest,
    db: Session = Depends(get_db),
    _: bool = Depends(require_api_key),
):
    """Accept validator attestations bound to a stored result.created event."""

    proof = db.scalar(
        select(Proof).where(Proof.proof_id == proof_id)
    )

    if proof is None:
        raise HTTPException(
            status_code=404,
            detail="Proof not found",
        )

    result_event = db.scalar(
        select(ProofEvent)
        .where(
            ProofEvent.proof_id == proof_id,
            ProofEvent.event_type == "result.created",
        )
        .order_by(ProofEvent.sequence.desc())
    )

    if result_event is None:
        raise HTTPException(
            status_code=409,
            detail="result.created event not found",
        )

    try:
        result = json.loads(result_event.payload_json)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=409,
            detail="Invalid result.created payload",
        ) from None

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=409,
            detail="Invalid result.created payload",
        )

    required_fields = (
        "task_hash",
        "model_hash",
        "gn_weight",
        "latency_ms",
        "decode_policy_hash",
        "tee_type",
        "output_hash",
    )

    if any(field not in result for field in required_fields):
        raise HTTPException(
            status_code=409,
            detail="result.created is not validator-ready",
        )

    try:
        attestations = [
            ValidatorAttestation(
                task_hash=bytes.fromhex(attestation.task_hash),
                gn_weight=attestation.gn_weight,
                latency_ms=attestation.latency_ms,
                model_hash=bytes.fromhex(attestation.model_hash),
                output_hash=bytes.fromhex(attestation.output_hash),
                decode_policy_hash=bytes.fromhex(attestation.decode_policy_hash),
                tee_type=attestation.tee_type,
                quote_verified=attestation.quote_verified,
                event_log_verified=attestation.event_log_verified,
                hardware_id_hash=bytes.fromhex(attestation.hardware_id_hash),
                validator_id=bytes.fromhex(attestation.validator_id),
                signature=base64.b64decode(
                    attestation.signature
                    + "=" * (-len(attestation.signature) % 4),
                    altchars=b"-_",
                    validate=True,
                ),
            )
            for attestation in request.attestations
        ]
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=422,
            detail="Invalid validator attestation encoding",
        ) from None

    validated = verify_validator_attestation_bundle_for_result(
        attestations=attestations,
        result=result,
        report_data=request.report_data,
        registry=validator_registry,
        threshold=VALIDATOR_ATTESTATION_THRESHOLD,
    )

    if not validated:
        raise HTTPException(
            status_code=409,
            detail="Validator attestation bundle rejected",
        )

    if not claim_processed_task(db, attestations[0].task_hash):
        raise HTTPException(
            status_code=409,
            detail="Validator attestation bundle rejected",
        )

    return {
        "accepted": True,
        "proof_id": proof_id,
        "task_hash": attestations[0].task_hash.hex(),
        "validators": len(attestations),
        "result_event_id": result_event.event_id,
        "evidence": {
            "class": "validator_attestation_binding",
            "execution_verified": False,
            "runtime_settled": False,
        },
    }



@app.post("/stark-batches")
def submit_stark_batch(
    payload: StarkBatchSubmitRequest,
    db: Session = Depends(get_db),
):
    task_hash = payload.task_hash.lower()

    existing = db.get(PendingVerification, task_hash)
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="task_hash already submitted",
        )

    pending = PendingVerification(
        task_hash=task_hash,
        proofs_json=json.dumps(
            payload.proofs,
            sort_keys=True,
            separators=(",", ":"),
        ),
        gn_weight=payload.gn_weight,
        latency_ms=payload.latency_ms,
        model_hash=payload.model_hash.lower(),
        output_hash=payload.output_hash.lower(),
    )

    db.add(pending)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="task_hash already submitted",
        )

    return {
        "accepted": True,
        "proof_verified": False,
        "verification_status": "pending",
        "task_hash": task_hash,
        "evidence": {
            "class": "stark_evidence_pending",
            "execution_verified": False,
            "runtime_settled": False,
        },
    }

@app.post("/validator-attestations/accept")
def accept_validator_attestations(
    request: ValidatorAttestationAcceptRequest,
    _: bool = Depends(require_api_key),
):
    """Local/test-only validator attestation acceptance boundary."""
    try:
        attestations = [
            ValidatorAttestation(
                task_hash=bytes.fromhex(attestation.task_hash),
                gn_weight=attestation.gn_weight,
                latency_ms=attestation.latency_ms,
                model_hash=bytes.fromhex(attestation.model_hash),
                output_hash=bytes.fromhex(attestation.output_hash),
                decode_policy_hash=bytes.fromhex(attestation.decode_policy_hash),
                tee_type=attestation.tee_type,
                quote_verified=attestation.quote_verified,
                event_log_verified=attestation.event_log_verified,
                hardware_id_hash=bytes.fromhex(attestation.hardware_id_hash),
                validator_id=bytes.fromhex(attestation.validator_id),
                signature=base64.b64decode(
                    attestation.signature + "=" * (-len(attestation.signature) % 4),
                    altchars=b"-_",
                    validate=True,
                ),
            )
            for attestation in request.attestations
        ]
    except (ValueError, TypeError):
        raise HTTPException(
            422,
            detail="Invalid validator attestation encoding",
        ) from None

    if not validate_gn_latency_throughput_tripwire(
        request.result["gn_weight"],
        request.result["latency_ms"],
    ):
        raise HTTPException(
            409,
            detail="Validator attestation bundle rejected: throughput tripwire",
        )

    accepted = verify_and_accept_validator_attestation_bundle_for_result(
        attestations=attestations,
        result=request.result,
        report_data=request.report_data,
        registry=validator_registry,
        threshold=VALIDATOR_ATTESTATION_THRESHOLD,
        processed_tasks=processed_validator_tasks,
    )

    if not accepted:
        raise HTTPException(
            409,
            detail="Validator attestation bundle rejected",
        )

    return {
        "accepted": True,
        "task_hash": attestations[0].task_hash.hex(),
        "validators": len(attestations),
        "evidence": {
            "class": "validator_attestation_binding",
            "execution_verified": False,
            "runtime_settled": False,
        },
    }


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
    _: bool = Depends(require_api_key),
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
    _: bool = Depends(require_api_key),
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
    _: bool = Depends(require_api_key),
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
    _: bool = Depends(require_api_key),
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

    existing_nonce = db.scalar(
        select(ProofEvent).where(
            ProofEvent.proof_id == proof_id,
            ProofEvent.nonce == event.signature.nonce,
        )
    )

    if existing_nonce is not None:
        raise HTTPException(
            status_code=409,
            detail="event nonce already used for this proof",
        )

    created = create_event(
        db=db,
        proof_id=proof_id,
        event_type=event.type,
        actor_did=event.actor_did,
        payload=event.payload,
        canonical=event.signature.canonical,
        signature=event.signature.sig,
        nonce=event.signature.nonce,
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
    _: bool = Depends(require_api_key),
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
    _: bool = Depends(require_api_key),
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

    verification = verify_proof_events(
        proof_id=proof_id,
        events=events,
    )

    verification["evidence"] = {
        "class": "proof_integrity_verified",
        "execution_verified": False,
        "runtime_settled": False,
    }

    return verification
