"""Every public FlopProofClient method, end to end against the application.

The SDK's HTTP layer is the in-process TestClient (`http_client=`), backed by
an in-memory database: real request validation, handlers and responses, with
no live server and no proofs.db.
"""

import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.canonical import build_event_canonical_v4, build_request_canonical_v4
from app.crypto import generate_test_keypair, public_key_to_test_did, sha256_json, sign_message
from app.main import app
from flop_proof_sdk import FlopProofClient, FlopProofHTTPError
from test_validator_result_validation import _matching_result, _signed_bundle

API_KEY = "sdk-against-app-key"


@pytest.fixture
def sdk(monkeypatch):
    from app import main, models  # noqa: F401  (models registers the tables)
    from app.database import Base, get_db

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(main, "API_KEY", API_KEY)
    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield FlopProofClient("http://testserver", api_key=API_KEY, http_client=test_client)
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        engine.dispose()


@pytest.fixture
def validator_registry(monkeypatch):
    from app import main

    attestation, report_data, validator_id = _signed_bundle()
    monkeypatch.setattr(main, "validator_registry", main.MockValidatorRegistry([validator_id]))
    monkeypatch.setattr(main, "processed_validator_tasks", main.ProcessedTasks())
    return attestation, report_data


def _actor():
    private_key, public_key = generate_test_keypair()
    return private_key, public_key_to_test_did(public_key)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _signed_proof(sdk, private_key, did):
    return sdk.create_signed_proof(
        private_key=private_key,
        did=did,
        text="sdk against app",
        room="sdk-room",
        nonce=f"sdk-{uuid.uuid4().hex}",
        request_id=f"sdk-{uuid.uuid4().hex}",
        created_at=_now(),
    )


def test_health(sdk):
    assert sdk.health() == {"status": "ok", "service": "flop-proof-api"}


def test_create_proof_with_a_prebuilt_signed_request(sdk):
    private_key, did = _actor()
    nonce = f"raw-{uuid.uuid4().hex}"
    canonical = build_request_canonical_v4("raw-room", nonce, "raw request")

    created = sdk.create_proof(
        {
            "request_id": f"raw-{uuid.uuid4().hex}",
            "from_did": did,
            "text": "raw request",
            "created_at": _now(),
            "signature": {"nonce": nonce, "sig": sign_message(private_key, canonical.encode()), "canonical": canonical},
        }
    )

    # Was "3": new proofs are version 4 (D-C2).
    assert created["version"] == "4"
    assert created["status"] == "pending"


def test_signed_proof_events_get_and_verify(sdk):
    """create_signed_proof, append_signed_event, append_event, get_proof, verify_proof."""
    private_key, did = _actor()
    proof_id = _signed_proof(sdk, private_key, did)["proof_id"]

    sdk.append_signed_event(proof_id, private_key, did, "agent.started", {"step": 1}, f"n-{uuid.uuid4().hex}")
    nonce = f"n-{uuid.uuid4().hex}"
    head = sdk.current_head(proof_id)
    canonical = build_event_canonical_v4(proof_id, "agent.finished", sha256_json({}), nonce, head)
    appended = sdk.append_event(
        proof_id,
        {
            "type": "agent.finished",
            "actor_did": did,
            "payload": {},
            "signature": {
                "nonce": nonce,
                "sig": sign_message(private_key, canonical.encode()),
                "canonical": canonical,
                "prior_head": head,
            },
        },
    )

    proof = sdk.get_proof(proof_id)
    verification = sdk.verify_proof(proof_id)

    assert appended["sequence"] == 3
    assert [event["type"] for event in proof["events"]] == ["request.created", "agent.started", "agent.finished"]
    assert verification["verdict"] == "valid"


def test_api_errors_raise_flop_proof_http_error(sdk):
    with pytest.raises(FlopProofHTTPError) as error:
        sdk.get_proof(f"proof_{uuid.uuid4().hex}")

    assert error.value.status_code == 404


def test_accept_proof_validator_attestations(sdk, validator_registry):
    attestation, report_data = validator_registry
    private_key, did = _actor()
    proof_id = _signed_proof(sdk, private_key, did)["proof_id"]
    sdk.append_signed_event(proof_id, private_key, did, "result.created", _matching_result(), f"r-{uuid.uuid4().hex}")

    accepted = sdk.accept_proof_validator_attestations(proof_id, report_data, [attestation])

    assert accepted["accepted"] is True
    assert accepted["proof_id"] == proof_id
    assert accepted["evidence"]["execution_verified"] is False


def test_accept_validator_attestation(sdk, validator_registry):
    attestation, report_data = validator_registry

    accepted = sdk.accept_validator_attestation(report_data, [attestation], result=_matching_result())

    assert accepted["accepted"] is True
    assert accepted["validators"] == 1


def test_submit_stark_evidence(sdk):
    task_hash = uuid.uuid4().hex * 2

    accepted = sdk.submit_stark_evidence(
        [{"proof": "opaque"}],
        task_hash=task_hash,
        gn_weight=5,
        latency_ms=5,
        model_hash="22" * 32,
        output_hash="33" * 32,
    )

    assert accepted == {
        "accepted": True,
        "proof_verified": False,
        "verification_status": "pending",
        "task_hash": task_hash,
        "evidence": {"class": "stark_evidence_pending", "execution_verified": False, "runtime_settled": False},
    }


# --- version 4: the signed chain head (docs/design/proof-closure.md D-C1, D-C4, D-C5) ---

def test_sdk_v4_flow_with_creator_delegate_and_close(sdk):
    from app.verifier import verify_proof_data

    creator_key, creator_did = _actor()
    delegate_key, delegate_did = _actor()
    proof_id = _signed_proof(sdk, creator_key, creator_did)["proof_id"]

    sdk.append_signed_event(proof_id, creator_key, creator_did, "task.delegated", {"delegates": [delegate_did]}, "v4-n1")
    sdk.append_signed_event(proof_id, delegate_key, delegate_did, "result.created", {"content": "done"}, "v4-n2")
    closed = sdk.append_signed_event(proof_id, creator_key, creator_did, "proof.completed", {}, "v4-n3")

    exported = sdk.get_proof(proof_id)
    online = sdk.verify_proof(proof_id)
    offline = verify_proof_data(exported)

    assert exported["version"] == "4"
    assert all(e["canonical"].startswith("FLOP/EVENT/v4|") for e in exported["events"][1:])
    assert closed["chain_head"] == exported["chain_head"] == online["chain_head"] == offline["chain_head"]
    assert (online["verdict"], online["closed"], online["event_count"]) == ("valid", True, 4)
    assert [c["prior_head_valid"] for c in online["checks"]] == [None, True, True, True]
    assert [c["role"] for c in online["checks"]] == ["creator", "creator", "delegate", "creator"]


def _stale_head_and_one_more_event(sdk):
    key, did = _actor()
    proof_id = _signed_proof(sdk, key, did)["proof_id"]
    stale = sdk.current_head(proof_id)
    sdk.append_signed_event(proof_id, key, did, "artifact.note", {"by": "another writer"}, f"n-{uuid.uuid4().hex}")
    return proof_id, key, did, stale


def test_sdk_raises_head_mismatch_with_the_current_head(sdk):
    from flop_proof_sdk import HeadMismatchError

    proof_id, key, did, stale = _stale_head_and_one_more_event(sdk)

    with pytest.raises(HeadMismatchError) as error:
        sdk.append_signed_event(proof_id, key, did, "agent.started", {}, "late", prior_head=stale)

    assert error.value.status_code == 409
    assert error.value.signed_head == stale
    assert error.value.current_head == sdk.get_proof(proof_id)["chain_head"] != stale
    assert len(sdk.get_proof(proof_id)["events"]) == 2


def test_sdk_retries_re_sign_on_the_new_head(sdk, monkeypatch):
    proof_id, key, did, stale = _stale_head_and_one_more_event(sdk)
    posted = []
    original = sdk.append_event
    monkeypatch.setattr(sdk, "append_event", lambda pid, event: posted.append(event) or original(pid, event))

    appended = sdk.append_signed_event(proof_id, key, did, "agent.started", {}, "retried", prior_head=stale, retries=2)

    assert appended["sequence"] == 3
    assert len(posted) == 2
    # First the stale head, then the head after the other writer's event.
    assert posted[0]["signature"]["prior_head"] == stale
    assert posted[1]["signature"]["prior_head"] == sdk.get_proof(proof_id)["events"][-1]["previous_event_hash"] != stale
    assert posted[0]["signature"]["nonce"] == posted[1]["signature"]["nonce"] == "retried"
    assert sdk.verify_proof(proof_id)["verdict"] == "valid"


@pytest.mark.parametrize("closing_type", ["proof.completed", "proof.failed"])
def test_sdk_never_re_signs_a_closing_event(sdk, monkeypatch, closing_type):
    """D-C4: retries= does not apply to closing events."""
    from flop_proof_sdk import HeadMismatchError

    proof_id, key, did, stale = _stale_head_and_one_more_event(sdk)
    posted = []
    original = sdk.append_event
    monkeypatch.setattr(sdk, "append_event", lambda pid, event: posted.append(event) or original(pid, event))

    with pytest.raises(HeadMismatchError):
        sdk.append_signed_event(proof_id, key, did, closing_type, {}, "close", prior_head=stale, retries=5)

    assert len(posted) == 1
    assert sdk.get_proof(proof_id)["status"] == "active"


def test_sdk_rejects_a_negative_retry_count(sdk):
    key, did = _actor()
    proof_id = _signed_proof(sdk, key, did)["proof_id"]
    with pytest.raises(ValueError, match="retries"):
        sdk.append_signed_event(proof_id, key, did, "agent.started", {}, "n", retries=-1)


def test_sdk_does_not_sign_when_the_servers_head_disagrees_with_its_events():
    """The server reports a chain_head that is not the head of the events it
    exports (for example it serves a shortened chain with the old head): the
    SDK raises before signing and posts nothing."""
    import httpx

    from flop_proof_sdk import FlopProofChainError, FlopProofClient, chain_head

    key, did = _actor()
    proof_id = f"proof_{uuid.uuid4().hex}"
    events = [{
        "event_id": "evt_1", "type": "request.created", "actor_did": did, "payload_hash": "a" * 64,
        "canonical": "FLOP/REQUEST/v4|r|n|t", "signature": "s" * 86,
        "created_at": "2026-10-23T08:00:00.123456", "sequence": 1, "previous_event_hash": None,
    }]
    honest_head = chain_head(events, proof_id=proof_id)
    requests = []

    def handler(request):
        requests.append(request.method)
        return httpx.Response(200, json={"proof_id": proof_id, "version": "4", "events": events, "chain_head": "f" * 64})

    lying = FlopProofClient("http://testserver", http_client=httpx.Client(transport=httpx.MockTransport(handler)))

    with pytest.raises(FlopProofChainError, match="does not match its exported events"):
        lying.append_signed_event(proof_id, key, did, "agent.started", {}, "n")

    assert requests == ["GET"]
    assert honest_head != "f" * 64
