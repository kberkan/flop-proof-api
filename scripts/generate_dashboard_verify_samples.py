"""Generate dashboard/src/lib/fixtures/verify-samples.json from the API.

The dashboard tests (dashboard/src/lib/chain-integrity.test.mjs) check their
display rules against these real GET /proofs/{id} and GET /proofs/{id}/verify
responses (docs/design/proof-closure.md D-C6, D-C7). Six scenarios:

    valid      a closed version-4 proof
    m9         its export with result.created removed and the links recomputed
               (verified offline, as the export would be)
    m13        a version-4 proof with an event written after proof.completed
    truncated  the export of a closed proof without its closing event
    v3, v2     proofs written directly, one event appended through the API

The API runs in-process (TestClient, in-memory database). Keys, nonces, ids
and timestamps are fixed, so the output is the same, byte for byte, on every
run: the API's uuid4 (proof and event ids) and datetime.now (timestamps) are
replaced while the samples are made, and restored afterwards. The clock steps
by 1.25 s, so some created_at values have no fraction (isoformat drops it).

    python scripts/generate_dashboard_verify_samples.py           # write the file
    python scripts/generate_dashboard_verify_samples.py --check   # exit 1 if stale
"""

import argparse
import contextlib
import copy
import difflib
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Set before app.database is imported (it reads the URL at import). The
# samples never touch a database file: get_db is overridden below.
os.environ.setdefault("FLOP_DATABASE_URL", "sqlite://")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

SAMPLES_PATH = REPO_ROOT / "dashboard" / "src" / "lib" / "fixtures" / "verify-samples.json"

API_KEY = "dashboard-verify-samples"
CLOCK_START = datetime(2026, 10, 24, 9, 0, 0, tzinfo=timezone.utc)
CLOCK_STEP = timedelta(seconds=1, microseconds=250000)
REQUEST_CREATED_AT = "2026-10-24T08:59:00+00:00"
REQUEST_WRITTEN_AT = datetime(2026, 10, 24, 8, 59, 30, tzinfo=timezone.utc)


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


@contextlib.contextmanager
def _deterministic_api():
    """A TestClient on a fresh in-memory database, with fixed ids and clock.
    Everything patched here is restored on exit."""
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import events as events_module
    from app import main
    from app import models  # noqa: F401  (registers the tables)
    from app.database import Base, get_db

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    counter = {"uuid": 0, "clock": 0}

    def fixed_uuid4():
        counter["uuid"] += 1
        return uuid.UUID(int=counter["uuid"])

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            value = CLOCK_START + counter["clock"] * CLOCK_STEP
            counter["clock"] += 1
            return value if tz is not None else value.replace(tzinfo=None)

    saved = {
        "uuid4": uuid.uuid4,
        "events_datetime": events_module.datetime,
        "main_datetime": main.datetime,
        "api_key": main.API_KEY,
        "rate_limit": main.RATE_LIMIT_ENABLED,
        "override": main.app.dependency_overrides.get(get_db),
    }
    uuid.uuid4 = fixed_uuid4
    events_module.datetime = FixedClock
    main.datetime = FixedClock
    main.API_KEY = API_KEY
    main.RATE_LIMIT_ENABLED = False
    main.app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(main.app, headers={"X-API-Key": API_KEY}) as client:
            yield client, Session
    finally:
        uuid.uuid4 = saved["uuid4"]
        events_module.datetime = saved["events_datetime"]
        main.datetime = saved["main_datetime"]
        main.API_KEY = saved["api_key"]
        main.RATE_LIMIT_ENABLED = saved["rate_limit"]
        if saved["override"] is None:
            main.app.dependency_overrides.pop(get_db, None)
        else:
            main.app.dependency_overrides[get_db] = saved["override"]
        engine.dispose()


def generate() -> dict:
    from app.canonical import (
        build_event_canonical_v3,
        build_event_canonical_v4,
        build_request_canonical_v3,
        build_request_canonical_v4,
    )
    from app.crypto import hash_event_record, public_key_to_test_did, sha256_json, sign_message
    from app.events import create_event
    from app.models import Proof
    from app.verification_core import verify_proof_events

    key = _key("dashboard-verify-samples creator")
    did = public_key_to_test_did(key.public_key())
    out = {}

    with _deterministic_api() as (client, Session):
        def check(response, status=201):
            assert response.status_code == status, response.text
            return response.json()

        def create_proof(label):
            nonce = f"{label}-request"
            canonical = build_request_canonical_v4("samples", nonce, "dashboard samples")
            return check(client.post("/proofs", json={"request": {
                "request_id": f"{label}-request-id",
                "from_did": did,
                "text": "dashboard samples",
                "created_at": REQUEST_CREATED_AT,
                "signature": {"nonce": nonce, "canonical": canonical, "sig": sign_message(key, canonical.encode())},
            }}))["proof_id"]

        def v4_event(proof_id, event_type, payload, nonce):
            head = client.get(f"/proofs/{proof_id}").json()["chain_head"]
            canonical = build_event_canonical_v4(proof_id, event_type, sha256_json(payload), nonce, head)
            return {
                "type": event_type,
                "actor_did": did,
                "payload": payload,
                "signature": {
                    "nonce": nonce,
                    "canonical": canonical,
                    "sig": sign_message(key, canonical.encode()),
                    "prior_head": head,
                },
            }

        def append(proof_id, event_type, payload, nonce):
            check(client.post(f"/proofs/{proof_id}/events", json=v4_event(proof_id, event_type, payload, nonce)))

        def sample(proof_id):
            return {
                "proof": check(client.get(f"/proofs/{proof_id}"), 200),
                "verify": check(client.get(f"/proofs/{proof_id}/verify"), 200),
            }

        # valid: closed version-4 proof.
        valid_id = create_proof("valid")
        for index, (event_type, payload) in enumerate([
            ("agent.started", {"t": "agent.started"}),
            ("artifact.note", {"t": "artifact.note"}),
            ("result.created", {"t": "result.created"}),
            ("proof.completed", {}),
        ]):
            append(valid_id, event_type, payload, f"valid-event-{index}")
        out["valid"] = sample(valid_id)
        exported = out["valid"]["proof"]

        # m9: result.created removed from the export, links recomputed.
        m9 = copy.deepcopy(exported)
        del m9["events"][3]
        previous = None
        for sequence, event in enumerate(m9["events"], start=1):
            event["sequence"] = sequence
            event["previous_event_hash"] = None if previous is None else hash_event_record(
                event_id=previous["event_id"], proof_id=valid_id, event_type=previous["type"],
                actor_did=previous["actor_did"], payload_hash=previous["payload_hash"],
                canonical=previous["canonical"], signature=previous["signature"],
                created_at=previous["created_at"], sequence=previous["sequence"],
            )
            previous = event
        out["m9"] = {"proof": m9, "verify": verify_proof_events(valid_id, m9["events"], "4")}

        # m13: an event written after proof.completed, around the API.
        m13_id = create_proof("m13")
        append(m13_id, "proof.completed", {}, "m13-close")
        late = v4_event(m13_id, "agent.started", {}, "m13-late")
        with Session() as db:
            create_event(
                db=db, proof_id=m13_id, event_type=late["type"], actor_did=did, payload=late["payload"],
                canonical=late["signature"]["canonical"], signature=late["signature"]["sig"],
                nonce=late["signature"]["nonce"],
            )
            db.commit()
        out["m13"] = sample(m13_id)

        # truncated: the closed proof's export without its closing event.
        truncated = copy.deepcopy(exported)
        truncated["events"] = truncated["events"][:-1]
        out["truncated"] = {
            "proof": truncated,
            "verify": verify_proof_events(valid_id, truncated["events"], "4"),
        }

        # v3 and v2: written directly, one event through the API.
        for version in ("3", "2"):
            nonce = f"v{version}-request"
            if version == "3":
                canonical = build_request_canonical_v3("samples", nonce, "t")
            else:
                canonical = f"samples|{nonce}|t"
            request = {
                "request_id": f"v{version}-request-id",
                "from_did": did,
                "text": "t",
                "created_at": REQUEST_CREATED_AT,
                "signature": {"nonce": nonce, "canonical": canonical, "sig": sign_message(key, canonical.encode())},
            }
            proof_id = f"proof_{uuid.uuid4().hex}"
            with Session() as db:
                # Written directly, so the row's times come from here, not from
                # the API's clock; fixed as well.
                now = REQUEST_WRITTEN_AT
                db.add(Proof(proof_id=proof_id, request_id=request["request_id"], version=version,
                             status="pending", created_at=now, updated_at=now))
                create_event(
                    db=db, proof_id=proof_id, event_type="request.created", actor_did=did, payload=request,
                    canonical=canonical, signature=request["signature"]["sig"],
                    nonce=nonce if version == "3" else "",
                )
                db.commit()
            event_nonce = f"v{version}-event"
            if version == "3":
                event_canonical = build_event_canonical_v3(proof_id, "agent.started", sha256_json({}), event_nonce)
            else:
                event_canonical = f"{proof_id}|agent.started|{sha256_json({})}"
            check(client.post(f"/proofs/{proof_id}/events", json={
                "type": "agent.started",
                "actor_did": did,
                "payload": {},
                "signature": {
                    "nonce": event_nonce,
                    "canonical": event_canonical,
                    "sig": sign_message(key, event_canonical.encode()),
                },
            }))
            out[f"v{version}"] = sample(proof_id)

    return {
        "description": (
            "Real GET /proofs/{id} and GET /proofs/{id}/verify responses of the API, made "
            "in-process by scripts/generate_dashboard_verify_samples.py with fixed keys, "
            "nonces, ids and clock; do not edit by hand. valid: closed v4 proof; m9: its "
            "export with result.created removed and the links recomputed (offline verifier "
            "result); m13: v4 proof with an event written after proof.completed; truncated: "
            "the closed proof's export without its closing event; v3, v2: proofs written "
            "directly with one event appended through the API. Used by "
            "chain-integrity.test.mjs (docs/design/proof-closure.md D-C6, D-C7)."
        ),
        **out,
    }


def render() -> str:
    return json.dumps(generate(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the file is stale")
    args = parser.parse_args()

    expected = render()
    relative = SAMPLES_PATH.relative_to(REPO_ROOT)
    if args.check:
        current = SAMPLES_PATH.read_text(encoding="utf-8") if SAMPLES_PATH.exists() else ""
        if current != expected:
            diff = list(difflib.unified_diff(
                current.splitlines(), expected.splitlines(),
                fromfile=f"{relative} (on disk)", tofile=f"{relative} (generated)", lineterm="", n=1,
            ))
            print(f"{relative} is stale; regenerate it with python scripts/generate_dashboard_verify_samples.py")
            print("\n".join(diff[:40]))
            if len(diff) > 40:
                print(f"... {len(diff) - 40} more diff lines")
            return 1
        print(f"{relative} is up to date.")
        return 0

    SAMPLES_PATH.parent.mkdir(parents=True, exist_ok=True)
    SAMPLES_PATH.write_text(expected, encoding="utf-8")
    print(f"wrote {relative}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
