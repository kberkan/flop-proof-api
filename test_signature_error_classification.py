"""Ed25519 signature errors on POST /proofs and POST /proofs/{id}/events:
malformed input is 422, a well-formed signature that does not verify is 401.

  422 "Invalid signature encoding": not 64 bytes of unpadded or padded
      base64url (a, b).
  422 "Invalid from_did" / "Invalid actor_did": not a did:key with an Ed25519
      multicodec key of 32 bytes that decodes as a point (RFC 8032 §5.1.3)
      and does not have small order (c, d). A small-order key admits forged
      signatures: with the identity point, R = identity and S = 0 verifies
      for every message.
  401 unchanged: a well-formed signature by another key or with a flipped bit
      (e, f).
"""

import base64
import uuid

import base58
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.canonical import build_event_canonical_v3, build_request_canonical_v3
from app.crypto import generate_test_keypair, public_key_to_test_did, sha256_json, sign_message
from app.main import app

API_KEY = "signature-classification-key"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _did_key(multicodec_and_key: bytes) -> str:
    return "did:key:z" + base58.b58encode(multicodec_and_key).decode()


ED25519 = bytes([0xED, 0x01])
SIGNER_KEY, SIGNER_PUBLIC = generate_test_keypair()
SIGNER_DID = public_key_to_test_did(SIGNER_PUBLIC)
OTHER_KEY, _ = generate_test_keypair()


def _flipped(message: bytes) -> str:
    raw = base64.urlsafe_b64decode(sign_message(SIGNER_KEY, message) + "==")
    return _b64(bytes([raw[0] ^ 1]) + raw[1:])


# (sig(message) -> str, signer DID)
MALFORMED_SIGNATURE = [
    pytest.param(lambda m: "!!!not-base64!!!", id="a-not-base64"),
    pytest.param(lambda m: "ab" * 64, id="a-hex-string"),
    pytest.param(lambda m: sign_message(SIGNER_KEY, m) + "!", id="a-valid-plus-junk-char"),
    pytest.param(lambda m: _b64(bytes(63)), id="b-63-bytes"),
    pytest.param(lambda m: _b64(bytes(65)), id="b-65-bytes"),
]
MALFORMED_DID = [
    pytest.param("did:web:example.com", id="c-did-web"),
    pytest.param("did:key:z0OIl", id="c-did-key-not-base58"),
    pytest.param(_did_key(bytes([0xE7, 0x01]) + bytes(33)), id="c-did-key-secp256k1"),
    pytest.param(_did_key(ED25519 + bytes(31)), id="c-did-key-31-byte-key"),
    pytest.param(_did_key(ED25519 + b"\xff" * 32), id="d-key-y-not-below-p"),
    pytest.param(_did_key(ED25519 + b"\x01" + bytes(30) + b"\x80"), id="d-key-x-zero-with-sign-bit"),
]
# The 8 Ed25519 points of order 1, 2, 4 or 8 (checked independently below).
SMALL_ORDER_KEYS = [
    # Built, not written out: as a hex literal, scripts/check_wire_vectors.py
    # flags it because 01 + 31 zero bytes also occurs inside upstream
    # DecodePolicy values.
    (b"\x01" + bytes(31)).hex(),
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]
MALFORMED_DID += [
    pytest.param(_did_key(ED25519 + bytes.fromhex(key)), id=f"d-small-order-{key[:4]}{key[-2:]}")
    for key in SMALL_ORDER_KEYS
]
WELL_FORMED_BUT_WRONG = [
    pytest.param(lambda m: sign_message(OTHER_KEY, m), SIGNER_DID, id="e-signed-by-another-key"),
    pytest.param(_flipped, SIGNER_DID, id="f-one-bit-flipped"),
]


@pytest.fixture
def client(monkeypatch):
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
        yield TestClient(app, headers={"X-API-Key": API_KEY}, raise_server_exceptions=False)
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        engine.dispose()


def _post_proof(client, sig=None, from_did=SIGNER_DID):
    nonce = f"n-{uuid.uuid4().hex}"
    canonical = build_request_canonical_v3("room", nonce, "text")
    signature = sign_message(SIGNER_KEY, canonical.encode()) if sig is None else sig(canonical.encode())
    return client.post(
        "/proofs",
        json={
            "request": {
                "request_id": f"r-{uuid.uuid4().hex}",
                "from_did": from_did,
                "text": "text",
                "created_at": "2026-10-07T00:00:00Z",
                "signature": {"nonce": nonce, "sig": signature, "canonical": canonical},
            }
        },
    )


def _post_event(client, proof_id, sig=None, actor_did=SIGNER_DID):
    nonce = f"e-{uuid.uuid4().hex}"
    canonical = build_event_canonical_v3(proof_id, "agent.started", sha256_json({}), nonce)
    signature = sign_message(SIGNER_KEY, canonical.encode()) if sig is None else sig(canonical.encode())
    return client.post(
        f"/proofs/{proof_id}/events",
        json={
            "type": "agent.started",
            "actor_did": actor_did,
            "payload": {},
            "signature": {"nonce": nonce, "sig": signature, "canonical": canonical},
        },
    )


@pytest.fixture
def proof_id(client):
    response = _post_proof(client)
    assert response.status_code == 201, response.text
    return response.json()["proof_id"]


# --- POST /proofs -------------------------------------------------------------------------

@pytest.mark.parametrize("sig", MALFORMED_SIGNATURE)
def test_proof_request_malformed_signature_is_422(client, sig):
    response = _post_proof(client, sig=sig)

    assert response.status_code == 422, response.text
    assert response.json() == {"detail": "Invalid signature encoding"}


@pytest.mark.parametrize("from_did", MALFORMED_DID)
def test_proof_request_malformed_from_did_is_422(client, from_did):
    response = _post_proof(client, from_did=from_did)

    assert response.status_code == 422, response.text
    assert response.json() == {"detail": "Invalid from_did"}


@pytest.mark.parametrize(("sig", "from_did"), WELL_FORMED_BUT_WRONG)
def test_proof_request_wrong_signature_stays_401(client, sig, from_did):
    response = _post_proof(client, sig=sig, from_did=from_did)

    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Invalid request signature"}


# --- POST /proofs/{id}/events --------------------------------------------------------------

@pytest.mark.parametrize("sig", MALFORMED_SIGNATURE)
def test_event_malformed_signature_is_422(client, proof_id, sig):
    response = _post_event(client, proof_id, sig=sig)

    assert response.status_code == 422, response.text
    assert response.json() == {"detail": "Invalid signature encoding"}


@pytest.mark.parametrize("actor_did", MALFORMED_DID)
def test_event_malformed_actor_did_is_422(client, proof_id, actor_did):
    response = _post_event(client, proof_id, actor_did=actor_did)

    assert response.status_code == 422, response.text
    assert response.json() == {"detail": "Invalid actor_did"}


@pytest.mark.parametrize(("sig", "actor_did"), WELL_FORMED_BUT_WRONG)
def test_event_wrong_signature_stays_401(client, proof_id, sig, actor_did):
    response = _post_event(client, proof_id, sig=sig, actor_did=actor_did)

    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Invalid event signature"}


def test_event_canonical_mismatch_is_still_checked_before_the_signature(client, proof_id):
    """The canonical comparison keeps its place: a mismatched canonical with a
    malformed signature is still 401 "Event canonical message mismatch"."""
    response = client.post(
        f"/proofs/{proof_id}/events",
        json={
            "type": "agent.started",
            "actor_did": SIGNER_DID,
            "payload": {},
            "signature": {"nonce": "n-1", "sig": "!!!", "canonical": "FLOP/EVENT/v3|other"},
        },
    )

    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Event canonical message mismatch"}


# --- the helpers on their own ---------------------------------------------------------------

def test_point_decoding_accepts_real_keys_and_rejects_undecodable_ones():
    import random

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from app.crypto import is_ed25519_point_encoding

    real_keys = [Ed25519PrivateKey.generate().public_key().public_bytes_raw() for _ in range(2000)]
    assert all(is_ed25519_point_encoding(key) for key in real_keys)
    # RFC 8032 §7.1, test 1 public key.
    assert is_ed25519_point_encoding(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    assert not is_ed25519_point_encoding(b"\xff" * 32)  # y >= p
    assert not is_ed25519_point_encoding(b"\x01" + bytes(30) + b"\x80")  # x = 0, sign bit set
    assert is_ed25519_point_encoding(bytes(32))  # small order: decodes; rejected separately
    # About half of all 32-byte strings decode (x^2 must have a square root).
    rng = random.Random(8032)
    decoded = sum(is_ed25519_point_encoding(rng.randbytes(32)) for _ in range(4000))
    assert 1800 < decoded < 2200, decoded


@pytest.mark.parametrize(
    "signature",
    [
        pytest.param("", id="empty"),
        pytest.param("A" * 85, id="85-chars"),
        pytest.param("A" * 87, id="87-chars"),
        pytest.param("A" * 86 + "=", id="single-padding"),
        pytest.param("A" * 85 + "B", id="non-canonical-trailing-bits"),
        pytest.param("+" * 86, id="standard-alphabet-plus"),
        pytest.param(None, id="not-a-string"),
    ],
)
def test_signature_decoding_rejects_malformed_values(signature):
    from app.crypto import decode_ed25519_signature

    with pytest.raises(ValueError):
        decode_ed25519_signature(signature)


def test_signature_decoding_accepts_unpadded_and_padded_sdk_signatures():
    from app.crypto import decode_ed25519_signature

    signature = sign_message(SIGNER_KEY, b"message")
    assert len(signature) == 86
    assert decode_ed25519_signature(signature) == decode_ed25519_signature(signature + "==")
    assert len(decode_ed25519_signature(signature)) == 64


# --- small-order keys: universal forgery is refused --------------------------------------

IDENTITY_DID = _did_key(ED25519 + b"\x01" + bytes(31))
# R = identity point, S = 0: verifies for every message under the identity key.
FORGED_SIGNATURE = _b64(b"\x01" + bytes(63))


def test_forged_signature_under_identity_key_creates_no_proof(client):
    """End to end: without any private key, this created a proof that /verify
    reported valid (and events could be appended the same way)."""
    response = _post_proof(client, sig=lambda m: FORGED_SIGNATURE, from_did=IDENTITY_DID)

    assert response.status_code == 422, response.text
    assert response.json() == {"detail": "Invalid from_did"}
    assert client.get("/proofs").json()["count"] == 0


def test_small_order_key_list_is_exactly_the_points_of_order_dividing_8():
    """Independent Edwards arithmetic: the 8 listed keys, and the module's set,
    are the distinct points with 8P = identity."""
    from app.crypto import SMALL_ORDER_ED25519_KEYS

    p = 2**255 - 19
    d = (-121665 * pow(121666, -1, p)) % p

    def decode(raw):
        y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
        u, v = (y * y - 1) % p, (d * y * y + 1) % p
        x = (u * pow(v, 3, p) * pow(u * pow(v, 7, p), (p - 5) // 8, p)) % p
        if (v * x * x) % p != u:
            x = x * pow(2, (p - 1) // 4, p) % p
        if (x & 1) != raw[31] >> 7:
            x = (-x) % p
        return x, y

    def add(a, b):
        (x1, y1), (x2, y2) = a, b
        t = d * x1 * x2 * y1 * y2 % p
        return (x1 * y2 + x2 * y1) * pow(1 + t, -1, p) % p, (y1 * y2 + x1 * x2) * pow(1 - t, -1, p) % p

    identity = (0, 1)
    for key in SMALL_ORDER_KEYS:
        point = decode(bytes.fromhex(key))
        multiple = identity
        for _ in range(8):
            multiple = add(multiple, point)
        assert multiple == identity, key

    assert len(set(SMALL_ORDER_KEYS)) == 8
    assert SMALL_ORDER_ED25519_KEYS == frozenset(bytes.fromhex(key) for key in SMALL_ORDER_KEYS)


# --- verifier path: did_key_to_public_key rejects small-order keys -------------------------

@pytest.mark.parametrize("key", SMALL_ORDER_KEYS, ids=lambda key: f"{key[:4]}{key[-2:]}")
def test_did_key_to_public_key_rejects_small_order_keys(key):
    """The verifier resolves actor DIDs with did_key_to_public_key; a
    small-order key must not resolve to a usable public key there either."""
    from app.crypto import did_key_to_public_key

    with pytest.raises(ValueError, match="small order"):
        did_key_to_public_key(_did_key(ED25519 + bytes.fromhex(key)))


def test_did_key_to_public_key_still_accepts_a_normal_key():
    from app.crypto import did_key_to_public_key

    assert did_key_to_public_key(SIGNER_DID).public_bytes_raw() == SIGNER_PUBLIC.public_bytes_raw()


def _write_chain_around_api(client, actor_did, signature):
    """A version-3 proof with request.created and result.created by `actor_did`,
    written straight to the database (bypassing the API's input checks)."""
    from datetime import datetime, timezone

    from app.database import get_db
    from app.events import create_event
    from app.models import Proof

    db = next(app.dependency_overrides[get_db]())
    proof_id = f"proof_{uuid.uuid4().hex}"
    nonce = f"n-{uuid.uuid4().hex}"
    canonical = build_request_canonical_v3("room", nonce, "text")
    request = {
        "request_id": f"r-{uuid.uuid4().hex}",
        "from_did": actor_did,
        "text": "text",
        "created_at": "2026-10-08T00:00:00+00:00",
        "signature": {"nonce": nonce, "sig": signature, "canonical": canonical},
    }
    now = datetime.now(timezone.utc)
    db.add(Proof(proof_id=proof_id, request_id=request["request_id"], version="3", status="pending", created_at=now, updated_at=now))
    create_event(db=db, proof_id=proof_id, event_type="request.created", actor_did=actor_did,
                 payload=request, canonical=canonical, signature=signature, nonce=nonce)
    event_nonce = f"e-{uuid.uuid4().hex}"
    payload = {"content": "x"}
    event_canonical = build_event_canonical_v3(proof_id, "result.created", sha256_json(payload), event_nonce)
    create_event(db=db, proof_id=proof_id, event_type="result.created", actor_did=actor_did,
                 payload=payload, canonical=event_canonical, signature=signature, nonce=event_nonce)
    db.commit()
    db.close()
    return proof_id


@pytest.mark.parametrize("key", SMALL_ORDER_KEYS, ids=lambda key: f"{key[:4]}{key[-2:]}")
def test_verifier_rejects_small_order_did_chain_written_around_the_api(client, key):
    """Guard: a chain whose actor has a small-order key is invalid in /verify
    and in the offline verifier, with signature_valid False on its events.
    The signature is 64 zero bytes."""
    from app.verifier import verify_proof_data

    proof_id = _write_chain_around_api(client, _did_key(ED25519 + bytes.fromhex(key)), _b64(bytes(64)))

    online = client.get(f"/proofs/{proof_id}/verify").json()
    offline = verify_proof_data(client.get(f"/proofs/{proof_id}").json())

    for result in (online, offline):
        assert result["verdict"] == "invalid"
        assert [check["signature_valid"] for check in result["checks"]] == [False, False]


def test_verifier_still_accepts_a_normal_proof(client, proof_id):
    """Guard (f): a proof made through the API with a normal key stays valid."""
    from app.verifier import verify_proof_data

    assert _post_event(client, proof_id).status_code == 201

    online = client.get(f"/proofs/{proof_id}/verify").json()
    offline = verify_proof_data(client.get(f"/proofs/{proof_id}").json())

    assert online["verdict"] == offline["verdict"] == "valid"
    assert all(check["signature_valid"] for check in online["checks"])


SMALL_ORDER_DELEGATE = _did_key(ED25519 + b"\x01" + bytes(31))


def _signed_delegation(proof_id, delegates):
    payload = {"delegates": delegates}
    nonce = f"d-{uuid.uuid4().hex}"
    canonical = build_event_canonical_v3(proof_id, "task.delegated", sha256_json(payload), nonce)
    return {
        "type": "task.delegated",
        "actor_did": SIGNER_DID,
        "payload": payload,
        "signature": {"nonce": nonce, "sig": sign_message(SIGNER_KEY, canonical.encode()), "canonical": canonical},
    }


def test_delegating_to_a_small_order_did_is_400(client, proof_id):
    response = client.post(f"/proofs/{proof_id}/events", json=_signed_delegation(proof_id, [SMALL_ORDER_DELEGATE]))

    assert response.status_code == 400, response.text
    assert response.json() == {"detail": "Invalid delegate DID"}


def test_verifier_treats_a_delegation_to_a_small_order_did_as_unauthorized(client, proof_id):
    """The same creator-signed delegation written around the API: the verifier
    replays the API's authorization rule and rejects it."""
    from app.database import get_db
    from app.events import create_event
    from app.verifier import verify_proof_data

    event = _signed_delegation(proof_id, [SMALL_ORDER_DELEGATE])
    db = next(app.dependency_overrides[get_db]())
    create_event(db=db, proof_id=proof_id, event_type=event["type"], actor_did=event["actor_did"],
                 payload=event["payload"], canonical=event["signature"]["canonical"],
                 signature=event["signature"]["sig"], nonce=event["signature"]["nonce"])
    db.commit()
    db.close()

    online = client.get(f"/proofs/{proof_id}/verify").json()
    offline = verify_proof_data(client.get(f"/proofs/{proof_id}").json())

    for result in (online, offline):
        delegation = result["checks"][-1]
        assert result["verdict"] == "invalid"
        assert delegation["signature_valid"] is True
        assert delegation["actor_authorized"] is False
