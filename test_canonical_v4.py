"""Unit tests for the version-4 canonical functions (app/canonical.py) and
chain_head (app/crypto.py); docs/design/proof-closure.md §3.2.1, D-C1, D-C2,
D-C5, §8 A; event-replay.md D-R3, D-R9, D-R10.

Pure, except the chain_head tests at the end, which build a proof through the
API on an in-memory database. Random cases use a fixed seed, so every run
checks the same inputs.
"""

import importlib.util
import json
import random
import uuid
from datetime import datetime as real_datetime, timezone
from pathlib import Path

import pytest

from app.canonical import (
    CURRENT_PROOF_VERSION,
    V3_PROOF_VERSION,
    EVENT_TAG,
    EVENT_TAG_V4,
    REQUEST_TAG,
    REQUEST_TAG_V4,
    build_event_canonical_v3,
    build_event_canonical_v4,
    build_request_canonical_v3,
    build_request_canonical_v4,
    parse_event_canonical_v3,
    parse_event_canonical_v4,
    parse_request_canonical_v3,
    parse_request_canonical_v4,
)
from app.crypto import chain_head, hash_event_record, sha256_json


REPO_ROOT = Path(__file__).resolve().parent
VECTORS_PATH = REPO_ROOT / "tests" / "fixtures" / "canonical_v4_vectors.json"

PROOF_ID = "proof_0123456789abcdef0123456789abcdef"
PAYLOAD_HASH = sha256_json({"content": "model output"})
PRIOR_HEAD = sha256_json({"previous": "event record"})

REQUEST_FIELDS = ("room-1", "nonce-1", "hello")
EVENT_FIELDS = (PROOF_ID, "result.created", PAYLOAD_HASH, "event-nonce-1", PRIOR_HEAD)

REQUEST = build_request_canonical_v4(*REQUEST_FIELDS)
EVENT = build_event_canonical_v4(*EVENT_FIELDS)


def test_formats_match_the_design():
    assert REQUEST_TAG_V4 == "FLOP/REQUEST/v4"
    assert EVENT_TAG_V4 == "FLOP/EVENT/v4"
    assert REQUEST == "FLOP/REQUEST/v4|room-1|nonce-1|hello"
    assert EVENT == (
        f"FLOP/EVENT/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}|event-nonce-1|{PRIOR_HEAD}"
    )


def test_v4_is_current_and_v3_unchanged():
    """Was test_v3_is_still_current_and_unchanged (§8 A); since §8 B new
    proofs are version 4 (D-C2) and the v3 formats stay as they were."""
    assert CURRENT_PROOF_VERSION == "4"
    assert V3_PROOF_VERSION == "3"
    assert (REQUEST_TAG, EVENT_TAG) == ("FLOP/REQUEST/v3", "FLOP/EVENT/v3")


# --- a) round trip ---------------------------------------------------------------

TEXTS = [
    "hello",
    "a|b",
    "|",
    "||",
    " ",
    "line one\nline two",
    "tab\tand\r\nnewline \x00 \x7f",
    "Türkçe ğüşıöç İ",
    "emoji 🔏|🧾",
    "FLOP/EVENT/v4|looks|like|an|event|x",
    "FLOP/REQUEST/v4|nested",
]


@pytest.mark.parametrize("text", TEXTS)
def test_request_round_trip(text):
    fields = ("room-ü 1", "nonce 2", text)
    assert parse_request_canonical_v4(build_request_canonical_v4(*fields)) == fields


@pytest.mark.parametrize(
    "event_type,nonce,prior_head",
    [
        ("result.created", "n", PRIOR_HEAD),
        ("task.delegated", "nonce with spaces", "0" * 64),
        ("custom.ünïcode", "日本", "f" * 64),
        ("proof.completed", "nonce-ü", PAYLOAD_HASH),
    ],
)
def test_event_round_trip(event_type, nonce, prior_head):
    fields = (PROOF_ID, event_type, PAYLOAD_HASH, nonce, prior_head)
    assert parse_event_canonical_v4(build_event_canonical_v4(*fields)) == fields


def test_request_v4_differs_from_v3_only_by_the_tag():
    v3 = build_request_canonical_v3(*REQUEST_FIELDS)
    assert REQUEST == "FLOP/REQUEST/v4" + v3[len("FLOP/REQUEST/v3"):]


# --- b) injectivity ----------------------------------------------------------------

def _random_string(rng, alphabet, max_length):
    # Length 0 included, so empty fields are among the rejected inputs.
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, max_length)))


def test_request_canonical_is_injective_over_random_fields():
    rng = random.Random(20261022)
    seen = {}
    built = rejected = 0

    for _ in range(50000):
        fields = (
            _random_string(rng, "aabb|", 3),
            _random_string(rng, "aabb|", 3),
            _random_string(rng, "ab||| ", 6),
        )
        try:
            canonical = build_request_canonical_v4(*fields)
        except ValueError:
            rejected += 1
            continue
        built += 1
        assert seen.setdefault(canonical, fields) == fields, canonical
        assert parse_request_canonical_v4(canonical) == fields

    assert built > 10000 and rejected > 10000, (built, rejected)
    assert len(seen) > 5000, len(seen)


def test_event_canonical_is_injective_over_random_fields():
    """type and nonce are "|"-heavy and short; prior_head is drawn from valid
    heads, invalid heads ("|"-joined pieces, short or upper-case) and hashes
    that equal a payload hash, so a field shifting into its neighbor would
    collide."""
    rng = random.Random(22102026)
    proof_ids = [f"proof_{rng.getrandbits(128):032x}" for _ in range(3)]
    hashes = [f"{rng.getrandbits(256):064x}" for _ in range(4)]
    heads = hashes * 3 + [
        "a|" + hashes[0][2:],
        hashes[1][:-1],
        hashes[2].upper(),
        "",
    ]
    seen = {}
    built = rejected = 0

    for _ in range(100000):
        fields = (
            rng.choice(proof_ids),
            _random_string(rng, "aab.|", 3),
            rng.choice(hashes),
            _random_string(rng, "aabb|", 3),
            rng.choice(heads),
        )
        try:
            canonical = build_event_canonical_v4(*fields)
        except ValueError:
            rejected += 1
            continue
        built += 1
        assert seen.setdefault(canonical, fields) == fields, canonical
        assert parse_event_canonical_v4(canonical) == fields

    assert built > 10000 and rejected > 10000, (built, rejected)
    assert len(seen) > 3000, len(seen)


# --- c) the D-R3 ambiguity is refused ----------------------------------------------

def test_ambiguous_event_fields_are_rejected_at_build():
    # Without D-R3 all three would be ...|a|b|n|<head> in some split.
    with pytest.raises(ValueError, match=r"^event_type: must not contain '\|'$"):
        build_event_canonical_v4(PROOF_ID, "a|b", PAYLOAD_HASH, "n", PRIOR_HEAD)
    with pytest.raises(ValueError, match=r"^nonce: must not contain '\|'$"):
        build_event_canonical_v4(PROOF_ID, "a", PAYLOAD_HASH, "b|n", PRIOR_HEAD)
    # nonce is no longer the last field: a "|" in it must not pass as a
    # prior_head split either.
    with pytest.raises(ValueError, match=r"^nonce: must not contain '\|'$"):
        build_event_canonical_v4(PROOF_ID, "a", PAYLOAD_HASH, f"n|{PRIOR_HEAD}", PRIOR_HEAD)


def test_extra_field_in_event_canonical_is_rejected_at_parse():
    # A seventh field lands in prior_head and fails its format.
    canonical = f"{EVENT_TAG_V4}|{PROOF_ID}|a|{PAYLOAD_HASH}|n|x|{PRIOR_HEAD}"
    with pytest.raises(ValueError, match=r"^prior_head: must not contain '\|'$"):
        parse_event_canonical_v4(canonical)
    with pytest.raises(ValueError, match=r"^prior_head: must not contain '\|'$"):
        parse_event_canonical_v4(f"{EVENT}|")


def test_ambiguous_request_fields_are_rejected_at_build():
    with pytest.raises(ValueError, match=r"^room: must not contain '\|'$"):
        build_request_canonical_v4("a|b", "c", "text")
    with pytest.raises(ValueError, match=r"^nonce: must not contain '\|'$"):
        build_request_canonical_v4("a", "b|c", "text")
    assert parse_request_canonical_v4("FLOP/REQUEST/v4|a|b|c|text") == ("a", "b", "c|text")


# --- d) cross rejection: v3 <-> v4, request <-> event ---------------------------------

V3_REQUEST = build_request_canonical_v3(*REQUEST_FIELDS)
V3_EVENT = build_event_canonical_v3(PROOF_ID, "result.created", PAYLOAD_HASH, "n")


def test_v3_canonicals_never_parse_as_v4():
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v4$"):
        parse_request_canonical_v4(V3_REQUEST)
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/EVENT/v4$"):
        parse_event_canonical_v4(V3_EVENT)
    # A v3 event given the v4 tag still lacks prior_head.
    with pytest.raises(ValueError, match=r"^canonical: wrong number of fields$"):
        parse_event_canonical_v4(EVENT_TAG_V4 + V3_EVENT[len(EVENT_TAG):])


def test_v4_canonicals_never_parse_as_v3():
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v3$"):
        parse_request_canonical_v3(REQUEST)
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/EVENT/v3$"):
        parse_event_canonical_v3(EVENT)
    # A v4 event relabelled v3: the sixth field lands in the v3 nonce.
    with pytest.raises(ValueError, match=r"^nonce: must not contain '\|'$"):
        parse_event_canonical_v3(EVENT_TAG + EVENT[len(EVENT_TAG_V4):])


def test_request_and_event_v4_never_parse_as_each_other():
    for text in TEXTS + [f"{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|{PRIOR_HEAD}"]:
        with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/EVENT/v4$"):
            parse_event_canonical_v4(build_request_canonical_v4("room", "n", text))
    for event_type in ("result.created", "request.created", "proof.completed"):
        canonical = build_event_canonical_v4(PROOF_ID, event_type, PAYLOAD_HASH, "n", PRIOR_HEAD)
        with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v4$"):
            parse_request_canonical_v4(canonical)


def test_v1_v2_canonicals_are_rejected():
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v4$"):
        parse_request_canonical_v4("room-1|nonce-1|hello")
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/EVENT/v4$"):
        parse_event_canonical_v4(f"{PROOF_ID}|result.created|{PAYLOAD_HASH}")


# --- e) tag variations -------------------------------------------------------------

BAD_REQUEST_TAGS = [
    "FLOP/REQUEST/v40", "FLOP/REQUEST/v3", "FLOP/REQUEST/v", "flop/request/v4",
    "FLOP/request/v4", " FLOP/REQUEST/v4", "FLOP/REQUEST/v4 ", "\nFLOP/REQUEST/v4",
    "FLOP/EVENT/v4", "",
]


@pytest.mark.parametrize("tag", BAD_REQUEST_TAGS)
def test_request_tag_must_match_exactly(tag):
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v4$"):
        parse_request_canonical_v4(f"{tag}|room-1|nonce-1|hello")


BAD_EVENT_TAGS = [
    "FLOP/EVENT/v40", "FLOP/EVENT/v3", "flop/event/v4", "Flop/Event/V4",
    " FLOP/EVENT/v4", "FLOP/EVENT/v4 ", "FLOP/EVENT/v4\t", "FLOP/REQUEST/v4", "",
]


@pytest.mark.parametrize("tag", BAD_EVENT_TAGS)
def test_event_tag_must_match_exactly(tag):
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/EVENT/v4$"):
        parse_event_canonical_v4(f"{tag}|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|{PRIOR_HEAD}")


def test_tag_without_fields_is_rejected():
    with pytest.raises(ValueError, match=r"^canonical: wrong number of fields$"):
        parse_request_canonical_v4("FLOP/REQUEST/v4")
    with pytest.raises(ValueError, match=r"^canonical: wrong number of fields$"):
        parse_event_canonical_v4("FLOP/EVENT/v4")


@pytest.mark.parametrize("value", [None, EVENT.encode(), 4])
def test_non_string_canonical_is_rejected(value):
    with pytest.raises(ValueError, match=r"^canonical: must be a string$"):
        parse_request_canonical_v4(value)
    with pytest.raises(ValueError, match=r"^canonical: must be a string$"):
        parse_event_canonical_v4(value)


# --- D-R10: control characters ---------------------------------------------------------

CONTROL_CHARACTERS = [chr(code) for code in range(0x20)] + ["\x7f"]


@pytest.mark.parametrize("char", CONTROL_CHARACTERS, ids=lambda c: f"0x{ord(c):02x}")
def test_control_characters_are_rejected_outside_request_text(char):
    with pytest.raises(ValueError, match=r"^room: must not contain control characters$"):
        build_request_canonical_v4(f"room{char}", "n", "t")
    with pytest.raises(ValueError, match=r"^nonce: must not contain control characters$"):
        build_request_canonical_v4("room", f"n{char}", "t")
    with pytest.raises(ValueError, match=r"^event_type: must not contain control characters$"):
        build_event_canonical_v4(PROOF_ID, f"type{char}", PAYLOAD_HASH, "n", PRIOR_HEAD)
    with pytest.raises(ValueError, match=r"^nonce: must not contain control characters$"):
        build_event_canonical_v4(PROOF_ID, "type", PAYLOAD_HASH, f"n{char}", PRIOR_HEAD)
    with pytest.raises(ValueError, match=r"^prior_head: must not contain control characters$"):
        build_event_canonical_v4(PROOF_ID, "type", PAYLOAD_HASH, "n", PRIOR_HEAD + char)
    with pytest.raises(ValueError, match=r"^nonce: must not contain control characters$"):
        parse_event_canonical_v4(f"{EVENT_TAG_V4}|{PROOF_ID}|type|{PAYLOAD_HASH}|n{char}|{PRIOR_HEAD}")


@pytest.mark.parametrize("char", CONTROL_CHARACTERS, ids=lambda c: f"0x{ord(c):02x}")
def test_control_characters_are_allowed_in_request_text(char):
    fields = ("room", "n", f"before{char}after")
    assert parse_request_canonical_v4(build_request_canonical_v4(*fields)) == fields


# --- f) each invalid field, at build and at parse -------------------------------------

def _event_parts(proof_id=PROOF_ID, event_type="result.created", payload_hash=PAYLOAD_HASH,
                 nonce="n", prior_head=PRIOR_HEAD):
    return proof_id, event_type, payload_hash, nonce, prior_head


INVALID_EVENT_FIELDS = [
    ({"proof_id": ""}, "proof_id: must not be empty"),
    ({"proof_id": "proof_task_hash_test"}, "proof_id: invalid format"),
    ({"proof_id": PROOF_ID + "\n"}, "proof_id: must not contain control characters"),
    ({"event_type": ""}, "event_type: must not be empty"),
    ({"event_type": "result|created"}, "event_type: must not contain '|'"),
    ({"payload_hash": PAYLOAD_HASH.upper()}, "payload_hash: must be 64 lowercase hex characters"),
    ({"payload_hash": PAYLOAD_HASH[:-1]}, "payload_hash: must be 64 lowercase hex characters"),
    ({"nonce": ""}, "nonce: must not be empty"),
    ({"nonce": "a|b"}, "nonce: must not contain '|'"),
    ({"nonce": None}, "nonce: must be a string"),
    ({"prior_head": ""}, "prior_head: must not be empty"),
    ({"prior_head": PRIOR_HEAD[:-1]}, "prior_head: must be 64 lowercase hex characters"),
    ({"prior_head": PRIOR_HEAD + "0"}, "prior_head: must be 64 lowercase hex characters"),
    ({"prior_head": PRIOR_HEAD.upper()}, "prior_head: must be 64 lowercase hex characters"),
    ({"prior_head": PRIOR_HEAD[:-1] + "A"}, "prior_head: must be 64 lowercase hex characters"),
    ({"prior_head": PRIOR_HEAD + "\n"}, "prior_head: must not contain control characters"),
    ({"prior_head": PRIOR_HEAD[:-1] + "\n"}, "prior_head: must not contain control characters"),
    ({"prior_head": "g" * 64}, "prior_head: must be 64 lowercase hex characters"),
    ({"prior_head": " " + PRIOR_HEAD[1:]}, "prior_head: must be 64 lowercase hex characters"),
    ({"prior_head": "sha256:" + PRIOR_HEAD}, "prior_head: must be 64 lowercase hex characters"),
    ({"prior_head": "0x" + PRIOR_HEAD[2:]}, "prior_head: must be 64 lowercase hex characters"),
    ({"prior_head": "a|" + PRIOR_HEAD[2:]}, "prior_head: must not contain '|'"),
    ({"prior_head": None}, "prior_head: must be a string"),
    ({"prior_head": bytes.fromhex(PRIOR_HEAD)}, "prior_head: must be a string"),
]


@pytest.mark.parametrize("override,message", INVALID_EVENT_FIELDS)
def test_build_event_rejects_invalid_field(override, message):
    with pytest.raises(ValueError) as error:
        build_event_canonical_v4(*_event_parts(**override))
    assert str(error.value) == message


@pytest.mark.parametrize(
    "override,message",
    [(o, m) for o, m in INVALID_EVENT_FIELDS if all(isinstance(v, str) for v in o.values())],
)
def test_parse_event_rejects_invalid_field(override, message):
    canonical = "|".join((EVENT_TAG_V4, *_event_parts(**override)))
    with pytest.raises(ValueError) as error:
        parse_event_canonical_v4(canonical)
    # A "|" inside an earlier field shifts the split, so the error then names
    # the field the extra part lands in; only the rejection is fixed there.
    shifted = any("|" in v for k, v in override.items() if k != "prior_head")
    if not shifted:
        assert str(error.value) == message


INVALID_REQUEST_FIELDS = [
    (("", "n", "t"), "room: must not be empty"),
    (("a|b", "n", "t"), "room: must not contain '|'"),
    ((PROOF_ID, "n", "t"), "room: must not be a proof_id"),
    (("room", "", "t"), "nonce: must not be empty"),
    (("room", "a|b", "t"), "nonce: must not contain '|'"),
    (("room", "n", ""), "text: must not be empty"),
    (("room", "n", None), "text: must be a string"),
]


@pytest.mark.parametrize("fields,message", INVALID_REQUEST_FIELDS)
def test_build_request_rejects_invalid_field(fields, message):
    with pytest.raises(ValueError) as error:
        build_request_canonical_v4(*fields)
    assert str(error.value) == message


# --- vectors for the SDK copy (§8 B) -------------------------------------------------

def _generator():
    spec = importlib.util.spec_from_file_location(
        "generate_canonical_v4_vectors",
        REPO_ROOT / "scripts" / "generate_canonical_v4_vectors.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vector_file_is_up_to_date_with_app():
    assert VECTORS_PATH.read_text(encoding="utf-8") == _generator().render(), (
        "run: python scripts/generate_canonical_v4_vectors.py"
    )


def test_vector_file_covers_valid_and_invalid_cases():
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    for kind in ("build_request", "build_event", "parse_request", "parse_event", "chain_head"):
        cases = vectors[kind]
        assert any("result" in case for case in cases), kind
        assert any("error" in case for case in cases), kind
    heads = vectors["chain_head"]
    assert any(case["events"] == [] and case["result"] is None for case in heads)
    prior_head_errors = {
        case["error"] for case in vectors["build_event"]
        if case.get("error", "").startswith("prior_head:")
    }
    assert len(prior_head_errors) >= 4, prior_head_errors


# --- chain_head ----------------------------------------------------------------------

def test_chain_head_of_no_events_is_none():
    assert chain_head([], proof_id=PROOF_ID) is None


def _exported_event(**overrides):
    event = {
        "event_id": "evt_" + "1" * 32,
        "type": "agent.started",
        "actor_did": "did:key:zExample",
        "payload_hash": PAYLOAD_HASH,
        "payload": {"a": 1},
        "canonical": EVENT,
        "signature": "s" * 86,
        "nonce": "n",
        "created_at": "2026-10-22T19:10:38.014507",
        "sequence": 2,
        "previous_event_hash": PRIOR_HEAD,
    }
    event.update(overrides)
    return event


def test_chain_head_reads_only_the_last_event_and_only_link_fields():
    last = _exported_event()
    expected = hash_event_record(
        event_id=last["event_id"], proof_id=PROOF_ID, event_type=last["type"],
        actor_did=last["actor_did"], payload_hash=last["payload_hash"],
        canonical=last["canonical"], signature=last["signature"],
        created_at=last["created_at"], sequence=last["sequence"],
    )
    assert chain_head([last], proof_id=PROOF_ID) == expected
    assert chain_head([_exported_event(event_id="evt_other"), last], proof_id=PROOF_ID) == expected
    # payload, nonce and previous_event_hash are not part of the link.
    for key, value in (("payload", {"b": 2}), ("nonce", "other"), ("previous_event_hash", None)):
        assert chain_head([_exported_event(**{key: value})], proof_id=PROOF_ID) == expected
    # Every link field is.
    for key, value in (
        ("event_id", "evt_x"), ("type", "x"), ("actor_did", "did:key:zOther"),
        ("payload_hash", PRIOR_HEAD), ("canonical", "c"), ("signature", "t" * 86),
        ("created_at", "2026-10-22T19:10:38.014508"), ("sequence", 3),
    ):
        assert chain_head([_exported_event(**{key: value})], proof_id=PROOF_ID) != expected, key
    assert chain_head([last], proof_id="proof_" + "f" * 32) != expected


@pytest.mark.parametrize(
    "events,message",
    [
        ("not a list", "events: must be a list"),
        (["x"], "events: last event must be an object"),
        ([{k: v for k, v in _exported_event().items() if k != "sequence"}],
         "events: last event is missing sequence"),
        ([_exported_event(created_at=real_datetime(2026, 10, 22, 19, 10, 38))],
         "events: created_at must be the exported string"),
    ],
)
def test_chain_head_rejects_malformed_input(events, message):
    with pytest.raises(ValueError) as error:
        chain_head(events, proof_id=PROOF_ID)
    assert str(error.value) == message


# --- chain_head against the API (M16) -------------------------------------------------

API_KEY = "canonical-v4-test-key"

# Server clock for create_event, in order: with and without microseconds, a
# trailing-zero fraction and a single microsecond (isoformat drops the
# fraction only when it is zero).
FIXED_TIMES = [
    real_datetime(2026, 10, 22, 19, 10, 38, 14507, tzinfo=timezone.utc),
    real_datetime(2026, 10, 22, 19, 10, 39, 0, tzinfo=timezone.utc),
    real_datetime(2026, 10, 22, 19, 10, 40, 500000, tzinfo=timezone.utc),
    real_datetime(2026, 10, 22, 19, 10, 41, 1, tzinfo=timezone.utc),
    real_datetime(2026, 10, 22, 19, 10, 42, 0, tzinfo=timezone.utc),
    real_datetime(2026, 10, 22, 19, 10, 43, 999999, tzinfo=timezone.utc),
]


@pytest.fixture
def api(monkeypatch):
    """TestClient on a fresh in-memory database; create_event reads FIXED_TIMES."""
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import events as events_module
    from app import main, models  # noqa: F401  (models registers the tables)
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

    times = iter(FIXED_TIMES)

    class FixedClock(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return next(times)

    monkeypatch.setattr(events_module, "datetime", FixedClock)
    monkeypatch.setattr(main, "API_KEY", API_KEY)
    previous = main.app.dependency_overrides.get(get_db)
    main.app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(main.app, headers={"X-API-Key": API_KEY}) as client:
            yield client
    finally:
        if previous is None:
            main.app.dependency_overrides.pop(get_db, None)
        else:
            main.app.dependency_overrides[get_db] = previous
        engine.dispose()


def test_chain_head_from_the_export_equals_the_next_previous_event_hash(api):
    """Before every append, chain_head over GET /proofs/{id} must equal the
    previous_event_hash the API then writes for the new event (§8 A, M16).
    The proof is version 4, so each event also signs that head; the API
    accepting it (201) shows the API computes the same value under its lock."""
    from app.crypto import generate_test_keypair, public_key_to_test_did, sign_message

    key, public_key = generate_test_keypair()
    did = public_key_to_test_did(public_key)
    request_nonce = f"n-{uuid.uuid4().hex}"
    request_canonical = build_request_canonical_v4("room-v4", request_nonce, "chain head")
    created = api.post("/proofs", json={"request": {
        "request_id": f"req-{uuid.uuid4().hex}",
        "from_did": did,
        "text": "chain head",
        "created_at": "2026-10-22T19:10:38+00:00",
        "signature": {
            "nonce": request_nonce,
            "canonical": request_canonical,
            "sig": sign_message(key, request_canonical.encode()),
        },
    }})
    assert created.status_code == 201, created.text
    proof_id = created.json()["proof_id"]

    rows = []
    for index, (event_type, payload) in enumerate([
        ("agent.started", {"step": 1}),
        ("artifact.note", {"ünïcode": "değer"}),
        ("result.created", {"content": "done"}),
        ("agent.finished", {}),
        ("proof.completed", {}),
    ]):
        exported = api.get(f"/proofs/{proof_id}").json()
        head = chain_head(exported["events"], proof_id=proof_id)
        nonce = f"n-{index}"
        canonical = build_event_canonical_v4(proof_id, event_type, sha256_json(payload), nonce, head)
        response = api.post(f"/proofs/{proof_id}/events", json={
            "type": event_type,
            "actor_did": did,
            "payload": payload,
            "signature": {
                "nonce": nonce,
                "canonical": canonical,
                "sig": sign_message(key, canonical.encode()),
                "prior_head": head,
            },
        })
        assert response.status_code == 201, response.text
        written = api.get(f"/proofs/{proof_id}").json()["events"][-1]
        rows.append((exported["events"][-1]["created_at"], head, written["previous_event_hash"]))
        assert written["sequence"] == len(exported["events"]) + 1
        assert head == written["previous_event_hash"], (event_type, exported["events"][-1]["created_at"])
        assert head == exported["chain_head"]

    final = api.get(f"/proofs/{proof_id}").json()["events"]
    created_at = [event["created_at"] for event in final]
    print()
    for hashed_created_at, head, written in rows:
        print(f"last created_at {hashed_created_at:<28} chain_head {head[:16]}…  "
              f"next previous_event_hash {written[:16]}…  equal {head == written}")
    print(f"final head {chain_head(final, proof_id=proof_id)}")
    # The fixed clock reached every event, with and without a fraction.
    assert created_at == [
        "2026-10-22T19:10:38.014507",
        "2026-10-22T19:10:39",
        "2026-10-22T19:10:40.500000",
        "2026-10-22T19:10:41.000001",
        "2026-10-22T19:10:42",
        "2026-10-22T19:10:43.999999",
    ]
