"""Unit tests for app/canonical.py (docs/design/event-replay.md, D-R2, D-R3).

Pure: no database, no HTTP. Random cases use a fixed seed, so every run checks
the same inputs.
"""

import random

import pytest

from app.canonical import (
    EVENT_TAG,
    REQUEST_TAG,
    build_event_canonical_v3,
    build_request_canonical_v3,
    parse_event_canonical_v3,
    parse_request_canonical_v3,
)
from app.crypto import canonical_signed_message, sha256_json


PROOF_ID = "proof_0123456789abcdef0123456789abcdef"
PAYLOAD_HASH = sha256_json({"content": "model output"})

REQUEST_FIELDS = ("room-1", "nonce-1", "hello")
EVENT_FIELDS = (PROOF_ID, "result.created", PAYLOAD_HASH, "event-nonce-1")

REQUEST = build_request_canonical_v3(*REQUEST_FIELDS)
EVENT = build_event_canonical_v3(*EVENT_FIELDS)


def test_formats_match_the_design():
    assert REQUEST_TAG == "FLOP/REQUEST/v3"
    assert EVENT_TAG == "FLOP/EVENT/v3"
    assert REQUEST == "FLOP/REQUEST/v3|room-1|nonce-1|hello"
    assert EVENT == f"FLOP/EVENT/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}|event-nonce-1"


# --- a) round trip ---------------------------------------------------------------

TEXTS = [
    "hello",
    "a|b",
    "|",
    "||",
    "|leading",
    "trailing|",
    " ",
    "  spaced  text  ",
    "line one\nline two",
    "tab\tand\r\nnewline",
    "Türkçe ğüşıöç İ",
    "日本語のテキスト",
    "emoji 🔏|🧾",
    "FLOP/EVENT/v3|looks|like|an|event",
    "FLOP/REQUEST/v3|nested",
]


@pytest.mark.parametrize("text", TEXTS)
def test_request_round_trip(text):
    fields = ("room-ü 1", "nonce\n2", text)
    assert parse_request_canonical_v3(build_request_canonical_v3(*fields)) == fields


@pytest.mark.parametrize(
    "event_type,nonce",
    [
        ("result.created", "n"),
        ("task.delegated", "nonce with spaces"),
        ("custom.ünïcode", "日本"),
        ("x", "line\nbreak"),
    ],
)
def test_event_round_trip(event_type, nonce):
    fields = (PROOF_ID, event_type, PAYLOAD_HASH, nonce)
    assert parse_event_canonical_v3(build_event_canonical_v3(*fields)) == fields


# --- b) injectivity ----------------------------------------------------------------

def _random_string(rng, alphabet, max_length):
    # Length 0 included, so empty fields are among the rejected inputs.
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, max_length)))


def test_request_canonical_is_injective_over_random_fields():
    """Small alphabets and short lengths make collisions likely if the format
    were ambiguous; text is "|"-heavy. Inputs a build rejects are skipped."""
    rng = random.Random(20261004)
    seen = {}
    built = rejected = 0

    for _ in range(50000):
        fields = (
            _random_string(rng, "aabb|", 3),
            _random_string(rng, "aabb|", 3),
            _random_string(rng, "ab||| ", 6),
        )
        try:
            canonical = build_request_canonical_v3(*fields)
        except ValueError:
            rejected += 1
            continue
        built += 1
        assert seen.setdefault(canonical, fields) == fields, canonical
        assert parse_request_canonical_v3(canonical) == fields

    assert built > 10000 and rejected > 10000, (built, rejected)
    assert len(seen) > 5000, len(seen)


def test_event_canonical_is_injective_over_random_fields():
    rng = random.Random(4102026)
    proof_ids = [f"proof_{rng.getrandbits(128):032x}" for _ in range(5)]
    hashes = [f"{rng.getrandbits(256):064x}" for _ in range(5)]
    seen = {}
    built = rejected = 0

    for _ in range(50000):
        fields = (
            rng.choice(proof_ids),
            _random_string(rng, "aab.|", 3),
            rng.choice(hashes),
            _random_string(rng, "aabb|", 3),
        )
        try:
            canonical = build_event_canonical_v3(*fields)
        except ValueError:
            rejected += 1
            continue
        built += 1
        assert seen.setdefault(canonical, fields) == fields, canonical
        assert parse_event_canonical_v3(canonical) == fields

    assert built > 10000 and rejected > 10000, (built, rejected)
    assert len(seen) > 3000, len(seen)


# --- c) the D-R3 ambiguity is refused at build time --------------------------------

def test_ambiguous_request_fields_are_rejected_at_build():
    # Without D-R3 both would be "FLOP/REQUEST/v3|a|b|c|text".
    with pytest.raises(ValueError, match=r"^room: must not contain '\|'$"):
        build_request_canonical_v3("a|b", "c", "text")
    with pytest.raises(ValueError, match=r"^nonce: must not contain '\|'$"):
        build_request_canonical_v3("a", "b|c", "text")
    # The one reading left: "|" belongs to text.
    assert parse_request_canonical_v3("FLOP/REQUEST/v3|a|b|c|text") == ("a", "b", "c|text")


def test_ambiguous_event_fields_are_rejected_at_build():
    with pytest.raises(ValueError, match=r"^event_type: must not contain '\|'$"):
        build_event_canonical_v3(PROOF_ID, "a|b", PAYLOAD_HASH, "n")
    with pytest.raises(ValueError, match=r"^nonce: must not contain '\|'$"):
        build_event_canonical_v3(PROOF_ID, "a", PAYLOAD_HASH, "b|n")


# --- d) a request never parses as an event, and the other way round ----------------

def test_request_canonical_never_parses_as_event():
    rng = random.Random(7)
    for text in TEXTS + [f"{PROOF_ID}|result.created|{PAYLOAD_HASH}|n"]:
        canonical = build_request_canonical_v3(f"room{rng.randint(0, 9)}", "n", text)
        with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/EVENT/v3$"):
            parse_event_canonical_v3(canonical)


def test_event_canonical_never_parses_as_request():
    for event_type in ("result.created", "task.delegated", "request.created"):
        canonical = build_event_canonical_v3(PROOF_ID, event_type, PAYLOAD_HASH, "n")
        with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v3$"):
            parse_request_canonical_v3(canonical)


# --- e) v1/v2 formats are rejected -------------------------------------------------

def test_v1_v2_request_canonical_is_rejected():
    old = canonical_signed_message("room-1", "nonce-1", "hello").decode("utf-8")
    assert old == "room-1|nonce-1|hello"
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v3$"):
        parse_request_canonical_v3(old)
    with pytest.raises(ValueError):
        parse_event_canonical_v3(old)


def test_v1_v2_event_canonical_is_rejected():
    old = f"{PROOF_ID}|result.created|{PAYLOAD_HASH}"
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/EVENT/v3$"):
        parse_event_canonical_v3(old)
    with pytest.raises(ValueError):
        parse_request_canonical_v3(old)


def test_event_canonical_without_nonce_is_rejected():
    with pytest.raises(ValueError, match=r"^canonical: wrong number of fields$"):
        parse_event_canonical_v3(f"{EVENT_TAG}|{PROOF_ID}|result.created|{PAYLOAD_HASH}")


# --- f) tag variations ---------------------------------------------------------------

BAD_REQUEST_TAGS = [
    "FLOP/REQUEST/v30",
    "FLOP/REQUEST/v2",
    "FLOP/REQUEST/v",
    "flop/request/v3",
    "FLOP/request/v3",
    " FLOP/REQUEST/v3",
    "FLOP/REQUEST/v3 ",
    "\nFLOP/REQUEST/v3",
    "FLOP/EVENT/v3",
    "",
]


@pytest.mark.parametrize("tag", BAD_REQUEST_TAGS)
def test_request_tag_must_match_exactly(tag):
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v3$"):
        parse_request_canonical_v3(f"{tag}|room-1|nonce-1|hello")


BAD_EVENT_TAGS = [
    "FLOP/EVENT/v30",
    "FLOP/EVENT/v2",
    "flop/event/v3",
    "Flop/Event/V3",
    " FLOP/EVENT/v3",
    "FLOP/EVENT/v3 ",
    "FLOP/EVENT/v3\t",
    "FLOP/REQUEST/v3",
    "",
]


@pytest.mark.parametrize("tag", BAD_EVENT_TAGS)
def test_event_tag_must_match_exactly(tag):
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/EVENT/v3$"):
        parse_event_canonical_v3(f"{tag}|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n")


def test_missing_tag_is_rejected():
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v3$"):
        parse_request_canonical_v3("|room-1|nonce-1|hello")
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/REQUEST/v3$"):
        parse_request_canonical_v3("")
    # A tag without fields is not a message.
    with pytest.raises(ValueError, match=r"^canonical: wrong number of fields$"):
        parse_request_canonical_v3("FLOP/REQUEST/v3")
    with pytest.raises(ValueError, match=r"^canonical: tag must be FLOP/EVENT/v3$"):
        parse_event_canonical_v3(f"|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n")


@pytest.mark.parametrize("value", [None, b"FLOP/REQUEST/v3|r|n|t", 3])
def test_non_string_canonical_is_rejected(value):
    with pytest.raises(ValueError, match=r"^canonical: must be a string$"):
        parse_request_canonical_v3(value)
    with pytest.raises(ValueError, match=r"^canonical: must be a string$"):
        parse_event_canonical_v3(value)


# --- g) each invalid field, at build and at parse -------------------------------------

def _request_parts(room="room-1", nonce="nonce-1", text="hello"):
    return room, nonce, text


INVALID_REQUEST_FIELDS = [
    ({"room": ""}, "room: must not be empty"),
    ({"room": "a|b"}, "room: must not contain '|'"),
    ({"room": PROOF_ID}, "room: must not be a proof_id"),
    ({"room": None}, "room: must be a string"),
    ({"nonce": ""}, "nonce: must not be empty"),
    ({"nonce": "a|b"}, "nonce: must not contain '|'"),
    ({"nonce": 7}, "nonce: must be a string"),
    ({"text": ""}, "text: must not be empty"),
    ({"text": None}, "text: must be a string"),
]


@pytest.mark.parametrize("override,message", INVALID_REQUEST_FIELDS)
def test_build_request_rejects_invalid_field(override, message):
    with pytest.raises(ValueError) as error:
        build_request_canonical_v3(*_request_parts(**override))
    assert str(error.value) == message


@pytest.mark.parametrize(
    "canonical,message",
    [
        ("FLOP/REQUEST/v3||nonce-1|hello", "room: must not be empty"),
        (f"FLOP/REQUEST/v3|{PROOF_ID}|nonce-1|hello", "room: must not be a proof_id"),
        ("FLOP/REQUEST/v3|room-1||hello", "nonce: must not be empty"),
        ("FLOP/REQUEST/v3|room-1|nonce-1|", "text: must not be empty"),
        ("FLOP/REQUEST/v3|room-1|nonce-1", "canonical: wrong number of fields"),
        ("FLOP/REQUEST/v3|room-1", "canonical: wrong number of fields"),
    ],
)
def test_parse_request_rejects_invalid_field(canonical, message):
    with pytest.raises(ValueError) as error:
        parse_request_canonical_v3(canonical)
    assert str(error.value) == message


def _event_parts(proof_id=PROOF_ID, event_type="result.created", payload_hash=PAYLOAD_HASH, nonce="n"):
    return proof_id, event_type, payload_hash, nonce


INVALID_EVENT_FIELDS = [
    ({"proof_id": ""}, "proof_id: must not be empty"),
    ({"proof_id": "proof_task_hash_test"}, "proof_id: invalid format"),
    ({"proof_id": PROOF_ID.upper()}, "proof_id: invalid format"),
    ({"proof_id": PROOF_ID + "0"}, "proof_id: invalid format"),
    ({"proof_id": PROOF_ID + "\n"}, "proof_id: invalid format"),
    ({"proof_id": "x|" + PROOF_ID}, "proof_id: must not contain '|'"),
    ({"event_type": ""}, "event_type: must not be empty"),
    ({"event_type": "result|created"}, "event_type: must not contain '|'"),
    ({"payload_hash": ""}, "payload_hash: must not be empty"),
    ({"payload_hash": "sha256:" + PAYLOAD_HASH}, "payload_hash: must be 64 lowercase hex characters"),
    ({"payload_hash": PAYLOAD_HASH.upper()}, "payload_hash: must be 64 lowercase hex characters"),
    ({"payload_hash": PAYLOAD_HASH[:-1]}, "payload_hash: must be 64 lowercase hex characters"),
    ({"payload_hash": PAYLOAD_HASH + "0"}, "payload_hash: must be 64 lowercase hex characters"),
    ({"payload_hash": PAYLOAD_HASH + "\n"}, "payload_hash: must be 64 lowercase hex characters"),
    ({"payload_hash": "g" * 64}, "payload_hash: must be 64 lowercase hex characters"),
    ({"nonce": ""}, "nonce: must not be empty"),
    ({"nonce": "a|b"}, "nonce: must not contain '|'"),
    ({"nonce": None}, "nonce: must be a string"),
]


@pytest.mark.parametrize("override,message", INVALID_EVENT_FIELDS)
def test_build_event_rejects_invalid_field(override, message):
    with pytest.raises(ValueError) as error:
        build_event_canonical_v3(*_event_parts(**override))
    assert str(error.value) == message


@pytest.mark.parametrize(
    "override,message",
    [(o, m) for o, m in INVALID_EVENT_FIELDS if all(isinstance(v, str) for v in o.values())],
)
def test_parse_event_rejects_invalid_field(override, message):
    canonical = "|".join((EVENT_TAG, *_event_parts(**override)))
    with pytest.raises(ValueError) as error:
        parse_event_canonical_v3(canonical)
    # A "|" inside a field shifts the split; the error then names the field
    # the extra part lands in, so only the rejection itself is fixed here.
    if "|" not in "".join(override.values()):
        assert str(error.value) == message
