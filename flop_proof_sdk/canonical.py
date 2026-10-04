"""Version-3 signed message formats, SDK copy.

    request: FLOP/REQUEST/v3|room|nonce|text
    event:   FLOP/EVENT/v3|proof_id|type|payload_hash|nonce

A copy of the API's app/canonical.py: the SDK is installed on its own and
cannot import the API package. test_sdk_canonical_v3.py checks that both give
the same canonical, or the same rejection message, for the shared vectors in
tests/fixtures/canonical_v3_vectors.json and for seeded random inputs.

Rules (docs/design/event-replay.md, D-R2, D-R3, D-R9, D-R10): room, nonce and
type are non-empty and contain neither "|" nor control characters; text is
non-empty and free; proof_id matches the API's proof_id pattern; payload_hash
is 64 lowercase hex characters; a room must not be a proof_id; the tag must
match exactly. Errors are ValueError.
"""

import re


REQUEST_TAG = "FLOP/REQUEST/v3"
EVENT_TAG = "FLOP/EVENT/v3"
SEPARATOR = "|"

# Same pattern as app/crypto.py PROOF_ID_PATTERN; used with fullmatch (D-R9).
PROOF_ID_PATTERN = re.compile(r"^proof_[0-9a-f]{32}$")
PAYLOAD_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def _check_field(name: str, value: object, *, free_text: bool = False) -> str:
    """free_text: the request text, which may contain "|" (D-R3) and control
    characters (D-R10)."""
    if not isinstance(value, str):
        raise ValueError(f"{name}: must be a string")
    if not value:
        raise ValueError(f"{name}: must not be empty")
    if not free_text and SEPARATOR in value:
        raise ValueError(f"{name}: must not contain '|'")
    if not free_text and CONTROL_CHARACTERS.search(value):
        raise ValueError(f"{name}: must not contain control characters")
    return value


def _check_room(room: object) -> str:
    room = _check_field("room", room)
    if PROOF_ID_PATTERN.fullmatch(room):
        raise ValueError("room: must not be a proof_id")
    return room


def _check_proof_id(proof_id: object) -> str:
    proof_id = _check_field("proof_id", proof_id)
    if not PROOF_ID_PATTERN.fullmatch(proof_id):
        raise ValueError("proof_id: invalid format")
    return proof_id


def _check_payload_hash(payload_hash: object) -> str:
    payload_hash = _check_field("payload_hash", payload_hash)
    if not PAYLOAD_HASH_PATTERN.fullmatch(payload_hash):
        raise ValueError("payload_hash: must be 64 lowercase hex characters")
    return payload_hash


def _split_tagged(canonical: object, tag: str, field_count: int) -> list[str]:
    if not isinstance(canonical, str):
        raise ValueError("canonical: must be a string")
    # maxsplit keeps any "|" in the last field (request text) inside it.
    parts = canonical.split(SEPARATOR, field_count)
    if parts[0] != tag:
        raise ValueError(f"canonical: tag must be {tag}")
    if len(parts) != field_count + 1:
        raise ValueError("canonical: wrong number of fields")
    return parts[1:]


def build_request_canonical_v3(room: str, nonce: str, text: str) -> str:
    room = _check_room(room)
    nonce = _check_field("nonce", nonce)
    text = _check_field("text", text, free_text=True)
    return SEPARATOR.join((REQUEST_TAG, room, nonce, text))


def parse_request_canonical_v3(canonical: str) -> tuple[str, str, str]:
    room, nonce, text = _split_tagged(canonical, REQUEST_TAG, 3)
    return (
        _check_room(room),
        _check_field("nonce", nonce),
        _check_field("text", text, free_text=True),
    )


def build_event_canonical_v3(
    proof_id: str,
    event_type: str,
    payload_hash: str,
    nonce: str,
) -> str:
    proof_id = _check_proof_id(proof_id)
    event_type = _check_field("event_type", event_type)
    payload_hash = _check_payload_hash(payload_hash)
    nonce = _check_field("nonce", nonce)
    return SEPARATOR.join((EVENT_TAG, proof_id, event_type, payload_hash, nonce))


def parse_event_canonical_v3(canonical: str) -> tuple[str, str, str, str]:
    # No event field may contain "|", so a fifth "|" lands in the nonce and is
    # rejected there.
    proof_id, event_type, payload_hash, nonce = _split_tagged(canonical, EVENT_TAG, 4)
    return (
        _check_proof_id(proof_id),
        _check_field("event_type", event_type),
        _check_payload_hash(payload_hash),
        _check_field("nonce", nonce),
    )
