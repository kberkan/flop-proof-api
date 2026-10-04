"""Version-3 signed message formats (docs/design/event-replay.md, D-R2, D-R3).

    request: FLOP/REQUEST/v3|room|nonce|text
    event:   FLOP/EVENT/v3|proof_id|type|payload_hash|nonce

Pure functions: no database, network or global state. Not wired into the API
or the verifier yet; the v1/v2 formats (app/crypto.py canonical_signed_message,
f"{proof_id}|{type}|{payload_hash}") are unchanged.

Every field before the last is free of "|", so splitting at "|" gives back the
fields and different field tuples never give the same message (D-R3). In a
request, text is the last field and may contain "|". In an event every field is
free of "|": proof_id and payload_hash by their format, type and nonce by D-R3.

Rules the design document does not state, chosen here:

- Empty fields are rejected. Today POST /proofs rejects an empty text
  (app/schemas.py, min_length=1) and verify_floop_signature an empty room.
  Whitespace-only values are accepted, as they are today.
- A request room matching the proof_id pattern is rejected. The tag already
  keeps event and request messages apart; the document calls the v1/v2 rule
  redundant for v3 but does not say it is dropped, so it is kept.
- payload_hash must be 64 lowercase hex characters, the format sha256_json
  produces and the only format in proofs.db today; no "sha256:" prefix.
- Patterns are applied with fullmatch: in Python "$" also matches before a
  trailing newline, so PROOF_ID_PATTERN.match accepts "proof_<32 hex>\n"
  (and so does app/crypto.py is_proof_id).
- No other character restrictions (newlines, control characters, Unicode are
  allowed in room, nonce and type); the document sets none.
"""

import re

from .crypto import PROOF_ID_PATTERN


REQUEST_TAG = "FLOP/REQUEST/v3"
EVENT_TAG = "FLOP/EVENT/v3"
SEPARATOR = "|"

PAYLOAD_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _check_field(name: str, value: object, *, allow_separator: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name}: must be a string")
    if not value:
        raise ValueError(f"{name}: must not be empty")
    if not allow_separator and SEPARATOR in value:
        raise ValueError(f"{name}: must not contain '|'")
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
    text = _check_field("text", text, allow_separator=True)
    return SEPARATOR.join((REQUEST_TAG, room, nonce, text))


def parse_request_canonical_v3(canonical: str) -> tuple[str, str, str]:
    room, nonce, text = _split_tagged(canonical, REQUEST_TAG, 3)
    return (
        _check_room(room),
        _check_field("nonce", nonce),
        _check_field("text", text, allow_separator=True),
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
