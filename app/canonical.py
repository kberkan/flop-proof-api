"""Signed message formats of version-3 (docs/design/event-replay.md, D-R2,
D-R3, D-R10) and version-4 proofs (docs/design/proof-closure.md, D-C1, D-C2;
below the v3 functions).

    request: FLOP/REQUEST/v3|room|nonce|text
    event:   FLOP/EVENT/v3|proof_id|type|payload_hash|nonce

Pure functions: no database, network or global state. Used by the API for
version-3 and version-4 proofs and by the verifier; the v1/v2 formats (app/crypto.py
canonical_signed_message, f"{proof_id}|{type}|{payload_hash}") are unchanged.
flop_proof_sdk/canonical.py is a copy that must give the same results
(test_sdk_canonical_v3.py).

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
- Patterns are applied with fullmatch (D-R9): in Python "$" also matches
  before a trailing newline.

D-R10: room, nonce and type must not contain control characters
(\x00-\x1f, \x7f). text may contain them. Unicode is allowed everywhere.
"""

import re

from .crypto import PROOF_ID_PATTERN


REQUEST_TAG = "FLOP/REQUEST/v3"
EVENT_TAG = "FLOP/EVENT/v3"
SEPARATOR = "|"
# Version-3 proofs use these formats; the tag version equals the proof version
# (D-R1, D-R2). v1/v2 proofs keep the untagged formats (D-R5). New proofs are
# version "4" (below; docs/design/proof-closure.md D-C2); "3" proofs are still
# verified on their own path, not as legacy v1/v2.
V3_PROOF_VERSION = "3"
CURRENT_PROOF_VERSION = "4"
LEGACY_PROOF_VERSIONS = frozenset({"1", "2"})

# Every tagged message starts with this. The v1/v2 verification path rejects
# any canonical that does (D-R11).
TAG_PREFIX = "FLOP/"

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


# --- Version 4 (docs/design/proof-closure.md §3.2.1, D-C1, D-C2) ---------------
#
#     request: FLOP/REQUEST/v4|room|nonce|text
#     event:   FLOP/EVENT/v4|proof_id|type|payload_hash|nonce|prior_head
#
# New proofs are version "4" (CURRENT_PROOF_VERSION above). The v4 request is
# the v3 request with another tag (D-C2: a tag change only), so the field rules
# are the v3 helpers above, unchanged. The v4 event
# adds prior_head as the last field; nonce is no longer last, which changes
# nothing for it: event fields are already "|"-free by D-R3.
#
# Rules the design document does not state, chosen here:
#
# - The v3 rule "a request room matching the proof_id pattern is rejected"
#   carries over to v4. The design says the v4 request differs only by its
#   tag, so the v3 field rules are kept as they are.
# - prior_head uses the payload_hash format (64 lowercase hex, fullmatch,
#   D-R9) with its own field name in error messages; an all-zero or otherwise
#   "trivial" head is not rejected, since any link hash is a valid value here.

REQUEST_TAG_V4 = "FLOP/REQUEST/v4"
EVENT_TAG_V4 = "FLOP/EVENT/v4"


def _check_prior_head(prior_head: object) -> str:
    prior_head = _check_field("prior_head", prior_head)
    if not PAYLOAD_HASH_PATTERN.fullmatch(prior_head):
        raise ValueError("prior_head: must be 64 lowercase hex characters")
    return prior_head


def build_request_canonical_v4(room: str, nonce: str, text: str) -> str:
    room = _check_room(room)
    nonce = _check_field("nonce", nonce)
    text = _check_field("text", text, free_text=True)
    return SEPARATOR.join((REQUEST_TAG_V4, room, nonce, text))


def parse_request_canonical_v4(canonical: str) -> tuple[str, str, str]:
    room, nonce, text = _split_tagged(canonical, REQUEST_TAG_V4, 3)
    return (
        _check_room(room),
        _check_field("nonce", nonce),
        _check_field("text", text, free_text=True),
    )


def build_event_canonical_v4(
    proof_id: str,
    event_type: str,
    payload_hash: str,
    nonce: str,
    prior_head: str,
) -> str:
    proof_id = _check_proof_id(proof_id)
    event_type = _check_field("event_type", event_type)
    payload_hash = _check_payload_hash(payload_hash)
    nonce = _check_field("nonce", nonce)
    prior_head = _check_prior_head(prior_head)
    return SEPARATOR.join(
        (EVENT_TAG_V4, proof_id, event_type, payload_hash, nonce, prior_head)
    )


def parse_event_canonical_v4(canonical: str) -> tuple[str, str, str, str, str]:
    # No event field may contain "|", so a sixth "|" lands in prior_head and
    # is rejected there by its format.
    proof_id, event_type, payload_hash, nonce, prior_head = _split_tagged(
        canonical, EVENT_TAG_V4, 5
    )
    return (
        _check_proof_id(proof_id),
        _check_field("event_type", event_type),
        _check_payload_hash(payload_hash),
        _check_field("nonce", nonce),
        _check_prior_head(prior_head),
    )
