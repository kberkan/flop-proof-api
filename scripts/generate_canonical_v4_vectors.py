"""Generate tests/fixtures/canonical_v4_vectors.json from app/canonical.py and
app/crypto.py.

The vectors pin the version-4 canonical rules and the chain head
(docs/design/proof-closure.md §3.2.1, D-C1, D-C2, D-C5; event-replay.md D-R3,
D-R9, D-R10) so the SDK copy can be checked against them without importing the
API package (proof-closure.md §8 B).

    python scripts/generate_canonical_v4_vectors.py           # write the file
    python scripts/generate_canonical_v4_vectors.py --check   # exit 1 if stale
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.canonical import (  # noqa: E402
    build_event_canonical_v4,
    build_request_canonical_v4,
    parse_event_canonical_v4,
    parse_request_canonical_v4,
)
from app.crypto import chain_head  # noqa: E402

VECTORS_PATH = REPO_ROOT / "tests" / "fixtures" / "canonical_v4_vectors.json"

PROOF_ID = "proof_0123456789abcdef0123456789abcdef"
PAYLOAD_HASH = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
PRIOR_HEAD = "9d5ed678fe57bcca610140957afab571b33d5c3e8a7e52b0ce3c8b5d5e1dd8b2"

BUILD_REQUEST_INPUTS = [
    # valid
    ("room-1", "nonce-1", "hello"),
    ("room-1", "nonce-1", "a|b||c|"),
    ("oda-ğüşıöç", "nonce-日本", "Türkçe metin 🔏"),
    ("room-1", "nonce-1", "line one\nline two\r\n\ttab \x00 \x7f"),
    ("room-1", "nonce-1", "FLOP/EVENT/v4|looks|like|an|event|x"),
    # invalid
    ("", "nonce-1", "hello"),
    ("a|b", "nonce-1", "hello"),
    ("room\n", "nonce-1", "hello"),
    (PROOF_ID, "nonce-1", "hello"),
    ("room-1", "", "hello"),
    ("room-1", "b|c", "hello"),
    ("room-1", "nonce\x7f", "hello"),
    ("room-1", "nonce-1", ""),
    (None, "nonce-1", "hello"),
]

BUILD_EVENT_INPUTS = [
    # valid
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", PRIOR_HEAD),
    (PROOF_ID, "custom.ünïcode", PAYLOAD_HASH, "nonce-日本 with spaces", PRIOR_HEAD),
    (PROOF_ID, "proof.completed", PAYLOAD_HASH, "n", "0" * 64),
    # invalid: the v3 fields
    ("proof_task_hash_test", "result.created", PAYLOAD_HASH, "n", PRIOR_HEAD),
    (PROOF_ID, "result|created", PAYLOAD_HASH, "n", PRIOR_HEAD),
    (PROOF_ID, "result.created\n", PAYLOAD_HASH, "n", PRIOR_HEAD),
    (PROOF_ID, "result.created", PAYLOAD_HASH.upper(), "n", PRIOR_HEAD),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "", PRIOR_HEAD),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "a|b", PRIOR_HEAD),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n\x00", PRIOR_HEAD),
    # invalid: prior_head
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", ""),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", PRIOR_HEAD[:-1]),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", PRIOR_HEAD + "0"),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", PRIOR_HEAD.upper()),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", PRIOR_HEAD + "\n"),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", "g" * 64),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", "sha256:" + PRIOR_HEAD),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", "a|" + PRIOR_HEAD[2:]),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n", None),
]

PARSE_REQUEST_INPUTS = [
    "FLOP/REQUEST/v4|room-1|nonce-1|hello",
    "FLOP/REQUEST/v4|a|b|c|text",
    "FLOP/REQUEST/v3|room-1|nonce-1|hello",
    "room-1|nonce-1|hello",
    f"FLOP/EVENT/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|{PRIOR_HEAD}",
    "FLOP/REQUEST/v40|room-1|nonce-1|hello",
    "flop/request/v4|room-1|nonce-1|hello",
    "FLOP/REQUEST/v4",
    "FLOP/REQUEST/v4|room-1|nonce-1",
    f"FLOP/REQUEST/v4|{PROOF_ID}|nonce-1|hello",
    "FLOP/REQUEST/v4|room-1|nonce\t|hello",
    None,
]

PARSE_EVENT_INPUTS = [
    f"FLOP/EVENT/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|{PRIOR_HEAD}",
    f"FLOP/EVENT/v4|{PROOF_ID}|custom.ünïcode|{PAYLOAD_HASH}|日本|{PRIOR_HEAD}",
    f"FLOP/EVENT/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|{PRIOR_HEAD}",
    f"FLOP/EVENT/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|x|{PRIOR_HEAD}",
    f"FLOP/EVENT/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|{PRIOR_HEAD}|",
    f"FLOP/EVENT/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|{PRIOR_HEAD}\n",
    f"FLOP/EVENT/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|{PRIOR_HEAD.upper()}",
    f"FLOP/EVENT/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}||{PRIOR_HEAD}",
    "FLOP/REQUEST/v4|room-1|nonce-1|hello",
    f"{PROOF_ID}|result.created|{PAYLOAD_HASH}",
    f"flop/event/v4|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|{PRIOR_HEAD}",
    None,
]

ACTOR = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


def _event(sequence, created_at, **overrides):
    event = {
        "event_id": f"evt_{sequence:032x}",
        "type": "agent.started" if sequence > 1 else "request.created",
        "actor_did": ACTOR,
        "payload_hash": PAYLOAD_HASH,
        "payload": {"ignored": "not part of the link"},
        "canonical": f"FLOP/EVENT/v4|{PROOF_ID}|agent.started|{PAYLOAD_HASH}|n{sequence}|{PRIOR_HEAD}",
        "signature": "s" * 86,
        "nonce": f"n{sequence}",
        "created_at": created_at,
        "sequence": sequence,
        "previous_event_hash": None,
    }
    event.update(overrides)
    return event


CHAIN_HEAD_INPUTS = [
    # valid
    [],
    [_event(1, "2026-10-22T19:10:38.014507")],
    [_event(1, "2026-10-22T19:10:38.014507"), _event(2, "2026-10-22T19:10:39")],
    [_event(1, "2026-10-22T19:10:39")],
    [_event(1, "2026-10-22T19:10:40.500000")],
    [_event(1, "2026-10-22T19:10:40.5")],
    [_event(1, "2026-10-22T19:10:38.014507", actor_did="did:key:zÜnïcode")],
    [_event(1, "2026-10-22T19:10:38.014507", payload={"different": True}, nonce="other")],
    # invalid
    [_event(1, None)],
    [{key: value for key, value in _event(1, "2026-10-22T19:10:38").items() if key != "event_id"}],
    ["not an event"],
]


def _outcome(function, *args, **kwargs):
    try:
        return {"result": function(*args, **kwargs)}
    except ValueError as exc:
        return {"error": str(exc)}


def generate() -> dict:
    def as_list(outcome):
        if isinstance(outcome.get("result"), tuple):
            return {"result": list(outcome["result"])}
        return outcome

    return {
        "description": (
            "Version-4 canonical and chain-head vectors "
            "(docs/design/proof-closure.md §3.2.1, D-C1, D-C2, D-C5). Generated "
            "by scripts/generate_canonical_v4_vectors.py from app/canonical.py "
            "and app/crypto.py; do not edit by hand. 'result' is the canonical "
            "(build), the field list (parse) or the head (chain_head, null for "
            "no events); 'error' is the ValueError message."
        ),
        "build_request": [
            {"args": list(args), **_outcome(build_request_canonical_v4, *args)}
            for args in BUILD_REQUEST_INPUTS
        ],
        "build_event": [
            {"args": list(args), **_outcome(build_event_canonical_v4, *args)}
            for args in BUILD_EVENT_INPUTS
        ],
        "parse_request": [
            {"canonical": canonical, **as_list(_outcome(parse_request_canonical_v4, canonical))}
            for canonical in PARSE_REQUEST_INPUTS
        ],
        "parse_event": [
            {"canonical": canonical, **as_list(_outcome(parse_event_canonical_v4, canonical))}
            for canonical in PARSE_EVENT_INPUTS
        ],
        "chain_head": [
            {
                "proof_id": PROOF_ID,
                "events": events,
                **_outcome(chain_head, events, proof_id=PROOF_ID),
            }
            for events in CHAIN_HEAD_INPUTS
        ],
    }


def render() -> str:
    return json.dumps(generate(), ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the file is stale")
    args = parser.parse_args()

    expected = render()
    if args.check:
        current = VECTORS_PATH.read_text(encoding="utf-8") if VECTORS_PATH.exists() else None
        if current != expected:
            print(f"{VECTORS_PATH.relative_to(REPO_ROOT)} is stale; regenerate it.")
            return 1
        print(f"{VECTORS_PATH.relative_to(REPO_ROOT)} is up to date.")
        return 0

    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(expected, encoding="utf-8")
    print(f"wrote {VECTORS_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
