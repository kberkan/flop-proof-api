"""Generate tests/fixtures/canonical_v3_vectors.json from app/canonical.py.

The vectors pin the version-3 canonical rules (docs/design/event-replay.md,
D-R2, D-R3, D-R9, D-R10) so the SDK copy (flop_proof_sdk/canonical.py) can be
checked against them without importing the API package.

    python scripts/generate_canonical_v3_vectors.py           # write the file
    python scripts/generate_canonical_v3_vectors.py --check   # exit 1 if stale
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.canonical import (  # noqa: E402
    build_event_canonical_v3,
    build_request_canonical_v3,
    parse_event_canonical_v3,
    parse_request_canonical_v3,
)

VECTORS_PATH = REPO_ROOT / "tests" / "fixtures" / "canonical_v3_vectors.json"

PROOF_ID = "proof_0123456789abcdef0123456789abcdef"
PAYLOAD_HASH = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

BUILD_REQUEST_INPUTS = [
    # valid
    ("room-1", "nonce-1", "hello"),
    ("room-1", "nonce-1", "a|b||c|"),
    ("room-1", "nonce-1", "|"),
    ("oda-ğüşıöç", "nonce-日本", "Türkçe metin 🔏"),
    ("room-1", "nonce-1", "line one\nline two\r\n\ttab \x00 \x7f"),
    ("room-1", "nonce-1", "FLOP/EVENT/v3|looks|like|an|event"),
    ("room with spaces", " nonce ", " "),
    # invalid
    ("", "nonce-1", "hello"),
    ("a|b", "nonce-1", "hello"),
    ("room\n", "nonce-1", "hello"),
    ("room\x00", "nonce-1", "hello"),
    ("room\x7f", "nonce-1", "hello"),
    ("room\x1f", "nonce-1", "hello"),
    (PROOF_ID, "nonce-1", "hello"),
    (PROOF_ID + "\n", "nonce-1", "hello"),
    ("room-1", "", "hello"),
    ("room-1", "b|c", "hello"),
    ("room-1", "nonce\t1", "hello"),
    ("room-1", "nonce\r", "hello"),
    ("room-1", "nonce-1", ""),
    (None, "nonce-1", "hello"),
    ("room-1", 7, "hello"),
    ("room-1", "nonce-1", None),
]

BUILD_EVENT_INPUTS = [
    # valid
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n"),
    (PROOF_ID, "custom.ünïcode", PAYLOAD_HASH, "nonce-日本 with spaces"),
    # invalid
    ("", "result.created", PAYLOAD_HASH, "n"),
    ("proof_task_hash_test", "result.created", PAYLOAD_HASH, "n"),
    (PROOF_ID.upper(), "result.created", PAYLOAD_HASH, "n"),
    (PROOF_ID + "0", "result.created", PAYLOAD_HASH, "n"),
    (PROOF_ID + "\n", "result.created", PAYLOAD_HASH, "n"),
    ("x|" + PROOF_ID, "result.created", PAYLOAD_HASH, "n"),
    (PROOF_ID, "", PAYLOAD_HASH, "n"),
    (PROOF_ID, "result|created", PAYLOAD_HASH, "n"),
    (PROOF_ID, "result.created\n", PAYLOAD_HASH, "n"),
    (PROOF_ID, "result\x7fcreated", PAYLOAD_HASH, "n"),
    (PROOF_ID, "result.created", "", "n"),
    (PROOF_ID, "result.created", "sha256:" + PAYLOAD_HASH, "n"),
    (PROOF_ID, "result.created", PAYLOAD_HASH.upper(), "n"),
    (PROOF_ID, "result.created", PAYLOAD_HASH[:-1], "n"),
    (PROOF_ID, "result.created", PAYLOAD_HASH + "\n", "n"),
    (PROOF_ID, "result.created", PAYLOAD_HASH, ""),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "a|b"),
    (PROOF_ID, "result.created", PAYLOAD_HASH, "n\x00"),
    (PROOF_ID, "result.created", PAYLOAD_HASH, None),
    (None, "result.created", PAYLOAD_HASH, "n"),
]

PARSE_REQUEST_INPUTS = [
    "FLOP/REQUEST/v3|room-1|nonce-1|hello",
    "FLOP/REQUEST/v3|a|b|c|text",
    "FLOP/REQUEST/v3|room-1|nonce-1|line\nbreak\x00",
    "FLOP/REQUEST/v3|oda|nonce|Türkçe 🔏",
    "room-1|nonce-1|hello",
    f"{PROOF_ID}|result.created|{PAYLOAD_HASH}",
    f"FLOP/EVENT/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n",
    "FLOP/REQUEST/v30|room-1|nonce-1|hello",
    "flop/request/v3|room-1|nonce-1|hello",
    " FLOP/REQUEST/v3|room-1|nonce-1|hello",
    "FLOP/REQUEST/v3 |room-1|nonce-1|hello",
    "|room-1|nonce-1|hello",
    "",
    "FLOP/REQUEST/v3",
    "FLOP/REQUEST/v3|room-1|nonce-1",
    "FLOP/REQUEST/v3||nonce-1|hello",
    "FLOP/REQUEST/v3|room-1||hello",
    "FLOP/REQUEST/v3|room-1|nonce-1|",
    f"FLOP/REQUEST/v3|{PROOF_ID}|nonce-1|hello",
    "FLOP/REQUEST/v3|room\n|nonce-1|hello",
    "FLOP/REQUEST/v3|room-1|nonce\t|hello",
    None,
]

PARSE_EVENT_INPUTS = [
    f"FLOP/EVENT/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v3|{PROOF_ID}|custom.ünïcode|{PAYLOAD_HASH}|日本",
    f"{PROOF_ID}|result.created|{PAYLOAD_HASH}",
    "FLOP/REQUEST/v3|room-1|nonce-1|hello",
    f"FLOP/EVENT/v30|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n",
    f"flop/event/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v3\t|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}",
    f"FLOP/EVENT/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n|extra",
    f"FLOP/EVENT/v3|{PROOF_ID}\n|result.created|{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v3|proof_task_hash_test|result.created|{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v3|{PROOF_ID}||{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v3|{PROOF_ID}|result\r|{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v3|{PROOF_ID}|result.created|sha256:{PAYLOAD_HASH}|n",
    f"FLOP/EVENT/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}|",
    f"FLOP/EVENT/v3|{PROOF_ID}|result.created|{PAYLOAD_HASH}|n\x7f",
    None,
]


def _outcome(function, *args):
    try:
        return {"result": function(*args)}
    except ValueError as exc:
        return {"error": str(exc)}


def generate() -> dict:
    def as_list(outcome):
        if isinstance(outcome.get("result"), tuple):
            return {"result": list(outcome["result"])}
        return outcome

    return {
        "description": (
            "Version-3 canonical vectors (docs/design/event-replay.md D-R2, "
            "D-R3, D-R9, D-R10). Generated by "
            "scripts/generate_canonical_v3_vectors.py from app/canonical.py; "
            "do not edit by hand. 'result' is the canonical (build) or the "
            "field list (parse); 'error' is the ValueError message."
        ),
        "build_request": [
            {"args": list(args), **_outcome(build_request_canonical_v3, *args)}
            for args in BUILD_REQUEST_INPUTS
        ],
        "build_event": [
            {"args": list(args), **_outcome(build_event_canonical_v3, *args)}
            for args in BUILD_EVENT_INPUTS
        ],
        "parse_request": [
            {"canonical": canonical, **as_list(_outcome(parse_request_canonical_v3, canonical))}
            for canonical in PARSE_REQUEST_INPUTS
        ],
        "parse_event": [
            {"canonical": canonical, **as_list(_outcome(parse_event_canonical_v3, canonical))}
            for canonical in PARSE_EVENT_INPUTS
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
