"""The SDK's copy of the version-4 canonical functions and chain_head
(flop_proof_sdk/canonical.py) must behave exactly like the API's
(app/canonical.py, app/crypto.py); docs/design/proof-closure.md D-C1, D-C11,
D-C12, §8 B.

(a) the SDK alone reproduces every vector of tests/fixtures/canonical_v4_vectors.json
    (no app import in that test; the file's freshness is checked in
    test_canonical_v4.py);
(b) on seeded random inputs app and SDK give the same canonical, head or
    rejection message;
(c) created_at is used as the exported text (D-C12);
(d) the SDK source never imports the API package: test_sdk_canonical_v3.py
    checks every file in flop_proof_sdk/, the v4 code included.
"""

import json
import random
from datetime import datetime, timezone
from pathlib import Path

import pytest

from flop_proof_sdk import canonical as sdk


REPO_ROOT = Path(__file__).resolve().parent
VECTORS_PATH = REPO_ROOT / "tests" / "fixtures" / "canonical_v4_vectors.json"

SDK_FUNCTIONS = {
    "build_request": sdk.build_request_canonical_v4,
    "build_event": sdk.build_event_canonical_v4,
    "parse_request": sdk.parse_request_canonical_v4,
    "parse_event": sdk.parse_event_canonical_v4,
}


def _outcome(function, *args, **kwargs):
    try:
        result = function(*args, **kwargs)
    except ValueError as exc:
        return {"error": str(exc)}
    return {"result": list(result) if isinstance(result, tuple) else result}


# --- (a) ----------------------------------------------------------------------------

def _vector_cases():
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    for kind in (*SDK_FUNCTIONS, "chain_head"):
        for index, case in enumerate(vectors[kind]):
            yield pytest.param(kind, case, id=f"{kind}-{index}")


@pytest.mark.parametrize("kind,case", list(_vector_cases()))
def test_sdk_reproduces_vector(kind, case):
    expected = {key: case[key] for key in ("result", "error") if key in case}
    if kind == "chain_head":
        outcome = _outcome(sdk.chain_head, case["events"], proof_id=case["proof_id"])
    else:
        args = case["args"] if kind.startswith("build") else [case["canonical"]]
        outcome = _outcome(SDK_FUNCTIONS[kind], *args)

    assert outcome == expected


# --- (b) ----------------------------------------------------------------------------

ALPHABET = list("ab|| \n\t\x00\x7fğ日0f") + ["FLOP/", "REQUEST/v4", "EVENT/v4", "proof_"]


def _random_field(rng):
    roll = rng.random()
    if roll < 0.05:
        return rng.choice([None, 7, b"x"])
    if roll < 0.15:
        return f"proof_{rng.getrandbits(128):032x}" + rng.choice(["", "\n", "0", "|"])
    if roll < 0.35:
        return f"{rng.getrandbits(256):064x}" + rng.choice(["", "", "\n", "0", "|"])
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 6)))


def _random_canonical(rng, tags):
    parts = [rng.choice(tags)] + [
        field if isinstance(field, str) else "x"
        for field in (_random_field(rng) for _ in range(rng.randint(0, 6)))
    ]
    return "|".join(parts)


def test_app_and_sdk_agree_on_random_inputs():
    from app import canonical as app_canonical

    app_functions = {
        "build_request": app_canonical.build_request_canonical_v4,
        "build_event": app_canonical.build_event_canonical_v4,
        "parse_request": app_canonical.parse_request_canonical_v4,
        "parse_event": app_canonical.parse_event_canonical_v4,
    }
    tags = ["FLOP/REQUEST/v4", "FLOP/EVENT/v4", "FLOP/EVENT/v3", "FLOP/REQUEST/v40", "", "room"]
    rng = random.Random(4_2026_10_23)
    outcomes = {"result": 0, "error": 0}

    for _ in range(4000):
        cases = [
            ("build_request", [_random_field(rng) for _ in range(3)]),
            ("build_event", [_random_field(rng) for _ in range(5)]),
            ("parse_request", [_random_canonical(rng, tags)]),
            ("parse_event", [_random_canonical(rng, tags)]),
        ]
        for kind, args in cases:
            app_outcome = _outcome(app_functions[kind], *args)
            assert _outcome(SDK_FUNCTIONS[kind], *args) == app_outcome, (kind, args)
            outcomes[next(iter(app_outcome))] += 1

    assert outcomes["result"] > 150 and outcomes["error"] > 5000, outcomes


def test_app_and_sdk_share_v4_tags():
    from app import canonical as app_canonical

    assert sdk.REQUEST_TAG_V4 == app_canonical.REQUEST_TAG_V4
    assert sdk.EVENT_TAG_V4 == app_canonical.EVENT_TAG_V4


def _event(created_at, **overrides):
    event = {
        "event_id": "evt_" + "a" * 32,
        "type": "agent.started",
        "actor_did": "did:key:zÜnïcode",
        "payload_hash": "b" * 64,
        "canonical": "FLOP/EVENT/v4|…",
        "signature": "s" * 86,
        "created_at": created_at,
        "sequence": 2,
    }
    event.update(overrides)
    return event


def test_app_and_sdk_chain_head_agree_on_random_events():
    from app.crypto import chain_head as app_chain_head

    rng = random.Random(23102026)
    for _ in range(500):
        created_at = f"2026-10-23T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
        created_at += rng.choice(["", f".{rng.randint(0, 999999):06d}", ".5", "+00:00"])
        events = [_event(created_at, sequence=rng.randint(1, 50), type=rng.choice(["a", "b.c", "ü"]))]
        proof_id = f"proof_{rng.getrandbits(128):032x}"
        assert sdk.chain_head(events, proof_id=proof_id) == app_chain_head(events, proof_id=proof_id)


# --- (c) D-C12 -------------------------------------------------------------------------

def test_sdk_chain_head_uses_created_at_as_the_exported_text():
    """The same instant written two ways gives two heads, in the SDK and in
    the app alike: the SDK must not parse or re-format created_at."""
    from app.crypto import chain_head as app_chain_head

    proof_id = "proof_" + "c" * 32
    heads = {}
    for text in ("2026-10-22T19:10:40.500000", "2026-10-22T19:10:40.5", "2026-10-22T19:10:40", "2026-10-22T19:10:40.000000"):
        heads[text] = sdk.chain_head([_event(text)], proof_id=proof_id)
        assert heads[text] == app_chain_head([_event(text)], proof_id=proof_id)

    assert len(set(heads.values())) == 4
    with pytest.raises(ValueError, match=r"^events: created_at must be the exported string$"):
        sdk.chain_head([_event(datetime(2026, 10, 22, 19, 10, 40, 500000, tzinfo=timezone.utc))], proof_id=proof_id)


def test_sdk_chain_head_of_no_events_is_none():
    assert sdk.chain_head([], proof_id="proof_" + "c" * 32) is None
