"""The SDK's copy of the version-3 canonical functions (flop_proof_sdk/canonical.py)
must behave exactly like the API's (app/canonical.py).

(a) the shared vector file is what app/canonical.py generates today;
(b) the SDK alone reproduces every vector (no app import in that test);
(c) on seeded random inputs app and SDK give the same canonical or the same
    rejection message;
(d) the SDK source never imports the API package.
"""

import ast
import json
import random
from pathlib import Path

import pytest

from flop_proof_sdk import canonical as sdk


REPO_ROOT = Path(__file__).resolve().parent
VECTORS_PATH = REPO_ROOT / "tests" / "fixtures" / "canonical_v3_vectors.json"
SDK_DIR = REPO_ROOT / "flop_proof_sdk"

SDK_FUNCTIONS = {
    "build_request": sdk.build_request_canonical_v3,
    "build_event": sdk.build_event_canonical_v3,
    "parse_request": sdk.parse_request_canonical_v3,
    "parse_event": sdk.parse_event_canonical_v3,
}


def _load_vectors():
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _outcome(function, *args):
    try:
        result = function(*args)
    except ValueError as exc:
        return {"error": str(exc)}
    return {"result": list(result) if isinstance(result, tuple) else result}


# --- (a) ----------------------------------------------------------------------------

def test_vector_file_is_up_to_date_with_app_canonical():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "generate_canonical_v3_vectors",
        REPO_ROOT / "scripts" / "generate_canonical_v3_vectors.py",
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)

    assert VECTORS_PATH.read_text(encoding="utf-8") == generator.render(), (
        "run: python scripts/generate_canonical_v3_vectors.py"
    )


def test_vector_file_covers_valid_and_invalid_cases():
    vectors = _load_vectors()
    errors = set()
    for kind in SDK_FUNCTIONS:
        cases = vectors[kind]
        assert any("result" in case for case in cases), kind
        assert any("error" in case for case in cases), kind
        errors |= {case["error"] for case in cases if "error" in case}

    for message in (
        "room: must not contain '|'",
        "room: must not contain control characters",
        "nonce: must not contain control characters",
        "event_type: must not contain control characters",
        "room: must not be a proof_id",
        "proof_id: invalid format",
        "payload_hash: must be 64 lowercase hex characters",
        "canonical: tag must be FLOP/REQUEST/v3",
        "canonical: tag must be FLOP/EVENT/v3",
    ):
        assert message in errors, message


# --- (b) ----------------------------------------------------------------------------

def _vector_cases():
    vectors = _load_vectors()
    for kind in SDK_FUNCTIONS:
        for index, case in enumerate(vectors[kind]):
            yield pytest.param(kind, case, id=f"{kind}-{index}")


@pytest.mark.parametrize("kind,case", list(_vector_cases()))
def test_sdk_reproduces_vector(kind, case):
    args = case["args"] if kind.startswith("build") else [case["canonical"]]
    expected = {key: case[key] for key in ("result", "error") if key in case}

    assert _outcome(SDK_FUNCTIONS[kind], *args) == expected


# --- (c) ----------------------------------------------------------------------------

# Alphabet with the characters the rules care about: "|", control characters,
# space, Unicode, hex digits and the pieces of tags and proof ids.
ALPHABET = list("ab|| \n\t\x00\x7fğ日0f") + ["FLOP/", "REQUEST/v3", "EVENT/v3", "proof_"]


def _random_field(rng):
    roll = rng.random()
    if roll < 0.05:
        return rng.choice([None, 7, b"x"])
    if roll < 0.15:
        return f"proof_{rng.getrandbits(128):032x}" + rng.choice(["", "\n", "0", "|"])
    if roll < 0.25:
        return f"{rng.getrandbits(256):064x}" + rng.choice(["", "\n", "0"])
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 6)))


def _random_canonical(rng, tags):
    parts = [rng.choice(tags)] + [
        field if isinstance(field, str) else "x"
        for field in (_random_field(rng) for _ in range(rng.randint(0, 5)))
    ]
    return "|".join(parts)


def test_app_and_sdk_agree_on_random_inputs():
    from app import canonical as app_canonical

    app_functions = {
        "build_request": app_canonical.build_request_canonical_v3,
        "build_event": app_canonical.build_event_canonical_v3,
        "parse_request": app_canonical.parse_request_canonical_v3,
        "parse_event": app_canonical.parse_event_canonical_v3,
    }
    tags = ["FLOP/REQUEST/v3", "FLOP/EVENT/v3", "FLOP/REQUEST/v30", "flop/event/v3", "", "room"]
    rng = random.Random(3_2026_10_04)
    outcomes = {"result": 0, "error": 0}

    for _ in range(4000):
        cases = [
            ("build_request", [_random_field(rng) for _ in range(3)]),
            ("build_event", [_random_field(rng) for _ in range(4)]),
            ("parse_request", [_random_canonical(rng, tags)]),
            ("parse_event", [_random_canonical(rng, tags)]),
        ]
        for kind, args in cases:
            app_outcome = _outcome(app_functions[kind], *args)
            assert _outcome(SDK_FUNCTIONS[kind], *args) == app_outcome, (kind, args)
            outcomes[next(iter(app_outcome))] += 1

    # Both branches are exercised, not only rejections.
    assert outcomes["result"] > 250 and outcomes["error"] > 5000, outcomes


def test_app_and_sdk_share_tags_and_proof_id_pattern():
    from app import canonical as app_canonical
    from app.crypto import PROOF_ID_PATTERN

    assert sdk.REQUEST_TAG == app_canonical.REQUEST_TAG
    assert sdk.EVENT_TAG == app_canonical.EVENT_TAG
    assert sdk.PROOF_ID_PATTERN.pattern == PROOF_ID_PATTERN.pattern
    assert sdk.PAYLOAD_HASH_PATTERN.pattern == app_canonical.PAYLOAD_HASH_PATTERN.pattern
    assert sdk.CONTROL_CHARACTERS.pattern == app_canonical.CONTROL_CHARACTERS.pattern


# --- (d) ----------------------------------------------------------------------------

def test_sdk_source_does_not_import_the_api_package():
    offenders = []
    for path in sorted(SDK_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # Relative imports stay inside flop_proof_sdk; level 2+ would
                # leave the package.
                if node.level > 1:
                    offenders.append(f"{path.name}:{node.lineno} relative level {node.level}")
                    continue
                names = [node.module or ""] if node.level == 0 else []
            else:
                continue
            for name in names:
                if name == "app" or name.startswith("app.") or name in {"client", "main"}:
                    offenders.append(f"{path.name}:{node.lineno} {name}")

    assert offenders == []
