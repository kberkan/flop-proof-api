import json
from pathlib import Path
from typing import Any

from .crypto import (
    hash_event_record,
    sha256_bytes,
    sha256_json,
    verify_canonical_signature,
)


def verify_proof_data(proof: dict[str, Any]) -> dict[str, Any]:
    from .verification_core import verify_proof_events

    proof_id = proof.get("proof_id")
    events = proof.get("events")

    if not proof_id:
        return {
            "verdict": "invalid",
            "error": "Missing proof_id",
        }

    if not isinstance(events, list):
        return {
            "verdict": "invalid",
            "error": "Invalid events",
        }

    # A missing version is passed on as None and makes the proof invalid;
    # the verifier does not guess which canonical rules apply.
    return verify_proof_events(
        proof_id=proof_id,
        events=events,
        version=proof.get("version"),
    )

def verify_proof_file(path: str | Path) -> dict[str, Any]:
    proof = json.loads(
        Path(path).read_text(encoding="utf-8")
    )
    return verify_proof_data(proof)

def check_expectations(
    result: dict[str, Any],
    expect_head: str | None = None,
    expect_count: int | None = None,
) -> dict[str, bool]:
    """Compare the result with values kept outside the service
    (docs/design/proof-closure.md D-C8). Only the given ones are checked. The
    verdict is not changed: it stays about the export's own consistency."""
    expectations = {}
    if expect_head is not None:
        expectations["head"] = result.get("chain_head") == expect_head
    if expect_count is not None:
        expectations["count"] = result.get("event_count") == expect_count
    return expectations


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify a FLOP proof JSON file."
    )
    parser.add_argument(
        "proof_file",
        help="Path to exported FLOP proof JSON",
    )
    parser.add_argument(
        "--expect-head",
        metavar="HEX",
        help="chain_head kept outside the service; a mismatch exits 1",
    )
    parser.add_argument(
        "--expect-count",
        metavar="N",
        type=int,
        help="event count kept outside the service; a mismatch exits 1",
    )

    args = parser.parse_args(argv)

    try:
        result = verify_proof_file(args.proof_file)
    except Exception as exc:
        print("FLOP PROOF VERIFICATION")
        print("-----------------------")
        print(f"Error: {exc}")
        return 1

    expectations = check_expectations(result, args.expect_head, args.expect_count)
    if expectations:
        result["expectations"] = expectations

    print("FLOP PROOF VERIFICATION")
    print("-----------------------")
    print(f"Proof: {result.get('proof_id', '-')}")
    print(f"Events: {result.get('events_checked', 0)}")
    print(f"Closed: {'yes' if result.get('closed') else 'no'}")
    print(f"Chain head: {result.get('chain_head') or '-'}")
    print()

    for check in result.get("checks", []):
        status = all(
            check.get(key, False)
            for key in (
                "sequence_valid",
                "chain_valid",
                "payload_hash_valid",
                "canonical_valid",
                "signature_valid",
                "format_valid",
                "replay_valid",
            )
        ) and check.get("prior_head_valid") is not False
        mark = "✓" if status else "✗"
        print(f"{mark} event {check.get('sequence')}: {check.get('type')}")

    print()

    checks = [
        ("sequence", "sequence_valid"),
        ("event chain", "chain_valid"),
        ("payload hashes", "payload_hash_valid"),
        ("canonical messages", "canonical_valid"),
        ("signatures", "signature_valid"),
        ("message format", "format_valid"),
        ("no replayed events", "replay_valid"),
    ]

    for label, key in checks:
        valid = all(
            check.get(key, False)
            for check in result.get("checks", [])
        )
        print(f"{'✓' if valid else '✗'} {label}")

    # Version 4 only; v1/v2/v3 events report null.
    prior_heads = [
        check.get("prior_head_valid")
        for check in result.get("checks", [])
        if check.get("prior_head_valid") is not None
    ]
    if prior_heads:
        print(f"{'✓' if all(prior_heads) else '✗'} signed chain heads")

    result_hash = result.get("result_hash_valid")
    artifact_hash = result.get("artifact_hash_valid")

    if result_hash is not None:
        print(f"{'✓' if result_hash else '✗'} result hash")

    if artifact_hash is not None:
        print(f"{'✓' if artifact_hash else '✗'} artifact hash")

    if result.get("reason"):
        print()
        print(f"Reason: {result['reason']}")

    print()
    print(f"Verdict: {result.get('verdict', 'invalid').upper()}")

    if "head" in expectations:
        print(f"Expected head: {'match' if expectations['head'] else 'MISMATCH'}")
    if "count" in expectations:
        print(f"Expected count: {'match' if expectations['count'] else 'MISMATCH'}")

    if result.get("verdict") != "valid":
        return 1
    return 0 if all(expectations.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

