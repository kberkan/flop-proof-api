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

    return verify_proof_events(
        proof_id=proof_id,
        events=events,
    )

def verify_proof_file(path: str | Path) -> dict[str, Any]:
    proof = json.loads(
        Path(path).read_text(encoding="utf-8")
    )
    return verify_proof_data(proof)

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify a FLOP proof JSON file."
    )
    parser.add_argument(
        "proof_file",
        help="Path to exported FLOP proof JSON",
    )

    args = parser.parse_args()

    try:
        result = verify_proof_file(args.proof_file)
    except Exception as exc:
        print("FLOP PROOF VERIFICATION")
        print("-----------------------")
        print(f"Error: {exc}")
        return 1

    print("FLOP PROOF VERIFICATION")
    print("-----------------------")
    print(f"Proof: {result.get('proof_id', '-')}")
    print(f"Events: {result.get('events_checked', 0)}")
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
            )
        )
        mark = "✓" if status else "✗"
        print(f"{mark} event {check.get('sequence')}: {check.get('type')}")

    print()

    checks = [
        ("sequence", "sequence_valid"),
        ("event chain", "chain_valid"),
        ("payload hashes", "payload_hash_valid"),
        ("canonical messages", "canonical_valid"),
        ("signatures", "signature_valid"),
    ]

    for label, key in checks:
        valid = all(
            check.get(key, False)
            for check in result.get("checks", [])
        )
        print(f"{'✓' if valid else '✗'} {label}")

    result_hash = result.get("result_hash_valid")
    artifact_hash = result.get("artifact_hash_valid")

    if result_hash is not None:
        print(f"{'✓' if result_hash else '✗'} result hash")

    if artifact_hash is not None:
        print(f"{'✓' if artifact_hash else '✗'} artifact hash")

    print()
    print(f"Verdict: {result.get('verdict', 'invalid').upper()}")

    return 0 if result.get("verdict") == "valid" else 1


if __name__ == "__main__":
    raise SystemExit(main())

