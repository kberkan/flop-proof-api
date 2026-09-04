import json
from typing import Any

from .crypto import (
    hash_event_record,
    sha256_bytes,
    sha256_json,
    verify_canonical_signature,
)


def verify_proof_events(
    proof_id: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    if not events:
        return {
            "proof_id": proof_id,
            "verdict": "invalid",
            "reason": "Proof contains no events.",
            "events_checked": 0,
            "result_hash_valid": None,
            "artifact_hash_valid": None,
            "checks": [],
        }

    checks = []
    expected_sequence = 1
    previous_event = None

    for event in events:
        event_id = event.get("event_id")
        event_type = event.get("type")
        actor_did = event.get("actor_did")
        payload = event.get("payload")
        payload_hash = event.get("payload_hash")
        canonical = event.get("canonical")
        signature = event.get("signature")
        created_at = event.get("created_at")
        sequence = event.get("sequence")
        previous_event_hash = event.get("previous_event_hash")

        sequence_ok = sequence == expected_sequence

        if previous_event is None:
            chain_ok = previous_event_hash is None
        else:
            try:
                expected_previous_hash = hash_event_record(
                    event_id=previous_event["event_id"],
                    proof_id=proof_id,
                    event_type=previous_event["type"],
                    actor_did=previous_event["actor_did"],
                    payload_hash=previous_event["payload_hash"],
                    canonical=previous_event["canonical"],
                    signature=previous_event["signature"],
                    created_at=previous_event["created_at"],
                    sequence=previous_event["sequence"],
                )
                chain_ok = previous_event_hash == expected_previous_hash
            except Exception:
                chain_ok = False

        try:
            recalculated_payload_hash = sha256_json(payload)
            payload_hash_ok = (
                recalculated_payload_hash == payload_hash
            )
        except Exception:
            payload_hash_ok = False

        if event_type == "request.created":
            request_signature = (
                payload.get("signature")
                if isinstance(payload, dict)
                else None
            )

            expected_canonical = (
                request_signature.get("canonical")
                if isinstance(request_signature, dict)
                else None
            )

            canonical_ok = (
                bool(expected_canonical)
                and canonical == expected_canonical
            )
        else:
            expected_canonical = (
                f"{proof_id}|{event_type}|{payload_hash}"
            )
            canonical_ok = canonical == expected_canonical

        try:
            signature_ok = verify_canonical_signature(
                did=actor_did,
                canonical=canonical,
                signature=signature,
            )
        except Exception:
            signature_ok = False

        checks.append(
            {
                "sequence": sequence,
                "event_id": event_id,
                "type": event_type,
                "sequence_valid": sequence_ok,
                "chain_valid": chain_ok,
                "payload_hash_valid": payload_hash_ok,
                "canonical_valid": canonical_ok,
                "signature_valid": signature_ok,
            }
        )

        expected_sequence += 1
        previous_event = event

    all_events_valid = all(
        check["sequence_valid"]
        and check["chain_valid"]
        and check["payload_hash_valid"]
        and check["canonical_valid"]
        and check["signature_valid"]
        for check in checks
    )

    result_hash_valid = None
    artifact_hash_valid = None

    for event in events:
        if event.get("type") == "result.created":
            payload = event.get("payload")

            if isinstance(payload, dict):
                content = payload.get("content")
                content_hash = payload.get("content_hash")

                if content is not None and content_hash:
                    calculated = (
                        f"sha256:{sha256_bytes(content.encode('utf-8'))}"
                    )
                    result_hash_valid = calculated == content_hash

        elif event.get("type") == "artifact.created":
            payload = event.get("payload")

            if isinstance(payload, dict):
                artifact_hash = payload.get("sha256")
                artifact_path = payload.get("path")

                if artifact_hash and artifact_path:
                    try:
                        with open(artifact_path, "rb") as artifact_file:
                            calculated_hash = sha256_bytes(artifact_file.read())
                        artifact_hash_valid = artifact_hash in (
                            calculated_hash,
                            f"sha256:{calculated_hash}",
                        )
                    except (FileNotFoundError, OSError):
                        artifact_hash_valid = False
                elif artifact_hash:
                    artifact_hash_valid = True

    if result_hash_valid is False or artifact_hash_valid is False:
        all_events_valid = False

    return {
        "proof_id": proof_id,
        "verdict": "valid" if all_events_valid else "invalid",
        "events_checked": len(events),
        "result_hash_valid": result_hash_valid,
        "artifact_hash_valid": artifact_hash_valid,
        "checks": checks,
    }
