import json
from typing import Any

from .authorization import authorize_event, check_single_result_created
from .canonical import (
    CURRENT_PROOF_VERSION,
    LEGACY_PROOF_VERSIONS,
    TAG_PREFIX,
    build_event_canonical_v3,
    parse_event_canonical_v3,
    parse_request_canonical_v3,
)
from .crypto import (
    compute_task_hash,
    hash_event_record,
    is_proof_id,
    sha256_bytes,
    sha256_json,
    verify_canonical_signature,
)


def _request_binding_ok(
    canonical: Any,
    signature: Any,
    actor_did: Any,
    payload: Any,
) -> bool:
    """Check that a request.created event is bound to its own request.

    The request canonical is room|nonce|text (app/crypto.py,
    canonical_signed_message). The room is not stored separately; it is read
    from the canonical. The canonical must rebuild from its parts, its nonce
    and text must equal the stored request's, the stored signature and actor
    must be the request's, and the room must not be a proof_id (an event
    canonical proof_id|type|payload_hash would otherwise pass as a request;
    docs/design/event-replay.md §1.2).
    """
    if not isinstance(payload, dict) or not isinstance(canonical, str):
        return False
    request_signature = payload.get("signature")
    if not isinstance(request_signature, dict):
        return False

    parts = canonical.split("|", 2)
    if len(parts) != 3:
        return False
    room, nonce, text = parts

    return (
        bool(room)
        and not is_proof_id(room)
        and f"{room}|{nonce}|{text}" == canonical
        and nonce == request_signature.get("nonce")
        and text == payload.get("text")
        and signature == request_signature.get("sig")
        and actor_did == payload.get("from_did")
    )


def _request_binding_ok_v3(
    canonical: Any,
    signature: Any,
    actor_did: Any,
    payload: Any,
) -> bool:
    """Version-3 request.created: the tagged canonical parses
    (app/canonical.py) and its nonce and text are the stored request's, and
    the stored signature and actor are the request's."""
    if not isinstance(payload, dict):
        return False
    request_signature = payload.get("signature")
    if not isinstance(request_signature, dict):
        return False
    try:
        _, nonce, text = parse_request_canonical_v3(canonical)
    except ValueError:
        return False

    return (
        nonce == request_signature.get("nonce")
        and text == payload.get("text")
        and signature == request_signature.get("sig")
        and actor_did == payload.get("from_did")
    )


def _signed_nonce_v3(event_type: Any, canonical: Any) -> str | None:
    """The nonce inside a version-3 canonical, or None if it does not parse."""
    try:
        if event_type == "request.created":
            return parse_request_canonical_v3(canonical)[1]
        return parse_event_canonical_v3(canonical)[3]
    except ValueError:
        return None


def verify_proof_events(
    proof_id: str,
    events: list[dict[str, Any]],
    version: Any,
) -> dict[str, Any]:
    """`version` is the proof's version. It picks the canonical rules:
    "3" takes only the tagged formats; "1"/"2" take only the untagged ones,
    with Option B replay detection (docs/design/event-replay.md D-R5, D-R11,
    D-R12). A missing or unknown version is not guessed: the proof is invalid.
    """
    is_v3 = version == CURRENT_PROOF_VERSION

    if not is_v3 and version not in LEGACY_PROOF_VERSIONS:
        return {
            "proof_id": proof_id,
            "proof_version": version,
            "verdict": "invalid",
            "reason": "Missing or unsupported proof version.",
            "events_checked": 0,
            "result_hash_valid": None,
            "artifact_hash_valid": None,
            "checks": [],
        }

    if not events:
        return {
            "proof_id": proof_id,
            "proof_version": version,
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
    # Events whose signature, canonical message and payload hash all verify.
    # Only these may grant authority to later events (authorize_event
    # precondition; docs/design/event-authorization.md D-A10).
    authorization_prior: list[dict[str, Any]] = []
    # Replay detection: signed nonces seen so far (v3), or (canonical,
    # signature) pairs seen so far (v1/v2, Option B).
    seen_nonces: set[str] = set()
    seen_pairs: set[tuple[Any, Any]] = set()

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
            request_binding_ok = (
                _request_binding_ok_v3 if is_v3 else _request_binding_ok
            )(canonical, signature, actor_did, payload)
        else:
            request_binding_ok = None
            if is_v3:
                try:
                    expected_canonical = build_event_canonical_v3(
                        proof_id, event_type, payload_hash, event.get("nonce")
                    )
                except ValueError:
                    expected_canonical = None
            else:
                expected_canonical = (
                    f"{proof_id}|{event_type}|{payload_hash}"
                )
            canonical_ok = (
                expected_canonical is not None
                and canonical == expected_canonical
            )

        # format_valid (D-R11, D-R12): the canonical is in this proof
        # version's format. v3: it parses as a tagged message of its kind and
        # the exported nonce is the signed one. v1/v2: it is not tagged.
        # replay_valid: v3, the signed nonce is new in this proof; v1/v2, the
        # (canonical, signature) pair is new in this proof (Option B, D-R5).
        if is_v3:
            signed_nonce = _signed_nonce_v3(event_type, canonical)
            format_ok = (
                signed_nonce is not None
                and event.get("nonce") == signed_nonce
            )
            replay_ok = signed_nonce is None or signed_nonce not in seen_nonces
            if signed_nonce is not None:
                seen_nonces.add(signed_nonce)
        else:
            format_ok = (
                isinstance(canonical, str)
                and not canonical.startswith(TAG_PREFIX)
            )
            pair = (canonical, signature)
            try:
                replay_ok = pair not in seen_pairs
                seen_pairs.add(pair)
            except TypeError:
                # Unhashable values: the canonical or signature check fails.
                replay_ok = True

        try:
            signature_ok = verify_canonical_signature(
                did=actor_did,
                canonical=canonical,
                signature=signature,
            )
        except Exception:
            signature_ok = False

        # D-A10: replay the API's authorization rule over the chain. The
        # sequence-1 request.created is the creator's own event.
        if previous_event is None and event_type == "request.created":
            role, authorization_reason = "creator", None
        elif not isinstance(actor_did, str):
            role, authorization_reason = "unauthorized", "not_delegated"
        else:
            decision = authorize_event(
                authorization_prior,
                actor_did,
                event_type,
                payload,
            )
            role, authorization_reason = decision.role, decision.reason
            if decision.allowed:
                authorization_reason = check_single_result_created(
                    authorization_prior,
                    event_type,
                )

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
                # request.created only; None for other event types.
                "request_binding_valid": request_binding_ok,
                "format_valid": format_ok,
                "replay_valid": replay_ok,
                "actor_did": actor_did,
                "role": role,
                "actor_authorized": authorization_reason is None,
                "authorization_reason": authorization_reason,
            }
        )

        if (
            signature_ok
            and canonical_ok
            and payload_hash_ok
            and request_binding_ok is not False
            and format_ok
            and replay_ok
        ):
            authorization_prior.append(
                {
                    "type": event_type,
                    "actor_did": actor_did,
                    "payload": payload,
                    "sequence": sequence,
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
        and check["request_binding_valid"] is not False
        and check["format_valid"]
        and check["replay_valid"]
        and check["actor_authorized"]
        for check in checks
    )

    result_hash_valid = None
    artifact_hash_valid = None
    task_hash_valid = None
    flop_metadata_status = "absent"

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

                task_hash = payload.get("task_hash")
                task_hash_inputs = payload.get("task_hash_inputs")

                flop_metadata_fields = {
                    "task_hash",
                    "model_hash",
                    "gn_weight",
                    "latency_ms",
                    "decode_policy_hash",
                    "tee_type",
                }

                present_fields = {
                    field
                    for field in flop_metadata_fields
                    if payload.get(field) is not None
                }

                if not present_fields:
                    flop_metadata_status = "absent"
                elif present_fields == flop_metadata_fields:
                    flop_metadata_status = "present"
                else:
                    flop_metadata_status = "incomplete"

                if task_hash is not None:
                    try:
                        if not isinstance(task_hash_inputs, dict):
                            raise ValueError("missing task_hash inputs")

                        calculated_task_hash = compute_task_hash(
                            agent=bytes.fromhex(task_hash_inputs["agent"]),
                            nonce=bytes.fromhex(task_hash_inputs["nonce"]),
                            model_hash=bytes.fromhex(
                                task_hash_inputs["model_hash"]
                            ),
                            payload_hash=bytes.fromhex(
                                task_hash_inputs["payload_hash"]
                            ),
                            commit_hash=bytes.fromhex(
                                task_hash_inputs["commit_hash"]
                            ),
                        )

                        task_hash_valid = (
                            task_hash == calculated_task_hash
                        )
                    except (KeyError, TypeError, ValueError):
                        task_hash_valid = False

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

    if (
        result_hash_valid is False
        or artifact_hash_valid is False
        or task_hash_valid is False
    ):
        all_events_valid = False

    return {
        "proof_id": proof_id,
        "proof_version": version,
        "verdict": "valid" if all_events_valid else "invalid",
        "events_checked": len(events),
        "result_hash_valid": result_hash_valid,
        "artifact_hash_valid": artifact_hash_valid,
        "task_hash_valid": task_hash_valid,
        "flop_metadata_status": flop_metadata_status,
        "checks": checks,
    }
