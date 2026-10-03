"""Event authorization rules (docs/design/event-authorization.md).

Pure functions over chain data: no database, no network, no global state.
Not wired into the API or the verifier yet.

Where the design document left a point open, the choice made here is marked
"DESIGN GAP" below and listed in the slice report.
"""

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence

from .crypto import did_key_to_public_key

Role = Literal["creator", "delegate", "unauthorized"]

REQUEST_CREATED = "request.created"
TASK_DELEGATED = "task.delegated"
RESULT_CREATED = "result.created"
CREATOR_ONLY_TYPES = frozenset({TASK_DELEGATED, "proof.completed", "proof.failed"})

# D7: at most 32 delegates per proof.
MAX_DELEGATES_PER_PROOF = 32

# Reason code -> (HTTP status, message). Codes and the 403 messages are from §5
# and §6. DESIGN GAP: §6 gives one 400 message ("Invalid delegate DID") and no
# message for the second result.created (D5, 409); the extra entries below are
# proposals in the same style.
REASONS: dict[str, tuple[int, str]] = {
    "no_creator": (403, "Actor is not authorized for this proof"),
    "not_delegated": (403, "Actor is not authorized for this proof"),
    "creator_only": (403, "Event type requires the proof creator"),
    "request_created_not_allowed": (
        403,
        "request.created can only be written by POST /proofs",
    ),
    "invalid_delegate_did": (400, "Invalid delegate DID"),
    "invalid_delegates": (400, "Invalid delegate list"),
    "result_already_created": (409, "result.created already exists for this proof"),
}


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    role: Role
    reason: str | None = None

    @property
    def http_status(self) -> int | None:
        return None if self.reason is None else REASONS[self.reason][0]

    @property
    def message(self) -> str | None:
        return None if self.reason is None else REASONS[self.reason][1]


def is_valid_did_key(value: Any) -> bool:
    """True for a did:key that app.crypto.did_key_to_public_key accepts."""
    if not isinstance(value, str):
        return False
    try:
        did_key_to_public_key(value)
    except (ValueError, TypeError):
        return False
    return True


def _delegates_field_error(payload: Any) -> str | None:
    """Validate the "delegates" field of a task.delegated payload.

    No "delegates" key is valid and delegates nobody (§3: legacy
    "delegated_to" payloads stay valid). DESIGN GAP: the document does not say
    whether an empty list or duplicate entries are malformed; here an empty
    list is valid (delegates nobody) and duplicates are rejected.
    """
    if not isinstance(payload, Mapping) or "delegates" not in payload:
        return None

    delegates = payload["delegates"]
    if not isinstance(delegates, list):
        return "invalid_delegates"
    if len(delegates) > MAX_DELEGATES_PER_PROOF:
        return "invalid_delegates"
    if not all(is_valid_did_key(did) for did in delegates):
        return "invalid_delegate_did"
    if len(set(delegates)) != len(delegates):
        return "invalid_delegates"
    return None


def creator_of(prior_events: Sequence[Mapping[str, Any]]) -> str | None:
    """The actor of the sequence-1 request.created event, or None (D4, §2).

    DESIGN GAP: §2 defines the creator through "sequence 1", while §5 says
    prior_events is ordered. Both are required here: the first event must be a
    request.created and, if it carries a sequence, that sequence must be 1.
    """
    if not prior_events:
        return None
    first = prior_events[0]
    if first.get("type") != REQUEST_CREATED:
        return None
    if "sequence" in first and first["sequence"] != 1:
        return None
    actor = first.get("actor_did")
    return actor if isinstance(actor, str) and actor else None


def delegates_of(prior_events: Sequence[Mapping[str, Any]]) -> frozenset[str]:
    """DIDs delegated so far by the creator's task.delegated events.

    Only "delegates" grants authority; "delegated_to" grants nothing (D2).
    Events are taken in order, so a delegation applies only to events after it.
    DESIGN GAP: the document defines what happens to a malformed delegate
    list on append (400) but not for one already in the chain (legacy data or
    a direct create_event write). Here such an event grants nothing.
    """
    creator = creator_of(prior_events)
    if creator is None:
        return frozenset()

    delegated: set[str] = set()
    for event in prior_events[1:]:
        if event.get("type") != TASK_DELEGATED or event.get("actor_did") != creator:
            continue
        payload = event.get("payload")
        if _delegates_field_error(payload) is not None:
            continue
        if isinstance(payload, Mapping):
            delegated.update(payload.get("delegates", []))
    delegated.discard(creator)
    return frozenset(delegated)


def authorize_event(
    prior_events: Sequence[Mapping[str, Any]],
    actor_did: str,
    event_type: str,
    payload: Any,
) -> AuthorizationDecision:
    """Decide whether actor_did may append an event of event_type.

    PRECONDITION: every event in prior_events has already passed signature
    verification, and prior_events is in sequence order starting with
    sequence 1 (§5). Items need "type", "actor_did" and "payload"; "sequence"
    is optional. A forged task.delegated in prior_events would grant authority.

    DESIGN DEVIATION: §5 sketches authorize_event(prior_events, actor_did,
    event_type). The payload of the new event is also needed, because a
    malformed delegate list on a new task.delegated must be rejected (§3, §6).

    Check order: no creator, request.created, role, creator-only types,
    delegate list. The second-result.created rule (D5, 409) is a separate
    check, see check_single_result_created.
    """
    creator = creator_of(prior_events)
    if creator is None:
        # §2: with no creator, every event in the chain is unauthorized.
        return AuthorizationDecision(False, "unauthorized", "no_creator")

    if actor_did == creator:
        role: Role = "creator"
    elif actor_did in delegates_of(prior_events):
        role = "delegate"
    else:
        role = "unauthorized"

    if event_type == REQUEST_CREATED:
        return AuthorizationDecision(False, role, "request_created_not_allowed")

    if role == "unauthorized":
        return AuthorizationDecision(False, role, "not_delegated")

    if event_type in CREATOR_ONLY_TYPES and role != "creator":
        # Covers sub-delegation: a delegate's task.delegated (D7).
        return AuthorizationDecision(False, role, "creator_only")

    if event_type == TASK_DELEGATED:
        error = _delegates_field_error(payload)
        if error is not None:
            return AuthorizationDecision(False, role, error)
        if isinstance(payload, Mapping) and "delegates" in payload:
            new = set(payload["delegates"]) - {creator}
            if len(delegates_of(prior_events) | new) > MAX_DELEGATES_PER_PROOF:
                # DESIGN GAP: D7 caps delegates "per proof" and §12 caps "the
                # list"; both are enforced. The creator does not count.
                return AuthorizationDecision(False, role, "invalid_delegates")

    return AuthorizationDecision(True, role)


def check_single_result_created(
    prior_events: Sequence[Mapping[str, Any]],
    event_type: str,
) -> str | None:
    """D5: at most one result.created per proof (409 on the second).

    Separate from authorize_event because it is not a role rule and maps to
    409, not 403 (DESIGN GAP: the document does not say where it lives).
    Returns "result_already_created" or None.
    """
    if event_type != RESULT_CREATED:
        return None
    if any(event.get("type") == RESULT_CREATED for event in prior_events):
        return "result_already_created"
    return None
