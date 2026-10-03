"""Unit tests for app/authorization.py (docs/design/event-authorization.md).

Pure: no database, no HTTP. Chains are lists of the dicts the verifier uses,
and every event in them is assumed to have a verified signature.
"""

import pytest

from app.authorization import (
    MAX_DELEGATES_PER_PROOF,
    REASONS,
    authorize_event,
    check_single_result_created,
    creator_of,
    delegates_of,
)
from app.crypto import generate_test_keypair, public_key_to_test_did


def new_did() -> str:
    _, public_key = generate_test_keypair()
    return public_key_to_test_did(public_key)


CREATOR = new_did()
DELEGATE = new_did()
OTHER_DELEGATE = new_did()
STRANGER = new_did()

OPEN_TYPES = ["result.created", "agent.started", "artifact.created", "custom.free_form"]
CREATOR_ONLY = ["task.delegated", "proof.completed", "proof.failed"]


def event(event_type, actor, payload=None, sequence=None):
    item = {"type": event_type, "actor_did": actor, "payload": payload or {}}
    if sequence is not None:
        item["sequence"] = sequence
    return item


def chain(*events):
    """Number the events from 1, as stored chains are."""
    return [dict(item, sequence=index) for index, item in enumerate(events, start=1)]


def request_created(actor=CREATOR):
    return event("request.created", actor, {"text": "request"})


def delegation(*dids, actor=CREATOR):
    return event("task.delegated", actor, {"delegates": list(dids)})


# --- creator --------------------------------------------------------------


@pytest.mark.parametrize("event_type", OPEN_TYPES + ["proof.completed", "proof.failed"])
def test_creator_may_append_every_allowed_type(event_type):
    decision = authorize_event(chain(request_created()), CREATOR, event_type, {})

    assert decision.allowed is True
    assert decision.role == "creator"
    assert decision.reason is None


def test_creator_may_delegate():
    decision = authorize_event(
        chain(request_created()), CREATOR, "task.delegated", {"delegates": [DELEGATE]}
    )

    assert (decision.allowed, decision.role) == (True, "creator")


# --- foreign actor ----------------------------------------------------------


@pytest.mark.parametrize("event_type", ["result.created", "proof.completed", "custom.free_form"])
def test_foreign_actor_may_append_nothing(event_type):
    decision = authorize_event(
        chain(request_created(), delegation(DELEGATE)), STRANGER, event_type, {}
    )

    assert decision.allowed is False
    assert decision.role == "unauthorized"
    assert decision.reason == "not_delegated"
    assert (decision.http_status, decision.message) == (
        403,
        "Actor is not authorized for this proof",
    )


# --- delegate ---------------------------------------------------------------


@pytest.mark.parametrize("event_type", OPEN_TYPES)
def test_delegate_may_append_open_types_after_delegation(event_type):
    decision = authorize_event(
        chain(request_created(), delegation(DELEGATE)), DELEGATE, event_type, {}
    )

    assert (decision.allowed, decision.role) == (True, "delegate")


def test_delegate_has_no_authority_before_the_delegation():
    events = chain(
        request_created(),
        event("agent.started", CREATOR),
        delegation(DELEGATE),
    )

    # Authorizing the third event: only the events before it count.
    decision = authorize_event(events[:2], DELEGATE, "result.created", {})

    assert (decision.allowed, decision.role, decision.reason) == (
        False,
        "unauthorized",
        "not_delegated",
    )


@pytest.mark.parametrize("event_type", ["proof.completed", "proof.failed"])
def test_delegate_may_not_close_the_proof(event_type):
    decision = authorize_event(
        chain(request_created(), delegation(DELEGATE)), DELEGATE, event_type, {}
    )

    assert (decision.allowed, decision.role, decision.reason) == (
        False,
        "delegate",
        "creator_only",
    )
    assert decision.http_status == 403


def test_delegate_may_not_sub_delegate():
    decision = authorize_event(
        chain(request_created(), delegation(DELEGATE)),
        DELEGATE,
        "task.delegated",
        {"delegates": [STRANGER]},
    )

    assert (decision.allowed, decision.reason) == (False, "creator_only")


def test_sub_delegation_in_the_chain_grants_nothing():
    """A delegate's task.delegated (e.g. written before enforcement) is ignored."""
    events = chain(
        request_created(),
        delegation(DELEGATE),
        delegation(STRANGER, actor=DELEGATE),
    )

    assert authorize_event(events, STRANGER, "result.created", {}).allowed is False


def test_delegated_to_grants_no_authority():
    events = chain(
        request_created(),
        event("task.delegated", CREATOR, {"task_id": "t1", "delegated_to": DELEGATE}),
    )

    assert delegates_of(events) == frozenset()
    assert authorize_event(events, DELEGATE, "result.created", {}).reason == "not_delegated"


def test_task_delegated_with_only_delegated_to_is_accepted_but_delegates_nobody():
    decision = authorize_event(
        chain(request_created()),
        CREATOR,
        "task.delegated",
        {"task_id": "t1", "delegated_to": DELEGATE},
    )

    assert decision.allowed is True


def test_delegations_accumulate():
    events = chain(request_created(), delegation(DELEGATE), delegation(OTHER_DELEGATE))

    assert delegates_of(events) == {DELEGATE, OTHER_DELEGATE}
    for actor in (DELEGATE, OTHER_DELEGATE):
        assert authorize_event(events, actor, "result.created", {}).allowed is True


def test_creator_self_delegation_is_harmless():
    events = chain(request_created(), delegation(CREATOR))

    assert delegates_of(events) == frozenset()
    decision = authorize_event(events, CREATOR, "proof.completed", {})
    assert (decision.allowed, decision.role) == (True, "creator")


# --- request.created ----------------------------------------------------------


@pytest.mark.parametrize(
    "actor", [CREATOR, DELEGATE, STRANGER], ids=["creator", "delegate", "stranger"]
)
def test_request_created_is_rejected_for_every_actor(actor):
    decision = authorize_event(
        chain(request_created(), delegation(DELEGATE)), actor, "request.created", {}
    )

    assert (decision.allowed, decision.reason) == (False, "request_created_not_allowed")
    assert decision.http_status == 403


# --- malformed delegate lists ------------------------------------------------------


@pytest.mark.parametrize(
    ("delegates", "reason"),
    [
        (DELEGATE, "invalid_delegates"),
        ({"did": DELEGATE}, "invalid_delegates"),
        ([new_did() for _ in range(MAX_DELEGATES_PER_PROOF + 1)], "invalid_delegates"),
        ([DELEGATE, DELEGATE], "invalid_delegates"),
        (["did:key:not-a-key"], "invalid_delegate_did"),
        (["did:web:example.com"], "invalid_delegate_did"),
        ([DELEGATE, 42], "invalid_delegate_did"),
        ([""], "invalid_delegate_did"),
    ],
    ids=[
        "string",
        "object",
        "33-entries",
        "duplicates",
        "malformed-did-key",
        "other-did-method",
        "non-string-entry",
        "empty-string",
    ],
)
def test_malformed_delegates_are_rejected(delegates, reason):
    decision = authorize_event(
        chain(request_created()), CREATOR, "task.delegated", {"delegates": delegates}
    )

    assert (decision.allowed, decision.role, decision.reason) == (False, "creator", reason)
    assert decision.http_status == 400


def test_exactly_32_delegates_are_allowed():
    delegates = [new_did() for _ in range(MAX_DELEGATES_PER_PROOF)]

    decision = authorize_event(
        chain(request_created()), CREATOR, "task.delegated", {"delegates": delegates}
    )

    assert decision.allowed is True


def test_delegate_cap_applies_per_proof_across_events():
    events = chain(
        request_created(),
        delegation(*[new_did() for _ in range(MAX_DELEGATES_PER_PROOF)]),
    )

    decision = authorize_event(events, CREATOR, "task.delegated", {"delegates": [new_did()]})

    assert (decision.allowed, decision.reason) == (False, "invalid_delegates")


def test_empty_delegate_list_is_accepted_and_delegates_nobody():
    events = chain(request_created())

    assert authorize_event(events, CREATOR, "task.delegated", {"delegates": []}).allowed
    assert delegates_of(events + [dict(delegation(), sequence=2)]) == frozenset()


def test_malformed_delegate_list_already_in_chain_grants_nothing():
    events = chain(
        request_created(),
        event("task.delegated", CREATOR, {"delegates": [DELEGATE, "did:key:bad"]}),
    )

    assert delegates_of(events) == frozenset()
    assert authorize_event(events, DELEGATE, "result.created", {}).allowed is False


# --- no creator ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "prior_events",
    [
        [],
        chain(event("agent.started", CREATOR)),
        [event("request.created", CREATOR, sequence=2)],
        chain(event("request.created", "")),
    ],
    ids=["empty", "first-not-request-created", "request-created-not-sequence-1", "empty-actor"],
)
def test_chain_without_creator_rejects_everyone(prior_events):
    assert creator_of(prior_events) is None

    for actor in (CREATOR, STRANGER):
        decision = authorize_event(prior_events, actor, "result.created", {})
        assert (decision.allowed, decision.role, decision.reason) == (
            False,
            "unauthorized",
            "no_creator",
        )


def test_second_request_created_does_not_change_the_creator():
    events = chain(request_created(), request_created(actor=STRANGER))

    assert creator_of(events) == CREATOR
    assert authorize_event(events, STRANGER, "result.created", {}).allowed is False


# --- one result.created per proof (D5) -------------------------------------------------


def test_first_result_created_is_allowed():
    assert check_single_result_created(chain(request_created()), "result.created") is None


def test_second_result_created_is_rejected_with_409():
    events = chain(request_created(), event("result.created", CREATOR))

    assert check_single_result_created(events, "result.created") == "result_already_created"
    assert REASONS["result_already_created"][0] == 409


def test_single_result_rule_ignores_other_types():
    events = chain(request_created(), event("result.created", CREATOR))

    assert check_single_result_created(events, "artifact.created") is None


# --- reason table --------------------------------------------------------------------------


def test_reason_codes_match_the_design_document():
    assert REASONS["no_creator"] == (403, "Actor is not authorized for this proof")
    assert REASONS["not_delegated"] == (403, "Actor is not authorized for this proof")
    assert REASONS["creator_only"] == (403, "Event type requires the proof creator")
    assert REASONS["request_created_not_allowed"] == (
        403,
        "request.created can only be written by POST /proofs",
    )
    assert REASONS["invalid_delegate_did"] == (400, "Invalid delegate DID")
