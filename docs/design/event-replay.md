# Event replay (design)

Status: **draft, not implemented.** Baseline for line references: commit
`d9cfc37`.

Measurements in this document were taken in memory (SQLite `StaticPool`,
`TestClient`), without writing to `proofs.db`.

## 1. Problem

`PARITY.md` → *Known Security Gaps*, row "Event nonce is not part of the
signed message" (`PARITY.md:44`), is **Open**. It is locked by
`test_signed_event_cannot_be_replayed_with_new_nonce`
(`test_security_regression.py:352-353`, strict xfail, reason `REPLAY_GAP` at
`:289`).

The event signature covers `proof_id|type|payload_hash` only
(`app/main.py:701-707`); the nonce travels next to it, unsigned, and is checked
for reuse within the proof (`app/main.py:768-772`). A signed event can
therefore be appended again with a different nonce by anyone holding the API
key. It keeps its original `actor_did` and signature, so event authorization
(`docs/design/event-authorization.md`) does not stop it.

`event-authorization.md` D-A10 says the verifier rejects any event the API
would reject. It cannot do that for nonce reuse: neither `GET /proofs/{id}`
(`app/main.py:846-855`) nor the event list built for `/verify`
(`app/main.py:888-897`) contains the nonce.

### 1.1 Effect today, after event authorization

Measured: for each type, an event was appended, then sent again with a new
nonce, then sent again with its original nonce.

| Event type (signer) | Original | Replay, new nonce | Replay, same nonce |
|---|---|---|---|
| `task.delegated` (creator) | 201 | **201** | 409 |
| `agent.started` (creator) | 201 | **201** | 409 |
| `artifact.created` (delegate) | 201 | **201** | 409 |
| free-form type (delegate) | 201 | **201** | 409 |
| `result.created` (delegate) | 201 | 409 "result.created already exists for this proof" | 409 |
| `proof.failed` (creator) | 201 | 409 "Proof is already failed" | 409 |
| `proof.completed` (creator) | 201 | 409 "Proof is already completed" | 409 |

`request.created` cannot be appended through the events endpoint at all (403).
After a replayed `agent.started`, both `/verify` and the offline verifier
report the proof as `valid`; the exported events contain the same signature
twice and no nonce.

Concrete harm, given an API-key holder:

- **Timeline forgery.** The server assigns `created_at` and `sequence` on
  append (`app/events.py:86-87`). A replayed event appears as a new,
  correctly signed event by the original actor at a later position, e.g.
  an `agent.started` after a result, or a second `artifact.created`.
- **Duplicate delegation.** A replayed `task.delegated` adds no authority
  (delegation is additive and idempotent, `event-authorization.md` D7), but
  shows the creator delegating twice.
- **Unbounded growth.** Any signed event can be appended repeatedly until the
  proof is closed.

Not affected: the result binding (one `result.created` per proof) and proof
closing (closed proofs reject all events).

### 1.2 Related finding: event signatures are valid proof requests

Not a replay of an event within its proof, but the same root cause (the signed
messages carry no domain): an event signature can be submitted to
`POST /proofs` as a request signature.

- Request signatures cover `room|nonce|text`
  (`app/crypto.py:877-882`, `canonical_signed_message`), checked by
  `verify_floop_signature`, which splits the canonical with
  `canonical.split("|", 2)` (`app/crypto.py:981`) and compares the parts with
  the request's `nonce` and `text` (`:991`, `:994`).
- An event canonical `proof_id|type|payload_hash` therefore parses as
  `room=proof_id`, `nonce=type`, `text=payload_hash`.

Measured: a victim's `agent.started` signature, submitted to `POST /proofs`
with `from_did` = victim, `nonce="agent.started"` and `text` = the payload
hash, was accepted (201). The new proof's creator is the victim's DID and
`/verify` reports it `valid`. The attacker needs only the API key and one
signed event of the victim.

This is a forged proof request attributed to the victim. It is addressed for
good by the domain tag in Option A (§3.1).

**Minimal fix applied** (tracked in `PARITY.md`, Known Security Gaps, "Event
signatures accepted as proof request signatures"):

- API: `verify_floop_signature` rejects a request whose room matches
  `^proof_[0-9a-f]{32}$` (`PROOF_ID_PATTERN` in `app/crypto.py`), so
  `POST /proofs` answers 401 "Invalid request signature". The pattern equals
  the proof_id format and the dashboard proxy's pattern; a test keeps them
  identical. No request in `proofs.db` or in the tests uses such a room.
- Verifier: each `request.created` gets `request_binding_valid`. The room,
  nonce and text are read from the signed canonical (the room is not stored
  separately); the room must not be a proof_id, the nonce and text must equal
  the stored request's, and the stored signature and actor must be the
  request's. A `false` value makes the verdict `invalid`. No `request.created`
  in `proofs.db` fails these checks.

This blocks the event-to-request direction only. Request signatures still
carry no domain tag; whether requests get one (`FLOP/REQUEST/v2`) stays open
question 2 in §6.

## 2. Current state

### 2.1 Where the event canonical is built and checked

| Place | Code | Role |
|---|---|---|
| API | `app/main.py:701-707` | builds `f"{proof_id}\|{event.type}\|{payload_hash}"` and compares it with the submitted canonical (401 on mismatch) |
| API | `app/main.py:714-725` | verifies the signature over the submitted canonical (401) |
| API | `app/main.py:768-772` | rejects a nonce already used in this proof (409) |
| Verifier | `app/verification_core.py:96-99` | recomputes `f"{proof_id}\|{event_type}\|{payload_hash}"` for every event except `request.created` |
| Verifier | `app/verification_core.py:78-95` | `request.created`: canonical must equal `payload.signature.canonical` |
| Verifier | `app/verification_core.py:102` | verifies the signature over the stored canonical |
| SDK | `flop_proof_sdk/client.py:164` | `append_signed_event` builds the same canonical; `nonce` is a separate argument (`:161`) sent unsigned (`:176`) |
| SDK copy | `client.py:164` | identical to the SDK |
| Tests | see §3.5 | build the canonical by hand |

### 2.2 Proof request signature

`create_signed_proof` (`flop_proof_sdk/client.py:124-152`) signs
`room|nonce|text` (`:134`); the API checks it with `verify_floop_signature`
(`app/main.py:539-552`). The request nonce **is** inside the signed message.
Replay of a whole request is also blocked by `request_id` uniqueness
(`app/main.py:555-592`). The verifier does not re-check the request's nonce
and text against its canonical (`app/verification_core.py:78-95`); it checks
only that the stored canonical equals `payload.signature.canonical` and that
the signature verifies.

### 2.3 Nonce storage and export

- Stored per event: `ProofEvent.nonce` (`app/models.py:36`), written by
  `create_event` (`app/events.py:35`, `:89`). `request.created` events are
  stored with the default empty nonce.
- **Not exported:** `GET /proofs/{id}` (`app/main.py:846-855`) and the
  `/verify` event list (`app/main.py:888-897`) omit it. The offline verifier
  (`app/verifier.py`) only sees the exported JSON, so it cannot check nonce
  uniqueness today.

### 2.4 Ed25519 is deterministic

`sign_message` (`app/crypto.py:925-930`) calls `Ed25519PrivateKey.sign`
(`cryptography` 47.0.0, RFC 8032). Measured: the same key and message give
byte-identical signatures; a different message gives a different signature.
Two events with the same signer, `proof_id`, type and payload therefore have
the same canonical **and** the same signature today.

## 3. Option A: sign the nonce

New canonical: `proof_id|type|payload_hash|nonce`, plus a domain tag (§3.1).

### 3.1 Domain tag

Without a tag, the new 4-part canonical would still parse as a request
canonical, because `verify_floop_signature` splits at most twice and puts the
rest in `text` (`app/crypto.py:981`). Proposed:
`FLOP/EVENT/v2|proof_id|type|payload_hash|nonce`. `verify_floop_signature`
should then reject a request canonical whose room starts with `FLOP/`, or
requests should get their own tag (`FLOP/REQUEST/v2|room|nonce|text`). The
second also changes the request wire format and is a separate decision (§6).

### 3.2 API and verifier

- API (`app/main.py:701-707`): build and compare the new canonical; the
  signature check (`:714-725`) is unchanged. A replay with a new nonce then
  fails the signature (401); with the same nonce it still gets 409 (`:768`).
- Export: add `nonce` to each event in `GET /proofs/{id}` and in the `/verify`
  event list (`app/main.py:846-855`, `:888-897`).
- Verifier (`app/verification_core.py:96-99`): recompute the new canonical from
  the exported `nonce`. It should also check that no two events in the chain
  share a nonce (D-A10 parity with the API's 409); with the nonce signed, a
  duplicate can only be an exact copy of an event.

### 3.3 Versioning

Existing events are signed with the old canonical and stay in their chains.

| Option | How the verifier picks the format | Effect |
|---|---|---|
| A1: proof version `"3"` | New proofs get `version="3"`; all their events must use the new canonical; `"1"`/`"2"` proofs keep the old one. | Clear rule. The proof version is not in the exported JSON's event list, so the verifier needs `version` from the exported proof (exported at proof level, `app/main.py:840`). Old proofs stay replayable unless Option B also applies (§5). |
| A2: per-event format | Each event declares its format (e.g. the domain tag); the verifier checks whichever format the event uses. | Old and new events can mix in one proof. A downgrade is possible: an attacker replays an old-format event into a new proof, unless the API refuses old-format events in new proofs. That makes A2 equal to A1 in practice. |
| A3: switch everything | All events, old and new, must use the new canonical. | Every existing proof becomes `invalid`. Not acceptable for exported proofs held by third parties. |

The proof version `"2"` already means "event authorization applies"
(`event-authorization.md` D6). Using `"3"` for "event canonical signs the
nonce" keeps one meaning per version.

### 3.4 SDK

`append_signed_event` (`flop_proof_sdk/client.py:154-182`) already takes a
`nonce` (`:161`); the change is to include it (and the domain tag) in the
canonical at `:164`. Callers keep the same signature. An old SDK talking to a
new API gets 401 on version-3 proofs ("Event canonical message mismatch",
`app/main.py:710`). `client.py` at the repo root is a copy and needs the same
change, or should be removed (`event-authorization.md` §10).

### 3.5 Tests that build the event canonical by hand

| File:line | Use |
|---|---|
| `test_client.py:65` | E2E script; also writes `/tmp/flop-proof.json`, which `test_verifier.py` reuses (`test_verifier.py:9-17`). A stale file from before the change would be verified under the old rule. |
| `test_event_replay.py:64` | exact replay (same nonce) → 409 |
| `test_lifecycle.py:68` | lifecycle appends |
| `test_lifecycle.py:255` | direct `create_event` with a non-standard canonical (concurrency test; not verified) |
| `test_security_regression.py:172`, `:202` | completed proof rejects events |
| `test_security_regression.py:299` | `signed_event` helper used by the authorization tests |
| `test_verifier.py:171` | `_build_signed_result_event` chain helper |

Tests that use the SDK (`test_client_signed.py`, `test_validator_api.py`)
change with the SDK.

### 3.6 Dashboard

The dashboard does not build or check canonicals. The proof page shows each
event's raw JSON, which includes `canonical` and `signature` and would show
`nonce` once it is exported. The Developer page has documentation examples
with `nonce` and `canonical_signed_message` (`dashboard/src/app/developer/page.tsx:70-108`)
that describe the request signature and would need updating if the request
format changes (§3.1).

## 4. Option B: reject a repeated (canonical, signature) pair

Reject an event whose canonical and signature already occur in the proof.

- **Legitimate duplicates.** Because Ed25519 is deterministic (§2.4), two
  legitimate events with the same signer, type and payload in one proof would
  be identical and the second would be rejected. Measured: none of the 931
  non-request events in `proofs.db` (689 proofs, almost all test data) repeats a
  pair within its proof, so no current flow does this. Status-style events with
  empty payloads (heartbeats, retries) would hit it; whether those are valid
  product flows is a product question.
- **Verifier.** Canonical and signature are exported (`app/main.py:851-852`),
  so the verifier can detect repeats in exported chains today, without new
  fields.
- **Nonce.** It would stay unsigned and only distinguish storage rows; the
  per-proof nonce check (`app/main.py:768`) becomes redundant for replay.
- **Limits.** B blocks exact copies only. It does not address §1.2 (an event
  signature used as a request) and keeps an unsigned field in the wire format.

## 5. Hybrid

A for new proofs (version `"3"`), and B for older proofs:

- Without B, events in version `"1"`/`"2"` proofs stay replayable after A,
  because their canonical cannot change.
- B is cheap for old proofs (no wire change, verifier can check it from the
  export) and its false-positive risk applies only to old chains, where no
  repeats exist today (§4).

## 6. Recommendation

Hybrid: Option A with a domain tag for version `"3"` proofs, and Option B for
version `"1"`/`"2"` proofs, in both the API and the verifier.

- A closes replay at the signature level and makes the nonce verifiable
  offline; the domain tag also closes §1.2 for new event signatures.
- B is needed because old chains cannot be re-signed.
- A3 (switch everything) would invalidate existing exported proofs.

Open questions for a *Decisions* section:

1. Proof version `"3"` for the new canonical (§3.3 A1), or per-event format?
2. Domain tag text, and whether requests also get a tag (`FLOP/REQUEST/v2`),
   which is a request wire-format change (§3.1).
3. For old proofs, is B acceptable given that it rejects identical
   legitimate events (§4)?
4. Should §1.2 be fixed on its own before this work, e.g. by making
   `verify_floop_signature` reject a canonical whose room is a `proof_` id?
5. Export `nonce` for all events, including old ones (§3.2)?
6. Should the verifier check nonce uniqueness for new proofs (§3.2), and B for
   old ones?
7. SDK compatibility window: is a 401 for an old SDK on version-3 proofs
   acceptable, or does the API need to accept both formats for a period
   (which reopens downgrade, §3.3 A2)?

## 7. Tests

With the recommendation:

| Test | Expected |
|---|---|
| `test_signed_event_cannot_be_replayed_with_new_nonce` (version-3 proof) | XPASS under A, so remove the xfail mark. Its current request uses the old canonical and would need the new format. |
| Same scenario on a version-2 proof | Passes under B (409), not under A alone. |

New tests:

- Version-3 replay with a new nonce → **401** (signature no longer matches).
- Version-3 replay with the same nonce → **409**.
- Version-2 replay of an identical event → **409** under B.
- Verifier: a replayed event inserted with `create_event` into an exported
  version-3 chain → `invalid` (duplicate nonce); into a version-2 chain →
  `invalid` (duplicate canonical and signature).
- Old-format event submitted to a version-3 proof → 401 (no downgrade).
- An event signature submitted to `POST /proofs` → rejected (§1.2).
- Export contains `nonce`; offline and API verification agree.
- SDK end to end: `append_signed_event` on a version-3 proof → 201; replay
  with a new nonce → 401.
- `test_verifier.py`: regenerate `/tmp/flop-proof.json` instead of reusing a
  stale file (§3.5).
