# Event replay (design)

Status: **design approved, not implemented.** See *Decisions* at the end.
Baseline for line references: commit `d9cfc37`.

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
`FLOP/EVENT/v2|proof_id|type|payload_hash|nonce`. Requests and events then
have to be kept apart in one of two ways:

- `verify_floop_signature` rejects a request canonical whose room starts with
  `FLOP/`. **Considered, not chosen (see D-R2).**
- Requests get their own tag (`FLOP/REQUEST/v2|room|nonce|text`). This also
  changes the request wire format. **Chosen (D-R2)**, with the tag version
  equal to the proof version: `FLOP/REQUEST/v3` and `FLOP/EVENT/v3`.

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
canonical at `:164`. `create_signed_proof` (`:124-152`) adds the request tag
to the canonical at `:134` (D-R2). Callers keep the same signature.

An old SDK is rejected at `POST /proofs`: its request has no tag, so it gets
401 before any proof is created (D-R4). It therefore never holds a version-3
proof to append to. The event-stage failure described in an earlier draft (an
old SDK getting 401 "Event canonical message mismatch", `app/main.py:710`, on
a version-3 proof it had just created) no longer occurs under D-R4. That 401
remains only for an old-format event sent to a version-3 proof created by a
new client.

`client.py` at the repo root is a copy of the SDK and is removed (D-R7).

### 3.5 Places to change

Every place that builds or checks a request or event canonical, plus the
other places D-R1 to D-R7 change. Line numbers in this section are at commit
`586a941`, not at the document baseline.

**Application code and SDK**

| File:line | Today | Change | Decision |
|---|---|---|---|
| `app/crypto.py:878-883` | `canonical_signed_message` builds `room\|nonce\|text` | add the request tag | D-R2 |
| `app/crypto.py:975-982` | `PROOF_ID_PATTERN`, `is_proof_id` (§1.2 minimal fix) | still used for v1/v2 request binding in the verifier; redundant for v3 requests | D-R2 |
| `app/crypto.py:985-1025` | `verify_floop_signature` splits `room\|nonce\|text` (`:992`) and rejects a `proof_` room (`:1006`) | require `FLOP/REQUEST/v3`, reject an untagged request, reject `\|` in room and nonce | D-R2, D-R3, D-R4 |
| `app/schemas.py:7-12`, `:31-36`, `:39-45` | `SignatureSchema.nonce`, `EventSignatureSchema.nonce`, `EventCreate.type`: only `min_length=1` | one possible place to reject `\|` in nonce and type (the other is the canonical check) | D-R3 |
| `app/main.py:539-552` | `create_proof` checks the request signature (401) | untagged request rejected here, before the proof row is written | D-R4 |
| `app/main.py:601` | `version="2"` | `version="3"` | D-R1 |
| `app/main.py:701-710` | builds `proof_id\|type\|payload_hash` and compares (401) | v3: tagged canonical with nonce; v1/v2 proofs keep the old canonical | D-R2 |
| `app/main.py:714-725` | verifies the signature over the submitted canonical | unchanged | — |
| `app/main.py:762-772` | rejects a nonce already used in the proof (409) | add Option B for v1/v2 proofs: reject a repeated (canonical, signature) pair | D-R5 |
| `app/main.py:837-858` | `GET /proofs/{id}` export without `nonce` | add `nonce` | D-R6 |
| `app/main.py:880-905` | `/verify` event list without `nonce`; calls `verify_proof_events(proof_id, events)` | add `nonce`; pass the proof version | D-R1, D-R6 |
| `app/events.py:35`, `:39-40` | `create_event` defaults to `nonce=""` (so `request.created` rows store an empty nonce) and builds the old canonical when none is given | default canonical for v3 or require one; decide which nonce is exported for `request.created` (stored row is empty, the request nonce is in `payload.signature.nonce`) | D-R2, D-R6 |
| `app/verification_core.py:15-48` | `_request_binding_ok` parses `room\|nonce\|text` | v3: parse the tagged form; reject `\|` in room and nonce | D-R2, D-R3 |
| `app/verification_core.py:53-56` | `verify_proof_events(proof_id, events)` has no version | take the proof version and pick the canonical rules by it | D-R1 |
| `app/verification_core.py:117-136` | `request.created`: canonical equals the stored request canonical, binding check | v3: tagged request canonical | D-R2 |
| `app/verification_core.py:137-142` | non-request events: recomputes `proof_id\|type\|payload_hash` | v3: tagged canonical with the exported nonce | D-R2 |
| `app/verification_core.py:75-208` (event loop) | no nonce or repeat check | v3: nonce unique in the proof; v1/v2: Option B | D-R5, D-R6 |
| `app/verifier.py:13-33` | `verify_proof_data` passes only `proof_id` and `events` | pass `version` from the exported proof | D-R1 |
| `flop_proof_sdk/client.py:124-152` | `create_signed_proof`, canonical at `:134` | request tag | D-R2, D-R7 |
| `flop_proof_sdk/client.py:154-182` | `append_signed_event`, canonical at `:164`, nonce unsigned at `:176` | event tag and signed nonce | D-R2, D-R7 |
| `pyproject.toml:7` | SDK version `0.2.0` | bump | D-R7 |
| `client.py` (root) | copy of the SDK; canonicals at `:134`, `:164` | remove | D-R7 |

**Tests that build a request canonical by hand** (all need the request tag, D-R2)

| File:line | Use |
|---|---|
| `test_api_contract.py:20` | contract tests' signed request |
| `test_client.py:39` | E2E script's request |
| `test_event_replay.py:25` | request for the replay tests (room is the `request_id`) |
| `test_idempotency.py:16` | idempotent `POST /proofs` |
| `test_lifecycle.py:31` | `create_signed_proof` helper (`:26`) |
| `test_security_regression.py:63-80` | `make_signed_request` helper (canonical at `:66`) |
| `test_security_regression.py:652-804` | §1.2 tests: `_victim_event_signature` (`:652`), `_request_from_event_signature` (`:662`), tests at `:680`, `:692`, `:733`, `:742`, `:790`. Under v3 they need tagged messages; the event-as-request case then fails on the tag. |
| `test_verifier.py:62` | `proof_file` fixture's request |
| `test_verifier.py:263` | `_build_signed_result_event` request |

**Tests that build an event canonical by hand** (v3 tag and nonce, D-R2)

| File:line | Use |
|---|---|
| `test_client.py:65` | E2E script; also writes `/tmp/flop-proof.json`. Since `17fa21d` no test reads that file. |
| `test_verifier.py:83` | `proof_file` fixture: builds a fresh four-event proof through the API in `tmp_path` on every run (`17fa21d`), so it follows the API's canonical and needs no stale-file handling. |
| `test_event_replay.py:64` | exact replay (same nonce) → 409 |
| `test_lifecycle.py:68` | lifecycle appends |
| `test_lifecycle.py:255` | direct `create_event` with a non-standard canonical (concurrency test; not verified) |
| `test_security_regression.py:172`, `:201-202` | completed proof rejects events |
| `test_security_regression.py:299` | `signed_event` helper used by the authorization tests |
| `test_verifier.py:290` | `_build_signed_result_event` chain helper |

`test_api_contract.py:127` and `test_client_errors.py:53` send the fixed
canonical `"invalid"`; they stay invalid under v3 and need no change.

**Tests that import the root `client.py`** (move to `flop_proof_sdk`, D-R7):
`test_client.py:11`, `test_client_errors.py:4`, `test_validator_api.py:737`,
`:921`, `:1077`, `:1123`, `:1184`, `:1333`. `test_client_signed.py:10` already
uses `flop_proof_sdk` and changes with the SDK.

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
   **Resolved by D-R1.**
2. Domain tag text, and whether requests also get a tag (`FLOP/REQUEST/v2`),
   which is a request wire-format change (§3.1). **Resolved by D-R2, D-R3.**
3. For old proofs, is B acceptable given that it rejects identical
   legitimate events (§4)? **Resolved by D-R5.**
4. Should §1.2 be fixed on its own before this work, e.g. by making
   `verify_floop_signature` reject a canonical whose room is a `proof_` id?
   **Resolved: minimal fix applied (see §1.2).**
5. Export `nonce` for all events, including old ones (§3.2)? **Resolved by D-R6.**
6. Should the verifier check nonce uniqueness for new proofs (§3.2), and B for
   old ones? **Resolved by D-R5, D-R6.**
7. SDK compatibility window: is a 401 for an old SDK on version-3 proofs
   acceptable, or does the API need to accept both formats for a period
   (which reopens downgrade, §3.3 A2)? **Resolved by D-R4, D-R7.**

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
- `test_verifier.py`: done in `17fa21d`; the `proof_file` fixture builds its
  proof in `tmp_path` on every run (§3.5).

## Decisions

Approved for implementation. Section numbers refer to this document.

| # | Decision | Section |
|---|---|---|
| D-R1 | Proof version `"3"`. The server creates every new proof as `"3"`; only the server sets the version. | §3.3 A1; §6 q1 |
| D-R2 | Both message kinds carry a domain tag. Request: `FLOP/REQUEST/v3\|room\|nonce\|text`. Event: `FLOP/EVENT/v3\|proof_id\|type\|payload_hash\|nonce`. The tag version equals the proof version. | §3.1; §6 q2 |
| D-R3 | In v3, `room`, `nonce` and `type` must not contain `\|`. In a request, `text` is the last field and may contain `\|`. Reason: otherwise different field combinations could produce the same signed text (parsing ambiguity). | §3.1; §6 q2 |
| D-R4 | An untagged (old-format) proof request is rejected before any proof is created. There is no compatibility window, so old clients cannot produce half-usable proofs. | §3.3, §3.4; §6 q7 |
| D-R5 | v1/v2 proofs stay verifiable. Option B applies to new events appended to them and in the verifier: the same (canonical, signature) pair is not accepted twice in one proof. | §4, §5; §6 q3, q6 |
| D-R6 | The nonce is included for all events, old ones too, in `GET /proofs/{id}`, `/verify` and the exported JSON. For v3 the verifier checks the tag and nonce uniqueness within the proof. | §2.3, §3.2; §6 q5, q6 |
| D-R7 | The root `client.py` (an old copy of the SDK) is removed; tests that import it use `flop_proof_sdk`. The SDK moves to the new format in the same change, with a version bump. | §3.4; §6 q7 |
| D-R8 | The dashboard Developer page examples are updated in a separate slice after this change. | §3.6 |
