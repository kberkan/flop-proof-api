# Event authorization (design)

Status: implemented (app/authorization.py, API in app/main.py, verifier in app/verification_core.py). Baseline for line references: commit `a325fd4`.
Decision taken: several actors may append events to one proof, but only
through explicit delegation by the proof's creator.

Line references are to the baseline commit.

## 1. Problem

`PARITY.md` → *Known Security Gaps* (`PARITY.md:34`) records that
`POST /proofs/{proof_id}/events` has no actor authorization. The handler
(`app/main.py:677-772`) checks that the proof exists (`:684`), that it is not
closed (`:694`), that the canonical message matches (`:702-710`), that the
signature verifies under the event's own `actor_did` (`:712-725`) and that the
nonce is new (`:727-738`). Nothing compares `actor_did` with the proof's
creator or any delegation.

Locked by strict xfail tests in `test_security_regression.py`:

| Test | Line | Gap |
|---|---|---|
| `test_foreign_actor_cannot_append_result_to_another_actors_proof` | 311 | authorization |
| `test_foreign_actor_cannot_complete_another_actors_proof` | 330 | authorization |
| `test_verify_rejects_proof_with_foreign_actor_result` | 370 | authorization (verifier) |
| `test_signed_event_cannot_be_replayed_with_new_nonce` | 351 | nonce replay |

**Scope.** This document covers authorization only. Nonce replay needs the
nonce inside the signed message (`proof_id|type|payload_hash` today,
`main.py:702-704`), which is a wire-format change for every signer and gets its
own document and slice.

**Interaction with replay.** Authorization does not stop replay: a replayed
event keeps its original, authorized `actor_did` and signature, so it passes
the role check. In particular a creator-signed `task.delegated` can be replayed
by anyone holding the API key. Under this design that is harmless only while
delegation is additive and idempotent (see §3 and §12, revocation).

## 2. Roles

- **creator**: `actor_did` of the proof's `request.created` event.
  `POST /proofs` writes that event in `app/main.py:610-618` with
  `actor_did=signed_request.from_did` (`:614`), after verifying the request
  signature against that DID (`:537-552`). The event's canonical is the
  request canonical `room|nonce|text` (`:616`), not `proof_id|type|hash`; the
  verifier already special-cases this (`app/verification_core.py:73-89`).
- **delegate**: a DID listed in a `task.delegated` event signed by the
  creator. Authority applies to events with a **higher sequence** than that
  `task.delegated` event.
- **unauthorized**: everyone else.

**Conflicts with current code**

- *Creator is not unique today.* The events endpoint does not restrict
  `type` (`app/schemas.py:42`, `type: str`), so anyone can append a second
  `request.created` through `POST /proofs/{id}/events`. The creator must
  therefore be defined as the actor of the **sequence-1** `request.created`
  event, and later `request.created` events must be rejected (§4).
- *Proofs without `request.created` exist.* `app/events.py:12-79`
  (`create_event`) writes any event without checks; `test_lifecycle.py:219`
  uses it to create proofs with only `test.concurrent` events from fake DIDs.
  `proofs.db` holds 34 such proofs. With no creator, every event in such a
  chain is unauthorized. They are only produced by tests that bypass the API.

## 3. `task.delegated` payload

Draft: `{"delegates": ["did:key:...", ...]}`.

- **Signed:** yes. The event canonical is `proof_id|type|payload_hash`
  (`main.py:702-704`) and `payload_hash = sha256_json(payload)` (`:700`), so
  the delegate list is covered by the creator's signature. The verifier
  recomputes the hash (`verification_core.py:65-71`).
- **DID validation:** `did_key_to_public_key` (`app/crypto.py:894-909`)
  rejects anything that is not `did:key:z` + base58 Ed25519 multicodec + 32
  bytes. It can validate each delegate. A malformed entry should make the
  whole `task.delegated` event invalid (400), not be skipped silently.
- **Today's usage conflicts with the draft key.** Existing payloads use a
  different shape:
  - `test_client_signed.py:37-41` and `test_client.py:89-95`:
    `{"task_id": ..., "delegated_to": "<did>", ...}`, with
    `delegated_to` equal to the creator.
  - `test_api_contract.py:121` and `test_client_errors.py:47`: no delegate
    field; these requests fail before authorization (404).
  - `test_security_regression.py:354`: `{"to": "worker-1"}` (replay test).
  - `proofs.db`: every `task.delegated` payload is
    `{"delegated_to": "<did>", "task_id": "pytest-task"}`, and in every case
    the delegate equals the creator.

  With `delegates` as the only recognised key, these events stay valid but
  delegate nobody. Nothing breaks today, because all existing delegations
  are to the creator. **Recommendation:** use the new `delegates` list
  only; treat `delegated_to` as a non-authorizing legacy field. Accepting both
  keys would create two meanings for one event type.
- Other payload fields (`task_id`, `instruction`) stay free-form.

## 4. Authorization matrix

| Event type | Who may append | Where |
|---|---|---|
| `request.created` | nobody via the events endpoint; written once by `POST /proofs` | `main.py:610-618` |
| `task.delegated` | creator | events endpoint |
| `proof.completed`, `proof.failed` | creator | events endpoint |
| all other types (`result.created`, `agent.started`, `artifact.created`, free-form) | creator or delegate | events endpoint |

Event types with special behavior today:

- `request.created`: canonical rule (`verification_core.py:73-89`);
  idempotency and ownership lookup in `POST /proofs` (`main.py:560-592`).
- `proof.completed` / `proof.failed`: set the proof status (`main.py:754-757`);
  closed proofs reject new events (`:694-698`).
- `result.created`: result-hash check (`verification_core.py:136-198`, gated at `:219-224`);
  validator-attestation binding (`main.py:153-160`).
- `artifact.created`: artifact-hash check (`verification_core.py:199-217`, gated at `:219-224`).

**Conflict:** `request.created` is accepted by the events endpoint today; the
matrix forbids it. No other conflict with the matrix.

## 5. One pure function

Proposed location: `app/authorization.py` (no imports from `main`, `database`
or `models`).

```
authorize_event(prior_events, actor_did, event_type) -> Decision
    prior_events: ordered chain data, items with "type", "actor_did",
                  "payload", "sequence" (the shape verification_core already
                  uses, verification_core.py:32-42)
    Decision: role in {"creator", "delegate"} or a rejection reason
              ("no_creator", "request_created_not_allowed",
               "creator_only", "not_delegated")
```

It reads chain data only: no database, no server state, no clock.
Delegation is in effect only for `task.delegated` events in `prior_events`, so
"after its sequence" holds by construction.

`prior_events` must contain only events that passed signature verification.
Otherwise a forged `task.delegated` that claims the creator's DID would grant
authority.
- API: events already in the database passed the signature check when they
  were written, except those written directly through `create_event`.
- Verifier: it already computes `signature_valid` per event
  (`verification_core.py:96-103`) and must pass only those events.

Callers:

- **API** (`main.py:677-772`): load the chain (it is already queried for the
  nonce check at `:727-733` and in `create_event`), call `authorize_event`
  **after** the signature check (`:712-725`) and before `create_event`
  (`:740`).
- **Verifier** (`verification_core.py:32-119`): call it per event with the
  events before it. `app/verifier.py:13-34` calls `verify_proof_events`, so
  offline verification gets the same rule with no extra code.

**Order: after signature verification.** `actor_did` is self-asserted until the
signature proves control of the key. Checking roles first would answer
"is this DID a delegate of this proof?" to unauthenticated callers, and would
return 403 where the real problem is a bad signature (401). Existing order is
canonical (401), then signature (401), then nonce (409); authorization slots in
as 403 between signature and nonce.

**Do not put the check in `create_event`** (`app/events.py:12`): tests and
future internal writers call it directly (`test_lifecycle.py:219`), and the
rule belongs to the API boundary and the verifier.

## 6. API behavior

- Unauthorized: **403**. `main.py` uses 401 for authentication and signature
  failures (`:549-552`, `:722-725`), 404 for missing resources and 409 for state
  conflicts. 403 is currently unused and fits "authenticated, not allowed".
- Messages, following the existing short, capitalised style
  ("Invalid event signature", "Proof not found"):
  - `"Actor is not authorized for this proof"` (`not_delegated`, `no_creator`)
  - `"Event type requires the proof creator"` (`creator_only`)
  - `"request.created can only be written by POST /proofs"`
    (`request_created_not_allowed`)
- Malformed delegate list in `task.delegated`: 400 `"Invalid delegate DID"`.

## 7. Verifier behavior

- Add `actor_did`, `role` (`creator`, `delegate`, `unauthorized`) and
  `actor_authorized` (bool) to each item of `checks`
  (`verification_core.py:105-116`). Optionally add `creator_did` at the top
  level (`:226-235`).
- `all_events_valid` (`:121-128`) also requires `actor_authorized`, so an
  unauthorized event makes the verdict `invalid`.
- **Compatibility:** these keys are additive. No test compares the verifier
  output exactly; `test_verifier.py` reads individual keys only. External
  consumers that require an exact key set would see new keys.
- Offline: `app/verifier.py` → `verify_proof_events`, so offline and API
  results come from one implementation. Exported JSON (`GET /proofs/{id}`,
  `main.py:797-818`) already carries `actor_did`, `type`, `payload` and
  `sequence` for every event, so nothing new needs exporting.

## 8. Validator-attestation binding

`POST /proofs/{proof_id}/validator-attestations/accept` binds to the
highest-sequence `result.created` (`main.py:153-160`). With authorization, only
the creator or a delegate can add `result.created`, but each of them can add
several, and a later one replaces the earlier as the binding target.

Options:

1. Keep "latest authorized `result.created`". Simple; authorized actors can
   still supersede each other's results.
2. Allow at most one `result.created` per proof (reject the second with 409).
   Unambiguous; breaks any flow that revises a result.
3. Have the attestation request name the `event_id` it binds to. Explicit;
   changes the request schema and the SDK.
4. Allow `result.created` only from delegates, or only from the creator.
   Narrows who can supersede; does not remove superseding.

**Recommendation:** option 2 for v1. No proof in `proofs.db` (1,215 proofs,
almost all from the test suite) has more than one `result.created`, and it
closes the attestation question without a schema change. Revisit with option 3 if result revision becomes a requirement.

## 9. Existing data and compatibility

- **Version field:** `Proof.version` exists (`app/models.py:15`, default
  `"1"`); `POST /proofs` always writes `"1"` (`main.py:600`) and
  `GET /proofs/{id}` exports it. The verifier does not read it.
- **Tests that would break:** none of the passing tests. All API-driven tests
  use one actor (the creator) per proof, and their `task.delegated` events
  delegate to the creator. `test_lifecycle.py:219` bypasses the API through
  `create_event`. `test_verifier.py` builds its proof with `test_client.py`, a
  single actor. Three of the four xfail tests would start passing (§11).
- **Existing exported proofs:** proofs with a single actor stay valid. Proofs
  with a foreign actor become `invalid`. In `proofs.db` that is one proof
  (`auth-audit-55b6e7c1…`), plus the 34 creator-less proofs from
  `test_lifecycle.py`, which no test verifies.

Options:

1. Apply the rule to every proof.
2. Apply it only to proofs with `version >= "2"`, and start writing `"2"`.
3. Apply it to every proof, and keep a separate `legacy_unauthorized` status for
   `version == "1"` proofs.

**Recommendation:** option 1. Existing data is test data plus one manual probe,
and option 2 would keep the gap open for any version-1 proof forged later.
Bump `version` to `"2"` anyway so consumers can tell which rule a proof was
written under.

## 10. SDK (scope only, not in this slice)

`flop_proof_sdk/client.py:154-182` (`append_signed_event`) already signs any
type and payload. Delegation needs:

- a helper that builds `{"delegates": [...]}` and validates the DIDs before
  signing;
- typed handling of 403 in the SDK error class (`flop_proof_sdk/client.py:44`, `FlopProofHTTPError`);
- a note that `client.py` at the repo root differs from
  `flop_proof_sdk/client.py` and needs the same change, or should be removed.

## 11. Tests

With authorization in place:

| Test | Expected |
|---|---|
| `test_foreign_actor_cannot_append_result_to_another_actors_proof` | XPASS, so remove the xfail mark |
| `test_foreign_actor_cannot_complete_another_actors_proof` | XPASS, so remove the xfail mark |
| `test_verify_rejects_proof_with_foreign_actor_result` | XPASS, so remove the xfail mark |
| `test_signed_event_cannot_be_replayed_with_new_nonce` | stays XFAIL (replay is out of scope) |

New tests:

- `authorize_event` unit tests: creator, delegate, unauthorized, no creator,
  second `request.created`, each reason code.
- A delegate event **before** the delegation (lower sequence) → unauthorized.
- A delegate appends `result.created` → 201.
- A delegate appends `proof.completed` / `proof.failed` / `task.delegated`
  → 403.
- Sub-delegation (a delegate's `task.delegated`) → 403.
- A `task.delegated` with a malformed DID → 400; one with `delegated_to` only
  delegates nobody.
- `request.created` through the events endpoint → 403.
- Verifier: `actor_did`, `role` and `actor_authorized` per check; an
  unauthorized event makes the verdict `invalid`.
- Offline and API verification give equal results for the same exported proof.
- A forged `task.delegated` (bad signature, creator's DID) does not grant
  authority in the verifier.
- Option 2 of §8: a second `result.created` → 409.

## 12. Open questions

Most of these are settled in *Decisions* below.

| Question | Suggestion |
|---|---|
| Revocation in v1? | No. Delegation is additive. Revocation needs ordering rules, and replay (§1) could re-grant authority until the nonce is signed. Add it after the replay fix. |
| Sub-delegation? | No in v1. Delegates cannot append `task.delegated`. |
| Can a delegate write `artifact.created`? | Yes (matrix row "all other types"). |
| Restrict free-form event types? | Not in this slice. Record it in `PARITY.md` as a separate item. |
| Delegate limit per proof? | Cap the list, e.g. 32, to bound verification work. |
| Should the creator be allowed to delegate to itself? | Allow it, since current data does this. It has no effect. |
| §8 binding rule | Option 2 (one `result.created` per proof). |
| §9 compatibility | Option 1 plus `version = "2"`. |

## Decisions

Approved for implementation. Section numbers refer to this document.

| # | Decision | Section |
|---|---|---|
| D1 | Check order on `POST /proofs/{proof_id}/events`: signature (401) → authorization (403) → nonce (409). | §5, §6 |
| D2 | Only the `delegates` list in a `task.delegated` payload grants authority. `delegated_to` stays a legacy field that grants nothing. | §3 |
| D3 | Authorization is enforced at the API boundary and in the verifier, not in `create_event` (`app/events.py:12`). | §5 |
| D4 | The events endpoint rejects `request.created`. The creator is the actor of the sequence-1 `request.created`. | §2, §4 |
| D5 | One `result.created` per proof; a second one gets 409 (v1). | §8, option 2 |
| D6 | The rule applies to every proof; new proofs are written with `version = "2"`. | §9, option 1 |
| D7 | No revocation and no sub-delegation in v1. At most 32 delegates per proof. | §12 |
| D8 | Restricting free-form event types is a separate work item. | §12 |

Implementation decisions for `app/authorization.py`, taken while implementing
the function:

| # | Decision | Section |
|---|---|---|
| D-A1 | `authorize_event` also takes the new event's `payload`, so a malformed delegate list can be rejected with 400. | §5, §3, §6 |
| D-A2 | The one-`result.created` rule is a separate function, `check_single_result_created`, returning 409. | D5, §8 |
| D-A3 | Messages: "Invalid delegate list" (400, `invalid_delegates`) and "result.created already exists for this proof" (409, `result_already_created`). | §6 |
| D-A4 | Delegate cap: at most 32 entries in one list and at most 32 distinct delegates per proof; the creator does not count. | D7, §12 |
| D-A5 | An empty `delegates` list is valid and has no effect; a repeated entry is 400. | §3 |
| D-A6 | A malformed delegation already in the chain grants nothing. | §3 |
| D-A7 | Creator: the first event must be `request.created` and, if it has a `sequence` field, the sequence must be 1. Otherwise there is no creator and every event is unauthorized. | §2, D4 |
| D-A8 | Check order inside the function: no creator → `request.created` → role → creator-only type → delegate list. | §5 |
| D-A9 | On rejection, `role` carries the actor's actual role. | §5 |
| D-A10 | Verifier: replays the chain. For each event *i*, it calls `authorize_event` and `check_single_result_created` with prior = `events[:i]`. The sequence-1 `request.created` is exempt from this loop. If any event would be rejected by the API, the verdict is `invalid`. API and verifier then apply the same rule, and events written around the API are caught too. | §5, §7 |

Note on D-A10: §5 requires `prior_events` to contain only events whose
signatures verified. A chain with any invalid signature is already `invalid`,
so this affects only which `role` is reported for later events. The verifier
integration should pass only signature-valid events as `prior`.

Not decided by this list:

- Whether the creator may delegate to itself. §12 suggests allowing it, since
  current data does this and it has no effect.
- How the dashboard gets a per-proof verdict for its list: one `/verify` call
  per proof, or a verdict field in `GET /proofs`. The second is an API change.
  See §13.6.
- The 403/400 messages in §6 are proposals; the wording is final only when it
  is implemented.

## 13. Dashboard impact

Scope only; nothing in `dashboard/` changes in this slice. References are to
the source under `dashboard/src/app/` (Next.js), not to build output. "S" below
is short for `dashboard/src/app/`.

### 13.1 Endpoints, API address and key

All calls go through one server-side proxy, `S/api/flop/[...path]/route.ts`:

- API address is hard-coded: `const API_URL = "http://127.0.0.1:8000";`
  (`route.ts:3`).
- API key comes from `process.env.FLOP_API_KEY` (`route.ts:9`), set in
  `dashboard/.env.local` (gitignored by `dashboard/.gitignore:34`, `.env*`).
  The proxy adds `X-API-Key` to every forwarded request (`route.ts:19`).
- Endpoints the pages call:
  - `GET /proofs?limit=8` (`S/page.tsx:64`)
  - `GET /proofs?limit=100[&status=…]` (`S/proofs/page.tsx:73-74`,
    `S/verification/page.tsx:39`)
  - `GET /proofs/{proof_id}` (`S/proofs/[proof_id]/page.tsx:82-83`)
  - `GET /proofs/{proof_id}/verify` (`S/verification/page.tsx:63-64`)
  - `GET /actors` (`S/actors/page.tsx:38`)

**Related risk, outside this design:** the proxy forwards **every method**
(`route.ts:43-50`: GET, POST, PUT, PATCH, DELETE, HEAD) and every path, and
adds the server's API key. The dashboard has no authentication of its own (no
middleware, no session handling in `dashboard/src`). Anyone who can reach the
dashboard can therefore call `POST /proofs/{id}/events` with the server's key,
which is exactly the operation §1 describes. The pages only use GET.
Restricting the proxy to GET (and to the paths above) closes this path
independently of event authorization, and should be tracked in `PARITY.md`.

### 13.2 Proof list and proof detail

- List (`S/proofs/page.tsx`) and overview (`S/page.tsx:31-39`, `Proof` type)
  show `proof_id`, `request_id`, `version`, `status`, `created_at`,
  `updated_at` and the event count `events`. These are the fields
  `GET /proofs` returns (`app/main.py:436-442`).
- Detail (`S/proofs/[proof_id]/page.tsx`) shows the proof identity fields, a
  status badge, an "Event timeline" (`:250`) whose heading per event is the
  event `type`, and each event as raw JSON (`formatValue(event)`, `:292`).

### 13.3 Verify result

- Only the Verification page calls `/verify`, and only for one proof it
  picks itself: the first `completed` proof, else the first `active`, else
  the first in the list (`S/verification/page.tsx:50-55`). The user cannot
  choose a proof.
- It shows `verdict` (`:93-94`, `:185`) with a green or red style, and
  `events_checked` (`:208`). `checks` and `evidence` are not rendered as UI
  elements; they appear only inside the raw JSON dump
  (`JSON.stringify(result, null, 2)`, `:252`).
- The proof detail page never calls `/verify`.

### 13.4 Evidence fields and stronger-than-actual claims

`execution_verified`, `runtime_settled` and `evidence.class` are not read
anywhere in `dashboard/src`. They are visible only in the raw JSON on the
Verification page. Several labels and icons claim more than the data shows:

| Location | Text or element | Problem |
|---|---|---|
| `S/proofs/page.tsx:39-43` | `completed: { label: "VALID", … }` | Status `completed` (set by any `proof.completed` event, `app/main.py:754-755`) is shown as **"VALID"**. Nothing is verified. |
| `S/proofs/[proof_id]/page.tsx:27-34` | `if (status === "completed") { return { label: "VALID", …` | Same, on the detail page. |
| `S/page.tsx:206` | `["Valid proofs", stats.completed.toString(), …]` | The "Valid proofs" counter counts `completed` proofs. |
| `S/proofs/[proof_id]/page.tsx:213-240` | "Verification evidence" / "Integrity primitives" with "Payload hashes", "Canonical messages", "Ed25519 signatures", "Event chain", each followed by `<CheckCircle2 … className="text-emerald-400" />` (`:237`) | Green checks are hard-coded. This page never calls `/verify`, so they show for tampered or invalid proofs too. |
| `S/proofs/[proof_id]/page.tsx:285` | `<CheckCircle2 … className="shrink-0 text-emerald-400" />` on every event | Every event gets a green check regardless of its signature or chain status. |
| `S/page.tsx:288` | `["Payload hashes", "Canonical messages", "Ed25519 signatures", "Event chain", "DID actor identity"]`, each with a green check | Static. "DID actor identity" in particular implies actor checks the API does not do (§1). |
| `S/verification/page.tsx:201-241` | Cards "Event chain", "Canonical messages", "Ed25519 signatures" ("Actor signature verification", `:228`), "Payload integrity", all with emerald icons | Rendered the same when the verdict is `invalid`. |
| `S/verification/page.tsx:122` | "Verify the integrity and authenticity of a proof." | "authenticity" overstates: signatures show who signed each event, not that the signer was entitled to (§1). |
| `S/developer/page.tsx:386`, `:397` | "Proof verification checks the complete evidence chain." and `["Ed25519 signature", "Verified"]` | "complete" overstates; actor authorization is not checked. |

The Developer page is accurate about the evidence boundary:
`evidenceBoundary` (`S/developer/page.tsx:80-105`) lists for each endpoint
what it does **not** prove, and `:328` says "API acceptance is not execution
verification or runtime settlement." This is the only place where the UI
states these limits.

### 13.5 Does the dashboard show `actor_did` today?

Only inside the raw event JSON on the detail page (`S/proofs/[proof_id]/page.tsx:292`).
It is not a labelled field, and nothing marks events whose actor differs from
the creator. The Actors page (`S/actors/page.tsx`) lists DIDs from
`GET /actors`, labelled "DID / cryptographic actor identity" (`:166`), with no
link to which proofs they may act on.

### 13.6 What has to change for this design

New verifier fields (§7: per-check `actor_did`, `role`, `actor_authorized`;
optional `creator_did`):

- **Nothing breaks.** The verify result type is open
  (`S/verification/page.tsx:22-26`, `[key: string]: unknown`) and the detail
  type likewise (`S/proofs/[proof_id]/page.tsx:16-25`). Missing fields are
  ignored silently, and new ones appear only in the raw JSON dump.
- **An `invalid` verdict from an unauthorized event shows correctly on the
  Verification page**, but only if that page happens to pick the affected
  proof (§13.3).
- **List, detail and overview would still show "VALID"** for such a proof,
  because they read `status`, not `verdict`. A foreign actor can set
  `completed` today (§1), and after the fix the creator still can for a proof
  that verifies `invalid` for another reason.

Changes needed, in priority order:

1. Derive "valid" labels and the overview counter from `/verify`'s `verdict`,
   not from `status`. Show `status` as lifecycle state ("COMPLETED"), not as
   "VALID".
2. Replace hard-coded green checks with values from `checks` (per event:
   `signature_valid`, `chain_valid`, `payload_hash_valid`, `canonical_valid`,
   and after this design `actor_authorized`).
3. Event timeline: show `actor_did` and `role` per event, and mark
   `unauthorized` events.
4. Render `evidence.class`, `execution_verified` and `runtime_settled` as
   fields, using the wording of `S/developer/page.tsx:80-105`.
5. Let the Verification page verify a chosen proof (e.g. from the detail
   page), not only an automatically picked one.
6. Restrict the proxy to the GET paths the pages use (§13.1).

Item 1 needs one `/verify` call per listed proof, or a verdict field in
`GET /proofs`. That is an API change, so it is an open question for the
implementation slice.

### 13.7 Data note

A dashboard pointed at the local API shows mostly test data. In `proofs.db`,
1,214 of 1,215 proofs come from the test suite (by `request_id` prefix and
payload text), plus one manual probe (`auth-audit-55b6e7c1…`, the only
proof with a foreign actor). The "Valid proofs" counter and the Verification
page's automatic choice of proof are therefore driven by test runs. Test
isolation is a separate item.
