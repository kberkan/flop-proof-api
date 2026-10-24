# Proof closure and tail truncation (design)

Status: **implemented** (§8 A, B and C). See *Decisions* at the end
(D-C1 to D-C12) and the plan in §8. Baseline for line references: commit
`a1a9344`.

Measurements in this document were taken in memory (SQLite `StaticPool`,
`TestClient`), without writing to `proofs.db`. `proofs.db` was read once in
read-only mode (`mode=ro`): it holds 1 proof (version `"3"`, status `active`,
4 events, no closing event), so no stored data constrains this design.

## 1. Problem

`README.md:52-58` ("What it does not verify") says the hash chain does not
detect events removed from the end of a proof, and that neither `/verify` nor
the offline verifier uses the closing `proof.completed` event or the export's
`status` field. The README asks readers to compare `events_checked` or the last
event with a record kept outside the service.

### 1.1 Tail truncation today

Proof built through the API: `request.created`, `agent.started`,
`result.created`, `proof.completed`. Then events were removed from the export
(or from the database) without re-linking anything.

| # | Change | Checked by | Verdict | `events_checked` |
|---|---|---|---|---|
| M1 | none | offline and `/verify` | valid | 4 |
| M2 | `proof.completed` removed; export `status` still `"completed"` | offline | **valid** | 3 |
| M3 | `result.created` and `proof.completed` removed; `status` `"completed"` | offline | **valid** | 2 |
| M4 | only `request.created` left; `status` `"completed"` | offline | **valid** | 1 |
| M5 | as M2, `status` edited to `"active"` | offline | **valid** | 3 |
| M6 | M2 file through `python -m app.verifier` | offline CLI | exit 0, `Events: 3`, `Verdict: VALID` | — |
| M7 | the `proof.completed` row deleted from the database | `/verify` | **valid** | 3 |

After M7, `GET /proofs/{id}` still reports `status: "completed"`: the status
is a separate column (`app/models.py:16`) that nobody rechecks.

Why the closing event and the status do not help:

- **Status** is set by the API in the same transaction as the closing event
  (`app/main.py:899-905`) and exported (`app/main.py:949`), but the verifier
  receives only `proof_id`, `events` and `version` (`app/verifier.py:13-37`,
  `app/main.py:1013-1017`). It is also unsigned.
- **The closing event** is an ordinary event to the verifier. Its payload is
  free-form, and nothing in the verifier refers to `proof.completed` or
  `proof.failed`. The only special handling is in the API: these types are
  creator-only (`app/authorization.py:20`), and a closed proof refuses new
  events (`app/main.py:752-756`, rechecked under the lock at `:828-832`).
- **The hash chain** links each event to its predecessor only
  (`previous_event_hash`, `app/events.py:57-70`). Removing the last event leaves
  every remaining link intact.

### 1.2 Related finding: the chain can be re-linked without any key

This goes beyond tail truncation. Proof: `request.created`, `agent.started`,
`artifact.note`, `result.created`, `proof.completed`. "Re-linked" means
renumbering `sequence` from 1 and recomputing every `previous_event_hash`
with `hash_event_record` from the exported fields.

| # | Change | Offline verdict |
|---|---|---|
| M8 | `result.created` removed, closing event kept, not re-linked | invalid (chain and sequence) |
| M9 | same, re-linked | **valid** |
| M10 | events 2 and 3 swapped, re-linked | **valid** |
| M11 | only `request.created`, `agent.started`, `proof.completed` kept, re-linked | **valid** |

Causes:

- `hash_event_record` (`app/crypto.py:884-907`) is a plain SHA-256 over fields
  that are all in the export. No key is involved.
- It does not include the predecessor's `previous_event_hash`, so the links
  are not cumulative: each link commits to one record, not to the prefix.
- `sequence`, `created_at`, `event_id` and `previous_event_hash` are not in the
  signed message. The v3 event canonical is
  `FLOP/EVENT/v3|proof_id|type|payload_hash|nonce`
  (`app/canonical.py:119-129`). Signatures therefore stay valid at any position.

`README.md:26-27` says "an edited, removed or reordered event in the middle of
a proof is detected". That holds only for an export that was not re-linked
(M8). The same applies to the dashboard's check label "Event chain (order and
links)" (`dashboard/src/lib/proof-view.ts:114`). This document does not
change either; see §5.4.

### 1.3 Closing today: API and verifier

| # | Action | Result |
|---|---|---|
| M12 | after `proof.completed`, append any event through the API | 409 "Proof is already completed" |
| M12b | after `proof.failed`, append `proof.completed` | 409 |
| M13 | after `proof.completed`, write a creator-signed `agent.started` with `create_event` (around the API) | `/verify` **valid** |
| M14 | after `proof.completed`, write `proof.failed` with `create_event` | `/verify` **valid** |
| M15 | append `proof.completed` with payload `{"prev_event_hash": "00…00", "event_count": 99}` | 201, `/verify` valid |
| M16 | compute `hash_event_record` of the last event from `GET /proofs/{id}`, then append one event | equals the new event's `previous_event_hash` |

M16 also showed that the `created_at` returned by `POST …/events`
(`app/main.py:912-920`) is the same string as in the export
(`"2026-10-22T19:10:38.014507"`, no offset; see
`dashboard/src/lib/timestamp.ts:3-6`). A client can therefore compute any
event's link hash from the export or from its own append response.

So today:

- The API enforces "nothing after a closing event". The verifier does not
  (M13, M14). This conflicts with `event-authorization.md` D-A10, under which
  the verifier rejects what the API would reject.
- A closing payload can carry anything (M15).

## 2. Current state

| Place | Code | Role |
|---|---|---|
| API | `app/main.py:752-756` | closed proof → 409, before signature checks |
| API | `app/main.py:758`, `:763-776`, `:804-820` | payload hash, v3 canonical, signature (401/422) |
| API | `app/main.py:825-832` | `begin_chain_write`, status rechecked under the lock |
| API | `app/main.py:834-847` | chain read under the lock |
| API | `app/main.py:849-886` | authorization (403), nonce (409), Option B (409, v1/v2), single result (409) |
| API | `app/main.py:888-897` | `create_event` |
| API | `app/main.py:899-905` | status `active` / `completed` / `failed` |
| API | `app/main.py:912-920` | append response: no link hash |
| Chain | `app/events.py:57-70` | `previous_event_hash` = `hash_event_record(last event)` |
| Chain | `app/crypto.py:884-907` | `hash_event_record`: non-cumulative, unkeyed |
| Export | `app/main.py:923-968` | `GET /proofs/{id}`, includes `status` and `version` |
| Verifier | `app/verification_core.py:98-132` | version gate; empty chain → invalid |
| Verifier | `app/verification_core.py:158-177` | sequence and link checks |
| Verifier | `app/verification_core.py:322-333`, `:431-441` | verdict and output; no closure field |
| Offline | `app/verifier.py:13-37` | passes `proof_id`, `events`, `version` only |
| Offline CLI | `app/verifier.py:45-119` | one positional argument; prints `Events:` (`:69`) |
| Authorization | `app/authorization.py:20` | closing types are creator-only |
| SDK | `flop_proof_sdk/client.py:170-200` | `append_signed_event`; no closing helper, no link hash function |

## 3. Proposed mechanism

### 3.1 Signed closure fields

A closing event (`proof.completed` or `proof.failed`) carries a reserved
`closure` object in its payload:

```json
{
  "result": "done",
  "closure": {
    "prior_event_count": 3,
    "prior_head": "9b1e…(64 lowercase hex)…"
  }
}
```

- `prior_event_count`: JSON integer (not a boolean or a float), at least 1
  (`request.created` is always sequence 1). It is the number of events before
  the closing event, which is the sequence of the last of them. The closing
  event's own sequence must be `prior_event_count + 1`.
- `prior_head`: 64 lowercase hex characters. It is the link hash of event
  number `prior_event_count`, which is exactly the value the closing event's
  `previous_event_hash` must have. §3.2 defines what that hash covers.
- `closure` contains exactly these two keys; any other key is malformed. Other
  payload keys (`result`, `message`, …) stay free.

**Are the fields signed?** Yes, with no change to the signing scheme:

- `payload_hash = sha256_json(payload)` (`app/main.py:758`) covers the nested
  object. `sha256_json` (`app/crypto.py:873-881`) sorts keys, so key order does
  not matter. It distinguishes `3` from `3.0`, which is why the count must be an
  integer.
- `payload_hash` is a field of the signed canonical (`app/canonical.py:119-129`,
  built at `app/main.py:763-776`), and the signature is verified at
  `app/main.py:804-820`.
- The verifier recomputes the payload hash (`app/verification_core.py:179-185`),
  the canonical (`:209-223`) and the signature (`:252-259`).
- Closing types are creator-only (`app/authorization.py:20`).

So nobody without the creator's key can add, change or strip these fields.

Under H4 (§3.2.1) these fields are not needed.

### 3.2 What `prior_head` commits to

| Option | Link function | Detects, for a closed proof whose closing event is kept |
|---|---|---|
| H1 (as requested) | today's `hash_event_record` | removal of any event before the closure (M9, M11): the count changes, and filling the gap would need another event signed for this proof with a fresh nonce. **Not** reordering of earlier events (M10): the last prior event and the count stay the same. |
| H2 | H1 plus a third field `prior_digest = sha256_json([link hash of events 1..N])` | removal and reordering. The external head (§3.5) still pins only the last event. |
| H3 | version-4 chains use a cumulative link: `hash_event_record` input plus the predecessor's `previous_event_hash` | removal and reordering, with a single field. `chain_head` (§3.4) then commits to the whole chain, so an external head also detects reordering. |

H3 changes the link computation for version-4 chains only, in two places:
`app/events.py:57-70` (`create_event` needs the proof's version) and
`app/verification_core.py:158-177`. v1–v3 chains keep today's links. Side
effect: relabelling an export between `"3"` and `"4"` breaks every link of a
chain with two or more events (§4).

**Recommendation: H3.** H1 leaves M10 open. H2 needs an extra field and leaves
the external head weaker than the closure. (Among H1–H3 only; the overall
recommendation is now H4, §3.2.1 and §7.)

None of the options H1–H3 make an **open** proof's chain tamper-evident. The
chain stays unkeyed, so M9–M11 still pass on a proof without a closing event
(§3.5). H4 (§3.2.1) does.

### 3.2.1 Option H4: every event signs the chain head

Each event signs the chain head it is appended to:

```
FLOP/EVENT/v4|proof_id|type|payload_hash|nonce|prior_head
```

- `prior_head` is 64 lowercase hex characters: the link hash of the last event
  in the chain when this event is appended, which is the value this event's
  `previous_event_hash` gets. It is the last field and cannot contain `|`, so
  the D-R3 parsing rule holds.
- It is sent as `signature.prior_head` next to `signature.nonce`
  (`EventSignatureSchema`, `app/schemas.py:48-53`). The API rebuilds the
  canonical from it, as it does for the nonce.

**What it detects.** Event *k+1* signs the link of event *k*, so an event's
predecessor is fixed by a signature.

| Case | H4 |
|---|---|
| M9: an event before the last one removed, links recomputed | detected: its successor's signed `prior_head` names the removed event. Open and closed proofs alike. |
| M10: events reordered, links recomputed | detected: each moved event's signed `prior_head` names its original predecessor |
| M11: several events removed | detected, as M9 |
| M13: event after a closing event, written around the API | narrowed but not closed. A captured event cannot be moved there, because it only fits after its original predecessor. An event that an authorized actor (the creator, or a delegate for open types) **signed** after the closing event still fits. The position rule (§3.4) stays necessary. |
| Tail truncation: last *n* events removed, closing event included | **not detected** (still the limit of §3.5). The remaining prefix is exactly a chain that once existed. |
| Unsigned fields of earlier events (`sequence`, `created_at`, `event_id`) | detected: they are inside the link hash that the successor signs |
| Unsigned fields of the **last** event | not detected (no successor). An external `chain_head` (§3.5) covers them. |
| A signed event the API **rejected** (for example 409 below) | a valid alternative at its position. Anyone who saw it (the API server, the network path) can build a chain up to its `prior_head`, add it, and drop everything after it: a truncation with substitution. The same holds for a closing event rejected under H3 + closure (§3.3). See §7 q16. |

**Link function: H1 or H3?** H1, today's `hash_event_record`, is enough.

- `hash_event_record` covers the record's `canonical` and `signature`
  (`app/crypto.py:895-906`), and under H4 the canonical contains that event's
  own `prior_head`. Each link therefore commits, through the signatures, to the
  whole prefix.
- A cumulative link (H3) adds nothing on top. Keeping H1 leaves one link
  function for every version, and the SDK only needs a copy of that one.

**`request.created` (sequence 1).**

- It has no `prior_head`. Its canonical stays
  `room|nonce|text` in form, with the tag `FLOP/REQUEST/v4`. The client signs
  it before the proof, and so the chain, exists.
- It is fixed by event 2, whose `prior_head` is the link of the
  `request.created` record.
- A proof with only `request.created` has nothing to bind.

**Cost.**

- *Knowing the head.* A client must know the current head before it signs.
  - A single writer can take it from its own last append response. The response
    needs `chain_head` (§3.3); the client can compute it itself (M16).
  - With other writers, it must read it. `GET /proofs/{id}` should then also
    export `chain_head`, so that clients need no copy of `hash_event_record`.
  - A client that wants to check the server's head computes it from the export.
- *Concurrent appends.*
  - Two writers that read the same head both sign it. The second one gets 409
    `head_mismatch`, "Event prior_head does not match the current chain", from
    a check under the lock after the existing checks, so 403 still comes first.
  - The second writer must re-read the head and sign again. The server cannot
    do it, because it has no key.
  - Today the conflict window is the database transaction. Under H4 it is the
    client's read → sign → post round trip.
- *Multi-actor flows with delegation.* With a creator and a few delegates
  appending occasionally, conflicts are rare and cost one extra round trip.
  With several delegates appending to one proof in parallel (workers posting
  artifacts), writes serialize per proof and retries grow with concurrency. A
  signed event now also states which chain its signer saw: that is causal
  order, and it is the point of H4.
- *SDK.*
  - `append_signed_event` gets an optional `prior_head`. Without it, the SDK
    reads `chain_head`.
  - On 409 `head_mismatch` the SDK raises a typed error that carries the
    current head.
  - Automatic re-signing is opt-in (`retries=`) and never applies to
    `proof.completed` / `proof.failed`. Re-signing changes the statement "after
    the chain I saw" without the caller seeing the new events, which matters
    most for a closing event.
  - Each rejected attempt is also a signed alternative (row above), so silent
    retries create more of them.

**Versioning.**

- The event canonical changes, so the tag is `FLOP/EVENT/v4`, and by D-R2
  `FLOP/REQUEST/v4` (a tag change only). This is V1 of §4. V2 (keep the v3
  tags) is not available, because a v3 parser rejects the sixth field.
- D-R2 holds as written.
- D-R4 holds: an SDK 0.4.x request (`FLOP/REQUEST/v3`) gets 401 at
  `POST /proofs`, before any proof exists, so there is no half-usable proof.
- Relabelling 4↔3 fails on the tags, as 3↔2 does today (D-R11, D-R12).
- Cost: V1's list (§4) plus every test that appends an event by hand, which
  now needs a head (§5.5).

**Closure fields under H4.**

- Not needed. The closing event's own `prior_head` binds the whole prefix.
- The event count is implied: the predecessor's record hash contains its
  `sequence`, which equals the count.
- §3.1, the closure checks of §3.3 and the field part of `closure_valid` in
  §3.4 fall away. The closing payload stays free.
- What remains is the position rule, `closed`, `chain_head`, and `event_count`
  as a convenience for `--expect-count`.

**Verifier.**

- For events 2…*N*: the parsed `prior_head` must equal the recomputed link of
  the predecessor and the exported `previous_event_hash`.
- A new per-event field `prior_head_valid`, `null` for `request.created`
  (§7 q17). A `false` makes the verdict `invalid`.

**Product claim under H4.**

- In every version-4 proof, open or closed, removing or reordering any event
  other than trailing events is detected.
- Adding an event needs an authorized signature made on that exact chain.
- Trailing events, the closing event included, can still be removed
  undetectably without an external `chain_head`.
- Events the API rejected remain possible substitutes at their position.

### 3.3 API

New pure function `check_closure(chain, event_type, payload, version)` in the
style of `check_single_result_created` (`app/authorization.py:193-207`),
returning a reason code with an entry in `REASONS` (`app/authorization.py:29-40`).
It is called inside the locked section, after the single-result check
(`app/main.py:882-886`) and before `create_event` (`:888`).
`begin_chain_write` (`:825`) and the order of the existing checks do not
change.

- Expected values come from the chain read under the lock (`:834-838`):
  `prior_event_count = len(chain)`, which equals `chain[-1].sequence` because
  sequences are contiguous. `prior_head` is the link hash of `chain[-1]`,
  computed by the **same** function `create_event` uses, so the stored
  `previous_event_hash` of the closing event equals `prior_head` by
  construction.
- Statuses and messages:

| Case | Status | Reason code / message |
|---|---|---|
| v4 closing event; `closure` missing, wrong shape, extra key, non-integer count, bad hex | 400 | `invalid_closure` / "Invalid closure fields" |
| v4 closing event; fields well formed but not equal to the current chain | 409 | `closure_mismatch` / "Closure does not match the current chain" |
| v1–v3 closing event with a `closure` key | 400 | `closure_not_supported` / "Closure fields are not supported for this proof version" (§4) |

409 for a mismatch fits the case it will mostly come from: the chain moved
between the creator's read and the close, for example because a delegate
appended an event. The client re-reads the chain and signs a new closing
event with a new nonce. Because the check runs under the lock, no event can be
inserted between the comparison and the insert.

Extended check order (event-authorization.md D1): 401 canonical → 422
malformed → 401 signature → [lock] → 409 closed → 403 authorization →
409 nonce → 409 repeat (v1/v2) → 409 second result → **400/409 closure**. An
unauthorized actor gets 403 before any closure check. Under H4 the closure
check is replaced by 409 `head_mismatch` for every event, at the same place
(§3.2.1).

Append response (`app/main.py:912-920`): add `chain_head`, the link hash of
the event just written. The client can compute it itself (M16), but returning
it makes the value to keep outside the service explicit. See §7 q6.

Status handling (`:899-905`) is unchanged.

### 3.4 Verifier

In `verify_proof_events` (`app/verification_core.py:98-441`), for every
version:

- **Position rule.** At most one closing event, and it must be the last event.
  The API has always enforced this (M12), so chains it wrote satisfy it. M13
  and M14 become `invalid`.

For version 4, additionally:

- The closing event has a well-formed `closure` object.
- `prior_event_count` equals the number of events before it, which also
  equals its `sequence - 1`.
- `prior_head` equals the closing event's `previous_event_hash` and the
  recomputed link of the previous event. The link equality is already checked
  as `chain_valid` (`:158-177`), so `prior_head` adds the signed binding.

For v1–v3: a closing event with a `closure` key fails (§4).

Under H4 the version-4 closure checks above are replaced by a per-event
`prior_head` check (§3.2.1). The position rule stays.

New top-level output fields, also in the early returns at `:110-132`:

| Field | Type | Meaning |
|---|---|---|
| `closed` | bool | the chain contains a closing event |
| `closure_valid` | bool or null | `true`: v4 closure, position rule and fields hold. `false`: position rule broken, v4 fields missing or wrong, or a v1–v3 closure with a `closure` key. `null`: no closing event, or a v1–v3 closing event that passes the position rule (closed, but not bound to the chain). |
| `chain_head` | hex string or null | link hash of the last event, using the version's link function; null for an empty or rejected chain. For v1–v3 it is today's non-cumulative hash. |
| `event_count` | int | number of events; the same value as `events_checked` (§7 q5) |

The verdict becomes `invalid` when `closure_valid` is `false`. `closed: false`
on its own is not invalid: an open proof is a normal state.

`/verify` (`app/main.py:971-1024`) and the offline verifier (`app/verifier.py`)
call the same function, so they report the same values. The CLI prints the new
fields next to `Events:` (`app/verifier.py:69`).

### 3.5 Remaining limit and the external reference

**Remaining limit.** If the closing event is removed too, and with it any tail,
the result is a version-4 proof that verifies as an open proof:
`closed: false`, verdict `valid`. Nothing in the export can tell it apart from
a proof that was never closed. On open proofs, M9–M11 (removal or reordering
with re-linking) also remain undetectable, because no signature commits to the
chain until it is closed. Under H4 they are detected on open proofs too; tail
truncation remains (§3.2.1).

**External reference.**

- `/verify`, the offline verifier and the append response report `chain_head`
  and `event_count`. A party that keeps them (for example the creator, from
  the closing event's response) can check an export later.
- Offline CLI, optional: `--expect-head HEX` and `--expect-count N`. The CLI
  prints `Expected head: match` or `MISMATCH` (and the same for the count), and
  exits 1 on a mismatch even when the verdict is valid. The result dict gets
  `expectations: {"head": bool, "count": bool}`; `verdict` keeps its current
  meaning, the internal consistency of the export (§7 q7).
- Under H3, a matching `--expect-head` pins the whole chain: tail truncation
  (closing event included), removal and reordering all change it. Under H1 it
  pins only the last event and its sequence; reordering earlier events is not
  caught.

**Rejected signed events (D-C10).** Under H4, an event that the API rejects
after checking its signature (for example 409 `head_mismatch`) is still a
validly signed event for its `prior_head`. Whoever saw it can build a chain
up to that head, add it and drop everything after it. This is a form of tail
truncation and part of the same limit; mitigating it is a separate design.

**What this changes in the product claim, and what it does not.**

- For a version-4 proof whose closing event is present, removing, reordering
  (H3) or adding events before the closure is detected by `/verify` and the
  offline verifier.
- Events after a closure make the proof `invalid` in every version.
- Completeness itself is still not verifiable from the export alone. A
  truncated closed proof looks like an open one; detecting that needs the
  `chain_head` or `event_count` kept outside the service.
- Nothing is signed by the server. Anyone holding the creator's key can
  fabricate a complete export, including `event_id`, `created_at` and links.
  The protection is against parties without that key: holders of the API key,
  the database or the export.
- `created_at` is still not a trusted timestamp.

## 4. Versioning

Principle: "keeps one meaning per version" (`event-replay.md:191-193`; D-R1
at `:377`). Related decisions:

- D-R2 (`:378`): the tag version equals the proof version.
- D-R4 (`:380`): old clients must not produce half-usable proofs.
- D-R11 (`:387`): the legacy path rejects tagged canonicals.
- D-R12 (`:388`): a chain never mixes formats.

The exported `version` is unsigned: the verifier takes it from the export
(`app/verifier.py:31-37`) and
it is in no canonical. Any option must survive relabelling.
`test_v3_export_relabelled_as_v2_is_invalid`
(`test_security_regression.py:1145`) relies on the tags for that today.

| Option | Description | Relabelling | Old SDK (0.4.x) | Changes |
|---|---|---|---|---|
| V1 | version `"4"`, new tags `FLOP/REQUEST/v4`, `FLOP/EVENT/v4` | blocked by the tags, as for 3↔2 | 401 at `POST /proofs`, before any proof exists (D-R4 kept) | every signer; 13 test files, `tests/fixtures/canonical_v3_vectors.json`, `scripts/generate_canonical_v3_vectors.py`, `scripts/e2e_client.py`, SDK canonical, dashboard Developer page |
| V2 | version `"4"`, tags stay `…/v3`; D-R2 amended ("the tag names the message format") | 4→3: with H3 every link breaks (≥2 events); with the closure kept, the v1–v3 rule "no `closure` key" also fails it. 3→4: links break (H3); a v3 closure lacks fields. A 1-event proof relabels harmlessly (nothing to bind). | can create v4 proofs and append events; closing gets 400 unless the caller adds `closure` by hand (half-usable, against D-R4's intent) | the closing tests and the version-3 assertions in §5.5 |
| V3 | optional in v3: fields checked when present | — | unaffected | smallest |

**V3 (optional rule): can it be abused?**

- **Not by a third party.** The fields are signed by the creator, so an
  attacker without the key can neither strip them from a bound closure nor add
  them to an unbound one.
- **The creator** can always fabricate a whole export (§3.5), so "optional"
  gives the creator nothing new.
- **The real weakness is meaning, not forgery.** Under V3:
  - A v3 closing event without fields stays valid with `closed: true`. After
    it, M9–M11 re-linking passes on a "closed" proof.
  - Such closures come from every existing client and SDK 0.4.x, so a reader
    must check `closure_valid == true` and cannot rely on `closed` or on the
    version.
  - That gives one version two meanings, against `event-replay.md:191-193`.
  - Existing v3 proofs whose closing payload happens to contain a `closure` key
    of another shape would become `invalid` after the fact.

**Existing v1/v2/v3 proofs** (V1 or V2):

- They stay verifiable under their own rules and get the new output fields.
  `closure_valid` is `null` unless the position rule or the "no `closure` key"
  rule fails.
- The position rule can change a verdict only for chains with an event after a
  closure. The API never writes those (M12); they come only from writes
  around it (M13, M14).
- Open v3 proofs still accept events and close with a legacy closure (no
  fields; a `closure` key gets 400). They cannot be upgraded to version 4
  (D-R12).

**Recommendation:** make the rule mandatory with version `"4"` (not V3), and
choose **V2 together with H3**.

- H3 already makes relabelling break the chain, and the "no `closure` key on
  v1–v3" rule covers the rest. Changing every signer's tag (V1) adds little
  safety for its cost.
- The cost of V2 is an amendment to D-R2, and old SDKs can create proofs they
  cannot close without adding fields. Both are decisions to take explicitly
  (§7 q1, q2).
- If D-R2 must stand as written, choose V1.
- H4 requires V1 and keeps D-R2 and D-R4 (§3.2.1). The V2 recommendation
  above applies only to H3 + closure (§7 q13).

## 5. Affected parts

### 5.1 Application code

| File:line | Change |
|---|---|
| `app/canonical.py:45-46` | `CURRENT_PROOF_VERSION = "4"`; `"3"` joins the versions still verified (it is no longer "legacy" in the v1/v2 sense, so a separate set may be clearer) |
| `app/main.py:655` | new proofs `version="4"` (through the constant) |
| `app/main.py:763-785` | v4 takes the v3 canonical (V2) |
| `app/main.py:882-888` | `check_closure` between the single-result check and `create_event` |
| `app/main.py:912-920` | `chain_head` in the append response |
| `app/authorization.py:29-40` | `invalid_closure`, `closure_mismatch`, `closure_not_supported` |
| `app/events.py:27-70` | link function by version (H3); `create_event` reads the proof's version. A missing `Proof` row (test-only chains, `event-authorization.md` §2) uses the legacy link. |
| `app/crypto.py:884-907` | add the cumulative link function next to `hash_event_record` |
| `app/verification_core.py:98-132`, `:158-177`, `:322-333`, `:431-441` | version gate, links by version, position rule, closure fields, new output fields |
| `app/verifier.py:45-119` | `--expect-head`, `--expect-count`, new output lines and exit status |

### 5.2 SDK

- New `close_proof(proof_id, private_key, did, *, nonce, outcome="completed" | "failed", payload=None)`:
  1. Reads `GET /proofs/{id}`.
  2. Computes `prior_event_count` and `prior_head` from the export.
  3. Refuses a `payload` that already has a `closure` key.
  4. Signs and appends.
  5. Returns the response with `chain_head` and `event_count`.

  On 409 `closure_mismatch` it raises as usual and does not retry silently.
  Under H4, `close_proof` is not needed. Every append carries a head instead,
  with the retry policy of §3.2.1.
- Needs a copy of the link function (both variants) in `flop_proof_sdk`, with
  a parity test like `test_sdk_canonical_v3.py`. Today the SDK has only
  `sha256_json` (`flop_proof_sdk/client.py:18-25`).
- The helper depends on the exported `created_at` string being the one the
  server hashed (M16). A test must lock that.
- `append_signed_event` (`flop_proof_sdk/client.py:170-200`) stays generic. A
  closing event without fields gets the API's 400 (§7 q8).
- Version `0.4.1` → `0.5.0` (`pyproject.toml:7`), and a CHANGELOG entry about
  the old SDK's closing behavior (§4).

### 5.3 Dashboard

- `proofFormat` (`dashboard/src/lib/proof-view.ts:187-197`): recognize `"4"`;
  label v3 as "Format: v3 (closure not bound)" or similar.
- Closure state on the detail and verification pages:
  - "Closed, bound to the chain" for `closure_valid: true`.
  - "Closed, not bound (format v1–v3)" for `closed` with `closure_valid: null`.
  - "Closure invalid" for `false`.
  - "Open" for `closed: false`, with the note that an open proof may be a
    truncated closed one, and the advice to compare `chain_head` with a kept
    record.
- Show `chain_head` (copyable) and `event_count`.
- `verdictBadge` (`:199-224`): a `closure_valid: false` must never show
  "Valid". The verdict is already `invalid` then, but the consistency check
  should include it.
- Status stays a neutral lifecycle word (`proof-view.ts:6-7`). "Completed"
  must not read as "complete".
- Wording: "Event chain (order and links)" (`proof-view.ts:114`), the home
  page list (`dashboard/src/app/page.tsx:299`) and
  `dashboard/src/lib/evidence-boundary.ts:14` claim more than §1.2 supports.

### 5.4 README, PARITY, CHANGELOG

- `README.md:52-58`: replace with what §3.5 states — for version-4 proofs,
  what a closing event binds; that removing the closing event leaves an
  open-looking proof; and to keep `chain_head` / `event_count` and use
  `--expect-head`.
- `README.md:26-27`: correct now or with this change (§1.2, §7 q9). The
  sentence is wrong for re-linked exports today, independent of this design.
- `PARITY.md`, *Known Security Gaps*:
  - New row "Proof truncation and re-linked exports are not detected", status
    **Open**, locked by strict-xfail tests (M2, M9, M10, M13) until
    implemented.
  - A separate row, or a note, for the position rule (M13, M14).
- `CHANGELOG.md`: proof version `"4"`, closure fields, new verifier fields,
  SDK 0.5.0.

### 5.5 Existing tests

Tests that append or write a closing event, or assert the new-proof version:

| Test | Today | Under V2 + H3 |
|---|---|---|
| `test_lifecycle.py:115` `test_active_to_completed_and_locked` | closing payload `{"message": "completed"}` → 201 | **breaks**: 400 `invalid_closure`; needs the `closure` object |
| `test_lifecycle.py:168` `test_active_to_failed_and_locked` | `proof.failed` → 201 | **breaks**, same reason |
| `test_security_regression.py:166` `test_completed_proof_rejects_new_event` | first close 201, second 409 | **breaks** at the first close; the second stays 409 (pre-lock status check `app/main.py:752-756`) |
| `test_security_regression.py:455` `test_delegation_end_to_end_with_verifier_roles` | delegate close 403, creator close 201 | 403 unchanged (authorization first); creator close **breaks** (`:469`) |
| `test_security_regression.py:351` `test_foreign_actor_cannot_complete_another_actors_proof` | 403 | unchanged |
| `test_security_regression.py:1145` `test_v3_export_relabelled_as_v2_is_invalid` | `"4"` is "unsupported" (`:1163`, `:1169`) | **breaks**: `"4"` becomes supported; a relabelled v3 export fails on links instead |
| `test_security_regression.py:830` `test_request_with_ordinary_room_is_still_accepted` | `proof_version == "3"` (`:836`) | **breaks** |
| `test_security_regression.py:953` `test_new_proofs_are_version_3_and_export_the_nonce` | `== "3"` (`:961`) | **breaks** (rename) |
| `test_security_regression.py:1172` `test_sdk_end_to_end_v3_flow` | `== "3"` (`:1205`) | **breaks** |
| `test_sdk_against_app.py:92` `test_create_proof_with_a_prebuilt_signed_request` | `== "3"` (`:107`) | **breaks** |
| `test_authorization.py:57`, `:77`, `:121`, `:186` | pure `authorize_event` calls with closing types | unchanged (`check_closure` is a separate function) |
| `test_verifier.py:251` helper, `:370`, `:393`, `:416` | hand-built chains with `version="3"` | unchanged (v3 links) |
| `test_client_signed.py:90`, `test_event_replay.py:104`, `test_verifier.py:158` | `events_checked` | unchanged (field kept) |
| `dashboard/src/lib/proof-view.test.mjs:296-309` | `"4"` → "Format: unknown" (`:304`) | **breaks** |

No test calls `create_event` with a closing type. `scripts/e2e_client.py`
does not close its proof. Under V1, the 13 test files that build v3 canonicals
(§4 table) change as well. Under H4 (always V1), every test that appends an
event by hand also needs the current head, while the closing tests above need
no `closure` object (§3.2.1).

## 6. Tests to add

| Test | Expected |
|---|---|
| Correct closure through the API (`proof.completed`, `proof.failed`) | 201; stored `previous_event_hash` = `prior_head`; `/verify` valid, `closed: true`, `closure_valid: true` |
| Wrong `prior_event_count` (±1) | 409 `closure_mismatch` |
| Wrong `prior_head` (one hex digit changed) | 409 `closure_mismatch` |
| Missing `closure`, extra key, count as `3.0`, `true` or `"3"`, upper-case or short hex | 400 `invalid_closure` |
| Race: creator reads head, delegate appends, creator closes with the old head | 409; re-read and close → 201 |
| Unauthorized actor with a malformed `closure` | 403 (order: authorization before closure) |
| `closure` key on a v3 (written) proof's closing event | 400 `closure_not_supported` |
| Event after a closure through the API | 409 (already true today: M12; keep as a regression test) |
| Verifier: creator-signed event written around the API after a closure (M13), second closing event (M14), any version | `invalid`, `closure_valid: false` |
| Verifier: v4 closed proof with an event before the closure removed and re-linked (M9), or two events swapped and re-linked (M10) | `invalid` |
| Verifier: v4 closed proof, closing event and tail removed (M2-style) | `valid`, `closed: false`, `closure_valid: null` |
| Same export with `--expect-head` / `--expect-count` from the original | CLI exit 1, `Expected head: MISMATCH`; with the correct values exit 0 |
| v4 export relabelled `"3"`, and v3 export relabelled `"4"` (≥2 events) | `invalid` |
| `/verify` and offline verifier on the same exports (all above) | equal `verdict`, `closed`, `closure_valid`, `chain_head`, `event_count` |
| SDK `close_proof` end to end | 201; returned `chain_head` = offline `chain_head`; a payload with its own `closure` key is refused locally |
| SDK link function parity with `app/crypto.py` (both variants) | equal results on fixed vectors |
| `created_at` round trip: append response string = export string = hashed string | equal (locks M16) |
| v1/v2/v3 chains from existing fixtures | verdicts unchanged; new fields present |

## 7. Open questions and recommendations

**Updated recommendation (after H4, §3.2.1): H4 alone.** That means H1 links,
the `FLOP/EVENT/v4` and `FLOP/REQUEST/v4` tags (V1), no closure fields, plus
the position rule and an exported `chain_head`. Not H3 + closure, and not
both together.

- H4 detects removal and reordering in open proofs too. H3 + closure does so
  only before a closing event that is still present.
- It keeps D-R2 and D-R4 as written, and the tags block relabelling without
  extra rules.
- The verifier rule is one check per event instead of a special case for the
  closing event.
- Under H4, closure fields and cumulative links add nothing (§3.2.1).
- The costs: clients must know the head before signing, concurrent writers get
  409 and must re-sign, and there is more test churn than under V2.
- If the 409 cost is unacceptable for the intended workloads (many parallel
  writers per proof), fall back to H3 + closure with V2. Questions 2–4 and 12
  below apply only to that fallback.

1. **Mandatory with version `"4"`, or optional in v3?** Recommendation:
   mandatory, version `"4"` (§4). The optional rule gives one version two
   meanings.
   **Resolved by D-C2.**

2. **Tags: V1 (`…/v4`) or V2 (keep `…/v3`, amend D-R2)?** Recommendation: V2
   with H3; choose V1 if D-R2 is to stay literal. (H4 fallback only; H4
   requires V1, q13.)
   **Not applicable: H4 chosen.**

3. **Link function: H1, H2 or H3?** Recommendation: H3 (cumulative links for
   v4 chains). (Under H4: H1, §3.2.1.)
   **Not applicable: H4 chosen** (link function H1, D-C1).

4. **Field names and placement:** `payload.closure.prior_event_count` and
   `payload.closure.prior_head`, exactly two keys, integer and 64 lowercase
   hex? Recommendation: yes. (Not needed under H4.)
   **Not applicable: H4 chosen.**

5. **`event_count` next to `events_checked`:** keep both, or add only
   `event_count`? Recommendation: add `event_count` as asked and keep
   `events_checked` for compatibility; document that they are equal.
   **Resolved by D-C6.**

6. **`chain_head` in every append response, or only for closing events?**
   Recommendation: every append. It is cheap, and the creator learns the head
   at each step.
   **Resolved by D-C5.**

7. **External reference:** should a mismatch with `--expect-head` /
   `--expect-count` make `verdict` invalid, or only the CLI exit status and an
   `expectations` field? Recommendation: keep `verdict` for internal
   consistency; mismatch → exit 1 and `expectations`. Should `/verify` also
   accept `expect_head`? Recommendation: no (the API is not the party that
   needs the outside record).
   **Resolved by D-C8.**

8. **Closing events through `append_signed_event`:** leave it to the API's
   400, or make the SDK refuse closing types there and point to
   `close_proof`? Recommendation: leave it to the API, so the SDK has one
   validation path.
   **Not applicable: H4 chosen.**

9. **README `:26-27` and dashboard wording (§1.2):** fix in a separate small
   slice before this change? Recommendation: yes. It is wrong today,
   independent of the closure.
   **Resolved:** done in `8b90e03` (README, dashboard wording, PARITY row).

10. **Status consistency:** report `status_consistent` (export or database
    `status` vs. the presence of a closing event) and make a mismatch
    `invalid`? It would catch M2–M4 and M7 (careless truncation, deleted
    database row), but not M5, because the status is unsigned.
    Recommendation: report it in `/verify` and offline; decide separately
    whether it affects the verdict.
    **Resolved by D-C9.**

11. **Position rule for v1–v3 proofs:** apply it to every version (verdict
    change only for chains written around the API)? Recommendation: yes; it
    is the D-A10 parity the API already implies.
    **Resolved by D-C7.**

12. **SDK 0.4.x under V2:** accept that it can create version-4 proofs it
    cannot close without adding the `closure` object by hand, or reject
    0.4.x requests? Recommendation: accept, with a clear 400 message and a
    CHANGELOG note. (Does not arise under H4: SDK 0.4.x gets 401 at
    `POST /proofs`, D-R4.)
    **Not applicable: H4 chosen.**

13. **H4, or H3 + closure?** Recommendation: H4 (see the updated
    recommendation above). The deciding question is whether a 409 and a
    re-sign on concurrent appends is acceptable for the intended multi-actor
    flows.
    **Resolved by D-C1.**

14. **SDK policy on 409 `head_mismatch`:** raise a typed error with the current
    head, or re-sign automatically? Recommendation: raise by default.
    Re-signing is opt-in (`retries=`) and never applies to closing events,
    because a re-signed event states that its signer saw a chain the caller
    has not looked at.
    **Resolved by D-C4.**

15. **Where clients get the head:** `chain_head` in `GET /proofs/{id}` and in
    every append response, or only computed client-side from the export?
    Recommendation: export it in both. Clients that want to check the server
    compute it from the export with the SDK's copy of `hash_event_record`.
    **Resolved by D-C5.**

16. **Rejected signed attempts as substitutes:** an event rejected with 409
    (or for any other reason after its signature was checked) is a validly
    signed event for its `prior_head`. Whoever saw it can build a truncated
    chain ending in it. This also holds for a rejected closing event under
    H3 + closure. Accept and document it as part of the tail-truncation limit,
    or mitigate it, for example with a server signature on accepted events
    (a separate design)? Recommendation: document it now as part of the limit
    in §3.5 and PARITY; any mitigation is a separate design.
    **Resolved by D-C10.**

17. **Per-event result field:** a new `prior_head_valid`, or fold it into
    `chain_valid`? Recommendation: a separate field. `chain_valid` keeps its
    meaning (the exported link matches), and the dashboard can show a failed
    signed binding on its own.
    **Resolved by D-C6.**

## 8. Implementation plan

Three slices, in this order, as for event authorization and event replay.
§5 was written for H3 + closure. Its rows on cumulative links, `check_closure`,
closure reason codes and `close_proof` do not apply under D-C1; everything
else in §5 applies, plus the H4 changes in §3.2.1.

### A. Pure functions and unit tests

No change to the API, verifier or SDK behavior. `CURRENT_PROOF_VERSION`
stays `"3"` in this slice.

| File | Change |
|---|---|
| `app/canonical.py` | `REQUEST_TAG_V4`, `EVENT_TAG_V4`. `build_request_canonical_v4` / `parse_request_canonical_v4` (as v3, new tag). `build_event_canonical_v4(proof_id, type, payload_hash, nonce, prior_head)` / `parse_event_canonical_v4`. `prior_head` must be 64 lowercase hex, checked with fullmatch (D-R9); the D-R3 and D-R10 field rules apply. |
| `app/crypto.py:884-907` | next to `hash_event_record`: a pure `chain_head(events, *, proof_id)` over exported event dicts (`proof_id` is separate because exported events do not carry it, D-C11). It returns the link hash of the last event, or `None` for an empty list, using the same fields and `created_at` string as `create_event` (`app/events.py:60-70`, M16; D-C12). |
| new `test_canonical_v4.py` | build/parse round trips; rejection of `\|`, control characters, empty fields, bad or upper-case `prior_head`, and v3 or untagged input. A v3 parser rejects a v4 canonical and the other way round. `chain_head` equals the `previous_event_hash` the API writes for the next event (M16), and is `None` for no events. |
| optional `scripts/generate_canonical_v4_vectors.py`, `tests/fixtures/canonical_v4_vectors.json` | fixed vectors for the SDK parity test in B, as for v3 |

### B. API, verifier, SDK, test migration

| File | Change | Decision |
|---|---|---|
| `app/canonical.py:45-46` | `CURRENT_PROOF_VERSION = "4"`; `"3"` verified on its own path, not as legacy v1/v2 | D-C2 |
| `app/main.py:573` ff. | `POST /proofs` accepts only `FLOP/REQUEST/v4` (v3 and untagged requests → 401) | D-C2, D-R4 |
| `app/schemas.py:48-53` | `EventSignatureSchema.prior_head` (required on v4 proofs, rejected on v1–v3) | D-C1 |
| `app/main.py:763-798` | v4: rebuild the canonical with nonce and `prior_head` (401 on mismatch). v1–v3 unchanged (D-R12). | D-C1, D-C2 |
| `app/main.py:882-888` | under the lock, after the single-result check: `prior_head` ≠ link of the last stored event → 409 `head_mismatch` | D-C3 |
| `app/authorization.py:29-40` | `head_mismatch` (409, "Event prior_head does not match the current chain") | D-C3 |
| `app/main.py:912-920`, `:923-968` | `chain_head` in the append response and in `GET /proofs/{id}` | D-C5 |
| `app/verification_core.py:98-441` | v4 path: per-event `prior_head_valid` (null for `request.created`); position rule for every version; top-level `closed`, `chain_head`, `event_count` (also in the early returns at `:110-132`); `events_checked` kept | D-C6, D-C7 |
| `app/verifier.py:45-119` | `--expect-head`, `--expect-count`, `expectations` in the result, exit 1 on a mismatch, `verdict` unchanged | D-C8 |
| `app/events.py` | no change: links stay H1 | D-C1 |
| `flop_proof_sdk/canonical.py`, `flop_proof_sdk/__init__.py` | v4 copies and exports; parity test as `test_sdk_canonical_v3.py` | D-C1 |
| `flop_proof_sdk/client.py:139-200` | `create_signed_proof` uses the v4 request tag. `append_signed_event(..., prior_head=None, retries=0)` reads `chain_head` when `prior_head` is not given. On 409 `head_mismatch` it raises a typed error (for example `FlopProofHeadMismatch`) carrying the current head. `retries` re-signs only non-closing types. | D-C4, D-C5 |
| `flop_proof_sdk` (head computation) | the SDK's copy of `chain_head` follows D-C12: it takes `created_at` from the export as text, unchanged. A test locks this: the `created_at` string of an export gives the same head in the SDK as in `app/crypto.py`, including values with and without a fraction and `.500000` against `.5`. | D-C11, D-C12 |
| `pyproject.toml:7` | `0.4.1` → `0.5.0` | — |
| tests (§5.5, and the 13 files of §4 V1) | v4 tags. Every hand-built event gets the current head. Version assertions `"3"` → `"4"`. `test_v3_export_relabelled_as_v2_is_invalid` (`test_security_regression.py:1145`) adds 4↔3 relabelling. | D-C2 |
| `test_security_regression.py` (re-linking block) | remove the strict-xfail marks: M9 and M10 fail on `prior_head_valid`, M13 on the position rule. Their helpers build v4 events. | D-C6, D-C7 |
| new tests | §6, adapted to H4: 409 `head_mismatch` (concurrent appends, a stale head, 403 before 409); `prior_head_valid` on M9, M10, M11; tail truncation stays `valid` with `closed: false`; `--expect-head` / `--expect-count`; API/offline parity of the new fields; SDK typed error and `retries` (never for closing types) | D-C3 to D-C8 |
| `scripts/e2e_client.py` | v4 request and events | D-C2 |
| `README.md`, `PARITY.md`, `CHANGELOG.md` | README "What it verifies" / "does not verify" for v4. PARITY row → Fixed for v4 proofs, keeping tail truncation and rejected signed events (D-C10) as the documented limit and v1–v3 as before. CHANGELOG: proof version `"4"`, SDK 0.5.0. | D-C10 |

### C. Dashboard

After B, because the pages need B's fields (as D-R8).

| File | Change | Decision |
|---|---|---|
| `dashboard/src/lib/proof-view.ts:104-119`, `:187-197`, `:199-224` | `prior_head_valid` as a per-event check (request.created: not applicable); `proofFormat` knows `"4"`; the valid badge needs `prior_head_valid` on every v4 event | D-C6 |
| `dashboard/src/lib/proof-view.ts` (new helpers) | `closed`, `chain_head`, `event_count` for display; an open proof notes that trailing events can be removed undetectably and that `chain_head` should be compared with a kept record | D-C5, D-C6, D-C10 |
| `dashboard/src/lib/proof-view.test.mjs` | `"4"` is no longer "Format: unknown" (`:304`); tests for the new fields | — |
| `dashboard/src/app/proofs/[proof_id]/page.tsx`, `dashboard/src/app/verification/page.tsx` | show the closed state, `chain_head` (copyable) and `event_count` | D-C5, D-C6 |
| `dashboard/src/app/developer/page.tsx` | v4 request and event examples with `prior_head`, SDK 0.5.0, run against a temporary API | D-C2 |

## Decisions

Approved for implementation. Section numbers refer to this document.

| # | Decision | Section |
|---|---|---|
| D-C1 | H4: every event signs the chain head at the moment it is appended: `FLOP/EVENT/v4\|proof_id\|type\|payload_hash\|nonce\|prior_head`. The link function stays H1 (today's `hash_event_record`). No cumulative link, no closure fields. | §3.2.1; §7 q3, q13 |
| D-C2 | Mandatory: new proofs are version `"4"`, with the tags `FLOP/REQUEST/v4` and `FLOP/EVENT/v4` (V1). D-R2 and D-R4 apply unchanged: old clients get 401 at `POST /proofs`. v1/v2/v3 proofs are verified by their own rules; a chain never mixes formats (D-R12). | §3.2.1, §4; §7 q1 |
| D-C3 | A `prior_head` that does not match the current chain gets 409 `head_mismatch`. The check runs under the lock, after the existing checks, so 403 comes first. | §3.2.1, §3.3 |
| D-C4 | On 409 `head_mismatch` the SDK raises a typed error carrying the current head. Automatic re-signing is opt-in (`retries=`) and never applies to `proof.completed` / `proof.failed`. | §3.2.1; §7 q14 |
| D-C5 | `chain_head` is returned by `GET /proofs/{id}` and by every append response. It is computed with `chain_head(events, *, proof_id)` (D-C11). | §3.2.1, §3.3; §7 q6, q15 |
| D-C6 | The verifier adds a per-event `prior_head_valid` (`null` for `request.created`); `false` makes the verdict `invalid`. New top-level fields: `closed`, `chain_head`, `event_count`; `events_checked` stays for compatibility. | §3.2.1, §3.4; §7 q5, q17 |
| D-C7 | Position rule in every version: at most one closing event, and it must be the last event; otherwise `invalid`. | §3.4; §7 q11 |
| D-C8 | Offline CLI `--expect-head` / `--expect-count`: they do not change `verdict`; a mismatch gives exit status 1 and an `expectations` field in the result. `/verify` does not take these parameters. | §3.5; §7 q7 |
| D-C9 | No `status_consistent`: a check that rests on an unsigned field gives no protection (M5). | §1.1; §7 q10 |
| D-C10 | That rejected but signed events can be used for truncation with substitution is documented as part of the tail-truncation limit (§3.5, PARITY); mitigation is a separate design. | §3.2.1, §3.5; §7 q16 |
| D-C11 | `chain_head(events, *, proof_id)`: exported events do not carry `proof_id`, so it is a separate, required parameter. | §8 A |
| D-C12 | `chain_head` and the SDK use `created_at` as the exported text, as is: no re-parsing or re-formatting (`.500000` and `.5` give different heads). A `datetime` object is rejected. | §8 A, §8 B |
