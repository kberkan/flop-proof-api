# FLOP Proof API — Canonical Protocol Parity Matrix
**Audit baseline:** FLOP Yellow Paper v0.5.0 (draft), updated 2026-09-05
**Official specification:** https://flop.finance/intro/yellowpaper/

> This is the canonical parity record for the FLOP Proof API.
> It does not claim that this API is the FLOP Network runtime, settlement runtime, TEE verifier, or execution engine.

## Status Legend
- 🟢 IMPLEMENTED (internal-test-verified)
- 🟡 PARTIAL / ADAPTER
- 🔴 NOT IMPLEMENTED

## External Parity
- VERIFIED — primary runtime/reference implementation or official KAT/vector independently confirms parity
- UNVERIFIED — API implementation/tests exist, but external runtime parity is not independently confirmed
- N/A — external/runtime parity is outside this API boundary

**Important:** `IMPLEMENTED (internal-test-verified)` does not mean `External parity: VERIFIED`.
Internal tests are not external runtime parity evidence.

### Misrepresentation Risk
- LOW — unlikely to imply unsupported guarantees
- MEDIUM — could be misunderstood without precise wording
- HIGH — could imply execution, hardware, provenance, or settlement guarantees

### Source Confidence
- SPEC-CONFORMANT
- IMPLEMENTATION CLAIM
- INTERNALLY TESTED
- EMPIRICALLY VERIFIED
- NOT IMPLEMENTED
**Internal tests are NOT external empirical evidence.**

# Known Security Gaps

> **Status per row.** Rows marked **Fixed** or **Mitigated** are kept for the
> record. For **Open** rows, a test marked "strict xfail" in
> `test_security_regression.py` starts failing (XPASS) once a fix lands. Rows
> marked "No test yet" are not locked by any test.

| Gap | Effect | Locked by |
|---|---|---|
| No actor authorization on event append (`POST /proofs/{proof_id}/events`) | **Fixed** by the event authorization change (docs/design/event-authorization.md). Was: any DID with a valid signature of its own could, with the API key, append any event type to any proof and close it, and `/verify` reported such a proof as `valid`. Now only the creator and DIDs the creator listed in a `task.delegated` `delegates` list may append; `task.delegated`, `proof.completed` and `proof.failed` are creator-only (403). `/verify` and the offline verifier replay the same rule, report `actor_did`, `role`, `actor_authorized` and `authorization_reason` per event, and return `invalid` for any unauthorized event, including one written around the API. See `docs/design/event-authorization.md`. | `test_foreign_actor_cannot_append_result_to_another_actors_proof`, `test_foreign_actor_cannot_complete_another_actors_proof`, `test_verify_rejects_proof_with_foreign_actor_result`, `test_delegation_end_to_end_with_verifier_roles`, `test_delegate_cannot_append_before_the_delegation`, `test_offline_verifier_matches_api_verification`, `test_authorization.py` |
| Event nonce is not part of the signed message | **Open.** The event signature covers `proof_id\|type\|payload_hash` only. A signed event can be appended again to the same proof with a new nonce, by anyone holding the API key; it keeps its original, authorized `actor_did`, so authorization does not stop it. A replayed `result.created` is now rejected by the one-`result.created` rule (409); other types, including a creator-signed `task.delegated`, are still accepted and the proof still verifies. | `test_signed_event_cannot_be_replayed_with_new_nonce` (strict xfail) |
| Validator attestation binds to the latest `result.created` | **Mitigated** by the event authorization change (docs/design/event-authorization.md). `POST /proofs/{proof_id}/validator-attestations/accept` still uses the highest-sequence `result.created`, but a proof can now hold only one `result.created` (a second one gets 409, also under concurrent requests), and only the creator or a delegate can write it. The binding target can no longer be replaced. | `test_second_result_created_is_rejected_with_409`, `test_concurrent_result_created_admits_exactly_one` |
| Dashboard has no authentication (`dashboard/src/app/api/flop/[...path]/route.ts`) | **Partly fixed.** The proxy now forwards only `GET` on `proofs`, `proofs/{proof_id}`, `proofs/{proof_id}/verify` and `actors`, with `proof_id` matching `proof_` + 32 hex, and only the `limit` and `status` query parameters on `proofs`; every other method returns 405 and every other path 404 without reaching the API (`dashboard/src/lib/proxy-policy.ts`). It forwards only `Accept` and the API key, not browser headers or cookies. **Remaining:** the dashboard has no authentication of its own, so anyone who can reach it can **read** proof data with the server's API key. The dashboard is run locally only, and `npm run dev` / `npm start` bind to `127.0.0.1`. | `dashboard/src/lib/proxy-policy.test.mjs` (`npm test` in `dashboard/`; runs in CI in the `dashboard` job of `.github/workflows/tests.yml`, with `npx tsc --noEmit`) |
| Events endpoint accepts `request.created` | **Fixed** by the event authorization change (docs/design/event-authorization.md). Was: a second `request.created` could be appended through `POST /proofs/{proof_id}/events` (201). Now it is rejected with 403 for every actor, and the creator is the actor of the sequence-1 `request.created`. | `test_request_created_cannot_be_appended_through_events_endpoint` |
| Event signatures accepted as proof request signatures | **Fixed (minimal).** Was: an event canonical `proof_id\|type\|payload_hash` also parses as a request canonical `room\|nonce\|text`, so anyone with the API key could submit a victim's event signature to `POST /proofs` and create a proof whose creator is the victim; `/verify` reported it `valid`. Now `verify_floop_signature` rejects a request whose room is a proof_id (`^proof_[0-9a-f]{32}$`, `app/crypto.py`, same pattern as the dashboard proxy) with 401 "Invalid request signature", and the verifier checks that each `request.created` is bound to its own request (`request_binding_valid`: room not a proof_id, signed nonce and text equal the stored ones, stored signature and actor are the request's). The permanent fix, domain-tagged signed messages, is still open in `docs/design/event-replay.md`. | `test_event_signature_cannot_create_proof`, `test_verify_rejects_proof_created_from_event_signature`, `test_verify_rejects_request_whose_stored_text_differs_from_signed_text`, `test_request_with_ordinary_room_is_still_accepted`, `test_proof_id_pattern_matches_generated_ids_and_dashboard_proxy` |

The previous `test_invalid_event_actor_is_rejected` did not test this: its
request had no signature block and an unknown field, so it passed on a schema
error (422). It is now named
`test_event_with_missing_signature_and_unknown_field_is_rejected`.

**Dashboard labels (fixed):** the dashboard used to derive a "VALID" label and
a "Valid proofs" counter from the proof `status` and showed hard-coded green
checks. It now shows status as a neutral lifecycle word and takes the
verdict, per-check results, roles and authorization from `/verify`; a missing
or failed `/verify` is shown as "Could not verify", never as valid
(`dashboard/src/lib/proof-view.ts`, tested in `proof-view.test.mjs`). The proof
list still shows status only, not a verdict. See
`docs/design/event-authorization.md` §13.

# 1. Protocol / Runtime Boundary

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| Substrate/FRAME verified-inference settlement runtime | 🔴 | HIGH | CAT-3 — runtime/chain state; API is not the FLOP runtime |
| Runtime ActiveValidators authority | 🔴 | HIGH | CAT-3 — runtime/chain state; Current MockValidatorRegistry is local/test-only |
| Runtime ProcessedTasks state | 🔴 | HIGH | CAT-3 — runtime/chain state; API replay mechanisms do not prove runtime parity |
| OnProofVerified | 🔴 | HIGH | CAT-3 — runtime/chain state; No runtime event/settlement hook |
| Runtime G_n credit | 🔴 | HIGH | CAT-3 — runtime/chain state; API accepts/binds gn_weight but does not credit runtime |
| Full FLOP runtime settlement | 🔴 | HIGH | CAT-3 — runtime/chain state; API acceptance is not runtime settlement |

**Product positioning:** FLOP protocol-compatible evidence validation and validator-attestation acceptance boundary.

# 2. Task Hash

| Capability | Status | Risk | Evidence |
|---|---:|---:|---|
| canonical task_hash v1 construction | 🟢 | LOW | CANONICAL WIRE VECTOR; INTERNALLY TESTED |
| Task identity binding | 🟢 | LOW | API-side hash binding; canonical V1 primitive covered by wire-vector test |

The canonical task_hash v1 construction is implemented and internally
verified against the public wire-format vector.

Runtime producer/consumer operational binding remains an E.51 runtime-side
tracking item. External runtime byte-level parity is not independently
verified.

# 3. Compute Channel ID

| Capability | Status | Risk | Evidence |
|---|---:|---:|---|
| canonical channel_id v1 construction | 🟢 | LOW | CANONICAL WIRE VECTOR; INTERNALLY TESTED |
| Compute-channel verification pipeline | 🟢 | HIGH | CAT-1 — FCC4 decode, VerifiedTurn V0–V3 signature/Merkle verification, collection aggregate_gn checks, and agent receipt v1 are implemented and internally tested |
| Compute-channel runtime lifecycle | 🔴 | HIGH | CAT-3 — open_channel / force_open / force_ack / settle / force_settle / dispute / finalization runtime semantics are not implemented or externally verified |

### CAT-3 blocker: upstream spec ambiguity

CAT-3 implementation is currently BLOCKED by unresolved upstream spec
ambiguity in FLOP Yellow Paper §12.1, tracked in flop-labs/yellowpaper
issues:

- #33: settlement tariff P's unit ("channel pay unit") is undefined;
  E-P cannot be computed from the text as written.
- #4: R12.1b's own receipt leaf-tuple example is the legacy V0 preimage,
  not the F.3 V3 leaf that settle/force_settle actually require (our
  agent_receipt_v1 implementation correctly follows F.3, not R12.1b).
- #85: settlement_class has no published enum/wire definition.
- #48: reservation-cap slot-release semantics on force_settle->finalize
  close are ambiguous between two readings.
- #77: Appendix D fee formula conflicts with Appendix A parameters for
  zero-G_n extrinsics.

Until these are resolved upstream (or we find a canonical flop-core
source), we do not implement open_channel/settle/force_settle/dispute
runtime state, tariff computation, or settlement_class encoding, to
avoid inventing protocol semantics.

The canonical `channel_id` v1 primitive is implemented and internally
verified against the public wire-format vector. The deterministic primitive
binds the protocol/domain tag, version, genesis hash, agent, miner, and
u64 little-endian nonce.

VerifiedTurn V0–V3 verification, Merkle aggregation, and agent receipt v1
are implemented and internally tested as part of CAT-1 (see the table
above). This does **not** claim implementation or external verification of
the runtime-side channel/session state: `open_channel`, `force_open`,
`force_ack`, `settle`, `force_settle`, `dispute`, escrow state, or
finalization semantics. These remain unimplemented under CAT-3 and are
blocked on the upstream spec issues listed in "CAT-3 blocker: upstream spec
ambiguity" above.

## External Parity Classification

| Capability | Implementation status | External parity |
|---|---|---|
| task_hash construction | IMPLEMENTED (internal-test-verified) | CANONICAL WIRE VECTOR — VERIFIED |
| channel_id v1 construction | IMPLEMENTED (internal-test-verified) | CANONICAL WIRE VECTOR — VERIFIED |
| Compute-channel verification pipeline | IMPLEMENTED (internal-test-verified) | CANONICAL FCC4 / VerifiedTurn / Merkle / receipt vectors — VERIFIED |
| ValidatorAttestation representation / SCALE encoding | IMPLEMENTED (internal-test-verified) | CANONICAL WIRE VECTOR — VERIFIED |
| sr25519 signed payload / binding | IMPLEMENTED (internal-test-verified) | CANONICAL WIRE VECTOR — VERIFIED |
| Quorum arithmetic (`ceil(active_count × threshold).max(1)`) | IMPLEMENTED (internal-test-verified) | N/A — protocol-defined arithmetic; no runtime-specific byte-level parity claim |
| model_hash binding | IMPLEMENTED (internal-test-verified) | UNVERIFIED |
| output_hash binding | IMPLEMENTED (internal-test-verified) | UNVERIFIED |
| report_data construction / binding | IMPLEMENTED (internal-test-verified) | CANONICAL WIRE VECTOR — VERIFIED |
| Canonical DecodePolicy v1 encoding | IMPLEMENTED (internal-test-verified) | UNVERIFIED |

**Direct-rail ValidatorAttestation vectors:** Verified against
flop-labs/yellowpaper `wire-format-v1.json` `direct_rail_v1` at commit
`3c97bbc8d6`: the 179-byte signable payload and 275-byte SCALE encoding match
byte-for-byte, and the published validator signature verifies. The corpus
generation metadata lists a single signature-generation command, an upstream
Rust SDK example (`sdk/rust-compute-channel`). This suggests the published
signature was produced by a separate implementation, but the metadata does not
attribute individual signatures to that command. It is not verification
against a live FLOP runtime.

**Compute-channel negative vectors:** Rejection behavior matches the
canonical negative vectors for the covered cases. `DuplicateVerifiedTurn` and
`UnsupportedLeafVersion` now match the spec's exception names.
A path longer than 64 items now raises `MerklePathTooLong`, and wrong
orientation or root mismatch raises `LeafNotInRoot`; `InvalidMerkleProof`
remains only for structural errors the spec does not name (malformed path
item, `u32` index overflow). The `wrong_path_orientation` vector is now tested
byte-exact at the `verify_turn_proof` layer. An invalid VerifiedTurn enclave
signature raises the internal `InvalidEnclaveSignature`; the spec defines no name for
this case, and it is not the spec's `BadValidatorSignature`, which belongs to
validator-attestation checking (`submit_validator_attestations/check_one`).
`legacy_leaf_current_channel` is now tested with the vector bytes; the pinned
policy used is `0x66 * 32` (the generator binds no separate policy to this
case), and because the policy check runs before signature and Merkle checks,
the result does not depend on that value. `legacy_receipt_current_channel` is
now tested with the vector bytes and is rejected with `BadReceiptSignature`;
its control tests monkeypatch `verified_work_from_turns`, so they prove only
the receipt-signature layer. `invalid_validator_signature` is now tested with
the upstream vector bytes; the only remaining difference is that the spec
uses the name `BadValidatorSignature`, while our function returns False.
`invalid_agent_ack_signature` is now tested with the vector bytes (see the
per-turn agent ack note below). Not yet covered: `unknown_retention_enum`.

**Per-turn agent ack:** `verify_turn_ack` (`app/crypto.py`) is a CAT-1 pure
function for off-chain / SDK verification; no extrinsic in Appendix G.1
consumes an ack. The signed message
`channel_id ‖ turn_index:u32LE ‖ leaf_hash ‖ agent_send_ms:u64LE ‖ agent_recv_ms:u64LE`
is defined in spec F.0/F.3 (closed upstream in flop-labs/yellowpaper#36 at
`3c97bbc8d6`) and carries no domain tag or version byte. Upstream publishes
an ack vector for V3 only; for other leaf versions the caller computes the
turn's own leaf hash, untested against upstream. The spec names no rejection
error, so the function returns False for an invalid signature and raises
`ValueError` only for malformed input. Semantic checks of the timing values
(e.g. clock skew) are out of scope. The FCC4 decoder parses acks but does not
verify them.

**sr25519 edge cases:** `sr25519.verify` raises `ValueError` (not False) for a
key that is not a Ristretto point and for a signature without the schnorrkel
marker. All four sr25519 verification paths convert these to False or to the
path's named error, and the validator-attestation endpoint returns 409; locked
by `test_sr25519_edge_cases.py`. The three older verifiers use a broad
`except Exception`, which also turns programming errors into False; narrowing
it is tracked as technical debt.

`LeafNotInRoot` does not appear in `yellowpaper.md`; the name comes from the
wire-format-v1 vector corpus (generator and JSON). The order of checks inside
`verify_turn_proof` is not specified by the spec; the implemented order (field
consistency and policy, signature, path length, path structure, Merkle
membership) is an implementation choice.

V0/V1 leaves with non-zero `h_ids` or TOPLOC commitment are rejected with
`LeafFieldsInconsistent` during leaf hash computation (`app/crypto.py`), before
signature and Merkle checks. Locked by
`test_verify_turn_proof_rejects_legacy_leaf_with_nonzero_v3_field` in
`test_compute_channel.py`. (An earlier revision of this document incorrectly
listed this as a known deviation.)

**CI coverage:** Compute-channel tests (`test_compute_channel.py`) were not
part of the configured pytest suite or CI until commit `d92f6d7`. Earlier
statements that this pipeline was internally tested were not enforced by the
configured suite or CI; whether the file was run manually before this point
is not recorded. From `d92f6d7` onward they run in CI (273 passed), and
`test_testpaths_guard.py` fails if a root test file is missing from
`testpaths`.

**Vector revision:** The canonical V3 turn tests use the enclave
key/signature pair (`207b…`/`2e60…`) published at upstream commit
`3c97bbc8d6`, and the test FCC4 transcript blob matches that commit's
`fcc4_transcript_blob_hex` byte-for-byte. Earlier revisions of these tests used
the pair (`b412…`/`94f2…`) from an earlier revision of `wire-format-v1.json`
(flop-labs/yellowpaper `3eaf2f25bc`). Leaf hashes, the Merkle root/path and all
non-signature FCC4 bytes are the same in both revisions; only the enclave key
and its randomized sr25519 signature differ, and both pairs verify against the
same V3 leaf hash. `b412…` remains in use as the agent receipt key, which is
unchanged upstream. The direct-rail validator values also changed
between upstream revisions (`3eaf2f25bc`: `b41236c5…`/`90cdb722…` →
`3c97bbc8d6`: `28cc07a9…`/`729d579c…`); the validator vector tests use
`3c97bbc8d6`. `scripts/check_wire_vectors.py` checks the values registered in
`_embedded_wire_vectors.py` against the pinned corpus, and also scans every hex
string constant of at least 64 characters in the root `test_*.py` files. CI
fails when such a value appears in the current corpus but is not registered, or
appears only in a previous corpus revision listed in `SOURCE.json`
`previous_commits`. Trivial input patterns (one repeated byte, or `00 01 02 …`)
are ignored and listed. The scan does not cover values built by expressions
(e.g. `"33" * 32`), hex values shorter than 64 characters, `bytes` literals, or
files other than the root test files. The stale enclave pair in
`test_task_hash.py` was found by manual search, before this scan existed.

**Parity boundary:** `UNVERIFIED` means the API behavior is covered by its internal test suite, but the corresponding FLOP runtime implementation or official external KAT/vector has not been independently verified. `N/A` means the item is not making a runtime-specific parity claim.

# 3. ValidatorAttestation

| Capability | Status | Risk | Exact nuance | Evidence |
|---|---:|---:|---|---|
| 12-field representation | 🟢 | LOW | Required fields represented | SPEC-CONFORMANT; INTERNALLY TESTED |
| First 10 fields signed | 🟢 | LOW | 179-byte signed subset | SPEC-CONFORMANT; INTERNALLY TESTED; CANONICAL WIRE VECTOR — VERIFIED (direct_rail_v1, 3c97bbc8d6) |
| Full SCALE representation | 🟢 | LOW | 275 B contract | SPEC-CONFORMANT; INTERNALLY TESTED; CANONICAL WIRE VECTOR — VERIFIED (direct_rail_v1, 3c97bbc8d6) |
| sr25519 signatures | 🟢 | LOW | Signature verification implemented | SPEC-CONFORMANT; INTERNALLY TESTED; CANONICAL WIRE VECTOR — VERIFIED (direct_rail_v1, 3c97bbc8d6) |
| Exact tuple agreement | 🟢 | LOW | Required signed fields agree | SPEC-CONFORMANT; INTERNALLY TESTED |
| Distinct-validator quorum | 🟢 | LOW | Internally verified quorum behavior | SPEC-CONFORMANT; INTERNALLY TESTED |
| Quorum formula | 🟢 | LOW | ceil(active_count × threshold).max(1) | SPEC-CONFORMANT; INTERNALLY TESTED |
| Runtime ActiveValidators membership | 🔴 | HIGH | CAT-3 — runtime/chain state; Local/test registry only | NOT IMPLEMENTED |
| Runtime unsigned inherent | 🔴 | HIGH | CAT-3 — runtime/chain state; HTTP analogue is not runtime inherent | NOT IMPLEMENTED |
| Runtime settlement | 🔴 | HIGH | CAT-3 — runtime/chain state; No runtime credit/event | NOT IMPLEMENTED |

**Important:** The 179 B signable payload, 275 B SCALE encoding and sr25519 signature verification are verified against the upstream canonical wire vector (direct_rail_v1). Quorum arithmetic is internally tested only. None of these are verified against a live FLOP runtime.

# 4. Validator Evidence / TEE

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| quote_verified field | 🟢 | HIGH | CAT-2 — hardware/execution evidence; Signed boolean claim; NOT actual quote verification |
| event_log_verified field | 🟢 | HIGH | CAT-2 — hardware/execution evidence; Signed boolean claim; NOT event-log replay |
| DCAP verification | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; No DCAP/dcap-qvl implementation |
| dstack verification | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; No dstack implementation |
| Intel TDX quote parsing | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; No quote parser/verifier |
| NVIDIA CC verification | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; No hardware attestation verifier |
| Event-log replay | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; Not implemented |
| RTMR3/MRTD binding | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; Not implemented |
| Real TEE evidence verification | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; API does not independently verify underlying TEE evidence |

**Safe wording:** quote_verified and event_log_verified are validator-signed evidence claims, not proof that this API independently verified the underlying TEE evidence.

# 5. model_hash

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| 32-byte representation | 🟢 | LOW | Shape validation |
| ValidatorAttestation binding | 🟢 | LOW | Signed/bound |
| report_data binding | 🟢 | LOW | Included in canonical report_data |
| Exact validator agreement | 🟢 | LOW | Bundle agreement |
| dm-verity measured root | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; Not implemented |
| EROFS + dm-verity verification | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; Not implemented |
| RTMR3/MRTD measurement binding | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; Not implemented |
| Model registry comparison | 🔴 | HIGH | CAT-3 — runtime/chain state; model registry comparison is runtime-owned |

**Safe wording:** validator-bound model_hash claim.

# 6. output_hash

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| 32-byte representation | 🟢 | LOW | Shape validation |
| ValidatorAttestation binding | 🟢 | LOW | Signed/bound |
| report_data binding | 🟢 | LOW | Included in report_data |
| Result binding | 🟢 | MEDIUM | API can bind claimed output_hash |
| Real model-execution provenance | 🔴 | HIGH | CAT-2/3 — execution evidence plus runtime verification; API does not execute the model |
| Independent output recomputation | 🔴 | HIGH | CAT-2/3 — execution plus runtime dispute/verification; Tier-3 execution verification absent |

**Safe wording:** validator-bound output_hash claim.
# 7. decode_policy_hash

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| 32-byte representation | 🟢 | LOW | Shape validation |
| ValidatorAttestation binding | 🟢 | LOW | Signed/bound |
| Canonical decode-policy object | 🟢 | MEDIUM | CAT-1 — API-boundary implementable; SPEC-CONFORMANT canonical DecodePolicy v1 encoding and hash derivation implemented; INTERNALLY TESTED with canonical encoding, TransformId, Other(u16), and validation tests. |
| Canonical external-parameter derivation | 🔴 | HIGH | CAT-1 — SPEC-GAP; canonical SamplingParams integer encoding is specified, but the Yellow Paper does not define a normative mapping from external float/string inference parameters to those integers. The API must not invent a conversion rule. |
| Independent execution verification | 🔴 | HIGH | CAT-2/3 — execution plus runtime verification; Not implemented |

**Safe wording:** decode_policy_hash can be derived from the canonical DecodePolicy v1 encoding; runtime/model-registry verification remains outside this API boundary.

# 8. report_data

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| Canonical field composition | 🟢 | LOW | SHA256(task_hash ‖ gn_weight:u64LE ‖ latency_ms:u64LE ‖ model_hash ‖ output_hash ‖ decode_policy_hash ‖ SCALE(tee_type)) ‖ 00×32 |
| SHA-256 construction | 🟢 | LOW | Canonical field encodings used |
| latency_ms inclusion | 🟢 | LOW | Included in report_data |
| Actual quote verification | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; No real quote parser/verifier |
| External KAT/vector verification | 🟢 | LOW | PUBLIC-CANONICAL WIRE VECTOR — VERIFIED |

# 9. latency

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| latency_ms u64 representation | 🟢 | LOW | Field exists and is validated |
| Signed binding | 🟢 | LOW | Included in signed subset |
| Exact validator agreement | 🟢 | LOW | Included in agreement |
| report_data binding | 🟢 | LOW | Included in report_data |
| miner_recv_ms | 🔴 | HIGH | CAT-2/3 — execution timing produced by miner and bound/validated by runtime |
| miner_done_ms | 🔴 | HIGH | CAT-2/3 — execution timing produced by miner and bound/validated by runtime |
| latency_ms = miner_done_ms - miner_recv_ms | 🔴 | HIGH | CAT-2/3 — execution timing plus runtime transcript validation |
| VerifiedTurn timing transcript | 🔴 | HIGH | CAT-3 — runtime/session transcript; VerifiedTurn contains canonical timing fields |
| V3 timing leaf binding | 🔴 | HIGH | CAT-3 — runtime/session transcript; V3 leaf canonically binds recv/done/latency |
| Latency-based G_n enforcement | 🟡 | HIGH | CAT-1 API-boundary enforcement: reject-only throughput tripwire implemented; exact threshold is SPEC-DERIVED. Canonical G_n meter remains a separate CAT-3 GAP. |

**Safe wording:** validator-signed latency claim is bound/validated.
# 10. STARK / PendingVerification

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| STARK evidence intake | 🟡 | MEDIUM | API accepts pending STARK evidence |
| API PendingVerification representation | 🟡 | MEDIUM | SQLite representation is not runtime storage parity |
| STARK task_hash replay guard | 🟡 | MEDIUM | API-side PendingVerification primary-key protection |
| Actual STARK proof verification | 🔴 | HIGH | CAT-3 — runtime verification; Proof JSON is accepted but not cryptographically verified |
| Runtime PendingVerifications semantics | 🔴 | HIGH | CAT-3 — runtime/chain state; Runtime storage/pruning absent |
| Runtime ProcessedTasks mutation | 🔴 | HIGH | CAT-3 — runtime/chain state; Runtime semantics not implemented |

Current STARK response deliberately distinguishes evidence intake from verification.
`accepted=true` MUST NOT be interpreted as STARK verification, execution verification, settlement, or crediting.

# 11. G_n / Reference Work

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| gn_weight representation | 🟢 | LOW | Field exists |
| gn_weight signature binding | 🟢 | LOW | Signed/validated |
| gn_weight report_data binding | 🟢 | LOW | Included |
| F_eff computation | 🔴 | HIGH | CAT-2/3 — canonical execution-input metering; reference implementation is externally owned and not available in this API repo |
| G_n = F_eff / 10^9 | 🔴 | HIGH | CAT-2/3 — canonical meter result; API does not compute G_n and only accepts externally supplied evidence |
| hp_poui::flop_meter | 🔴 | HIGH | CAT-2/3 — canonical meter primitive; normative reference exists, but exact public implementation/KAT source could not be independently retrieved |
| Execution-input meter | 🔴 | HIGH | CAT-2/3 — canonical execution-input metering; required reference implementation is outside this API boundary |
| Throughput tripwire | 🟢 | HIGH | CAT-1 API-boundary enforcement; exact spec-derived threshold = 2,000,000 GFLOPS/s (Appendix A / R4.3, D-0405). Runtime settlement gate is a separate CAT-3 concern. |
| MLPerf ceiling | 🔴 | HIGH | CAT-2/3 — hardware calibration evidence plus runtime enforcement; Not implemented here |
| Under-report floor | 🔴 | HIGH | CAT-2/3 — execution/work evidence plus runtime metering; Not implemented here |
| Calibration cap | 🔴 | HIGH | CAT-3 — runtime hardware-calibration state; Not implemented |
| G_n unit taxonomy | 🔴 | MEDIUM | SPEC-TBD — normative taxonomy remains explicitly unresolved |
| VerifiedTurn | 🔴 | HIGH | CAT-3 — runtime/session transcript; Not implemented |
| Aggregate distinct g_n validation | 🔴 | HIGH | CAT-3 — runtime/session settlement validation; Not implemented |
| Runtime G_n credit | 🔴 | HIGH | CAT-3 — runtime/chain state; Not implemented |

**CRITICAL:** Never introduce a guessed `2*P*N` meter.

# 12. TOPLOC / Tiered Evidence

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| TEE-optional participation | 🟡 | MEDIUM | TEE is optional HARD tier in the Yellow Paper |
| Tier-1 TEE verification | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; Not implemented |
| Tier-2 TOPLOC | 🔴 | HIGH | CAT-2/3 — execution activation evidence plus runtime verification; Not implemented |
| Tier-3 optimistic re-execution | 🔴 | HIGH | CAT-2/3 — independent execution plus runtime dispute/slashing; Not implemented |
| Tier-4 validator quorum | 🟡 | HIGH | API models signatures/quorum, not runtime authority/settlement |
| TOPLOC protocol-to-proof bridge | 🔴 | HIGH | CAT-2/3 + SPEC-GAP — execution evidence bridge and runtime semantics; E.43 remains open |

Missing TEE is not itself a V1 defect because the Yellow Paper makes TEE optional.
The risk is claiming signed booleans are actual TEE verification.
# 13. Replay Protection

| Layer / Endpoint | Mechanism | Status | Exact nuance |
|---|---|---:|---|
| /validator-attestations/accept | in-memory processed_validator_tasks | 🟡 | Process lifetime only |
| /proofs/{proof_id}/validator-attestations/accept | persistent ProcessedTask / claim_processed_task | 🟡 | Persistent API-side protection |
| /stark-batches | PendingVerification primary-key task_hash guard | 🟡 | API-side protection |
| FLOP runtime ProcessedTasks | runtime state | 🔴 | CAT-3 — runtime/chain state; Not implemented / not independently verified |

These mechanisms MUST NOT be collapsed into one generic runtime ProcessedTasks claim.

# 14. Evidence Status Contract v0.1

This is an API-owned contract, not a normative Yellow Paper field.

| Endpoint | Evidence class |
|---|---|
| POST /proofs | proof_request_signed |
| POST /proofs/{proof_id}/events | signed_event |
| GET /proofs/{proof_id} | proof_event_chain |
| GET /proofs/{proof_id}/verify | proof_integrity_verified |
| POST /stark-batches | stark_evidence_pending |
| POST /validator-attestations/accept | validator_attestation_binding |
| POST /proofs/{proof_id}/validator-attestations/accept | validator_attestation_binding |

### Locked invariant

No current API code path may emit execution_verified: true or runtime_settled: true.

execution_verified=true is reserved for actual verified execution evidence.
runtime_settled=true is reserved for actual FLOP runtime settlement.

Regression coverage exists for this invariant.

# 15. Endpoint Scope

| Endpoint | Scope |
|---|---|
| POST /proofs | V1 CORE |
| POST /proofs/{proof_id}/events | V1 CORE |
| GET /proofs/{proof_id} | V1 CORE |
| GET /proofs/{proof_id}/verify | V1 CORE |
| POST /proofs/{proof_id}/validator-attestations/accept | V1 CORE |
| POST /validator-attestations/accept | V1 ADAPTER |
| POST /stark-batches | V1 ADAPTER |
| GET /proofs | OPERATIONS |
| GET /actors | OPERATIONS |
| GET /health | OPERATIONS |

# 16. API Ownership Boundary

## API Core
- signed proof/event storage
- hash-chain integrity
- task identity validation
- cryptographic signature validation
- ValidatorAttestation validation
- exact tuple agreement
- API-side quorum calculation
- API-side replay protection
- evidence acceptance/binding
- explicit pending states
- Evidence Status contract

## API Adapter / Evidence Boundary
- validator evidence intake
- model_hash claims
- output_hash claims
- decode_policy_hash claims
- latency_ms claims
- gn_weight claims
- pending STARK evidence

## Outside API ownership
- TEE quote generation/verification
- DCAP/dcap-qvl
- dstack
- TDX/NVIDIA CC hardware evidence
- event-log replay
- dm-verity measurement
- RTMR3/MRTD binding
- TOPLOC
- optimistic re-execution
- dispute/slashing
- runtime ActiveValidators
- runtime PendingVerifications
- runtime ProcessedTasks
- G_n settlement credit
- OnProofVerified
- FLOP runtime settlement

# 17. Phase 4 — Bounded Research Exit Criterion

The Yellow Paper requires the shared deterministic hp_poui::flop_meter for reference-work G_n computation.

Before implementing any G_n meter:
1. Search official FLOP sources for hp_poui::flop_meter.
2. Search for its reference implementation.
3. Search for deterministic test vectors / KATs.
4. Search for the mirrored tee-bridge/inference/attestor/flop_meter.py.
5. Verify the discovered source against Yellow Paper §4.

**DO NOT invent an approximation.**

If the official reference implementation/KATs cannot be located after bounded research:
> Mark the G_n meter as SOURCE UNAVAILABLE / GAP and move to Phase 5 Safe API Adapters.

# 18. Canonical Audit Rule

This file is the canonical parity matrix.

Future summaries, dashboards, SDKs, and documentation MUST NOT independently reconstruct protocol parity from memory.

When implementation changes:
1. Update the relevant matrix entry.
2. Run regression tests.
3. Only then update higher-level product surfaces.

**Current test baseline:** 504 passed, 1 xfailed (with the API server running on 127.0.0.1:8000).

# 19. Phase 4 Closure — G_n Reference Artifact

| Item | Result |
|---|---|
| Yellow Paper definition of hp_poui::flop_meter | VERIFIED |
| Reference path specified by Yellow Paper | VERIFIED — specification path only; source artifact not retrieved |
| Exact official source artifact retrieved | NO |
| Exact official KAT vectors retrieved | NO (G_n meter / hp_poui::flop_meter only; wire-format vectors are covered elsewhere in this document) |
| Independent empirical verification | NO |
| Canonical G_n meter implementation | GAP |

### Locked decision

The API MUST NOT implement or claim canonical FLOP G_n computation until the exact reference implementation and deterministic KATs are available.
No guessed 2*P*N meter, approximation, or third-party implementation may be substituted.
The current API may only accept, bind, validate, and expose gn_weight as an externally supplied evidence claim.

Phase 4 status: CLOSED — SOURCE ARTIFACT UNAVAILABLE / GAP.
Next phase: Phase 5 — Safe API Adapters.

# 16. Runtime-Side Tracking

The following Yellow Paper items are runtime-side and are not audited
against implementation source because the corresponding public runtime
source is not available in this repository.

| Item | Status | External source |
|---|---|---|
| E.51 Canonical wire-format operational binding | TRACKING | Runtime source unavailable |
| E.52 Verification-liveness gate | TRACKING | Runtime source unavailable |
| E.53 Re-execution checker lane | TRACKING | Runtime source unavailable |

These items MUST NOT be represented as implemented, externally verified,
or runtime-parity-confirmed by the Proof API.

Their current state is based on the Yellow Paper specification/status only,
not on direct runtime source inspection.

## §12.1 / VerifiedTurn Spec Verification Note

`VerifiedTurn` and its runtime/session transcript semantics are not treated
as externally verified for V1.

Any classification that depends on secondary or inferred material remains
outside the V1 external-parity claim until confirmed directly against the
primary Yellow Paper text.

**Current treatment:** V1.1 candidate / spec verification pending.
