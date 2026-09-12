# FLOP Proof API — Canonical Protocol Parity Matrix
**Audit baseline:** FLOP Yellow Paper v0.5.0 (draft), updated 2026-09-05
**Official specification:** https://flop.finance/intro/yellowpaper/

> This is the canonical parity record for the FLOP Proof API.
> It does not claim that this API is the FLOP Network runtime, settlement runtime, TEE verifier, or execution engine.

## Status Legend
- 🟢 IMPLEMENTED / PARITY
- 🟡 PARTIAL / ADAPTER
- 🔴 NOT IMPLEMENTED

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
| task_hash construction | 🟢 | LOW | SPEC-CONFORMANT; INTERNALLY TESTED |
| Task identity binding | 🟢 | LOW | SPEC-CONFORMANT; INTERNALLY TESTED |

Current implementation matches the specified task-hash construction.

# 3. ValidatorAttestation

| Capability | Status | Risk | Exact nuance | Evidence |
|---|---:|---:|---|---|
| 12-field representation | 🟢 | LOW | Required fields represented | SPEC-CONFORMANT; INTERNALLY TESTED |
| First 10 fields signed | 🟢 | LOW | 179-byte signed subset | SPEC-CONFORMANT; INTERNALLY TESTED |
| Full SCALE representation | 🟢 | LOW | 275 B contract | SPEC-CONFORMANT; INTERNALLY TESTED |
| sr25519 signatures | 🟢 | LOW | Signature verification implemented | SPEC-CONFORMANT; INTERNALLY TESTED |
| Exact tuple agreement | 🟢 | LOW | Required signed fields agree | SPEC-CONFORMANT; INTERNALLY TESTED |
| Distinct-validator quorum | 🟢 | LOW | Internally verified quorum behavior | SPEC-CONFORMANT; INTERNALLY TESTED |
| Quorum formula | 🟢 | LOW | ceil(active_count × threshold).max(1) | SPEC-CONFORMANT; INTERNALLY TESTED |
| Runtime ActiveValidators membership | 🔴 | HIGH | CAT-3 — runtime/chain state; Local/test registry only | NOT IMPLEMENTED |
| Runtime unsigned inherent | 🔴 | HIGH | CAT-3 — runtime/chain state; HTTP analogue is not runtime inherent | NOT IMPLEMENTED |
| Runtime settlement | 🔴 | HIGH | CAT-3 — runtime/chain state; No runtime credit/event | NOT IMPLEMENTED |

**Important:** 179 B / 275 B / sr25519 / quorum claims are internally tested, not externally empirically verified against the real FLOP runtime.
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
| Parameter derivation | 🔴 | HIGH | CAT-1 — API-boundary implementable; canonical SamplingParams encoding is specified, but API derivation is not implemented |
| Independent execution verification | 🔴 | HIGH | CAT-2/3 — execution plus runtime verification; Not implemented |

**Safe wording:** decode_policy_hash can be derived from the canonical DecodePolicy v1 encoding; runtime/model-registry verification remains outside this API boundary.

# 8. report_data

| Capability | Status | Risk | Exact nuance |
|---|---:|---:|---|
| Canonical field composition | 🟢 | LOW | task_hash ‖ gn_weight ‖ latency_ms ‖ model_hash ‖ output_hash ‖ decode_policy_hash ‖ tee_type |
| SHA-256 construction | 🟢 | LOW | Canonical field encodings used |
| latency_ms inclusion | 🟢 | LOW | Included in report_data |
| Actual quote verification | 🔴 | HIGH | CAT-2 — hardware/execution infrastructure; No real quote parser/verifier |
| External KAT/vector verification | 🔴 | MEDIUM | EXTERNAL-VERIFICATION — official runtime/vector evidence required |

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

**Current test baseline:** 177 passed.

# 19. Phase 4 Closure — G_n Reference Artifact

| Item | Result |
|---|---|
| Yellow Paper definition of hp_poui::flop_meter | VERIFIED |
| Reference path specified by Yellow Paper | VERIFIED — specification path only; source artifact not retrieved |
| Exact official source artifact retrieved | NO |
| Exact official KAT vectors retrieved | NO |
| Independent empirical verification | NO |
| Canonical G_n meter implementation | GAP |

### Locked decision

The API MUST NOT implement or claim canonical FLOP G_n computation until the exact reference implementation and deterministic KATs are available.
No guessed 2*P*N meter, approximation, or third-party implementation may be substituted.
The current API may only accept, bind, validate, and expose gn_weight as an externally supplied evidence claim.

Phase 4 status: CLOSED — SOURCE ARTIFACT UNAVAILABLE / GAP.
Next phase: Phase 5 — Safe API Adapters.
