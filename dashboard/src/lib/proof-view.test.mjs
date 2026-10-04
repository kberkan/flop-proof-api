// Run with: npm test (node --test; see proxy-policy.test.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  cardTone,
  eventRows,
  evidenceChecks,
  evidenceSummary,
  roleLabel,
  shortDid,
  statusLabel,
  verdictBadge,
} from "./proof-view.ts";
import { isProofId } from "./proxy-policy.ts";

const CREATOR = "did:key:z6MkCreator000000000000000000000000000000000001";
const DELEGATE = "did:key:z6MkDelegate00000000000000000000000000000000002";
const STRANGER = "did:key:z6MkStranger00000000000000000000000000000000003";

function check(sequence, overrides = {}) {
  return {
    sequence,
    sequence_valid: true,
    chain_valid: true,
    payload_hash_valid: true,
    canonical_valid: true,
    signature_valid: true,
    actor_authorized: true,
    authorization_reason: null,
    role: "creator",
    ...overrides,
  };
}

const VALID = {
  verdict: "valid",
  checks: [check(1), check(2, { role: "delegate" })],
  evidence: { class: "proof_integrity_verified", execution_verified: false, runtime_settled: false },
};

const INVALID_FOREIGN = {
  verdict: "invalid",
  checks: [
    check(1),
    check(2, { role: "unauthorized", actor_authorized: false, authorization_reason: "not_delegated" }),
  ],
  evidence: VALID.evidence,
};

// --- verdict badge: nothing but a consistent valid response is "valid" --------

const NEVER_VALID = {
  loading: { kind: "loading" },
  "network error": { kind: "error", message: "Failed to fetch" },
  "HTTP 404": { kind: "error", message: "API returned 404" },
  "null body": { kind: "result", data: null },
  "empty object": { kind: "result", data: {} },
  "string body": { kind: "result", data: "valid" },
  "verdict missing": { kind: "result", data: { checks: VALID.checks } },
  "verdict invalid": { kind: "result", data: INVALID_FOREIGN },
  "verdict unknown word": { kind: "result", data: { ...VALID, verdict: "VALID" } },
  "valid without checks": { kind: "result", data: { verdict: "valid" } },
  "valid with empty checks": { kind: "result", data: { verdict: "valid", checks: [] } },
  "valid but a check fails": { kind: "result", data: { verdict: "valid", checks: [check(1, { chain_valid: false })] } },
  "valid but authorization missing": {
    kind: "result",
    data: { verdict: "valid", checks: [{ ...check(1), actor_authorized: undefined }] },
  },
};

for (const [name, state] of Object.entries(NEVER_VALID)) {
  test(`verdict badge is never valid for: ${name}`, () => {
    const badge = verdictBadge(state);
    assert.notEqual(badge.tone, "valid");
    assert.notEqual(badge.label, "Valid");
  });
}

test("verdict badge is valid only for a consistent valid response", () => {
  assert.deepEqual(verdictBadge({ kind: "result", data: VALID }), {
    tone: "valid",
    label: "Valid",
    detail: null,
  });
});

test("verdict badge shows invalid for an invalid verdict", () => {
  assert.equal(verdictBadge({ kind: "result", data: INVALID_FOREIGN }).tone, "invalid");
});

test("verdict badge reports an error message as could-not-verify", () => {
  assert.deepEqual(verdictBadge({ kind: "error", message: "API returned 404" }), {
    tone: "unknown",
    label: "Could not verify",
    detail: "API returned 404",
  });
});

// --- checks -> evidence list ----------------------------------------------------

test("evidence checks reflect the real check values", () => {
  const summary = Object.fromEntries(evidenceChecks(INVALID_FOREIGN).map((c) => [c.key, c.ok]));
  assert.deepEqual(summary, {
    signatures: true,
    canonical: true,
    payload: true,
    chain: true,
    authorization: false,
  });
});

test("evidence checks are unknown without a verify result", () => {
  for (const data of [null, undefined, {}, { checks: [] }, { checks: "x" }]) {
    assert.ok(evidenceChecks(data).every((c) => c.ok === null), JSON.stringify(data));
  }
});

test("chain check fails when either sequence or chain link fails", () => {
  const ok = (data) => evidenceChecks(data).find((c) => c.key === "chain").ok;
  assert.equal(ok({ checks: [check(1, { sequence_valid: false })] }), false);
  assert.equal(ok({ checks: [check(1, { chain_valid: false })] }), false);
});

test("card tone is never pass unless the verdict is valid", () => {
  assert.equal(cardTone(true, "valid"), "pass");
  assert.equal(cardTone(true, "invalid"), "pass-muted");
  assert.equal(cardTone(true, "unknown"), "pass-muted");
  assert.equal(cardTone(false, "valid"), "fail");
  assert.equal(cardTone(null, "valid"), "unknown");
});

// --- status, roles, events ---------------------------------------------------------

test("status labels are neutral lifecycle words", () => {
  assert.deepEqual(
    ["pending", "active", "completed", "failed", "weird", undefined].map(statusLabel),
    ["Pending", "Active", "Completed", "Failed", "Unknown", "Unknown"],
  );
  for (const status of ["pending", "active", "completed", "failed"]) {
    assert.doesNotMatch(statusLabel(status), /valid|verif/i);
  }
});

test("role labels", () => {
  assert.deepEqual(
    ["creator", "delegate", "unauthorized", "unknown"].map(roleLabel),
    ["Creator", "Delegate", "Unauthorized", "Unknown"],
  );
});

test("event rows join verify checks by sequence and flag unauthorized events", () => {
  const events = [
    { sequence: 1, type: "request.created", actor_did: CREATOR },
    { sequence: 2, type: "result.created", actor_did: STRANGER },
  ];
  const [first, second] = eventRows(events, INVALID_FOREIGN);

  assert.equal(first.role, "creator");
  assert.equal(first.authorized, true);
  assert.equal(first.flagged, false);
  assert.equal(first.authorizationReason, null);

  assert.equal(second.role, "unauthorized");
  assert.equal(second.roleLabel, "Unauthorized");
  assert.equal(second.authorized, false);
  assert.equal(second.authorizationReason, "not_delegated");
  assert.equal(second.flagged, true);
  assert.equal(second.actorDid, STRANGER);
});

test("event rows without a verify result have unknown role and authorization", () => {
  const [row] = eventRows([{ sequence: 1, type: "request.created", actor_did: DELEGATE }], null);
  assert.equal(row.role, "unknown");
  assert.equal(row.authorized, null);
  assert.equal(row.flagged, false);
});

test("event rows tolerate malformed events", () => {
  assert.deepEqual(eventRows("not a list", VALID), []);
  const [row] = eventRows([null], VALID);
  assert.equal(row.type, "Event 1");
  assert.equal(row.actorShort, "—");
});

test("short DID keeps the start and end", () => {
  assert.equal(shortDid(CREATOR), "did:key:z6MkCrea…000001");
  assert.equal(shortDid("did:key:z6Mk"), "did:key:z6Mk");
});

// --- evidence fields -------------------------------------------------------------

test("evidence summary reads the evidence block", () => {
  assert.deepEqual(evidenceSummary(VALID), {
    evidenceClass: "proof_integrity_verified",
    executionVerified: false,
    runtimeSettled: false,
  });
  assert.deepEqual(evidenceSummary(null), {
    evidenceClass: null,
    executionVerified: null,
    runtimeSettled: null,
  });
});

// --- proof_id input uses the proxy rule -------------------------------------------

test("proof_id input check matches the proxy pattern", () => {
  assert.equal(isProofId("proof_0123456789abcdef0123456789abcdef"), true);
  for (const bad of ["", "proof_", "proof_XYZ", "proof_0123456789abcdef0123456789abcdef/verify", "../actors"]) {
    assert.equal(isProofId(bad), false, bad);
  }
});
