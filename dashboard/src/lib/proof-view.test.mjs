// Run with: npm test (node --test; see proxy-policy.test.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  LEGACY_FORMAT_NOTE,
  cardTone,
  checkStateLabel,
  eventChecks,
  eventRows,
  evidenceChecks,
  evidenceSummary,
  proofFormat,
  roleLabel,
  shortDid,
  shortNonce,
  statusLabel,
  verdictBadge,
} from "./proof-view.ts";
import { isProofId } from "./proxy-policy.ts";

const CREATOR = "did:key:z6MkCreator000000000000000000000000000000000001";
const DELEGATE = "did:key:z6MkDelegate00000000000000000000000000000000002";
const STRANGER = "did:key:z6MkStranger00000000000000000000000000000000003";

// Shape of one entry of GET /proofs/{id}/verify "checks" (app/verification_core.py):
// sequence 1 is request.created with a boolean request_binding_valid; other
// events report request_binding_valid: null.
function check(sequence, overrides = {}) {
  const isRequest = (overrides.type ?? (sequence === 1 ? "request.created" : "agent.started")) === "request.created";
  return {
    sequence,
    type: sequence === 1 ? "request.created" : "agent.started",
    sequence_valid: true,
    chain_valid: true,
    payload_hash_valid: true,
    canonical_valid: true,
    signature_valid: true,
    request_binding_valid: isRequest ? true : null,
    format_valid: true,
    replay_valid: true,
    actor_authorized: true,
    authorization_reason: null,
    role: "creator",
    ...overrides,
  };
}

const VALID = {
  proof_version: "3",
  verdict: "valid",
  checks: [check(1), check(2, { role: "delegate" })],
  evidence: { class: "proof_integrity_verified", execution_verified: false, runtime_settled: false },
};

const withChecks = (checks) => ({ ...VALID, checks });

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
  // request_binding_valid is required on request.created.
  "valid but request binding false": { kind: "result", data: withChecks([check(1, { request_binding_valid: false }), check(2)]) },
  "valid but request binding null": { kind: "result", data: withChecks([check(1, { request_binding_valid: null }), check(2)]) },
  "valid but request binding missing": {
    kind: "result",
    data: withChecks([{ ...check(1), request_binding_valid: undefined }, check(2)]),
  },
  "valid but no request.created event": {
    kind: "result",
    data: withChecks([check(2), check(3)]),
  },
  // false still fails on an event the binding check does not apply to.
  "valid but request binding false on another event": {
    kind: "result",
    data: withChecks([check(1), check(2, { request_binding_valid: false })]),
  },
  // format_valid and replay_valid are required on every event.
  ...Object.fromEntries(
    ["format_valid", "replay_valid"].flatMap((field) =>
      [
        ["false", false],
        ["null", null],
        ["missing", undefined],
        ["a string", "true"],
      ].flatMap(([name, value]) =>
        [1, 2].map((sequence) => [
          `valid but ${field} ${name} on event ${sequence}`,
          {
            kind: "result",
            data: withChecks([1, 2].map((s) => (s === sequence ? { ...check(s), [field]: value } : check(s)))),
          },
        ]),
      ),
    ),
  ),
};

for (const [name, state] of Object.entries(NEVER_VALID)) {
  test(`verdict badge is never valid for: ${name}`, () => {
    const badge = verdictBadge(state);
    assert.notEqual(badge.tone, "valid");
    assert.notEqual(badge.label, "Valid");
  });
}

test("a valid v3 proof gives a valid badge", () => {
  assert.equal(verdictBadge({ kind: "result", data: VALID }).tone, "valid");
  assert.ok(evidenceChecks(VALID).every((c) => c.ok === true));
});

test("request_binding_valid null on a non-request event does not affect the badge", () => {
  const data = withChecks([check(1), check(2, { request_binding_valid: null }), { ...check(3), request_binding_valid: undefined }]);
  assert.equal(verdictBadge({ kind: "result", data }).tone, "valid");
  assert.equal(evidenceChecks(data).find((c) => c.key === "request_binding").ok, true);
});

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
    request_binding: true,
    format: true,
    replay: true,
  });
});

test("new checks fail or become unavailable by scope", () => {
  const ok = (data, key) => evidenceChecks(data).find((c) => c.key === key).ok;
  assert.equal(ok(withChecks([check(1), check(2, { replay_valid: false })]), "replay"), false);
  assert.equal(ok(withChecks([check(1), check(2, { format_valid: null })]), "format"), null);
  assert.equal(ok(withChecks([check(1, { request_binding_valid: null }), check(2)]), "request_binding"), null);
  assert.equal(ok(withChecks([check(1, { request_binding_valid: false }), check(2)]), "request_binding"), false);
  assert.equal(ok(withChecks([check(2)]), "request_binding"), null);
});

test("per-event checks: not applicable, not available, pass, fail", () => {
  const states = (c) => Object.fromEntries(eventChecks(c).map((item) => [item.key, item.state]));
  assert.deepEqual(states(check(1)), { request_binding: "pass", format: "pass", replay: "pass" });
  assert.deepEqual(states(check(2)), { request_binding: "not-applicable", format: "pass", replay: "pass" });
  assert.deepEqual(states(check(2, { replay_valid: false })), {
    request_binding: "not-applicable",
    format: "pass",
    replay: "fail",
  });
  assert.deepEqual(states({ ...check(1), request_binding_valid: undefined, format_valid: null }), {
    request_binding: "not-available",
    format: "not-available",
    replay: "pass",
  });
  assert.deepEqual(states(undefined), {
    request_binding: "not-available",
    format: "not-available",
    replay: "not-available",
  });
  assert.deepEqual(
    ["pass", "fail", "not-applicable", "not-available"].map(checkStateLabel),
    ["Pass", "Fail", "Not applicable", "Not available"],
  );
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

test("event rows carry nonce and per-event checks, and flag a replayed event", () => {
  const events = [
    { sequence: 1, type: "request.created", actor_did: CREATOR, nonce: "request-nonce" },
    { sequence: 2, type: "agent.started", actor_did: CREATOR, nonce: "event-0123456789abcdef0123456789abcdef" },
    { sequence: 3, type: "agent.started", actor_did: CREATOR, nonce: "event-0123456789abcdef0123456789abcdef" },
  ];
  const data = withChecks([check(1), check(2), check(3, { replay_valid: false })]);
  const [first, second, third] = eventRows(events, data);

  assert.equal(first.nonce, "request-nonce");
  assert.equal(first.nonceShort, "request-nonce");
  assert.equal(second.nonce, events[1].nonce);
  assert.equal(second.nonceShort, "event-012345…abcdef");
  assert.equal(second.flagged, false);
  assert.equal(second.checks.find((c) => c.key === "request_binding").state, "not-applicable");
  assert.equal(third.flagged, true);
  assert.equal(third.checks.find((c) => c.key === "replay").state, "fail");
});

test("short nonce", () => {
  assert.equal(shortNonce(null), "—");
  assert.equal(shortNonce(""), "(none)");
  assert.equal(shortNonce("n-1"), "n-1");
});

test("proof format from proof_version", () => {
  assert.deepEqual(proofFormat(VALID), { version: "3", label: "Format: v3", legacy: false, note: null });
  for (const version of ["1", "2"]) {
    const format = proofFormat({ ...VALID, proof_version: version });
    assert.equal(format.label, `Format: legacy v${version}`);
    assert.equal(format.legacy, true);
    assert.equal(format.note, LEGACY_FORMAT_NOTE);
  }
  for (const data of [null, {}, { proof_version: 3 }, { proof_version: "4" }]) {
    assert.equal(proofFormat(data).label, "Format: unknown", JSON.stringify(data));
  }
  assert.match(LEGACY_FORMAT_NOTE, /nonce is not part of the signed message/);
  assert.match(LEGACY_FORMAT_NOTE, /repeated \(canonical, signature\) pair/);
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
