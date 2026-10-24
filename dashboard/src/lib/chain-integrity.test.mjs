// Run with: npm test. Display rules for version-4 proofs: the signed chain
// head, the closing-event position rule, lifecycle status next to the
// verified chain's closing event, and the chain head to keep
// (docs/design/proof-closure.md D-C5 to D-C10). The "real" tests use
// GET /proofs/{id} and /verify responses captured from the API
// (fixtures/verify-samples.json), so the rules follow what the verifier
// actually reports.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  CHAIN_HEAD_NOTE,
  LEGACY_FORMAT_NOTE,
  NO_CHAIN_HEAD_NOTE,
  STATUS_TOOLTIP,
  chainHeadView,
  closureView,
  eventRows,
  evidenceChecks,
  expectHeadCommand,
  positionViolation,
  proofFormat,
  summaryTone,
  verdictBadge,
  verifyReason,
} from "./proof-view.ts";

const SAMPLES = JSON.parse(readFileSync(new URL("./fixtures/verify-samples.json", import.meta.url), "utf8"));

const badgeOf = (data) => verdictBadge({ kind: "result", data });
const priorHeadStates = (sample) =>
  eventRows(sample.proof.events, sample.verify).map(
    (row) => [row.type, row.checks.find((c) => c.key === "prior_head").state],
  );
const card = (data, key) => evidenceChecks(data).find((c) => c.key === key);

// --- real /verify responses ----------------------------------------------------------

test("real: the fixture is what the verifier reports for prior_head_valid", () => {
  // The rules below rest on these values; if the API changes them, this fails first.
  const raw = (name) => SAMPLES[name].verify.checks.map((c) => [c.type, c.prior_head_valid]);
  assert.deepEqual(raw("valid"), [
    ["request.created", null],
    ["agent.started", true],
    ["artifact.note", true],
    ["result.created", true],
    ["proof.completed", true],
  ]);
  assert.deepEqual(raw("v3"), [["request.created", null], ["agent.started", null]]);
  assert.deepEqual(raw("v2"), [["request.created", null], ["agent.started", null]]);
  assert.equal(SAMPLES.m9.verify.checks.at(-1).prior_head_valid, false);
});

test("real: a valid closed v4 proof", () => {
  const { proof, verify } = SAMPLES.valid;
  assert.deepEqual(badgeOf(verify), { tone: "valid", label: "Valid", detail: null });
  assert.equal(proofFormat(verify).label, "Format: v4");
  assert.equal(proofFormat(verify).note, null);
  assert.deepEqual(priorHeadStates(SAMPLES.valid), [
    ["request.created", "not-applicable"],
    ["agent.started", "pass"],
    ["artifact.note", "pass"],
    ["result.created", "pass"],
    ["proof.completed", "pass"],
  ]);
  assert.deepEqual(card(verify, "prior_head"), { key: "prior_head", label: "Signed chain head", ok: true, applies: true });
  const closure = closureView(proof.status, verify);
  assert.equal(closure.statusLabel, "Completed");
  assert.equal(closure.closedLabel, "Yes");
  assert.equal(closure.warning, null);
  const head = chainHeadView(verify);
  assert.equal(head.head, verify.chain_head);
  assert.equal(head.eventCount, 5);
  assert.equal(positionViolation(verify), null);
});

test("real: M9 (event removed, links recomputed) is invalid with prior_head Fail on the event after the gap", () => {
  const { verify } = SAMPLES.m9;
  assert.equal(badgeOf(verify).tone, "invalid");
  assert.deepEqual(priorHeadStates(SAMPLES.m9).at(-1), ["proof.completed", "fail"]);
  const rows = eventRows(SAMPLES.m9.proof.events, verify);
  assert.deepEqual(rows.map((r) => r.flagged), [false, false, false, true]);
  assert.equal(card(verify, "prior_head").ok, false);
  assert.equal(card(verify, "chain").ok, true); // the recomputed links pass
});

test("real: M13 (event after the closing event) is invalid with the verifier's position message", () => {
  const { proof, verify } = SAMPLES.m13;
  assert.equal(badgeOf(verify).tone, "invalid");
  const violation = positionViolation(verify);
  assert.equal(violation.message, verify.reason);
  assert.match(violation.message, /closing event/);
  assert.deepEqual(violation.sequences, [3]);
  const rows = eventRows(proof.events, verify);
  assert.deepEqual(rows.map((r) => [r.type, r.positionViolation, r.flagged]), [
    ["request.created", false, false],
    ["proof.completed", false, false],
    ["agent.started", true, true],
  ]);
  // Every per-event check passes; only the position rule explains "Invalid".
  assert.ok(evidenceChecks(verify).every((c) => !c.applies || c.ok === true));
});

test("real: closing event removed but status completed: Valid badge and a conflict warning", () => {
  const { proof, verify } = SAMPLES.truncated;
  assert.equal(proof.status, "completed");
  assert.equal(verify.closed, false);
  assert.deepEqual(badgeOf(verify), { tone: "valid", label: "Valid", detail: null });
  const closure = closureView(proof.status, verify);
  assert.equal(closure.closedLabel, "No");
  assert.match(closure.warning, /says Completed, but the verified chain has no closing event/);
  assert.match(closure.warning, /cut short/);
  assert.match(closure.warning, /unsigned database field/);
  // D-C9: display only. verdictBadge takes no status, so the badge above is
  // the verifier's verdict regardless of the warning.
});

test("real: v3 and v2 proofs show their format, the chain-head limit, and prior_head not applicable", () => {
  for (const [name, label, legacy] of [["v3", "Format: v3", false], ["v2", "Format: legacy v2", true]]) {
    const { verify } = SAMPLES[name];
    const format = proofFormat(verify);
    assert.equal(format.label, label);
    assert.equal(format.legacy, legacy);
    assert.ok(format.note.includes(NO_CHAIN_HEAD_NOTE), name);
    if (legacy) assert.ok(format.note.startsWith(LEGACY_FORMAT_NOTE));
    assert.deepEqual(priorHeadStates(SAMPLES[name]).map(([, state]) => state), ["not-applicable", "not-applicable"]);
    assert.equal(card(verify, "prior_head").applies, false);
    assert.equal(summaryTone(card(verify, "prior_head"), "valid"), "not-applicable");
    assert.equal(badgeOf(verify).tone, "valid", name);
  }
});

// --- prior_head_valid rules on synthetic responses -------------------------------------

function v4Check(sequence, type, overrides = {}) {
  return {
    sequence,
    type,
    sequence_valid: true,
    chain_valid: true,
    payload_hash_valid: true,
    canonical_valid: true,
    signature_valid: true,
    request_binding_valid: type === "request.created" ? true : null,
    format_valid: true,
    replay_valid: true,
    prior_head_valid: type === "request.created" ? null : true,
    actor_authorized: true,
    authorization_reason: null,
    role: "creator",
    ...overrides,
  };
}

const V4 = {
  proof_version: "4",
  verdict: "valid",
  closed: true,
  chain_head: "a".repeat(64),
  event_count: 3,
  checks: [v4Check(1, "request.created"), v4Check(2, "agent.started"), v4Check(3, "proof.completed")],
};
const v4With = (sequence, overrides, base = V4) => ({
  ...base,
  checks: base.checks.map((c) => (c.sequence === sequence ? { ...c, ...overrides } : c)),
});

test("synthetic: the v4 baseline is valid", () => {
  assert.equal(badgeOf(V4).tone, "valid");
});

const NEVER_VALID_V4 = {
  "prior_head_valid false on a v4 event": v4With(2, { prior_head_valid: false }),
  "prior_head_valid null on a v4 event": v4With(2, { prior_head_valid: null }),
  "prior_head_valid missing on a v4 event": v4With(2, { prior_head_valid: undefined }),
  "prior_head_valid a string on a v4 event": v4With(3, { prior_head_valid: "true" }),
  "prior_head_valid false on request.created": v4With(1, { prior_head_valid: false }),
  "no proof_version and no prior_head_valid": {
    ...V4,
    proof_version: undefined,
    checks: V4.checks.map((c) => ({ ...c, prior_head_valid: undefined })),
  },
  "a v3 event reporting prior_head_valid false": { ...v4With(2, { prior_head_valid: false }), proof_version: "3" },
  // An API that does not enforce the position rule (older than §8 B) would
  // say valid; the dashboard must not.
  "valid but an event after the closing event": {
    ...V4,
    checks: [...V4.checks, v4Check(4, "agent.started")],
  },
  "valid but two closing events": {
    ...V4,
    checks: [...V4.checks, v4Check(4, "proof.failed")],
  },
  "verdict invalid with a position reason": {
    ...V4,
    verdict: "invalid",
    reason: "A closing event (proof.completed or proof.failed) is not the last event, or there is more than one.",
    checks: [...V4.checks, v4Check(4, "agent.started")],
  },
};

for (const [name, data] of Object.entries(NEVER_VALID_V4)) {
  test(`synthetic: badge is never valid for: ${name}`, () => {
    const badge = badgeOf(data);
    assert.notEqual(badge.tone, "valid");
    assert.notEqual(badge.label, "Valid");
  });
}

test("synthetic: per-event prior_head states by version and event type", () => {
  const state = (data, sequence) =>
    eventRows(data.checks.map((c) => ({ sequence: c.sequence, type: c.type })), data)
      .find((row) => row.sequence === sequence)
      .checks.find((c) => c.key === "prior_head").state;
  assert.equal(state(V4, 1), "not-applicable");
  assert.equal(state(V4, 2), "pass");
  assert.equal(state(v4With(2, { prior_head_valid: false }), 2), "fail");
  assert.equal(state(v4With(2, { prior_head_valid: null }), 2), "not-available");
  assert.equal(state(v4With(2, { prior_head_valid: undefined }), 2), "not-available");
  const v3 = { ...v4With(2, { prior_head_valid: null }), proof_version: "3" };
  assert.equal(state(v3, 2), "not-applicable");
  assert.equal(state({ ...v4With(2, { prior_head_valid: false }), proof_version: "2" }, 2), "fail");
});

test("synthetic: the position rule flags every event after the first closing event", () => {
  const data = { ...V4, checks: [...V4.checks, v4Check(4, "proof.failed"), v4Check(5, "agent.started")] };
  const violation = positionViolation(data);
  assert.deepEqual(violation.sequences, [4, 5]);
  assert.match(violation.message, /not the last event/); // own text when /verify gives no reason
  assert.equal(positionViolation(V4), null);
  assert.equal(positionViolation({ ...V4, checks: V4.checks.slice(0, 2) }), null); // open proof
  assert.equal(positionViolation(null), null);
});

test("synthetic: verifier reason", () => {
  assert.equal(verifyReason({ reason: "Missing or unsupported proof version." }), "Missing or unsupported proof version.");
  for (const data of [null, {}, { reason: "" }, { reason: 3 }]) {
    assert.equal(verifyReason(data), null, JSON.stringify(data));
  }
});

// --- lifecycle status next to the closing event ------------------------------------------

test("closure: a disagreement between status and closing event warns, agreement does not", () => {
  const warn = (status, closed) => closureView(status, { closed }).warning;
  assert.match(warn("completed", false), /says Completed, but the verified chain has no closing event/);
  assert.match(warn("failed", false), /says Failed/);
  assert.match(warn("active", true), /has a closing event, but the server record says Active/);
  assert.match(warn("pending", true), /says Pending/);
  for (const [status, closed] of [["completed", true], ["failed", true], ["active", false], ["pending", false]]) {
    assert.equal(warn(status, closed), null, `${status}/${closed}`);
  }
});

test("closure: without a closed field nothing is claimed", () => {
  for (const data of [null, {}, { closed: "yes" }]) {
    const view = closureView("completed", data);
    assert.equal(view.closed, null);
    assert.equal(view.closedLabel, "Not available");
    assert.equal(view.warning, null);
  }
  assert.equal(closureView(undefined, { closed: false }).statusLabel, "Unknown");
});

test("status tooltip says server record, not verified", () => {
  assert.match(STATUS_TOOLTIP, /server record/);
  assert.match(STATUS_TOOLTIP, /not verified/);
});

// --- chain head ------------------------------------------------------------------------

test("chain head view and the expect-head command", () => {
  const head = "0123456789abcdef".repeat(4);
  const view = chainHeadView({ chain_head: head, event_count: 7 });
  assert.equal(view.head, head);
  assert.equal(view.headShort, "0123456789ab…abcdef");
  assert.equal(view.eventCount, 7);
  assert.equal(expectHeadCommand(head), `python -m app.verifier proof.json --expect-head ${head}`);
  for (const data of [null, {}, { chain_head: null }, { chain_head: "" }]) {
    assert.deepEqual(chainHeadView(data), { head: null, headShort: "—", eventCount: null });
  }
  assert.equal(expectHeadCommand(null), "python -m app.verifier proof.json --expect-head <chain_head>");
  assert.match(CHAIN_HEAD_NOTE.keep, /outside this service/);
  assert.match(CHAIN_HEAD_NOTE.limit, /closing event included, is not detected/);
  assert.match(CHAIN_HEAD_NOTE.limit, /signed event the API rejected/);
});
