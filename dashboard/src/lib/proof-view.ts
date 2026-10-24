// Pure display logic for proof pages. Turns API data (GET /proofs/{id} and
// GET /proofs/{id}/verify) into labels and states. No React, no fetch, so it
// can be tested with `node --test`.
//
// Rule: nothing here may produce a "valid" result unless the /verify response
// says so and every reported check agrees. Proof status is a lifecycle state,
// never a verification result.

export type VerifyState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "result"; data: unknown };

export type VerdictTone = "valid" | "invalid" | "unknown";

export type VerdictBadge = {
  tone: VerdictTone;
  label: string;
  detail: string | null;
};

export type CheckKey =
  | "signatures"
  | "canonical"
  | "payload"
  | "chain"
  | "authorization"
  | "request_binding"
  | "format"
  | "replay"
  | "prior_head";

export type CheckSummary = {
  key: CheckKey;
  label: string;
  ok: boolean | null; // null: not reported or no verify result
  // false: the check applies to no event of this proof (e.g. the signed chain
  // head on a v1–v3 proof). Such a check neither passes nor blocks "Valid".
  applies: boolean;
};

/** One check on one event. "not-applicable": the check does not apply to
 * this event type; "not-available": it applies but was not reported. */
export type CheckState = "pass" | "fail" | "not-applicable" | "not-available";

export type EventCheck = {
  key: CheckKey;
  label: string;
  state: CheckState;
};

export type ProofFormat = {
  version: string | null;
  label: string;
  legacy: boolean;
  note: string | null;
};

export type CardTone = "pass" | "pass-muted" | "fail" | "unknown" | "not-applicable";

export type Role = "creator" | "delegate" | "unauthorized" | "unknown";

export type EventRow = {
  index: number;
  sequence: number | null;
  type: string;
  actorDid: string | null;
  actorShort: string;
  role: Role;
  roleLabel: string;
  authorized: boolean | null;
  authorizationReason: string | null;
  nonce: string | null;
  nonceShort: string;
  checks: EventCheck[];
  // The event breaks the closing-event position rule (D-C7): it follows a
  // closing event, or it is a second closing event.
  positionViolation: boolean;
  flagged: boolean;
};

export type EvidenceSummary = {
  evidenceClass: string | null;
  executionVerified: boolean | null;
  runtimeSettled: boolean | null;
};

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function checksOf(data: unknown): Json[] | null {
  if (!isObject(data) || !Array.isArray(data.checks) || data.checks.length === 0) {
    return null;
  }
  return data.checks.every(isObject) ? (data.checks as Json[]) : null;
}

// Where each per-event field of GET /proofs/{id}/verify is required. This is
// the one place these rules live; it follows app/verification_core.py, which
// reports every field below for every event, except request_binding_valid
// (a boolean for request.created, null for every other event type) and
// prior_head_valid (a boolean for version-4 events after request.created,
// null for request.created and for every event of a v1–v3 proof; checked
// against real /verify responses in fixtures/verify-samples.json).
//   "every-event":     must be a boolean on every event.
//   "request-created": must be a boolean on request.created events; on other
//                      events null (or absent) means "not applicable" and does
//                      not count, while false still fails.
//   "v4-after-request": must be a boolean on every non-request.created event
//                      unless the proof is version 1, 2 or 3; there, and on
//                      request.created, it is "not applicable" (false still
//                      fails). An unknown or missing proof_version counts as
//                      version 4, so a missing field can never pass.
type FieldScope = "every-event" | "request-created" | "v4-after-request";

const PRE_V4_VERSIONS = new Set(["1", "2", "3"]);

const CHECK_FIELDS: {
  key: CheckKey;
  label: string;
  fields: string[];
  scope: FieldScope;
  perEvent: boolean; // shown per event in the event list
}[] = [
  { key: "signatures", label: "Ed25519 signatures", fields: ["signature_valid"], scope: "every-event", perEvent: false },
  { key: "canonical", label: "Canonical messages", fields: ["canonical_valid"], scope: "every-event", perEvent: false },
  { key: "payload", label: "Payload hashes", fields: ["payload_hash_valid"], scope: "every-event", perEvent: false },
  { key: "chain", label: "Event numbering and links", fields: ["sequence_valid", "chain_valid"], scope: "every-event", perEvent: false },
  { key: "authorization", label: "Actor authorization", fields: ["actor_authorized"], scope: "every-event", perEvent: false },
  { key: "request_binding", label: "Request binding", fields: ["request_binding_valid"], scope: "request-created", perEvent: true },
  { key: "format", label: "Message format", fields: ["format_valid"], scope: "every-event", perEvent: true },
  { key: "replay", label: "No replayed events", fields: ["replay_valid"], scope: "every-event", perEvent: true },
  { key: "prior_head", label: "Signed chain head", fields: ["prior_head_valid"], scope: "v4-after-request", perEvent: true },
];

function versionOf(data: unknown): string | null {
  return isObject(data) && typeof data.proof_version === "string" ? data.proof_version : null;
}

function scopeApplies(check: Json, scope: FieldScope, version: string | null): boolean {
  if (scope === "every-event") return true;
  if (scope === "request-created") return check.type === "request.created";
  return check.type !== "request.created" && !(version !== null && PRE_V4_VERSIONS.has(version));
}

function fieldState(check: Json, field: string, scope: FieldScope, version: string | null): CheckState {
  const value = check[field];
  const applies = scopeApplies(check, scope, version);
  if (!applies) {
    // A false outside the event type the check is for still fails.
    return value === false ? "fail" : "not-applicable";
  }
  if (typeof value !== "boolean") return "not-available";
  return value ? "pass" : "fail";
}

function combine(states: CheckState[]): CheckState {
  if (states.includes("fail")) return "fail";
  if (states.includes("not-available")) return "not-available";
  if (states.includes("pass")) return "pass";
  return states.length === 0 ? "not-available" : "not-applicable";
}

function checkState(check: Json, fields: string[], scope: FieldScope, version: string | null): CheckState {
  return combine(fields.map((field) => fieldState(check, field, scope, version)));
}

/** One entry per check family. ok is true only if every event the check
 * applies to reports true, and at least one event does; null if any of them
 * did not report it, or if no event applies (e.g. no request.created).
 * applies is false only for the signed chain head when no event of the proof
 * needs one (a v1–v3 proof, or a v4 proof with only request.created). */
export function evidenceChecks(data: unknown): CheckSummary[] {
  const checks = checksOf(data);
  const version = versionOf(data);

  return CHECK_FIELDS.map(({ key, label, fields, scope }) => {
    if (checks === null) {
      return { key, label, ok: null, applies: true };
    }
    const states = checks.map((check) => checkState(check, fields, scope, version));
    if (scope === "v4-after-request" && states.every((value) => value === "not-applicable")) {
      return { key, label, ok: null, applies: false };
    }
    const state = combine(states.filter((value) => value !== "not-applicable"));
    return { key, label, ok: state === "pass" ? true : state === "fail" ? false : null, applies: true };
  });
}

/** The per-event checks shown in the event list, for one /verify check.
 * proofVersion is the /verify proof_version (null if unknown). */
export function eventChecks(check: Json | undefined, proofVersion: string | null = null): EventCheck[] {
  return CHECK_FIELDS.filter((family) => family.perEvent).map(({ key, label, fields, scope }) => ({
    key,
    label,
    state: check === undefined ? "not-available" : checkState(check, fields, scope, proofVersion),
  }));
}

const CLOSING_EVENT_TYPES = new Set(["proof.completed", "proof.failed"]);

export type PositionViolation = {
  message: string;
  sequences: number[]; // the events that break the rule
};

/** D-C7, every version: at most one closing event, and it is the last event.
 * Read from the /verify checks (their types and order). The message is the
 * /verify reason when it gives one. null if the rule holds or there are no
 * checks. */
export function positionViolation(data: unknown): PositionViolation | null {
  const checks = checksOf(data);
  if (checks === null) return null;
  const first = checks.findIndex((check) => CLOSING_EVENT_TYPES.has(String(check.type)));
  if (first === -1 || first === checks.length - 1) return null;
  const sequences = checks
    .slice(first + 1)
    .map((check) => (typeof check.sequence === "number" ? check.sequence : null))
    .filter((sequence): sequence is number => sequence !== null);
  const reason = isObject(data) && typeof data.reason === "string" ? data.reason : null;
  return {
    message:
      reason ??
      "A closing event (proof.completed or proof.failed) is not the last event, or there is more than one.",
    sequences,
  };
}

/** The top-level /verify reason (why a proof is invalid when no single check
 * says so, or why it could not be checked), or null. */
export function verifyReason(data: unknown): string | null {
  return isObject(data) && typeof data.reason === "string" && data.reason !== "" ? data.reason : null;
}

export function checkStateLabel(state: CheckState): string {
  return {
    pass: "Pass",
    fail: "Fail",
    "not-applicable": "Not applicable",
    "not-available": "Not available",
  }[state];
}

// Wording follows PARITY.md, Known Security Gaps ("Event nonce is not part of
// the signed message").
export const LEGACY_FORMAT_NOTE =
  "Version 1/2 proofs keep the old message formats: an event's nonce is not part of " +
  "the signed message, so replay protection rests on rejecting a repeated " +
  "(canonical, signature) pair within the proof.";

// Wording follows README "What it does not verify" and PARITY.md ("Export
// events can be removed or reordered and re-linked …", open for v1–v3).
export const NO_CHAIN_HEAD_NOTE =
  "Events of version 1–3 proofs sign no chain head: events removed from such a proof, " +
  "or put in another order, with the links recomputed, are not detected.";

/** The proof's message format, from the /verify proof_version field. */
export function proofFormat(data: unknown): ProofFormat {
  const version = versionOf(data);
  if (version === "4") {
    return { version, label: "Format: v4", legacy: false, note: null };
  }
  if (version === "3") {
    return { version, label: "Format: v3", legacy: false, note: NO_CHAIN_HEAD_NOTE };
  }
  if (version === "1" || version === "2") {
    return {
      version,
      label: `Format: legacy v${version}`,
      legacy: true,
      note: `${LEGACY_FORMAT_NOTE} ${NO_CHAIN_HEAD_NOTE}`,
    };
  }
  return { version, label: "Format: unknown", legacy: false, note: null };
}

export function verdictBadge(state: VerifyState): VerdictBadge {
  if (state.kind === "loading") {
    return { tone: "unknown", label: "Verifying…", detail: null };
  }
  if (state.kind === "error") {
    return { tone: "unknown", label: "Could not verify", detail: state.message };
  }

  const data = state.data;
  const verdict = isObject(data) ? data.verdict : undefined;

  if (verdict === "invalid") {
    return { tone: "invalid", label: "Invalid", detail: null };
  }
  if (verdict === "valid") {
    const consistent =
      evidenceChecks(data).every((check) => !check.applies || check.ok === true) &&
      positionViolation(data) === null;
    return consistent
      ? { tone: "valid", label: "Valid", detail: null }
      : {
          tone: "unknown",
          label: "Could not verify",
          detail: "The verify response reports valid but its checks do not all pass.",
        };
  }
  return { tone: "unknown", label: "Could not verify", detail: "Unexpected verify response." };
}

/** A passing check is only shown as a green pass when the verdict is valid. */
export function cardTone(ok: boolean | null, verdict: VerdictTone): CardTone {
  if (ok === null) return "unknown";
  if (!ok) return "fail";
  return verdict === "valid" ? "pass" : "pass-muted";
}

/** cardTone for a check summary; a check that applies to no event is
 * "not-applicable", never a pass. */
export function summaryTone(check: CheckSummary, verdict: VerdictTone): CardTone {
  return check.applies ? cardTone(check.ok, verdict) : "not-applicable";
}

export type ClosureView = {
  statusLabel: string; // lifecycle status from the server record
  closed: boolean | null; // a closing event in the verified chain; null: not reported
  closedLabel: string;
  warning: string | null;
};

const CLOSED_STATUSES = new Set(["completed", "failed"]);

/** The server's lifecycle status next to the verified chain's closing event
 * (D-C6, D-C9). The status is an unsigned database field; closed is what
 * /verify found in the chain. A disagreement is shown as a warning and never
 * changes the verdict. */
export function closureView(status: unknown, verifyData: unknown): ClosureView {
  const closed = isObject(verifyData) && typeof verifyData.closed === "boolean" ? verifyData.closed : null;
  const label = statusLabel(status);
  let warning: string | null = null;
  if (closed === false && typeof status === "string" && CLOSED_STATUSES.has(status)) {
    warning =
      `The server record says ${label}, but the verified chain has no closing event ` +
      "(proof.completed or proof.failed). The chain may have been cut short. The status " +
      "is an unsigned database field and is not part of the verification.";
  } else if (closed === true && typeof status === "string" && !CLOSED_STATUSES.has(status)) {
    warning =
      `The verified chain has a closing event, but the server record says ${label}. ` +
      "The status is an unsigned database field and is not part of the verification.";
  }
  return {
    statusLabel: label,
    closed,
    closedLabel: closed === null ? "Not available" : closed ? "Yes" : "No",
    warning,
  };
}

export type ChainHeadView = {
  head: string | null;
  headShort: string;
  eventCount: number | null;
};

/** chain_head and event_count from /verify, for display (D-C5, D-C6). */
export function chainHeadView(verifyData: unknown): ChainHeadView {
  const head =
    isObject(verifyData) && typeof verifyData.chain_head === "string" && verifyData.chain_head !== ""
      ? verifyData.chain_head
      : null;
  const count =
    isObject(verifyData) && typeof verifyData.event_count === "number" ? verifyData.event_count : null;
  return {
    head,
    headShort: head === null ? "—" : head.length > 20 ? `${head.slice(0, 12)}…${head.slice(-6)}` : head,
    eventCount: count,
  };
}

// Wording follows README "What it does not verify" and docs/design/proof-closure.md
// §3.5, D-C8, D-C10. Shown as: keep, then the command, then limit.
export const CHAIN_HEAD_NOTE = {
  keep:
    "To check later that this proof was not cut short, keep this chain head (or the event " +
    "count) outside this service and check an export with",
  limit:
    "Without such a record, removing the last events, the closing event included, is not " +
    "detected; nor is ending the chain at a signed event the API rejected.",
};

export function expectHeadCommand(head: string | null): string {
  return `python -m app.verifier proof.json --expect-head ${head ?? "<chain_head>"}`;
}

const STATUS_LABELS: Record<string, string> = {
  pending: "Pending",
  active: "Active",
  completed: "Completed",
  failed: "Failed",
};

/** Tooltip for lifecycle status labels in lists (D-C9): the status is the
 * server's unsigned record, not a verification result. */
export const STATUS_TOOLTIP = "Lifecycle status from the server record; not verified.";

/** Lifecycle status as neutral text. Never a verification word. */
export function statusLabel(status: unknown): string {
  return typeof status === "string" && status in STATUS_LABELS
    ? STATUS_LABELS[status]
    : "Unknown";
}

export function roleLabel(role: Role): string {
  return {
    creator: "Creator",
    delegate: "Delegate",
    unauthorized: "Unauthorized",
    unknown: "Unknown",
  }[role];
}

export function shortDid(did: string): string {
  return did.length > 28 ? `${did.slice(0, 16)}…${did.slice(-6)}` : did;
}

/** Nonce for display; the full value goes in a title attribute. v1/v2
 * request.created rows store an empty nonce. */
export function shortNonce(nonce: string | null): string {
  if (nonce === null) return "—";
  if (nonce === "") return "(none)";
  return nonce.length > 24 ? `${nonce.slice(0, 12)}…${nonce.slice(-6)}` : nonce;
}

function asRole(value: unknown): Role {
  return value === "creator" || value === "delegate" || value === "unauthorized"
    ? value
    : "unknown";
}

/** Events from GET /proofs/{id}, joined with /verify checks by sequence. */
export function eventRows(events: unknown, verifyData: unknown): EventRow[] {
  if (!Array.isArray(events)) {
    return [];
  }
  const bySequence = new Map<unknown, Json>();
  for (const check of checksOf(verifyData) ?? []) {
    bySequence.set(check.sequence, check);
  }
  const version = versionOf(verifyData);
  const outOfPlace = new Set(positionViolation(verifyData)?.sequences ?? []);

  return events.map((raw, index) => {
    const event = isObject(raw) ? raw : {};
    const sequence = typeof event.sequence === "number" ? event.sequence : null;
    const check = sequence === null ? undefined : bySequence.get(sequence);
    const actorDid = typeof event.actor_did === "string" ? event.actor_did : null;
    const role = asRole(check?.role);
    const authorized =
      typeof check?.actor_authorized === "boolean" ? check.actor_authorized : null;
    const reason =
      typeof check?.authorization_reason === "string" ? check.authorization_reason : null;
    const nonce = typeof event.nonce === "string" ? event.nonce : null;
    const checks = eventChecks(check, version);
    const positionBroken = sequence !== null && outOfPlace.has(sequence);

    return {
      index,
      sequence,
      type: typeof event.type === "string" ? event.type : `Event ${index + 1}`,
      actorDid,
      actorShort: actorDid === null ? "—" : shortDid(actorDid),
      role,
      roleLabel: roleLabel(role),
      authorized,
      authorizationReason: authorized === false ? reason : null,
      nonce,
      nonceShort: shortNonce(nonce),
      checks,
      positionViolation: positionBroken,
      flagged: authorized === false || positionBroken || checks.some((item) => item.state === "fail"),
    };
  });
}

export function evidenceSummary(data: unknown): EvidenceSummary {
  const evidence = isObject(data) && isObject(data.evidence) ? data.evidence : {};
  return {
    evidenceClass: typeof evidence.class === "string" ? evidence.class : null,
    executionVerified:
      typeof evidence.execution_verified === "boolean" ? evidence.execution_verified : null,
    runtimeSettled:
      typeof evidence.runtime_settled === "boolean" ? evidence.runtime_settled : null,
  };
}
