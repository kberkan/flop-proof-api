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
  | "replay";

export type CheckSummary = {
  key: CheckKey;
  label: string;
  ok: boolean | null; // null: not reported or no verify result
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

export type CardTone = "pass" | "pass-muted" | "fail" | "unknown";

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
// reports every field below for every event, except request_binding_valid:
// a boolean for request.created and null for every other event type.
//   "every-event":     must be a boolean on every event.
//   "request-created": must be a boolean on request.created events; on other
//                      events null (or absent) means "not applicable" and does
//                      not count, while false still fails.
type FieldScope = "every-event" | "request-created";

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
  { key: "chain", label: "Event chain (order and links)", fields: ["sequence_valid", "chain_valid"], scope: "every-event", perEvent: false },
  { key: "authorization", label: "Actor authorization", fields: ["actor_authorized"], scope: "every-event", perEvent: false },
  { key: "request_binding", label: "Request binding", fields: ["request_binding_valid"], scope: "request-created", perEvent: true },
  { key: "format", label: "Message format", fields: ["format_valid"], scope: "every-event", perEvent: true },
  { key: "replay", label: "No replayed events", fields: ["replay_valid"], scope: "every-event", perEvent: true },
];

function fieldState(check: Json, field: string, scope: FieldScope): CheckState {
  const value = check[field];
  const applies = scope === "every-event" || check.type === "request.created";
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

function checkState(check: Json, fields: string[], scope: FieldScope): CheckState {
  return combine(fields.map((field) => fieldState(check, field, scope)));
}

/** One entry per check family. ok is true only if every event the check
 * applies to reports true, and at least one event does; null if any of them
 * did not report it, or if no event applies (e.g. no request.created). */
export function evidenceChecks(data: unknown): CheckSummary[] {
  const checks = checksOf(data);

  return CHECK_FIELDS.map(({ key, label, fields, scope }) => {
    if (checks === null) {
      return { key, label, ok: null };
    }
    const state = combine(
      checks
        .map((check) => checkState(check, fields, scope))
        .filter((value) => value !== "not-applicable"),
    );
    return { key, label, ok: state === "pass" ? true : state === "fail" ? false : null };
  });
}

/** The per-event checks shown in the event list, for one /verify check. */
export function eventChecks(check: Json | undefined): EventCheck[] {
  return CHECK_FIELDS.filter((family) => family.perEvent).map(({ key, label, fields, scope }) => ({
    key,
    label,
    state: check === undefined ? "not-available" : checkState(check, fields, scope),
  }));
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

/** The proof's message format, from the /verify proof_version field. */
export function proofFormat(data: unknown): ProofFormat {
  const version = isObject(data) && typeof data.proof_version === "string" ? data.proof_version : null;
  if (version === "3") {
    return { version, label: "Format: v3", legacy: false, note: null };
  }
  if (version === "1" || version === "2") {
    return { version, label: `Format: legacy v${version}`, legacy: true, note: LEGACY_FORMAT_NOTE };
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
    const consistent = evidenceChecks(data).every((check) => check.ok === true);
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

const STATUS_LABELS: Record<string, string> = {
  pending: "Pending",
  active: "Active",
  completed: "Completed",
  failed: "Failed",
};

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
    const checks = eventChecks(check);

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
      flagged: authorized === false || checks.some((item) => item.state === "fail"),
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
