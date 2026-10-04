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

export type CheckKey = "signatures" | "canonical" | "payload" | "chain" | "authorization";

export type CheckSummary = {
  key: CheckKey;
  label: string;
  ok: boolean | null; // null: not reported or no verify result
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

const CHECK_FIELDS: { key: CheckKey; label: string; fields: string[] }[] = [
  { key: "signatures", label: "Ed25519 signatures", fields: ["signature_valid"] },
  { key: "canonical", label: "Canonical messages", fields: ["canonical_valid"] },
  { key: "payload", label: "Payload hashes", fields: ["payload_hash_valid"] },
  { key: "chain", label: "Event chain (order and links)", fields: ["sequence_valid", "chain_valid"] },
  { key: "authorization", label: "Actor authorization", fields: ["actor_authorized"] },
];

/** One entry per check family; ok is true only if every event reports true. */
export function evidenceChecks(data: unknown): CheckSummary[] {
  const checks = checksOf(data);

  return CHECK_FIELDS.map(({ key, label, fields }) => {
    if (checks === null) {
      return { key, label, ok: null };
    }
    const values = checks.flatMap((check) => fields.map((field) => check[field]));
    if (!values.every((value) => typeof value === "boolean")) {
      return { key, label, ok: null };
    }
    return { key, label, ok: values.every((value) => value === true) };
  });
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
      flagged: authorized === false,
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
