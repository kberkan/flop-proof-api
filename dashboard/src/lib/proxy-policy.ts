// Decides which dashboard requests the /api/flop proxy may forward to the
// FLOP Proof API. Pure and dependency-free so it can be tested with
// `node --test` (Node strips the type annotations).
//
// Only what the dashboard pages actually call is allowed:
//   GET proofs                (?limit=, ?status=)  src/app/page.tsx, proofs/page.tsx, verification/page.tsx
//   GET proofs/{proof_id}                          src/app/proofs/[proof_id]/page.tsx
//   GET proofs/{proof_id}/verify                   src/app/verification/page.tsx
//   GET actors                                     src/app/actors/page.tsx

export type ProxyDecision =
  | { allowed: true; path: string; search: string }
  | { allowed: false; status: 404 | 405 };

// proof_id as issued by POST /proofs: "proof_" + uuid4().hex (app/main.py).
const PROOF_ID = /^proof_[0-9a-f]{32}$/;

const PROOF_STATUSES = new Set(["pending", "active", "completed", "failed"]);

function proofsQuery(searchParams: URLSearchParams): string {
  const kept = new URLSearchParams();

  const limit = searchParams.get("limit");
  if (limit !== null && /^[0-9]{1,3}$/.test(limit)) {
    const value = Number(limit);
    if (value >= 1 && value <= 100) {
      kept.set("limit", String(value));
    }
  }

  const status = searchParams.get("status");
  if (status !== null && PROOF_STATUSES.has(status)) {
    kept.set("status", status);
  }

  const query = kept.toString();
  return query ? `?${query}` : "";
}

/**
 * pathSegments are the raw (still percent-encoded) segments after /api/flop,
 * e.g. ["proofs", "proof_<hex>", "verify"]. Any segment that is empty or
 * contains characters outside the expected pattern (".", "%", "/") is
 * rejected rather than decoded.
 */
export function evaluateProxyRequest(
  method: string,
  pathSegments: readonly string[],
  searchParams: URLSearchParams,
): ProxyDecision {
  if (method !== "GET") {
    return { allowed: false, status: 405 };
  }

  const [first, second, third, ...rest] = pathSegments;

  if (rest.length > 0) {
    return { allowed: false, status: 404 };
  }

  if (first === "actors" && pathSegments.length === 1) {
    return { allowed: true, path: "/actors", search: "" };
  }

  if (first !== "proofs") {
    return { allowed: false, status: 404 };
  }

  if (pathSegments.length === 1) {
    return { allowed: true, path: "/proofs", search: proofsQuery(searchParams) };
  }

  if (second === undefined || !PROOF_ID.test(second)) {
    return { allowed: false, status: 404 };
  }

  if (pathSegments.length === 2) {
    return { allowed: true, path: `/proofs/${second}`, search: "" };
  }

  if (third === "verify") {
    return { allowed: true, path: `/proofs/${second}/verify`, search: "" };
  }

  return { allowed: false, status: 404 };
}
