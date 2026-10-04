// API status badge for the Developer page. Pure apart from the injected fetch,
// so it can be tested with `node --test`.
//
// Rule: the badge is "operational" (green) only when GET /health answers 200
// with the body the API sends (app/main.py: {"status": "ok", "service":
// "flop-proof-api"}). Anything else, including a still-running check, is not
// green.

export const HEALTH_PATH = "/api/flop/health";
export const HEALTH_TIMEOUT_MS = 5000;

export type HealthCheck =
  | { kind: "checking" }
  | { kind: "response"; status: number; body: unknown }
  | { kind: "network-error"; message: string }
  | { kind: "timeout"; timeoutMs: number };

export type ApiStatus = "checking" | "operational" | "unreachable" | "error";

export type ApiStatusBadge = {
  status: ApiStatus;
  label: string;
  detail: string | null;
};

function isExpectedHealth(body: unknown): boolean {
  return (
    typeof body === "object" &&
    body !== null &&
    !Array.isArray(body) &&
    (body as Record<string, unknown>).status === "ok" &&
    (body as Record<string, unknown>).service === "flop-proof-api"
  );
}

export function apiStatusBadge(check: HealthCheck): ApiStatusBadge {
  switch (check.kind) {
    case "checking":
      return { status: "checking", label: "Checking API…", detail: null };
    case "timeout":
      return {
        status: "unreachable",
        label: "API unreachable",
        detail: `No answer within ${check.timeoutMs / 1000} s`,
      };
    case "network-error":
      return { status: "unreachable", label: "API unreachable", detail: check.message };
    case "response":
      if (check.status === 200 && isExpectedHealth(check.body)) {
        return { status: "operational", label: "API operational", detail: null };
      }
      // The dashboard proxy answers 500 when it cannot reach the API.
      return {
        status: "error",
        label: "API unavailable",
        detail: check.status === 200 ? "Unexpected health response" : `HTTP ${check.status}`,
      };
    default:
      return { status: "error", label: "API unavailable", detail: "Unknown check state" };
  }
}

/** One GET /health through the dashboard proxy, aborted after timeoutMs. */
export async function checkHealth(
  fetchImpl: typeof fetch,
  timeoutMs: number = HEALTH_TIMEOUT_MS,
): Promise<HealthCheck> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(HEALTH_PATH, {
      cache: "no-store",
      signal: controller.signal,
    });
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      if (controller.signal.aborted) throw new Error("aborted");
      body = undefined;
    }
    return { kind: "response", status: response.status, body };
  } catch (error) {
    if (controller.signal.aborted) {
      return { kind: "timeout", timeoutMs };
    }
    return {
      kind: "network-error",
      message: error instanceof Error ? error.message : "Request failed",
    };
  } finally {
    clearTimeout(timer);
  }
}
