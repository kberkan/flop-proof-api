// Run with: npm test (node --test; see proxy-policy.test.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";

import { HEALTH_PATH, apiStatusBadge, checkHealth } from "./api-status.ts";

// GET /health body as returned by app/main.py.
const HEALTH = { status: "ok", service: "flop-proof-api" };

// --- badge: nothing but 200 with the expected body is operational -------------

const NEVER_OPERATIONAL = {
  checking: { kind: "checking" },
  "network error": { kind: "network-error", message: "Failed to fetch" },
  timeout: { kind: "timeout", timeoutMs: 5000 },
  "HTTP 500 (proxy cannot reach the API)": { kind: "response", status: 500, body: { detail: "x" } },
  "HTTP 502": { kind: "response", status: 502, body: undefined },
  "HTTP 503": { kind: "response", status: 503, body: HEALTH },
  "HTTP 404": { kind: "response", status: 404, body: { detail: "Not found" } },
  "HTTP 401": { kind: "response", status: 401, body: HEALTH },
  "HTTP 204": { kind: "response", status: 204, body: undefined },
  "200 without body": { kind: "response", status: 200, body: undefined },
  "200 null body": { kind: "response", status: 200, body: null },
  "200 empty object": { kind: "response", status: 200, body: {} },
  "200 string body": { kind: "response", status: 200, body: "ok" },
  "200 array body": { kind: "response", status: 200, body: [HEALTH] },
  "200 status not ok": { kind: "response", status: 200, body: { ...HEALTH, status: "degraded" } },
  "200 status OK uppercase": { kind: "response", status: 200, body: { ...HEALTH, status: "OK" } },
  "200 wrong service": { kind: "response", status: 200, body: { ...HEALTH, service: "other" } },
  "200 status missing": { kind: "response", status: 200, body: { service: HEALTH.service } },
  "unknown state": { kind: "something-else" },
};

for (const [name, check] of Object.entries(NEVER_OPERATIONAL)) {
  test(`badge is never operational for: ${name}`, () => {
    const badge = apiStatusBadge(check);
    assert.notEqual(badge.status, "operational");
    assert.doesNotMatch(badge.label, /operational/i);
  });
}

test("badge is operational only for 200 with the expected body", () => {
  assert.deepEqual(apiStatusBadge({ kind: "response", status: 200, body: HEALTH }), {
    status: "operational",
    label: "API operational",
    detail: null,
  });
});

test("badge states and labels", () => {
  assert.deepEqual(apiStatusBadge({ kind: "checking" }), {
    status: "checking",
    label: "Checking API…",
    detail: null,
  });
  assert.deepEqual(apiStatusBadge({ kind: "timeout", timeoutMs: 5000 }), {
    status: "unreachable",
    label: "API unreachable",
    detail: "No answer within 5 s",
  });
  assert.equal(apiStatusBadge({ kind: "network-error", message: "Failed to fetch" }).status, "unreachable");
  assert.deepEqual(apiStatusBadge({ kind: "response", status: 500, body: undefined }), {
    status: "error",
    label: "API unavailable",
    detail: "HTTP 500",
  });
  assert.equal(
    apiStatusBadge({ kind: "response", status: 200, body: {} }).detail,
    "Unexpected health response",
  );
});

// --- checkHealth: what each fetch outcome becomes ------------------------------

const jsonResponse = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

test("checkHealth requests the proxied health path once, uncached, with a signal", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push([url, init]);
    return jsonResponse(200, HEALTH);
  };

  assert.deepEqual(await checkHealth(fetchImpl), { kind: "response", status: 200, body: HEALTH });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], HEALTH_PATH);
  assert.equal(HEALTH_PATH, "/api/flop/health");
  assert.equal(calls[0][1].cache, "no-store");
  assert.ok(calls[0][1].signal instanceof AbortSignal);
});

test("checkHealth reports HTTP errors and non-JSON bodies as responses", async () => {
  const error = await checkHealth(async () => jsonResponse(500, { detail: "x" }));
  assert.deepEqual(error, { kind: "response", status: 500, body: { detail: "x" } });

  const html = await checkHealth(async () => new Response("<html>", { status: 200 }));
  assert.deepEqual(html, { kind: "response", status: 200, body: undefined });
  assert.notEqual(apiStatusBadge(html).status, "operational");
});

test("checkHealth reports a network error", async () => {
  const result = await checkHealth(async () => {
    throw new TypeError("Failed to fetch");
  });
  assert.deepEqual(result, { kind: "network-error", message: "Failed to fetch" });
  assert.equal(apiStatusBadge(result).status, "unreachable");
});

test("checkHealth gives up after the timeout", async () => {
  const neverAnswers = (url, init) =>
    new Promise((resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    });

  const started = Date.now();
  const result = await checkHealth(neverAnswers, 50);

  assert.deepEqual(result, { kind: "timeout", timeoutMs: 50 });
  assert.ok(Date.now() - started < 2000);
  assert.equal(apiStatusBadge(result).status, "unreachable");
});
