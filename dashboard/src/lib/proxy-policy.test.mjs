// Run with: npm test  (node --test; Node >= 22.18 strips the TypeScript types
// of the imported module, so no extra dependency is needed). This file is .mjs
// so `next build` does not type-check it.
import assert from "node:assert/strict";
import { test } from "node:test";

import { evaluateProxyRequest } from "./proxy-policy.ts";

const PROOF_ID = "proof_0123456789abcdef0123456789abcdef";
const params = (query = "") => new URLSearchParams(query);
const evaluate = (method, path, query) =>
  evaluateProxyRequest(method, path.split("/"), params(query));

const ALLOWED = [
  ["proofs", "/proofs"],
  [`proofs/${PROOF_ID}`, `/proofs/${PROOF_ID}`],
  [`proofs/${PROOF_ID}/verify`, `/proofs/${PROOF_ID}/verify`],
  ["actors", "/actors"],
  ["health", "/health"],
];

for (const [path, upstream] of ALLOWED) {
  test(`GET ${path} is forwarded to ${upstream}`, () => {
    assert.deepEqual(evaluate("GET", path), {
      allowed: true,
      path: upstream,
      search: "",
    });
  });

  for (const method of ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]) {
    test(`${method} ${path} is rejected with 405`, () => {
      assert.deepEqual(evaluate(method, path), { allowed: false, status: 405 });
    });
  }
}

const REJECTED_PATHS = {
  "dot segments": "proofs/../actors",
  "encoded dot segments": "proofs/%2e%2e",
  "encoded slash": `proofs/${PROOF_ID}%2fverify`,
  "too deep": "proofs/x/y/z",
  "empty proof_id": "proofs/",
  "empty path": "",
  "trailing slash on verify": `proofs/${PROOF_ID}/verify/`,
  "malformed proof_id": "proofs/proof_XYZ",
  "uppercase hex proof_id": `proofs/${PROOF_ID.toUpperCase()}`,
  "unknown sub-resource": `proofs/${PROOF_ID}/events`,
  "health sub-path": "health/x",
  "health trailing slash": "health/",
  "validator attestations": "validator-attestations/accept",
  "stark batches": "stark-batches",
  "actors sub-path": "actors/x",
};

for (const [name, path] of Object.entries(REJECTED_PATHS)) {
  test(`GET ${JSON.stringify(path)} (${name}) is rejected with 404`, () => {
    assert.deepEqual(evaluate("GET", path), { allowed: false, status: 404 });
  });
}

test("proofs keeps only valid limit and status", () => {
  assert.deepEqual(evaluate("GET", "proofs", "limit=100&status=completed"), {
    allowed: true,
    path: "/proofs",
    search: "?limit=100&status=completed",
  });
});

test("proofs drops unknown query parameters", () => {
  assert.deepEqual(evaluate("GET", "proofs", "limit=8&debug=1&api_key=x"), {
    allowed: true,
    path: "/proofs",
    search: "?limit=8",
  });
});

test("proofs drops out-of-range or malformed limit and unknown status", () => {
  for (const query of ["limit=0", "limit=101", "limit=1e2", "limit=-1", "status=all", "status=COMPLETED"]) {
    assert.equal(evaluate("GET", "proofs", query).search, "", query);
  }
});

test("detail, verify, actors and health drop every query parameter", () => {
  for (const path of [`proofs/${PROOF_ID}`, `proofs/${PROOF_ID}/verify`, "actors", "health"]) {
    assert.equal(evaluate("GET", path, "limit=8&status=active").search, "", path);
  }
});

test("health forwards no query parameter", () => {
  assert.deepEqual(evaluate("GET", "health", "debug=1&api_key=x"), {
    allowed: true,
    path: "/health",
    search: "",
  });
});
