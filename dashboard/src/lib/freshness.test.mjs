// Run with: npm test (node --test; see proxy-policy.test.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";

import { freshness } from "./freshness.ts";

test("only a successful last load is live", () => {
  assert.deepEqual(freshness("ok"), { live: true, label: "Live" });
});

for (const outcome of ["pending", "failed", undefined, "", "OK", "live"]) {
  test(`not live for: ${JSON.stringify(outcome)}`, () => {
    const result = freshness(outcome);
    assert.equal(result.live, false);
    assert.notEqual(result.label, "Live");
  });
}

test("neutral labels for pending and failed loads", () => {
  assert.equal(freshness("pending").label, "Loading…");
  assert.equal(freshness("failed").label, "Not updated");
});
