// Run with: npm test (node --test; see proxy-policy.test.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";

import { formatTimestamp } from "./timestamp.ts";

const ISTANBUL = "Europe/Istanbul"; // UTC+3, no DST
const NEW_YORK = "America/New_York"; // UTC-4 in October

test("a value with Z is shown in local time with its offset", () => {
  assert.deepEqual(formatTimestamp("2026-10-08T20:19:48.008Z", ISTANBUL), {
    text: "08.10.2026 23:19:48 GMT+3",
    iso: "2026-10-08T20:19:48.008Z",
  });
});

test("a value with +00:00 is the same instant", () => {
  assert.deepEqual(formatTimestamp("2026-10-08T20:19:48.008071+00:00", ISTANBUL), {
    text: "08.10.2026 23:19:48 GMT+3",
    iso: "2026-10-08T20:19:48.008071Z",
  });
});

test("a value without an offset, as the API sends it, is read as UTC", () => {
  assert.deepEqual(formatTimestamp("2026-10-08T20:19:48.008071", ISTANBUL), {
    text: "08.10.2026 23:19:48 GMT+3",
    iso: "2026-10-08T20:19:48.008071Z",
  });
  // SQLite's own spelling, with a space, is the same instant.
  assert.equal(formatTimestamp("2026-10-08 20:19:48", ISTANBUL).iso, "2026-10-08T20:19:48Z");
});

test("another time zone shows the same instant at its own offset", () => {
  assert.deepEqual(formatTimestamp("2026-10-08T20:19:48.008071", NEW_YORK), {
    text: "08.10.2026 16:19:48 GMT-4",
    iso: "2026-10-08T20:19:48.008071Z",
  });
  assert.equal(formatTimestamp("2026-10-08T20:19:48", "UTC").text, "08.10.2026 20:19:48 GMT");
});

test("a non-UTC offset in the value is applied, across midnight", () => {
  assert.deepEqual(formatTimestamp("2026-10-09T01:30:00+05:30", "UTC"), {
    text: "08.10.2026 20:00:00 GMT",
    iso: "2026-10-08T20:00:00Z",
  });
});

for (const value of [
  undefined,
  null,
  "",
  42,
  "not a date",
  "2026-10-08",
  "2026-02-30T12:00:00", // rolls over to March in Date.UTC
  "2026-13-01T00:00:00Z",
  "2026-10-08T24:00:00Z",
  "2026-10-08T20:19:48+25:00",
  "1759954788",
]) {
  test(`unreadable value shows a dash, never a time: ${JSON.stringify(value)}`, () => {
    assert.deepEqual(formatTimestamp(value, ISTANBUL), { text: "—", iso: null });
  });
}
