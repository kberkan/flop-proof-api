// Display of API timestamps (created_at, updated_at).
//
// The API writes these as UTC but serializes them without an offset
// ("2026-10-08T20:19:48.008071"), and it cannot add one: an event's created_at
// string is part of the event-chain hash that /verify and the offline verifier
// recompute (app/crypto.py hash_event_record). JavaScript parses an ISO
// date-time without an offset as *local* time, so `new Date(value)` shifted
// every value by the viewer's UTC offset. Here a value without an offset is
// read as UTC; one with Z or ±HH:MM keeps its offset.

export type FormattedTimestamp = {
  /** Local time with its UTC offset, e.g. "08.10.2026 23:19:48 GMT+3"; "—" if unreadable. */
  text: string;
  /** The same instant as UTC ISO 8601 with Z, e.g. "2026-10-08T20:19:48.008071Z"; null if unreadable. */
  iso: string | null;
};

const ISO =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})?$/;

type Parsed = { epochMs: number; fraction: string };

/** The instant of an API timestamp, or null when the value is not one. Never guesses. */
function parse(value: unknown): Parsed | null {
  if (typeof value !== "string") return null;
  const match = ISO.exec(value.trim());
  if (!match) return null;
  const [, y, mo, d, h, mi, s, fraction = "", offset = "Z"] = match;
  const [year, month, day, hour, minute, second] = [y, mo, d, h, mi, s].map(Number);
  const ms = Number(fraction.slice(0, 3).padEnd(3, "0"));

  const wall = Date.UTC(year, month - 1, day, hour, minute, second, ms);
  const check = new Date(wall);
  // Date.UTC rolls 2026-02-30 over to March 2; a value that does not survive the
  // round trip is not a date-time.
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day ||
    check.getUTCHours() !== hour ||
    check.getUTCMinutes() !== minute ||
    check.getUTCSeconds() !== second
  ) {
    return null;
  }

  let offsetMinutes = 0;
  if (offset !== "Z") {
    const sign = offset[0] === "-" ? -1 : 1;
    const [oh, om] = offset.slice(1).split(":").map(Number);
    if (oh > 23 || om > 59) return null;
    offsetMinutes = sign * (oh * 60 + om);
  }
  return { epochMs: wall - offsetMinutes * 60_000, fraction };
}

function offsetLabel(date: Date, timeZone: string | undefined): string {
  const part = new Intl.DateTimeFormat("en-US", { timeZone, timeZoneName: "shortOffset" })
    .formatToParts(date)
    .find((p) => p.type === "timeZoneName");
  // ICU spells UTC as "GMT" or "GMT+0" depending on its version; show one form.
  const label = part?.value ?? "GMT";
  return label === "GMT+0" ? "GMT" : label;
}

/**
 * Format an API timestamp for display in `timeZone` (default: the viewer's).
 * Unreadable values give text "—" and iso null, never a wrong time.
 */
export function formatTimestamp(value: unknown, timeZone?: string): FormattedTimestamp {
  const parsed = parse(value);
  if (!parsed) return { text: "—", iso: null };

  const date = new Date(parsed.epochMs);
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-US", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
    })
      .formatToParts(date)
      .map((p) => [p.type, p.value]),
  );
  const text =
    `${parts.day}.${parts.month}.${parts.year} ` +
    `${parts.hour}:${parts.minute}:${parts.second} ${offsetLabel(date, timeZone)}`;
  // Seconds from toISOString, then the fraction exactly as it came: the API sends
  // microseconds, which an offset of whole minutes never changes.
  const seconds = date.toISOString().slice(0, 19);
  const iso = `${seconds}${parsed.fraction ? `.${parsed.fraction}` : ""}Z`;
  return { text, iso };
}
