// The FLOP Proof API the dashboard proxy forwards to (src/app/api/flop/[...path]/route.ts).
// No server-only imports, so pages can show the target too.
export const API_URL = "http://127.0.0.1:8000";

/** host:port of API_URL, for display. */
export const API_HOST = new URL(API_URL).host;
