# FLOP Proof API dashboard

A local Next.js dashboard for the FLOP Proof API: it lists proofs and actors,
shows a proof's events and its verification result, and has a Developer page
with request examples. It reads from the API through its own server-side,
read-only proxy (`src/app/api/flop/[...path]/route.ts`), so the API key stays
on the server and never reaches the browser.

## Requirements

- Node.js `^22.18.0 || >=23.6.0` (the `engines` field in `package.json`)
- The API running at `http://127.0.0.1:8000` (see the repository README,
  "Quickstart")

## Configuration

Create `dashboard/.env.local` with:

- `FLOP_API_KEY`: the API key the API was started with

## Commands

```sh
npm install
npm run dev     # http://127.0.0.1:3000
npm test
```

`npm run build`, `npm start` and `npm run lint` are also available. `dev` and
`start` bind to `127.0.0.1`; the dashboard has no login of its own.

The proxy forwards only `GET` requests on an allow-list of paths (`proofs`,
`proofs/{proof_id}`, `proofs/{proof_id}/verify`, `actors`, `health`); other
methods get 405 and other paths 404 without reaching the API
(`src/lib/proxy-policy.ts`).
