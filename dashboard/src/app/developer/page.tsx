"use client";

import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  Code2,
  Copy,
  ExternalLink,
  Fingerprint,
  GitBranch,
  KeyRound,
  LockKeyhole,
  Server,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { useState } from "react";

import { ApiStatusIndicator } from "@/components/api-status-indicator";
import { evidenceBoundary } from "@/lib/evidence-boundary";

const endpoints = [
  {
    method: "GET",
    path: "/health",
    description: "API health and service status",
  },
  {
    method: "POST",
    path: "/proofs",
    description: "Create a new proof",
  },
  {
    method: "POST",
    path: "/proofs/{proof_id}/events",
    description: "Append a proof event",
  },
  {
    method: "GET",
    path: "/proofs",
    description: "List proofs and aggregate statistics",
  },
  {
    method: "GET",
    path: "/proofs/{proof_id}",
    description: "Retrieve a complete proof",
  },
  {
    method: "GET",
    path: "/proofs/{proof_id}/verify",
    description: "Verify proof integrity and cryptographic signatures",
  },
  {
    method: "POST",
    path: "/validator-attestations/accept",
    description: "Accept and bind validator attestation evidence",
  },
  {
    method: "POST",
    path: "/proofs/{proof_id}/validator-attestations/accept",
    description: "Accept and bind validator evidence to a stored proof",
  },
  {
    method: "POST",
    path: "/stark-batches",
    description: "Accept STARK evidence for pending verification",
  },
];

// Examples for SDK 0.3.0 and API proof version "3" (docs/design/event-replay.md).
// Placeholders in {braces} are filled in by the caller; the Python examples
// run as written with FLOP_API_KEY set.
const createExample = `# The signature is Ed25519 over FLOP/REQUEST/v3|{room}|{nonce}|{text}
# (base64url, no padding). See "Canonical signing" below.
curl -X POST http://localhost:8000/proofs \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: $FLOP_API_KEY" \\
  -d '{
    "request": {
      "request_id": "{request_id}",
      "from_did": "{did}",
      "text": "{text}",
      "created_at": "2026-10-04T12:00:00Z",
      "signature": {
        "nonce": "{nonce}",
        "sig": "{signature}",
        "canonical": "FLOP/REQUEST/v3|{room}|{nonce}|{text}"
      }
    }
  }'`;

const appendExample = `# The signature is Ed25519 over
# FLOP/EVENT/v3|{proof_id}|agent.started|{payload_hash}|{event_nonce};
# payload_hash is the SHA-256 hex of the payload as compact, key-sorted JSON.
curl -X POST http://localhost:8000/proofs/{proof_id}/events \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: $FLOP_API_KEY" \\
  -d '{
    "type": "agent.started",
    "actor_did": "{did}",
    "payload": {"step": 1},
    "signature": {
      "nonce": "{event_nonce}",
      "sig": "{event_signature}",
      "canonical": "FLOP/EVENT/v3|{proof_id}|agent.started|{payload_hash}|{event_nonce}"
    }
  }'`;

const verifyExample = `curl http://localhost:8000/proofs/{proof_id}/verify \\
  -H "X-API-Key: $FLOP_API_KEY"`;

const installExample = `pip install dist/flop_proof_sdk-0.3.0-py3-none-any.whl`;

const pythonExample = `import os
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flop_proof_sdk import FlopProofClient, public_key_to_test_did

client = FlopProofClient(
    "http://localhost:8000",
    api_key=os.environ["FLOP_API_KEY"],
)

private_key = Ed25519PrivateKey.generate()
did = public_key_to_test_did(private_key.public_key())

proof = client.create_signed_proof(
    private_key=private_key,
    did=did,
    text="Summarize the report",
    room="demo-room",
    nonce=f"request-{uuid.uuid4().hex}",
    request_id=f"demo-{uuid.uuid4().hex}",
    created_at=datetime.now(timezone.utc).isoformat(),
)

client.append_signed_event(
    proof_id=proof["proof_id"],
    private_key=private_key,
    did=did,
    event_type="result.created",
    payload={"content": "summary text"},
    nonce=f"event-{uuid.uuid4().hex}",
)

result = client.verify_proof(proof["proof_id"])

print(proof["version"], result["verdict"])`;

const signingExample = `from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flop_proof_sdk import (
    build_event_canonical_v3,
    build_request_canonical_v3,
    sha256_json,
    sign_message,
)

private_key = Ed25519PrivateKey.generate()

# Request: FLOP/REQUEST/v3|room|nonce|text. room and nonce must not contain
# "|" or control characters; text may.
request_canonical = build_request_canonical_v3(
    "demo-room", "request-nonce-1", "Summarize | report"
)
request_signature = sign_message(private_key, request_canonical.encode("utf-8"))

# Event: FLOP/EVENT/v3|proof_id|type|payload_hash|nonce. The nonce is signed.
payload = {"content": "summary text"}
event_canonical = build_event_canonical_v3(
    "proof_0123456789abcdef0123456789abcdef",
    "result.created",
    sha256_json(payload),
    "event-nonce-1",
)
event_signature = sign_message(private_key, event_canonical.encode("utf-8"))

print(request_canonical)
print(event_canonical)`;

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <button
      onClick={copy}
      className="absolute right-3 top-3 rounded-lg border border-white/[0.08] bg-white/[0.04] p-2 text-slate-400 transition hover:bg-white/[0.08] hover:text-white"
      title="Copy"
    >
      {copied ? <CheckCircle2 size={15} /> : <Copy size={15} />}
    </button>
  );
}

function CodeBlock({ children }: { children: string }) {
  return (
    <div className="relative mt-4 overflow-hidden rounded-xl border border-white/[0.07] bg-black/40">
      <CopyButton value={children} />
      <pre className="overflow-x-auto p-5 pr-14 text-xs leading-6 text-slate-300">
        <code>{children}</code>
      </pre>
    </div>
  );
}

export default function DeveloperPage() {
  return (
    <main className="min-h-screen bg-[#050505] text-white">
      <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">
        <div className="mb-10">
          <Link
            href="/"
            className="mb-5 inline-flex items-center gap-2 text-xs text-slate-500 transition hover:text-white"
          >
            <ArrowLeft size={14} />
            Back to Overview
          </Link>

          <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
            <div>
              <div className="mb-3 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.2em] text-emerald-400">
                <Code2 size={14} />
                Developer platform
              </div>

              <h1 className="text-3xl font-semibold tracking-tight">
                Developer Center
              </h1>

              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
                Build, sign, append and verify cryptographic proofs with the
                FLOP Proof API.
              </p>
            </div>

            <ApiStatusIndicator />
          </div>
        </div>

        <section className="grid gap-4 sm:grid-cols-3">
          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
            <Server className="text-emerald-400" size={19} />
            <div className="mt-4 text-sm font-medium">REST API</div>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              HTTP API for proof lifecycle operations.
            </p>
          </div>

          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
            <Fingerprint className="text-emerald-400" size={19} />
            <div className="mt-4 text-sm font-medium">DID identities</div>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              Ed25519-backed did:key actor identities.
            </p>
          </div>

          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
            <LockKeyhole className="text-emerald-400" size={19} />
            <div className="mt-4 text-sm font-medium">Hash-linked proofs</div>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              Canonical messages, signatures and event hash chains.
            </p>
          </div>
        </section>

        <section className="mt-8 rounded-2xl border border-white/[0.07] bg-white/[0.02]">
          <div className="border-b border-white/[0.07] px-5 py-5">
            <div className="flex items-center gap-3">
              <Terminal size={18} />
              <div>
                <h2 className="font-medium">API Reference</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Available HTTP endpoints
                </p>
              </div>
            </div>
          </div>

          <div className="divide-y divide-white/[0.06]">
            {endpoints.map((endpoint) => (
              <div
                key={`${endpoint.method}-${endpoint.path}`}
                className="grid gap-3 px-5 py-4 md:grid-cols-[90px_1fr_1.5fr] md:items-center"
              >
                <span
                  className={`w-fit rounded-md px-2 py-1 text-[10px] font-semibold ${
                    endpoint.method === "POST"
                      ? "bg-blue-500/10 text-blue-300"
                      : "bg-emerald-500/10 text-emerald-300"
                  }`}
                >
                  {endpoint.method}
                </span>

                <code className="font-mono text-xs text-slate-200">
                  {endpoint.path}
                </code>

                <span className="text-xs text-slate-500">
                  {endpoint.description}
                </span>
              </div>
            ))}
          </div>
        </section>

        <div className="mt-8 grid gap-8 lg:grid-cols-2">
          <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
            <div className="flex items-center gap-3">
              <Code2 size={18} />
              <div>
                <h2 className="font-medium">Create a proof</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Start a proof lifecycle through REST.
                </p>
              </div>
            </div>

            <CodeBlock>{createExample}</CodeBlock>
          </section>

          <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
            <div className="flex items-center gap-3">
              <Code2 size={18} />
              <div>
                <h2 className="font-medium">Append an event</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Events on version-3 proofs sign their nonce.
                </p>
              </div>
            </div>

            <CodeBlock>{appendExample}</CodeBlock>
          </section>

          <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
            <div className="flex items-center gap-3">
              <ShieldCheck size={18} />
              <div>
                <h2 className="font-medium">Verify a proof</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Check signatures, event chain, payload hashes and actor authorization.
                </p>
              </div>
            </div>

            <CodeBlock>{verifyExample}</CodeBlock>
          </section>
        </div>

        <section className="mt-8 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
          <div className="flex items-center gap-3">
            <GitBranch size={18} />
            <div>
              <h2 className="font-medium">Python SDK</h2>
              <p className="mt-1 text-xs text-slate-500">
                Use the FLOP client without constructing HTTP requests
                manually.
              </p>
            </div>
          </div>

          <div className="mt-5 rounded-xl border border-white/[0.06] bg-black/20 p-4">
            <code className="text-xs text-emerald-300">{installExample}</code>
          </div>

          <CodeBlock>{pythonExample}</CodeBlock>
        </section>

        <section className="mt-8 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
          <div className="flex items-center gap-3">
            <ShieldCheck size={18} />
            <div>
              <h2 className="font-medium">Evidence boundary</h2>
              <p className="mt-1 text-xs text-slate-500">
                API acceptance is not execution verification or runtime settlement.
              </p>
            </div>
          </div>

          <div className="mt-5 space-y-4">
            {evidenceBoundary.map((item) => (
              <div
                key={item.endpoint}
                className="rounded-xl border border-white/[0.06] bg-black/20 p-4"
              >
                <code className="font-mono text-xs text-slate-200">
                  {item.endpoint}
                </code>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.16em] text-emerald-400">
                      Proves
                    </div>
                    <p className="mt-1 text-xs leading-5 text-slate-400">
                      {item.proves}
                    </p>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.16em] text-amber-400">
                      Does not prove
                    </div>
                    <p className="mt-1 text-xs leading-5 text-slate-400">
                      {item.doesNotProve}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-8 grid gap-8 lg:grid-cols-2">
          <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
            <div className="flex items-center gap-3">
              <KeyRound size={18} />
              <div>
                <h2 className="font-medium">Canonical signing</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Version-3 request and event messages, signed before transmission.
                </p>
              </div>
            </div>

            <CodeBlock>{signingExample}</CodeBlock>
          </section>

          <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
            <div className="flex items-center gap-3">
              <ShieldCheck size={18} />
              <div>
                <h2 className="font-medium">Verification model</h2>
                <p className="mt-1 text-xs text-slate-500">
                  What /verify checks for each event. It does not check execution or settlement.
                </p>
              </div>
            </div>

            <div className="mt-5 space-y-3">
              {[
                ["Event sequence", "Ordered"],
                ["Previous event hash", "Linked"],
                ["Payload hash", "Checked"],
                ["Canonical message", "Checked"],
                ["Ed25519 signature", "Checked"],
                ["Request binding (request.created)", "Checked"],
                ["Message format (v3 tags; legacy v1/v2)", "Checked"],
                ["Replayed events in the proof", "Rejected"],
                ["Actor authorization (creator or delegate)", "Checked"],
              ].map(([label, value]) => (
                <div
                  key={label}
                  className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-black/20 px-4 py-3"
                >
                  <span className="text-xs text-slate-400">{label}</span>
                  <span className="text-xs text-slate-300">{value}</span>
                </div>
              ))}
            </div>
          </section>
        </section>

        <section className="mt-8 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
          <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
            <div>
              <h2 className="font-medium">Open source</h2>
              <p className="mt-1 text-xs text-slate-500">
                Source code, SDK and release artifacts.
              </p>
            </div>

            <a
              href="https://github.com/kberkan/flop-proof-api"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-2.5 text-xs text-slate-300 transition hover:bg-white/[0.08] hover:text-white"
            >
              View GitHub
              <ExternalLink size={14} />
            </a>
          </div>
        </section>
      </div>
    </main>
  );
}
