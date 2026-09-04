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
    description: "Cryptographically verify a proof",
  },
];

const createExample = `curl -X POST http://localhost:8000/proofs \\
  -H "Content-Type: application/json" \\
  -d '{
    "request_id": "req_demo_001",
    "room": "demo-room",
    "nonce": "nonce-001",
    "text": "hello FLOP",
    "actor_did": "did:key:z..."
  }'`;

const verifyExample = `curl http://localhost:8000/proofs/{proof_id}/verify`;

const pythonExample = `from flop_proof_sdk import FlopProofClient

client = FlopProofClient("http://localhost:8000")

proof = client.create_proof(
    request_id="req_demo_001",
    room="demo-room",
    nonce="nonce-001",
    text="hello FLOP",
    actor_did="did:key:z...",
)

result = client.verify_proof(proof["proof_id"])

print(result["verdict"])`;

const signingExample = `from flop_proof_sdk import (
    canonical_signed_message,
    sign_message,
)

message = canonical_signed_message(
    room="demo-room",
    nonce="nonce-001",
    text="hello FLOP",
)

signature = sign_message(private_key, message)`;

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

            <div className="flex items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-4 py-2.5 text-xs text-emerald-300">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              API operational
            </div>
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
              <ShieldCheck size={18} />
              <div>
                <h2 className="font-medium">Verify a proof</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Validate the complete cryptographic proof chain.
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
            <code className="text-xs text-emerald-300">
              pip install git+https://github.com/kberkan/flop-proof-api.git
            </code>
          </div>

          <CodeBlock>{pythonExample}</CodeBlock>
        </section>

        <section className="mt-8 grid gap-8 lg:grid-cols-2">
          <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
            <div className="flex items-center gap-3">
              <KeyRound size={18} />
              <div>
                <h2 className="font-medium">Canonical signing</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Deterministic request signing before transmission.
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
                  Proof verification checks the complete evidence chain.
                </p>
              </div>
            </div>

            <div className="mt-5 space-y-3">
              {[
                ["Event sequence", "Ordered"],
                ["Previous event hash", "Linked"],
                ["Payload hash", "Checked"],
                ["Canonical message", "Checked"],
                ["Ed25519 signature", "Verified"],
              ].map(([label, value]) => (
                <div
                  key={label}
                  className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-black/20 px-4 py-3"
                >
                  <span className="text-xs text-slate-400">{label}</span>
                  <span className="flex items-center gap-2 text-xs text-emerald-300">
                    <CheckCircle2 size={13} />
                    {value}
                  </span>
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
