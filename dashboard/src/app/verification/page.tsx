"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  Fingerprint,
  Hash,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from "lucide-react";

type Proof = {
  proof_id: string;
  status: string;
  events: number;
  created_at: string;
};

type VerifyResult = {
  verdict?: string;
  events_checked?: number;
  [key: string]: unknown;
};

export default function VerificationPage() {
  const [proof, setProof] = useState<Proof | null>(null);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function verifyLatest() {
    try {
      setLoading(true);
      setError("");

      const response = await fetch("/api/flop/proofs?limit=100", {
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error("Failed to load proofs");
      }

      const data = await response.json();
      const items = (data.items ?? []) as Proof[];

      // Prefer a completed proof so the verification center
      // demonstrates a real finalized proof.
      const selected =
        items.find((item) => item.status === "completed") ??
        items.find((item) => item.status === "active") ??
        items[0];

      if (!selected) {
        throw new Error("No proofs available");
      }

      setProof(selected);

      const verifyResponse = await fetch(
        `/api/flop/proofs/${selected.proof_id}/verify`,
        {
          cache: "no-store",
        }
      );

      const verifyData = await verifyResponse.json();

      if (!verifyResponse.ok) {
        throw new Error(
          typeof verifyData.detail === "string"
            ? verifyData.detail
            : "Verification failed"
        );
      }

      setResult(verifyData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    verifyLatest();
  }, []);

  const verdict = result?.verdict ?? "unknown";
  const valid = verdict === "valid";

  return (
    <main className="min-h-screen bg-[#050505] text-white">
      <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">
        <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
          <div>
            <Link
              href="/"
              className="mb-5 inline-flex items-center gap-2 text-xs text-slate-500 transition hover:text-white"
            >
              <ArrowLeft size={14} />
              Back to Overview
            </Link>

            <div className="flex items-center gap-3">
              <div className="rounded-xl border border-white/[0.08] bg-white/[0.04] p-2.5">
                <ShieldCheck size={20} />
              </div>

              <div>
                <div className="text-xs font-medium uppercase tracking-[0.2em] text-emerald-400">
                  Cryptographic verification
                </div>
                <h1 className="mt-1 text-2xl font-semibold tracking-tight">
                  Verification Center
                </h1>
                <p className="mt-1 text-sm text-slate-500">
                  Verify the integrity and authenticity of a proof.
                </p>
              </div>
            </div>
          </div>

          <button
            onClick={verifyLatest}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-2.5 text-sm text-slate-300 transition hover:bg-white/[0.07] hover:text-white disabled:opacity-50"
          >
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
            Verify latest
          </button>
        </div>

        {loading ? (
          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-12 text-center text-sm text-slate-500">
            Running cryptographic verification...
          </div>
        ) : error ? (
          <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-8">
            <div className="flex items-center gap-3 text-red-300">
              <XCircle size={20} />
              <span className="font-medium">Verification failed</span>
            </div>
            <p className="mt-3 text-sm text-red-300/70">{error}</p>
          </div>
        ) : (
          <>
            <section
              className={`rounded-2xl border p-6 ${
                valid
                  ? "border-emerald-500/20 bg-emerald-500/[0.04]"
                  : "border-red-500/20 bg-red-500/[0.04]"
              }`}
            >
              <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
                <div className="flex items-center gap-4">
                  <div
                    className={`rounded-2xl p-3 ${
                      valid ? "bg-emerald-500/10" : "bg-red-500/10"
                    }`}
                  >
                    {valid ? (
                      <CheckCircle2
                        size={28}
                        className="text-emerald-400"
                      />
                    ) : (
                      <XCircle size={28} className="text-red-400" />
                    )}
                  </div>

                  <div>
                    <div className="text-xs uppercase tracking-[0.18em] text-slate-500">
                      Verification verdict
                    </div>
                    <div
                      className={`mt-1 text-3xl font-semibold ${
                        valid ? "text-emerald-300" : "text-red-300"
                      }`}
                    >
                      {verdict.toUpperCase()}
                    </div>
                  </div>
                </div>

                {proof && (
                  <div className="max-w-full md:max-w-md">
                    <div className="text-xs text-slate-500">Proof ID</div>
                    <code className="mt-1 block truncate font-mono text-xs text-slate-300">
                      {proof.proof_id}
                    </code>
                  </div>
                )}
              </div>
            </section>

            <section className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
                <Hash size={19} className="text-emerald-400" />
                <div className="mt-4 text-sm font-medium">
                  Event chain
                </div>
                <div className="mt-1 text-xs text-slate-500">
                  {result?.events_checked ?? proof?.events ?? 0} events checked
                </div>
              </div>

              <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
                <Fingerprint size={19} className="text-emerald-400" />
                <div className="mt-4 text-sm font-medium">
                  Canonical messages
                </div>
                <div className="mt-1 text-xs text-slate-500">
                  Deterministic message validation
                </div>
              </div>

              <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
                <ShieldCheck size={19} className="text-emerald-400" />
                <div className="mt-4 text-sm font-medium">
                  Ed25519 signatures
                </div>
                <div className="mt-1 text-xs text-slate-500">
                  Actor signature verification
                </div>
              </div>

              <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
                <CheckCircle2 size={19} className="text-emerald-400" />
                <div className="mt-4 text-sm font-medium">
                  Payload integrity
                </div>
                <div className="mt-1 text-xs text-slate-500">
                  Hash consistency validation
                </div>
              </div>
            </section>

            <section className="mt-6 rounded-2xl border border-white/[0.07] bg-white/[0.02]">
              <div className="border-b border-white/[0.07] px-5 py-5">
                <h2 className="font-medium">Verification evidence</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Cryptographic verification response returned by the API.
                </p>
              </div>

              <pre className="max-h-[420px] overflow-auto p-5 text-xs leading-6 text-slate-400">
                {JSON.stringify(result, null, 2)}
              </pre>
            </section>
          </>
        )}
      </div>
    </main>
  );
}
