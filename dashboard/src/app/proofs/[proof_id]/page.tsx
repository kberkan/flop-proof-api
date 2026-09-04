"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  Clock3,
  Copy,
  Fingerprint,
  Hash,
  ShieldCheck,
  XCircle,
} from "lucide-react";

type ProofDetail = {
  proof_id: string;
  request_id?: string | null;
  version?: string;
  status?: string;
  created_at?: string;
  updated_at?: string;
  events?: unknown[];
  [key: string]: unknown;
};

function statusInfo(status: string) {
  if (status === "completed") {
    return {
      label: "VALID",
      icon: CheckCircle2,
      className: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
    };
  }

  if (status === "failed") {
    return {
      label: "FAILED",
      icon: XCircle,
      className: "border-red-400/20 bg-red-400/10 text-red-300",
    };
  }

  return {
    label: status.toUpperCase(),
    icon: Clock3,
    className: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  };
}

function formatValue(value: unknown) {
  if (value === null || value === undefined) return "—";

  if (typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }

  return String(value);
}

export default function ProofDetailPage({
  params,
}: {
  params: Promise<{ proof_id: string }>;
}) {
  const [proof, setProof] = useState<ProofDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [proofId, setProofId] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const resolved = await params;

      if (cancelled) return;

      setProofId(resolved.proof_id);

      try {
        const response = await fetch(
          `/api/flop/proofs/${encodeURIComponent(resolved.proof_id)}`,
          { cache: "no-store" },
        );

        if (!response.ok) {
          throw new Error(`API returned ${response.status}`);
        }

        const result = await response.json();

        if (!cancelled) {
          setProof(result);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Unable to load proof");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    load();

    return () => {
      cancelled = true;
    };
  }, [params]);

  const status = statusInfo(proof?.status ?? "unknown");
  const StatusIcon = status.icon;

  const events = Array.isArray(proof?.events) ? proof.events : [];

  return (
    <main className="min-h-screen bg-[#080b10] text-white">
      <div className="mx-auto max-w-[1450px] p-6 lg:p-10">
        <Link
          href="/proofs"
          className="mb-7 inline-flex items-center gap-2 text-xs text-slate-500 hover:text-white"
        >
          <ArrowLeft size={14} />
          Back to proofs
        </Link>

        {loading ? (
          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-12 text-center text-sm text-slate-600">
            Loading cryptographic proof...
          </div>
        ) : error ? (
          <div className="rounded-2xl border border-red-400/10 bg-red-400/[0.03] p-12 text-center">
            <XCircle className="mx-auto text-red-400" size={30} />
            <p className="mt-4 text-sm text-red-300">{error}</p>
            <p className="mt-2 font-mono text-xs text-slate-600">{proofId}</p>
          </div>
        ) : proof ? (
          <>
            <header className="mb-8 flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
              <div>
                <p className="text-[10px] uppercase tracking-[0.22em] text-emerald-400">
                  Proof Explorer
                </p>

                <h1 className="mt-2 break-all font-mono text-2xl font-semibold tracking-tight lg:text-3xl">
                  {proof.proof_id}
                </h1>

                <p className="mt-3 text-sm text-slate-500">
                  Cryptographic proof record and verification evidence.
                </p>
              </div>

              <div
                className={`inline-flex w-fit items-center gap-2 rounded-full border px-3 py-2 text-xs font-semibold ${status.className}`}
              >
                <StatusIcon size={14} />
                {status.label}
              </div>
            </header>

            <div className="grid gap-5 lg:grid-cols-3">
              <section className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-6 lg:col-span-2">
                <div className="mb-5 flex items-center gap-3">
                  <div className="rounded-xl bg-emerald-400/10 p-2.5">
                    <Fingerprint size={18} className="text-emerald-400" />
                  </div>

                  <div>
                    <h2 className="text-sm font-semibold">Proof identity</h2>
                    <p className="text-xs text-slate-600">
                      Core record metadata
                    </p>
                  </div>
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  {[
                    ["Proof ID", proof.proof_id],
                    ["Request ID", proof.request_id],
                    ["Version", proof.version],
                    ["Status", proof.status],
                    ["Created", proof.created_at],
                    ["Updated", proof.updated_at],
                  ].map(([label, value]) => (
                    <div
                      key={label}
                      className="rounded-xl border border-white/[0.06] bg-black/20 p-4"
                    >
                      <p className="text-[10px] uppercase tracking-[0.16em] text-slate-600">
                        {label}
                      </p>
                      <p className="mt-2 break-all font-mono text-xs leading-5 text-slate-300">
                        {value ?? "—"}
                      </p>
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-2xl border border-emerald-400/10 bg-emerald-400/[0.025] p-6">
                <div className="flex items-center gap-3">
                  <div className="rounded-xl bg-emerald-400/10 p-2.5">
                    <ShieldCheck size={18} className="text-emerald-400" />
                  </div>

                  <div>
                    <h2 className="text-sm font-semibold">
                      Verification evidence
                    </h2>
                    <p className="text-xs text-slate-600">
                      Integrity primitives
                    </p>
                  </div>
                </div>

                <div className="mt-6 space-y-3">
                  {[
                    { label: "Payload hashes", Icon: Hash },
                    { label: "Canonical messages", Icon: Fingerprint },
                    { label: "Ed25519 signatures", Icon: ShieldCheck },
                    { label: "Event chain", Icon: CheckCircle2 },
                  ].map(({ label, Icon }) => (
                    <div
                      key={String(label)}
                      className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-black/20 px-4 py-3"
                    >
                      <div className="flex items-center gap-3 text-xs text-slate-400">
                        <Icon size={15} />
                        {label}
                      </div>

                      <CheckCircle2
                        size={15}
                        className="text-emerald-400"
                      />
                    </div>
                  ))}
                </div>
              </section>
            </div>

            <section className="mt-5 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-6">
              <div className="mb-6 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Event timeline</h2>
                  <p className="mt-1 text-xs text-slate-600">
                    {events.length} event{events.length === 1 ? "" : "s"} recorded
                  </p>
                </div>
              </div>

              {events.length === 0 ? (
                <div className="rounded-xl border border-white/[0.06] bg-black/20 p-8 text-center text-xs text-slate-600">
                  No events available.
                </div>
              ) : (
                <div className="space-y-3">
                  {events.map((event, index) => (
                    <div
                      key={index}
                      className="relative rounded-xl border border-white/[0.06] bg-black/20 p-5"
                    >
                      <div className="flex items-start gap-4">
                        <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-emerald-400/20 bg-emerald-400/10 text-xs font-semibold text-emerald-300">
                          {index + 1}
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-4">
                            <p className="text-sm font-medium text-slate-200">
                              {typeof event === "object" &&
                              event !== null &&
                              "type" in event
                                ? String(
                                    (event as Record<string, unknown>).type,
                                  )
                                : `Event ${index + 1}`}
                            </p>

                            <CheckCircle2
                              size={15}
                              className="shrink-0 text-emerald-400"
                            />
                          </div>

                          <pre className="mt-4 overflow-x-auto rounded-lg border border-white/[0.05] bg-[#06080c] p-4 text-[11px] leading-5 text-slate-500">
                            {formatValue(event)}
                          </pre>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="mt-5 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-6">
              <div className="flex items-center gap-3">
                <div className="rounded-xl border border-white/[0.06] bg-white/[0.04] p-2.5">
                  <Hash size={18} className="text-slate-300" />
                </div>

                <div>
                  <h2 className="text-sm font-semibold">Raw proof record</h2>
                  <p className="text-xs text-slate-600">
                    API response for independent inspection
                  </p>
                </div>
              </div>

              <pre className="mt-5 max-h-[500px] overflow-auto rounded-xl border border-white/[0.06] bg-[#06080c] p-5 text-[11px] leading-5 text-slate-500">
                {JSON.stringify(proof, null, 2)}
              </pre>
            </section>
          </>
        ) : null}
      </div>
    </main>
  );
}
