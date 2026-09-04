"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  FileCheck2,
  Fingerprint,
  LayoutDashboard,
  Network,
  Search,
  ShieldCheck,
  TerminalSquare,
  XCircle,
} from "lucide-react";

const proofs = [
  ["proof_fac398664d684d77803cc0f2f34153e4", "VALID", "2 events", "2 min ago"],
  ["proof_9ff48249e58b4e05a56ca164f6092185", "VALID", "1 event", "8 min ago"],
  ["proof_4208145ab703485ab4e68ddae4c8b73b", "VALID", "3 events", "21 min ago"],
];

function Status({ value }: { value: string }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-[11px] font-semibold tracking-wide text-emerald-300">
      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
      {value}
    </span>
  );
}

type Proof = {
  proof_id: string;
  request_id: string | null;
  version: string;
  status: "pending" | "active" | "completed" | "failed";
  created_at: string;
  updated_at: string;
  events: number;
};

type ProofResponse = {
  items: Proof[];
  count: number;
  total: number;
  stats: {
    total: number;
    pending: number;
    active: number;
    completed: number;
    failed: number;
  };
};

export default function Home() {
  const [data, setData] = useState<ProofResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadProofs() {
      try {
        const response = await fetch("/api/flop/proofs?limit=8", {
          cache: "no-store",
        });

        if (!response.ok) {
          throw new Error(`API returned ${response.status}`);
        }

        const result: ProofResponse = await response.json();

        if (!cancelled) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Unable to reach API");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadProofs();

    const interval = setInterval(loadProofs, 10000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const stats = data?.stats ?? {
    total: 0,
    pending: 0,
    active: 0,
    completed: 0,
    failed: 0,
  };

  return (
    <main className="min-h-screen bg-[#080b10] text-slate-100">
      <div className="flex min-h-screen">
        <aside className="hidden w-64 shrink-0 border-r border-white/[0.06] bg-[#0a0e14] lg:flex lg:flex-col">
          <div className="flex h-20 items-center gap-3 border-b border-white/[0.06] px-6">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white font-black text-black">F</div>
            <div>
              <div className="font-semibold">FLOP</div>
              <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Proof Infrastructure</div>
            </div>
          </div>

          <nav className="space-y-1">
            <Link
              href="/"
              className="flex items-center gap-3 rounded-xl bg-white/[0.07] px-3 py-2.5 text-sm text-white transition hover:bg-white/[0.10]"
            >
              <LayoutDashboard size={17} />
              Overview
            </Link>

            <Link
              href="/proofs"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-400 transition hover:bg-white/[0.04] hover:text-white"
            >
              <FileCheck2 size={17} />
              Proofs
            </Link>

            <Link
              href="/verification"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-400 transition hover:bg-white/[0.04] hover:text-white"
            >
              <ShieldCheck size={17} />
              Verification
            </Link>

            <Link
              href="/actors"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-400 transition hover:bg-white/[0.04] hover:text-white"
            >
              <Fingerprint size={17} />
              Actors
            </Link>

            <Link
              href="/developer"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-400 transition hover:bg-white/[0.04] hover:text-white"
            >
              <TerminalSquare size={17} />
              Developer
            </Link>
          </nav>

          <div className="border-t border-white/[0.06] p-4">
            <div className="rounded-xl border border-white/[0.06] bg-white/[0.025] p-3">
              <div className="mb-2 flex items-center gap-2 text-xs text-slate-400">
                <Network size={14} /> API Status
              </div>
              <div className="flex items-center gap-2 text-sm font-medium text-emerald-300">
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                Operational
              </div>
              <div className="mt-1 text-[11px] text-slate-600">localhost:8000</div>
            </div>
          </div>
        </aside>

        <section className="min-w-0 flex-1">
          <header className="flex h-20 items-center justify-between border-b border-white/[0.06] px-5 sm:px-8">
            <div>
              <div className="text-xs text-slate-500">Workspace</div>
              <h1 className="text-lg font-semibold">Proof Operations</h1>
            </div>

            <div className="flex items-center gap-3">
              <div className="hidden items-center gap-2 rounded-xl border border-white/[0.07] bg-white/[0.025] px-3 py-2 text-xs text-slate-500 sm:flex">
                <Search size={14} /> Search proofs
              </div>
              <div className="flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-xs font-semibold">BK</div>
            </div>
          </header>

          <div className="mx-auto max-w-[1400px] p-5 sm:p-8">
            <div className="mb-8">
              <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.18em] text-emerald-400">
                <Activity size={14} /> System overview
              </div>
              <h2 className="text-3xl font-semibold tracking-[-0.03em] sm:text-4xl">
                Cryptographic proof, <span className="text-slate-500">made observable.</span>
              </h2>
              <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-500">
                Monitor proof lifecycle, inspect event chains and independently verify cryptographic integrity from one workspace.
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              {[
                ["Total proofs", stats.total.toString(), "Live", FileCheck2],
                ["Valid proofs", stats.completed.toString(), `${stats.total ? ((stats.completed / stats.total) * 100).toFixed(1) : "0.0"}%`, CheckCircle2],
                ["Active", stats.active.toString(), "Live", CircleDot],
                ["Failed", stats.failed.toString(), `${stats.total ? ((stats.failed / stats.total) * 100).toFixed(1) : "0.0"}%`, XCircle],
              ].map(([label, value, change, Icon]) => {
                const I = Icon as typeof FileCheck2;
                return (
                  <div key={String(label)} className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
                    <div className="flex items-start justify-between">
                      <div className="rounded-xl border border-white/[0.06] bg-white/[0.04] p-2.5"><I size={17} /></div>
                      <span className="text-[11px] text-slate-600">{String(change)}</span>
                    </div>
                    <div className="mt-5 text-3xl font-semibold">{String(value)}</div>
                    <div className="mt-1 text-xs text-slate-500">{String(label)}</div>
                  </div>
                );
              })}
            </div>

            <div className="mt-6 grid gap-6 xl:grid-cols-[1.7fr_1fr]">
              <section className="overflow-hidden rounded-2xl border border-white/[0.07] bg-white/[0.02]">
                <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-4">
                  <div>
                    <h3 className="text-sm font-semibold">Recent proofs</h3>
                    <p className="mt-1 text-xs text-slate-600">Latest cryptographic proof activity</p>
                  </div>
                  <button className="flex items-center gap-1 text-xs text-slate-400">View all <ArrowUpRight size={13} /></button>
                </div>

                <div className="divide-y divide-white/[0.05]">
                  {proofs.map(([id, status, events, time]) => (
                    <div key={id} className="group flex items-center gap-4 px-5 py-4 hover:bg-white/[0.025]">
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-white/[0.06] bg-white/[0.025]">
                        <ShieldCheck size={16} className="text-emerald-400" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="truncate font-mono text-xs text-slate-300">{id}</div>
                        <div className="mt-1 text-[11px] text-slate-600">{events} • {time}</div>
                      </div>
                      <Status value={status} />
                      <ChevronRight size={16} className="hidden text-slate-700 sm:block" />
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
                <div className="flex items-center gap-3">
                  <div className="rounded-xl bg-emerald-400/10 p-2.5"><ShieldCheck size={18} className="text-emerald-400" /></div>
                  <div>
                    <h3 className="text-sm font-semibold">Verification engine</h3>
                    <p className="text-xs text-slate-600">Cryptographic integrity</p>
                  </div>
                </div>

                <div className="mt-6 space-y-3">
                  {["Payload hashes", "Canonical messages", "Ed25519 signatures", "Event chain", "DID actor identity"].map((item) => (
                    <div key={item} className="flex items-center justify-between rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2.5">
                      <span className="text-xs text-slate-400">{item}</span>
                      <CheckCircle2 size={15} className="text-emerald-400" />
                    </div>
                  ))}
                </div>

                <button className="mt-5 flex w-full items-center justify-center gap-2 rounded-xl bg-white px-4 py-3 text-xs font-semibold text-black hover:bg-slate-200">
                  <ShieldCheck size={15} /> Verify a proof
                </button>
              </section>
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-3">
              {[
                ["Proof lifecycle", "pending → active → completed"],
                ["Signature scheme", "Ed25519"],
                ["Hash algorithm", "SHA-256"],
              ].map(([title, value]) => (
                <div key={title} className="rounded-2xl border border-white/[0.06] bg-white/[0.018] p-4">
                  <div className="text-xs text-slate-600">{title}</div>
                  <div className="mt-2 text-xs font-medium text-slate-300">{value}</div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
