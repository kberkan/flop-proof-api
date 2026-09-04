"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  CircleDot,
  Clock3,
  FileCheck2,
  RefreshCw,
  Search,
  XCircle,
} from "lucide-react";

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

const statusMeta = {
  completed: {
    label: "VALID",
    icon: CheckCircle2,
    className: "text-emerald-300 bg-emerald-400/10 border-emerald-400/20",
  },
  active: {
    label: "ACTIVE",
    icon: CircleDot,
    className: "text-sky-300 bg-sky-400/10 border-sky-400/20",
  },
  pending: {
    label: "PENDING",
    icon: Clock3,
    className: "text-amber-300 bg-amber-400/10 border-amber-400/20",
  },
  failed: {
    label: "FAILED",
    icon: XCircle,
    className: "text-red-300 bg-red-400/10 border-red-400/20",
  },
};

export default function ProofsPage() {
  const [data, setData] = useState<ProofResponse | null>(null);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [loading, setLoading] = useState(true);

  async function loadProofs() {
    setLoading(true);

    try {
      const query = status === "all"
        ? "/api/flop/proofs?limit=100"
        : `/api/flop/proofs?limit=100&status=${status}`;

      const response = await fetch(query, { cache: "no-store" });

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }

      setData(await response.json());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadProofs();
  }, [status]);

  const proofs = (data?.items ?? []).filter((proof) => {
    const q = search.toLowerCase().trim();

    if (!q) return true;

    return (
      proof.proof_id.toLowerCase().includes(q) ||
      (proof.request_id ?? "").toLowerCase().includes(q)
    );
  });

  return (
    <main className="min-h-screen bg-[#080b10] text-white">
      <div className="mx-auto max-w-[1500px] p-6 lg:p-10">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <Link
              href="/"
              className="mb-5 inline-flex items-center gap-2 text-xs text-slate-500 hover:text-white"
            >
              <ArrowLeft size={14} />
              Back to overview
            </Link>

            <div className="flex items-center gap-3">
              <div className="rounded-xl border border-white/10 bg-white/[0.04] p-2.5">
                <FileCheck2 size={20} className="text-emerald-400" />
              </div>

              <div>
                <p className="text-[10px] uppercase tracking-[0.22em] text-emerald-400">
                  Proof Operations
                </p>
                <h1 className="mt-1 text-3xl font-semibold tracking-tight">
                  Proofs
                </h1>
              </div>
            </div>

            <p className="mt-3 max-w-2xl text-sm text-slate-500">
              Inspect and operate on cryptographically verifiable proof records.
            </p>
          </div>

          <button
            onClick={loadProofs}
            className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-4 py-2.5 text-sm text-slate-300 hover:bg-white/[0.07]"
          >
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>

        <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          {[
            ["Total", data?.stats.total ?? 0],
            ["Pending", data?.stats.pending ?? 0],
            ["Active", data?.stats.active ?? 0],
            ["Completed", data?.stats.completed ?? 0],
            ["Failed", data?.stats.failed ?? 0],
          ].map(([label, value]) => (
            <div
              key={String(label)}
              className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5"
            >
              <p className="text-xs text-slate-500">{label}</p>
              <p className="mt-2 text-2xl font-semibold">{value}</p>
            </div>
          ))}
        </div>

        <div className="mb-5 flex flex-col gap-3 rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4 lg:flex-row">
          <div className="flex flex-1 items-center gap-3 rounded-xl border border-white/[0.07] bg-black/20 px-3">
            <Search size={16} className="text-slate-600" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search proof ID or request ID..."
              className="w-full bg-transparent py-3 text-sm text-white outline-none placeholder:text-slate-600"
            />
          </div>

          <div className="flex gap-2 overflow-x-auto">
            {["all", "pending", "active", "completed", "failed"].map((item) => (
              <button
                key={item}
                onClick={() => setStatus(item)}
                className={`rounded-xl border px-4 py-2.5 text-xs font-medium capitalize ${
                  status === item
                    ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300"
                    : "border-white/[0.07] bg-white/[0.02] text-slate-500 hover:text-white"
                }`}
              >
                {item}
              </button>
            ))}
          </div>
        </div>

        <section className="overflow-hidden rounded-2xl border border-white/[0.07] bg-white/[0.02]">
          <div className="grid grid-cols-[1.7fr_1fr_120px_110px_180px] border-b border-white/[0.07] px-6 py-4 text-[10px] uppercase tracking-[0.18em] text-slate-600">
            <span>Proof</span>
            <span>Request</span>
            <span>Status</span>
            <span>Events</span>
            <span>Updated</span>
          </div>

          {loading && !data ? (
            <div className="px-6 py-16 text-center text-sm text-slate-600">
              Loading proof records...
            </div>
          ) : proofs.length === 0 ? (
            <div className="px-6 py-16 text-center text-sm text-slate-600">
              No proof records found.
            </div>
          ) : (
            proofs.map((proof) => {
              const meta = statusMeta[proof.status];
              const Icon = meta.icon;

              return (
                <Link
                  href={`/proofs/${proof.proof_id}`}
                  key={proof.proof_id}
                  className="grid grid-cols-[1.7fr_1fr_120px_110px_180px] items-center border-b border-white/[0.05] px-6 py-5 transition hover:bg-white/[0.025]"
                >
                  <div>
                    <p className="font-mono text-sm text-slate-200">
                      {proof.proof_id}
                    </p>
                    <p className="mt-1 text-[11px] text-slate-600">
                      v{proof.version}
                    </p>
                  </div>

                  <p className="truncate pr-6 font-mono text-xs text-slate-500">
                    {proof.request_id ?? "—"}
                  </p>

                  <div>
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-semibold ${meta.className}`}
                    >
                      <Icon size={12} />
                      {meta.label}
                    </span>
                  </div>

                  <p className="text-sm text-slate-400">
                    {proof.events}
                  </p>

                  <p className="text-xs text-slate-500">
                    {new Date(proof.updated_at).toLocaleString()}
                  </p>
                </Link>
              );
            })
          )}
        </section>

        <p className="mt-4 text-right text-[11px] text-slate-600">
          Showing {proofs.length} of {data?.total ?? 0} proofs
        </p>
      </div>
    </main>
  );
}
