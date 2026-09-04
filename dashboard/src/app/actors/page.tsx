"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  CircleDot,
  Fingerprint,
  RefreshCw,
  ShieldCheck,
  UserRound,
  XCircle,
} from "lucide-react";

type Actor = {
  did: string;
  proofs: number;
  active: number;
  completed: number;
  failed: number;
};

type ActorsResponse = {
  items: Actor[];
  count: number;
};

export default function ActorsPage() {
  const [actors, setActors] = useState<Actor[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadActors() {
    try {
      setError("");

      const response = await fetch("/api/flop/actors", {
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error("Failed to load actors");
      }

      const data = (await response.json()) as ActorsResponse;

      setActors(data.items ?? []);
    } catch {
      setError("Actors could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadActors();
  }, []);

  return (
    <main className="min-h-screen bg-[#050505] text-white">
      <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <Link
              href="/"
              className="mb-4 inline-flex items-center gap-2 text-xs text-slate-500 transition hover:text-white"
            >
              <ArrowLeft size={14} />
              Back to Overview
            </Link>

            <div className="flex items-center gap-3">
              <div className="rounded-xl border border-white/[0.08] bg-white/[0.04] p-2.5">
                <Fingerprint size={20} />
              </div>
              <div>
                <h1 className="text-2xl font-semibold tracking-tight">
                  Actors
                </h1>
                <p className="mt-1 text-sm text-slate-500">
                  Identity activity across the proof network
                </p>
              </div>
            </div>
          </div>

          <button
            onClick={loadActors}
            className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-2.5 text-sm text-slate-300 transition hover:bg-white/[0.07] hover:text-white"
          >
            <RefreshCw size={15} />
            Refresh
          </button>
        </div>

        <section className="grid gap-4 sm:grid-cols-3">
          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <UserRound size={14} />
              Unique actors
            </div>
            <div className="mt-3 text-3xl font-semibold">
              {actors.length}
            </div>
          </div>

          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <ShieldCheck size={14} />
              Proof activity
            </div>
            <div className="mt-3 text-3xl font-semibold">
              {actors.reduce((sum, actor) => sum + actor.proofs, 0)}
            </div>
          </div>

          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <CheckCircle2 size={14} />
              Completed
            </div>
            <div className="mt-3 text-3xl font-semibold">
              {actors.reduce((sum, actor) => sum + actor.completed, 0)}
            </div>
          </div>
        </section>

        <section className="mt-6 overflow-hidden rounded-2xl border border-white/[0.07] bg-white/[0.02]">
          <div className="border-b border-white/[0.07] px-5 py-4">
            <h2 className="font-medium">Actor registry</h2>
            <p className="mt-1 text-xs text-slate-500">
              Actors observed in proof events
            </p>
          </div>

          {loading ? (
            <div className="p-10 text-center text-sm text-slate-500">
              Loading actors...
            </div>
          ) : error ? (
            <div className="p-10 text-center text-sm text-red-400">
              {error}
            </div>
          ) : actors.length === 0 ? (
            <div className="p-10 text-center text-sm text-slate-500">
              No actors found in the current proof set.
            </div>
          ) : (
            <div className="divide-y divide-white/[0.06]">
              {actors.map((actor) => (
                <div
                  key={actor.did}
                  className="grid gap-4 px-5 py-5 md:grid-cols-[1fr_auto] md:items-center"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-3">
                      <div className="rounded-lg border border-white/[0.07] bg-white/[0.035] p-2">
                        <Fingerprint size={16} />
                      </div>
                      <div className="min-w-0">
                        <div className="truncate font-mono text-sm text-slate-200">
                          {actor.did}
                        </div>
                        <div className="mt-1 text-xs text-slate-600">
                          DID / cryptographic actor identity
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="rounded-lg border border-white/[0.07] px-3 py-1.5 text-slate-300">
                      {actor.proofs} proofs
                    </span>

                    {actor.active > 0 && (
                      <span className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/20 bg-blue-500/5 px-3 py-1.5 text-blue-300">
                        <CircleDot size={12} />
                        {actor.active} active
                      </span>
                    )}

                    {actor.completed > 0 && (
                      <span className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-1.5 text-emerald-300">
                        <CheckCircle2 size={12} />
                        {actor.completed} completed
                      </span>
                    )}

                    {actor.failed > 0 && (
                      <span className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-1.5 text-red-300">
                        <XCircle size={12} />
                        {actor.failed} failed
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
