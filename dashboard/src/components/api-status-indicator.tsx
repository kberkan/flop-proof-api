"use client";

import { useEffect, useState } from "react";

import {
  type ApiStatus,
  type HealthCheck,
  apiStatusBadge,
  checkHealth,
} from "@/lib/api-status";

const STATUS_STYLE: Record<ApiStatus, { box: string; dot: string }> = {
  operational: {
    box: "border-emerald-500/20 bg-emerald-500/5 text-emerald-300",
    dot: "bg-emerald-400",
  },
  checking: { box: "border-white/[0.08] bg-white/[0.03] text-slate-400", dot: "bg-slate-500" },
  unreachable: { box: "border-red-500/20 bg-red-500/5 text-red-300", dot: "bg-red-400" },
  error: { box: "border-amber-500/20 bg-amber-500/5 text-amber-300", dot: "bg-amber-400" },
};

/**
 * API status from GET /health (src/lib/api-status.ts). Checks once when shown,
 * and again only when Retry is pressed; no polling. "stacked" is the narrow
 * layout used in the overview sidebar.
 */
export function ApiStatusIndicator({ layout = "inline" }: { layout?: "inline" | "stacked" }) {
  // Each check is an attempt; the result is stored with the attempt it
  // answers, so "Checking…" is derived and never set inside the effect.
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<{ attempt: number; check: HealthCheck } | null>(null);

  useEffect(() => {
    let cancelled = false;
    checkHealth(fetch).then((check) => {
      if (!cancelled) setResult({ attempt, check });
    });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const check: HealthCheck =
    result !== null && result.attempt === attempt ? result.check : { kind: "checking" };
  const badge = apiStatusBadge(check);
  const style = STATUS_STYLE[badge.status];

  return (
    <div className={layout === "stacked" ? "flex flex-col items-start gap-2" : "flex items-center gap-2"}>
      <div
        data-testid="api-status"
        data-status={badge.status}
        title={badge.detail ?? undefined}
        className={`flex items-center gap-2 rounded-xl border px-4 py-2.5 text-xs ${style.box}`}
      >
        <span className={`h-2 w-2 rounded-full ${style.dot}`} />
        {badge.label}
        {badge.detail && <span className="text-slate-500">({badge.detail})</span>}
      </div>
      {badge.status !== "operational" && badge.status !== "checking" && (
        <button
          type="button"
          onClick={() => setAttempt((previous) => previous + 1)}
          className="rounded-xl border border-white/[0.08] bg-white/[0.04] px-3 py-2.5 text-xs text-slate-300 transition hover:bg-white/[0.08]"
        >
          Retry
        </button>
      )}
    </div>
  );
}
