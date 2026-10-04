"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowLeft,
  CheckCircle2,
  CircleHelp,
  RefreshCw,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  XCircle,
} from "lucide-react";

import { verifyBoundary } from "@/lib/evidence-boundary";
import {
  type CardTone,
  type VerifyState,
  cardTone,
  eventRows,
  evidenceChecks,
  statusLabel,
  verdictBadge,
} from "@/lib/proof-view";
import { isProofId } from "@/lib/proxy-policy";

type ProofItem = {
  proof_id: string;
  status: string;
  events: number;
  created_at: string;
};

const VERDICT_STYLE = {
  valid: { icon: ShieldCheck, box: "border-emerald-500/20 bg-emerald-500/[0.04]", text: "text-emerald-300" },
  invalid: { icon: ShieldX, box: "border-red-500/20 bg-red-500/[0.04]", text: "text-red-300" },
  unknown: { icon: ShieldQuestion, box: "border-slate-500/20 bg-slate-500/[0.04]", text: "text-slate-300" },
};

const CARD_STYLE: Record<CardTone, { icon: typeof CheckCircle2; className: string; text: string }> = {
  pass: { icon: CheckCircle2, className: "text-emerald-400", text: "Pass" },
  "pass-muted": { icon: CheckCircle2, className: "text-slate-400", text: "Pass" },
  fail: { icon: XCircle, className: "text-red-400", text: "Fail" },
  unknown: { icon: CircleHelp, className: "text-slate-500", text: "Not available" },
};

const INVALID_ID_MESSAGE =
  "Enter a proof ID of the form proof_ followed by 32 hex characters.";

export default function VerificationPage() {
  // useSearchParams needs a Suspense boundary for static rendering.
  return (
    <Suspense>
      <VerificationCenter />
    </Suspense>
  );
}

function VerificationCenter() {
  // ?proof_id=… preselects a proof (e.g. linked from a proof page).
  const requested = useSearchParams().get("proof_id");
  const requestedIsValid = requested !== null && isProofId(requested);

  const [proofs, setProofs] = useState<ProofItem[]>([]);
  const [input, setInput] = useState(requested ?? "");
  const [inputError, setInputError] = useState(
    requested !== null && !requestedIsValid ? INVALID_ID_MESSAGE : "",
  );
  // Each submit creates a new request; results are stored with the request
  // they answer, so a stale or in-flight result is never shown as current.
  const [request, setRequest] = useState<{ proofId: string; id: number } | null>(
    requestedIsValid ? { proofId: requested, id: 0 } : null,
  );
  const [result, setResult] = useState<{
    requestId: number;
    verify: VerifyState;
    events: unknown[];
  } | null>(null);

  useEffect(() => {
    fetch("/api/flop/proofs?limit=100", { cache: "no-store" })
      .then((response) => (response.ok ? response.json() : { items: [] }))
      .then((data) => setProofs(Array.isArray(data.items) ? data.items : []))
      .catch(() => setProofs([]));
  }, []);

  useEffect(() => {
    if (request === null) return;
    let cancelled = false;
    const { proofId, id } = request;

    Promise.allSettled([
      fetch(`/api/flop/proofs/${proofId}/verify`, { cache: "no-store" }).then(async (response) => {
        if (!response.ok) throw new Error(`Verify returned ${response.status}`);
        return response.json();
      }),
      fetch(`/api/flop/proofs/${proofId}`, { cache: "no-store" }).then(async (response) => {
        if (!response.ok) throw new Error(`API returned ${response.status}`);
        return response.json();
      }),
    ]).then(([verifyResult, proofResult]) => {
      if (cancelled) return;
      setResult({
        requestId: id,
        verify:
          verifyResult.status === "fulfilled"
            ? { kind: "result", data: verifyResult.value }
            : {
                kind: "error",
                message:
                  verifyResult.reason instanceof Error
                    ? verifyResult.reason.message
                    : "Verification failed",
              },
        events:
          proofResult.status === "fulfilled" && Array.isArray(proofResult.value?.events)
            ? proofResult.value.events
            : [],
      });
    });

    return () => {
      cancelled = true;
    };
  }, [request]);

  function submit(proofId: string) {
    if (!isProofId(proofId)) {
      setInputError(INVALID_ID_MESSAGE);
      return;
    }
    setInputError("");
    setRequest((previous) => ({ proofId, id: (previous?.id ?? 0) + 1 }));
  }

  const current = request !== null && result?.requestId === request.id ? result : null;
  const verify: VerifyState | null =
    request === null ? null : current ? current.verify : { kind: "loading" };
  const events = current?.events ?? [];
  const selected = request?.proofId ?? null;

  const badge = verify ? verdictBadge(verify) : null;
  const verifyData = verify?.kind === "result" ? verify.data : null;
  const checks = evidenceChecks(verifyData);
  const rows = eventRows(events, verifyData);

  return (
    <main className="min-h-screen bg-[#050505] text-white">
      <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">
        <div className="mb-8">
          <Link
            href="/"
            className="mb-5 inline-flex items-center gap-2 text-xs text-slate-500 transition hover:text-white"
          >
            <ArrowLeft size={14} />
            Back to Overview
          </Link>

          <div className="text-xs font-medium uppercase tracking-[0.2em] text-slate-400">
            Proof verification
          </div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">Verification Center</h1>
          <p className="mt-1 text-sm text-slate-500">
            Check a proof&apos;s signatures, event chain, payload hashes and actor authorization.
            This does not verify execution or settlement.
          </p>
        </div>

        <section className="mb-6 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
          <form
            className="flex flex-col gap-3 sm:flex-row"
            onSubmit={(event) => {
              event.preventDefault();
              submit(input.trim());
            }}
          >
            <select
              aria-label="Choose a proof"
              className="rounded-xl border border-white/[0.08] bg-black/40 px-3 py-2.5 font-mono text-xs text-slate-300 sm:w-[420px]"
              value={proofs.some((p) => p.proof_id === input) ? input : ""}
              onChange={(event) => setInput(event.target.value)}
            >
              <option value="">Choose a recent proof…</option>
              {proofs.map((proof) => (
                <option key={proof.proof_id} value={proof.proof_id}>
                  {proof.proof_id} ({statusLabel(proof.status)})
                </option>
              ))}
            </select>
            <input
              aria-label="Proof ID"
              placeholder="or paste a proof ID"
              className="flex-1 rounded-xl border border-white/[0.08] bg-black/40 px-3 py-2.5 font-mono text-xs text-slate-300"
              value={input}
              onChange={(event) => setInput(event.target.value)}
            />
            <button
              type="submit"
              disabled={verify?.kind === "loading"}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.06] px-4 py-2.5 text-sm text-slate-200 transition hover:bg-white/[0.1] disabled:opacity-50"
            >
              <RefreshCw size={15} className={verify?.kind === "loading" ? "animate-spin" : ""} />
              Verify
            </button>
          </form>
          {inputError && <p className="mt-3 text-xs text-red-300">{inputError}</p>}
        </section>

        {!verify || !badge ? (
          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-12 text-center text-sm text-slate-500">
            Choose or enter a proof to verify.
          </div>
        ) : (
          <>
            <section
              data-testid="verdict-badge"
              data-verdict={badge.tone}
              className={`rounded-2xl border p-6 ${VERDICT_STYLE[badge.tone].box}`}
            >
              <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
                <div className="flex items-center gap-4">
                  {(() => {
                    const Icon = VERDICT_STYLE[badge.tone].icon;
                    return <Icon size={28} className={VERDICT_STYLE[badge.tone].text} />;
                  })()}
                  <div>
                    <div className="text-xs uppercase tracking-[0.18em] text-slate-500">
                      Verification verdict
                    </div>
                    <div className={`mt-1 text-3xl font-semibold ${VERDICT_STYLE[badge.tone].text}`}>
                      {badge.label}
                    </div>
                    {badge.detail && <p className="mt-1 text-xs text-slate-500">{badge.detail}</p>}
                  </div>
                </div>
                {selected && (
                  <div className="max-w-full md:max-w-md">
                    <div className="text-xs text-slate-500">Proof ID</div>
                    <Link
                      href={`/proofs/${selected}`}
                      className="mt-1 block truncate font-mono text-xs text-slate-300 hover:text-white"
                    >
                      {selected}
                    </Link>
                  </div>
                )}
              </div>
            </section>

            <section className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
              {checks.map((check) => {
                const style = CARD_STYLE[cardTone(check.ok, badge.tone)];
                const Icon = style.icon;
                return (
                  <div
                    key={check.key}
                    data-check={check.key}
                    data-ok={String(check.ok)}
                    className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5"
                  >
                    <Icon size={19} className={style.className} />
                    <div className="mt-4 text-sm font-medium">{check.label}</div>
                    <div className={`mt-1 text-xs ${style.className}`}>{style.text}</div>
                  </div>
                );
              })}
            </section>

            {rows.length > 0 && (
              <section className="mt-6 overflow-hidden rounded-2xl border border-white/[0.07] bg-white/[0.02]">
                <div className="grid grid-cols-[60px_1fr_1.4fr_120px_1fr] border-b border-white/[0.07] px-5 py-3 text-[10px] uppercase tracking-[0.16em] text-slate-600">
                  <span>Seq</span>
                  <span>Event</span>
                  <span>Actor</span>
                  <span>Role</span>
                  <span>Authorized</span>
                </div>
                {rows.map((row) => (
                  <div
                    key={row.index}
                    data-event-sequence={row.sequence ?? ""}
                    data-role={row.role}
                    data-authorized={String(row.authorized)}
                    className={`grid grid-cols-[60px_1fr_1.4fr_120px_1fr] items-center border-b border-white/[0.05] px-5 py-3 text-xs ${
                      row.flagged ? "bg-red-400/[0.06] text-red-200" : "text-slate-300"
                    }`}
                  >
                    <span>{row.sequence ?? "—"}</span>
                    <span>{row.type}</span>
                    <span className="font-mono" title={row.actorDid ?? undefined}>
                      {row.actorShort}
                    </span>
                    <span>{row.roleLabel}</span>
                    <span>
                      {row.authorized === null ? "Unknown" : row.authorized ? "Yes" : "No"}
                      {row.authorizationReason && (
                        <span className="ml-2 font-mono">({row.authorizationReason})</span>
                      )}
                    </span>
                  </div>
                ))}
              </section>
            )}

            <p className="mt-4 text-xs text-slate-500">
              <code>/verify</code> does not prove: {verifyBoundary.doesNotProve}
            </p>

            <section className="mt-6 rounded-2xl border border-white/[0.07] bg-white/[0.02]">
              <div className="border-b border-white/[0.07] px-5 py-5">
                <h2 className="font-medium">Verification response</h2>
                <p className="mt-1 text-xs text-slate-500">Raw response returned by the API.</p>
              </div>
              <pre className="max-h-[420px] overflow-auto p-5 text-xs leading-6 text-slate-400">
                {verify.kind === "result"
                  ? JSON.stringify(verify.data, null, 2)
                  : verify.kind === "error"
                    ? verify.message
                    : "…"}
              </pre>
            </section>
          </>
        )}
      </div>
    </main>
  );
}
