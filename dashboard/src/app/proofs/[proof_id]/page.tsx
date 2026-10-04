"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  CircleHelp,
  Fingerprint,
  Hash,
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
  evidenceSummary,
  statusLabel,
  verdictBadge,
} from "@/lib/proof-view";

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

const VERDICT_STYLE = {
  valid: { icon: ShieldCheck, className: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300" },
  invalid: { icon: ShieldX, className: "border-red-400/20 bg-red-400/10 text-red-300" },
  unknown: { icon: ShieldQuestion, className: "border-slate-400/20 bg-slate-400/10 text-slate-300" },
};

const CHECK_STYLE: Record<CardTone, { icon: typeof CheckCircle2; className: string; text: string }> = {
  pass: { icon: CheckCircle2, className: "text-emerald-400", text: "Pass" },
  "pass-muted": { icon: CheckCircle2, className: "text-slate-400", text: "Pass" },
  fail: { icon: XCircle, className: "text-red-400", text: "Fail" },
  unknown: { icon: CircleHelp, className: "text-slate-500", text: "Not available" },
};

function formatValue(value: unknown) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

function yesNo(value: boolean | null) {
  return value === null ? "Unknown" : value ? "Yes" : "No";
}

export default function ProofDetailPage({
  params,
}: {
  params: Promise<{ proof_id: string }>;
}) {
  const [proof, setProof] = useState<ProofDetail | null>(null);
  const [verify, setVerify] = useState<VerifyState>({ kind: "loading" });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [proofId, setProofId] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const resolved = await params;
      if (cancelled) return;
      setProofId(resolved.proof_id);
      const id = encodeURIComponent(resolved.proof_id);

      const loadProof = fetch(`/api/flop/proofs/${id}`, { cache: "no-store" }).then(
        async (response) => {
          if (!response.ok) throw new Error(`API returned ${response.status}`);
          return response.json();
        },
      );
      const loadVerify = fetch(`/api/flop/proofs/${id}/verify`, { cache: "no-store" }).then(
        async (response) => {
          if (!response.ok) throw new Error(`Verify returned ${response.status}`);
          return response.json();
        },
      );

      const [proofResult, verifyResult] = await Promise.allSettled([loadProof, loadVerify]);
      if (cancelled) return;

      if (proofResult.status === "fulfilled") {
        setProof(proofResult.value);
        setError(null);
      } else {
        setError(
          proofResult.reason instanceof Error ? proofResult.reason.message : "Unable to load proof",
        );
      }

      setVerify(
        verifyResult.status === "fulfilled"
          ? { kind: "result", data: verifyResult.value }
          : {
              kind: "error",
              message:
                verifyResult.reason instanceof Error
                  ? verifyResult.reason.message
                  : "Unable to verify proof",
            },
      );
      setLoading(false);
    }

    load();

    return () => {
      cancelled = true;
    };
  }, [params]);

  const badge = verdictBadge(verify);
  const verdictStyle = VERDICT_STYLE[badge.tone];
  const VerdictIcon = verdictStyle.icon;
  const verifyData = verify.kind === "result" ? verify.data : null;
  const checks = evidenceChecks(verifyData);
  const evidence = evidenceSummary(verifyData);
  const events = Array.isArray(proof?.events) ? proof.events : [];
  const rows = eventRows(events, verifyData);

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
            Loading proof and verification...
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
                <p className="text-[10px] uppercase tracking-[0.22em] text-slate-400">
                  Proof Explorer
                </p>
                <h1 className="mt-2 break-all font-mono text-2xl font-semibold tracking-tight lg:text-3xl">
                  {proof.proof_id}
                </h1>
                <p className="mt-3 text-sm text-slate-500">
                  Proof record and the result of <code>/verify</code> for it.
                </p>
              </div>

              <div className="flex flex-col items-start gap-2 lg:items-end">
                <div
                  data-testid="verdict-badge"
                  data-verdict={badge.tone}
                  className={`inline-flex w-fit items-center gap-2 rounded-full border px-3 py-2 text-xs font-semibold ${verdictStyle.className}`}
                >
                  <VerdictIcon size={14} />
                  Verification: {badge.label}
                </div>
                {badge.detail && <p className="text-xs text-slate-500">{badge.detail}</p>}
                <div className="text-xs text-slate-500">
                  Lifecycle status: <span className="text-slate-300">{statusLabel(proof.status)}</span>
                </div>
              </div>
            </header>

            <div className="grid gap-5 lg:grid-cols-3">
              <section className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-6 lg:col-span-2">
                <div className="mb-5 flex items-center gap-3">
                  <div className="rounded-xl bg-white/[0.04] p-2.5">
                    <Fingerprint size={18} className="text-slate-300" />
                  </div>
                  <div>
                    <h2 className="text-sm font-semibold">Proof identity</h2>
                    <p className="text-xs text-slate-600">Core record metadata</p>
                  </div>
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  {[
                    ["Proof ID", proof.proof_id],
                    ["Request ID", proof.request_id],
                    ["Version", proof.version],
                    ["Status", statusLabel(proof.status)],
                    ["Created", proof.created_at],
                    ["Updated", proof.updated_at],
                  ].map(([label, value]) => (
                    <div key={label} className="rounded-xl border border-white/[0.06] bg-black/20 p-4">
                      <p className="text-[10px] uppercase tracking-[0.16em] text-slate-600">{label}</p>
                      <p className="mt-2 break-all font-mono text-xs leading-5 text-slate-300">
                        {value ?? "—"}
                      </p>
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-6">
                <h2 className="text-sm font-semibold">Verification evidence</h2>
                <p className="text-xs text-slate-600">Per-check results from /verify</p>

                <div className="mt-6 space-y-3">
                  {checks.map((check) => {
                    const style = CHECK_STYLE[cardTone(check.ok, badge.tone)];
                    const Icon = style.icon;
                    return (
                      <div
                        key={check.key}
                        data-check={check.key}
                        data-ok={String(check.ok)}
                        className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-black/20 px-4 py-3"
                      >
                        <span className="text-xs text-slate-400">{check.label}</span>
                        <span className={`flex items-center gap-1.5 text-xs ${style.className}`}>
                          <Icon size={15} />
                          {style.text}
                        </span>
                      </div>
                    );
                  })}
                </div>

                <div className="mt-6 space-y-2 border-t border-white/[0.06] pt-5 text-xs">
                  <div className="flex justify-between gap-3">
                    <span className="text-slate-500">Evidence class</span>
                    <code className="text-slate-300">{evidence.evidenceClass ?? "—"}</code>
                  </div>
                  <div className="flex justify-between gap-3">
                    <span className="text-slate-500">Execution verified</span>
                    <span className="text-slate-300">{yesNo(evidence.executionVerified)}</span>
                  </div>
                  <div className="flex justify-between gap-3">
                    <span className="text-slate-500">Runtime settled</span>
                    <span className="text-slate-300">{yesNo(evidence.runtimeSettled)}</span>
                  </div>
                  {(evidence.executionVerified === false || evidence.runtimeSettled === false) && (
                    <p className="pt-2 leading-5 text-slate-500">
                      <code>/verify</code> does not prove: {verifyBoundary.doesNotProve}
                    </p>
                  )}
                </div>
              </section>
            </div>

            <section className="mt-5 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-6">
              <div className="mb-6">
                <h2 className="text-sm font-semibold">Event timeline</h2>
                <p className="mt-1 text-xs text-slate-600">
                  {events.length} event{events.length === 1 ? "" : "s"} recorded
                </p>
              </div>

              {rows.length === 0 ? (
                <div className="rounded-xl border border-white/[0.06] bg-black/20 p-8 text-center text-xs text-slate-600">
                  No events available.
                </div>
              ) : (
                <div className="space-y-3">
                  {rows.map((row) => (
                    <div
                      key={row.index}
                      data-event-sequence={row.sequence ?? ""}
                      data-role={row.role}
                      data-authorized={String(row.authorized)}
                      className={`rounded-xl border p-5 ${
                        row.flagged
                          ? "border-red-400/30 bg-red-400/[0.05]"
                          : "border-white/[0.06] bg-black/20"
                      }`}
                    >
                      <div className="flex items-start gap-4">
                        <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-xs font-semibold text-slate-300">
                          {row.sequence ?? row.index + 1}
                        </div>

                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium text-slate-200">{row.type}</p>

                          <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-3">
                            <div>
                              <dt className="text-[10px] uppercase tracking-[0.14em] text-slate-600">Actor</dt>
                              <dd className="mt-1 font-mono text-slate-300" title={row.actorDid ?? undefined}>
                                {row.actorShort}
                              </dd>
                            </div>
                            <div>
                              <dt className="text-[10px] uppercase tracking-[0.14em] text-slate-600">Role</dt>
                              <dd className={`mt-1 ${row.flagged ? "text-red-300" : "text-slate-300"}`}>
                                {row.roleLabel}
                              </dd>
                            </div>
                            <div>
                              <dt className="text-[10px] uppercase tracking-[0.14em] text-slate-600">Authorized</dt>
                              <dd className={`mt-1 ${row.flagged ? "text-red-300" : "text-slate-300"}`}>
                                {yesNo(row.authorized)}
                                {row.authorizationReason && (
                                  <span className="ml-2 font-mono text-red-300">({row.authorizationReason})</span>
                                )}
                              </dd>
                            </div>
                          </dl>

                          <pre className="mt-4 overflow-x-auto rounded-lg border border-white/[0.05] bg-[#06080c] p-4 text-[11px] leading-5 text-slate-500">
                            {formatValue(events[row.index])}
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
                  <p className="text-xs text-slate-600">API response for independent inspection</p>
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
