"use client";

// Panels shared by the proof detail and verification pages: lifecycle status
// next to the verified chain's closing event, the verifier's reason and the
// position rule, and the chain head to keep outside the service
// (docs/design/proof-closure.md D-C5 to D-C10). Display only; nothing here
// changes the verdict.

import { useState } from "react";
import { AlertTriangle, Copy } from "lucide-react";

import {
  CHAIN_HEAD_NOTE,
  type ChainHeadView,
  type ClosureView,
  type PositionViolation,
  expectHeadCommand,
} from "@/lib/proof-view";

export function ClosurePanel({ closure }: { closure: ClosureView }) {
  return (
    <div className="space-y-1 text-xs">
      <div data-testid="lifecycle-status" className="text-slate-500">
        Lifecycle status (server record):{" "}
        <span className="text-slate-300">{closure.statusLabel}</span>
      </div>
      <div data-testid="closing-event" data-closed={String(closure.closed)} className="text-slate-500">
        Closing event in verified chain: <span className="text-slate-300">{closure.closedLabel}</span>
      </div>
    </div>
  );
}

export function ClosureWarning({ closure }: { closure: ClosureView }) {
  if (!closure.warning) return null;
  return (
    <div
      role="alert"
      data-testid="closure-warning"
      className="mt-5 flex gap-3 rounded-2xl border border-amber-400/30 bg-amber-400/[0.06] p-4 text-xs leading-5 text-amber-200"
    >
      <AlertTriangle size={16} className="mt-0.5 shrink-0" />
      <p>{closure.warning}</p>
    </div>
  );
}

export function VerifierReason({
  reason,
  position,
}: {
  reason: string | null;
  position: PositionViolation | null;
}) {
  const message = position?.message ?? reason;
  if (!message) return null;
  return (
    <div
      role="alert"
      data-testid="verify-reason"
      data-position-violation={String(position !== null)}
      className="mt-5 flex gap-3 rounded-2xl border border-red-400/30 bg-red-400/[0.06] p-4 text-xs leading-5 text-red-200"
    >
      <AlertTriangle size={16} className="mt-0.5 shrink-0" />
      <div>
        <p>Verifier: {message}</p>
        {position && position.sequences.length > 0 && (
          <p className="mt-1 text-red-300/80">
            Out of place: event{position.sequences.length === 1 ? "" : "s"} {position.sequences.join(", ")}.
          </p>
        )}
      </div>
    </div>
  );
}

export function ChainHeadPanel({ view }: { view: ChainHeadView }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    if (!view.head) return;
    try {
      await navigator.clipboard.writeText(view.head);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div data-testid="chain-head-panel" className="space-y-2 text-xs">
      <div className="flex items-center justify-between gap-3">
        <span className="text-slate-500">Chain head</span>
        <span className="flex items-center gap-2">
          <code data-testid="chain-head" data-head={view.head ?? ""} title={view.head ?? undefined} className="text-slate-300">
            {view.headShort}
          </code>
          {view.head && (
            <button
              type="button"
              onClick={copy}
              aria-label="Copy chain head"
              className="rounded border border-white/10 p-1 text-slate-400 hover:text-white"
            >
              <Copy size={12} />
            </button>
          )}
          {copied && <span className="text-slate-500">Copied</span>}
        </span>
      </div>
      <div className="flex justify-between gap-3">
        <span className="text-slate-500">Events in verified chain</span>
        <span data-testid="event-count" className="text-slate-300">{view.eventCount ?? "—"}</span>
      </div>
      <p className="leading-5 text-slate-500">
        {CHAIN_HEAD_NOTE.keep} <code className="break-all text-slate-400">{expectHeadCommand(view.head)}</code>.{" "}
        {CHAIN_HEAD_NOTE.limit}
      </p>
    </div>
  );
}
