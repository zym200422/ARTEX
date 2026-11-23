"use client";

import { type ApprovalVerdict, VERDICT_META } from "@/lib/approval-engine";
import { cn } from "@/lib/utils";

/** 审批结论徽章：通过 / 需补证 / 拒绝上报。 */
export function ApprovalVerdictBadge({
  verdict,
  score,
  className,
}: {
  verdict: ApprovalVerdict;
  score?: number;
  className?: string;
}) {
  const meta = VERDICT_META[verdict];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap",
        meta.tone,
        className,
      )}
      title={score != null ? `${meta.label} · 规则通过率 ${score}%` : meta.label}
    >
      {meta.label}
      {score != null && <span className="tabular-nums opacity-80">{score}%</span>}
    </span>
  );
}
