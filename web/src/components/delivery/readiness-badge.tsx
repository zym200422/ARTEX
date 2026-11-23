"use client";

import { CheckIcon, FileCheck2Icon } from "lucide-react";

import { type DeliveryReadiness, readinessLabel } from "@/lib/delivery";
import { cn } from "@/lib/utils";

const TONE: Record<string, string> = {
  green: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/25",
  amber: "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/25",
  slate: "bg-muted text-muted-foreground border-transparent",
};

export function ReadinessBadge({ readiness, className }: { readiness: DeliveryReadiness; className?: string }) {
  const meta = readinessLabel(readiness);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap",
        TONE[meta.tone],
        className,
      )}
      title={`交付就绪度 ${readiness.score}/4`}
    >
      <FileCheck2Icon className="size-3" />
      {meta.label}
    </span>
  );
}

/** 交付就绪清单：四项硬指标，报告里也复用同一口径。 */
export function DeliveryChecklist({ readiness }: { readiness: DeliveryReadiness }) {
  const items = [
    { label: "漏洞已确认", done: readiness.confirmed },
    { label: "结构化复现", done: readiness.has_repro },
    { label: "请求/响应证据", done: readiness.has_evidence },
    { label: "描述/影响/修复", done: readiness.has_narrative },
  ];
  return (
    <ul className="space-y-1.5">
      {items.map((item) => (
        <li key={item.label} className="flex items-center gap-2 text-xs">
          <span
            className={cn(
              "flex size-4 shrink-0 items-center justify-center rounded-full border",
              item.done
                ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                : "border-border text-muted-foreground/50",
            )}
          >
            {item.done && <CheckIcon className="size-2.5" />}
          </span>
          <span className={item.done ? "" : "text-muted-foreground"}>{item.label}</span>
        </li>
      ))}
    </ul>
  );
}
