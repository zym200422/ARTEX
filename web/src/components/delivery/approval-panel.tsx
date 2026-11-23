"use client";

import * as React from "react";

import { CheckIcon, SparklesIcon, XIcon } from "lucide-react";

import { ApprovalVerdictBadge } from "@/components/delivery/approval-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { ACTION_META, type ApprovalReview, type ApprovalVerdict, reviewFinding } from "@/lib/approval-engine";
import { addApprovalReview, getCustomRules, getRuleDisabledMap, subscribeApproval } from "@/lib/approval-store";
import type { ReportFindingSnapshot } from "@/lib/delivery";
import { cn } from "@/lib/utils";

const VERDICT_DESC: Record<ApprovalVerdict, string> = {
  approved: "满足上报要求，可进入报告",
  needs_more_evidence: "有漏洞方向但证据不足，补证后重审",
  rejected: "未达到实际上报标准（理论漏洞/证据不足）",
};

function RuleRow({ hit }: { hit: ApprovalReview["hits"][number] }) {
  const meta = ACTION_META[hit.action];
  return (
    <div
      className={cn(
        "flex items-start gap-2 rounded-md border px-2.5 py-2",
        hit.passed
          ? "border-border"
          : hit.action === "reject"
            ? "border-red-500/30 bg-red-500/5"
            : "border-amber-500/30 bg-amber-500/5",
      )}
    >
      <span
        className={cn(
          "mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border",
          hit.passed
            ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
            : "border-border text-muted-foreground",
        )}
      >
        {hit.passed ? <CheckIcon className="size-2.5" /> : <XIcon className="size-2.5" />}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className={cn("text-xs font-medium", hit.passed ? "" : "text-foreground")}>{hit.ruleName}</span>
          <Badge variant="outline" className={cn("h-4 px-1 text-[9px]", meta.tone)}>
            {meta.label}
          </Badge>
          {hit.custom && (
            <Badge variant="secondary" className="h-4 px-1 text-[9px]">
              自定义
            </Badge>
          )}
        </div>
        <p className="mt-0.5 text-muted-foreground text-[11px] leading-relaxed">{hit.detail}</p>
      </div>
    </div>
  );
}

/** 单个漏洞的 AI 审批结果面板：结论 + 逐条规则命中 + 补证清单。 */
export function ApprovalPanel({ snapshot }: { snapshot: ReportFindingSnapshot }) {
  const [review, setReview] = React.useState<ApprovalReview | null>(null);

  React.useEffect(() => {
    const run = () => {
      const result = reviewFinding(snapshot, {
        disabledRules: getRuleDisabledMap(),
        customRules: getCustomRules(),
      });
      setReview(result);
      addApprovalReview(result);
    };
    run();
    return subscribeApproval(() => {
      const result = reviewFinding(snapshot, {
        disabledRules: getRuleDisabledMap(),
        customRules: getCustomRules(),
      });
      setReview(result);
    });
  }, [snapshot]);

  if (!review) {
    return <p className="text-muted-foreground text-sm">AI 审批中…</p>;
  }

  const failed = review.hits.filter((hit) => !hit.passed);
  const passed = review.hits.filter((hit) => hit.passed);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <ApprovalVerdictBadge verdict={review.verdict} score={review.score} />
        <span className="text-muted-foreground text-xs">{VERDICT_DESC[review.verdict]}</span>
      </div>
      <Progress value={review.score} className="h-1.5" />
      <p className="text-sm leading-relaxed">{review.summary}</p>

      {review.fixes.length > 0 && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
          <div className="text-xs font-medium">补证清单（处理后可重新审批）</div>
          <ul className="mt-1.5 space-y-1 text-xs text-muted-foreground">
            {review.fixes.map((fix, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: 静态列表
              <li key={index} className="flex gap-1.5">
                <span className="mt-1.5 size-1 shrink-0 rounded-full bg-amber-500/70" />
                {fix}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="space-y-1.5">
        {failed.map((hit) => (
          <RuleRow key={`${hit.ruleId}-${hit.ruleName}`} hit={hit} />
        ))}
        {passed.map((hit) => (
          <RuleRow key={`${hit.ruleId}-${hit.ruleName}`} hit={hit} />
        ))}
      </div>
    </div>
  );
}

/** AI 审批弹窗：发现详情「AI 审批」入口与报告生成前复核共用。 */
export function ApprovalDialog({
  open,
  onOpenChange,
  snapshot,
  findingId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  snapshot: ReportFindingSnapshot;
  findingId?: string;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[88vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <SparklesIcon className="size-4" />
            AI 上报审批{findingId ? ` · #${findingId}` : ""}
          </DialogTitle>
          <DialogDescription>
            依据审批规则库逐条核查「实际危害」：有真实危害证据才允许上报，理论漏洞一律拦截。规则可在「上报审批」页增删。
          </DialogDescription>
        </DialogHeader>
        <ApprovalPanel snapshot={snapshot} />
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            关闭
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
