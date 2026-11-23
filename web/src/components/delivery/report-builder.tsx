"use client";

import * as React from "react";
import { useSyncExternalStore } from "react";

import { useRouter } from "next/navigation";

import { CheckIcon, FileTextIcon, Loader2Icon, SparklesIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { type ApprovalReview, reviewFinding } from "@/lib/approval-engine";
import {
  addApprovalReview,
  approvalServerVersion,
  approvalVersion,
  getCustomRules,
  getRuleDisabledMap,
  subscribeApproval,
} from "@/lib/approval-store";
import {
  buildFindingSnapshot,
  deliveryReadiness,
  type ReportFindingSnapshot,
  type ReportRecord,
  severityLabel,
} from "@/lib/delivery";
import { createReportRecord, getDeliveryEnrichment, getDeliveryReproduction } from "@/lib/delivery-store";
import { statusMeta } from "@/lib/status";
import type { Finding, Task } from "@/lib/types";
import { cn } from "@/lib/utils";

import { ApprovalVerdictBadge } from "./approval-badge";
import { ApprovalDialog } from "./approval-panel";
import { ReadinessBadge } from "./readiness-badge";

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * ReportBuilder：选择任务与已确认漏洞，按用户提供的 docx 模板导出。
 * 模板只有五段：漏洞标题 / 漏洞危害 / 漏洞描述 / 漏洞复现 / 修复建议。
 */
export function ReportBuilder({
  open,
  onOpenChange,
  presetTaskId,
  onGenerated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  presetTaskId?: string;
  onGenerated?: (record: ReportRecord) => void;
}) {
  const router = useRouter();
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [taskId, setTaskId] = React.useState("");
  const [showAll, setShowAll] = React.useState(false);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [generating, setGenerating] = React.useState(false);
  const [approvalDetail, setApprovalDetail] = React.useState<{
    snapshot: ReportFindingSnapshot;
    review: ApprovalReview;
  } | null>(null);
  const aVersion = useSyncExternalStore(subscribeApproval, approvalVersion, approvalServerVersion);

  const task = tasks.find((item) => item.id === taskId) ?? null;
  const taskLabel = task?.name || task?.description || "";

  React.useEffect(() => {
    if (!open) return;
    setShowAll(false);
    api
      .tasks()
      .then((r) => {
        setTasks(r.tasks);
        const initial = presetTaskId && r.tasks.some((item) => item.id === presetTaskId) ? presetTaskId : "";
        setTaskId(initial);
      })
      .catch(() => setTasks([]));
  }, [open, presetTaskId]);

  React.useEffect(() => {
    if (!open || !taskId) {
      setFindings([]);
      setSelected(new Set());
      return;
    }
    let alive = true;
    setLoading(true);
    api
      .findings(taskId)
      .then((list) => {
        if (!alive) return;
        setFindings(list);
        const confirmed = list.filter(
          (item) => deliveryReadiness(item, getDeliveryEnrichment(item), getDeliveryReproduction(item)).confirmed,
        );
        setSelected(new Set(confirmed.map((item) => item.id)));
      })
      .catch(() => {
        if (alive) setFindings([]);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [open, taskId]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: aVersion 仅用于触发重算
  const rows = React.useMemo(
    () =>
      findings
        .map((finding) => {
          const enrichment = getDeliveryEnrichment(finding);
          const reproduction = getDeliveryReproduction(finding);
          const snapshot = buildFindingSnapshot(finding, enrichment, reproduction);
          return {
            finding,
            enrichment,
            readiness: deliveryReadiness(finding, enrichment, reproduction),
            snapshot,
            review: reviewFinding(snapshot, {
              disabledRules: getRuleDisabledMap(),
              customRules: getCustomRules(),
            }),
          };
        })
        .sort(
          (left, right) => (SEVERITY_ORDER[left.finding.severity] ?? 9) - (SEVERITY_ORDER[right.finding.severity] ?? 9),
        ),
    [findings, aVersion],
  );

  const visible = rows.filter((row) => showAll || row.readiness.confirmed);
  const selectable = visible.map((row) => row.finding.id);
  const allSelected = selectable.length > 0 && selectable.every((id) => selected.has(id));

  const approvalStats = React.useMemo(() => {
    let approved = 0;
    let needsMore = 0;
    let rejected = 0;
    for (const row of visible) {
      if (row.review.verdict === "approved") approved += 1;
      else if (row.review.verdict === "needs_more_evidence") needsMore += 1;
      else rejected += 1;
    }
    return { approved, needsMore, rejected };
  }, [visible]);

  // AI 审批拒绝的漏洞不可上报：自动从勾选中剔除。
  React.useEffect(() => {
    const rejected = new Set(rows.filter((row) => row.review.verdict === "rejected").map((row) => row.finding.id));
    if (rejected.size === 0) return;
    setSelected((prev) => {
      let changed = false;
      const next = new Set(prev);
      for (const id of rejected) {
        if (next.delete(id)) changed = true;
      }
      return changed ? next : prev;
    });
  }, [rows]);

  function toggleAll(next: boolean) {
    setSelected((prev) => {
      const updated = new Set(prev);
      for (const id of selectable) {
        if (next) updated.add(id);
        else updated.delete(id);
      }
      return updated;
    });
  }

  async function generate() {
    if (!task) {
      toast.error("请先选择任务");
      return;
    }
    const picked = findings.filter((finding) => selected.has(finding.id));
    if (picked.length === 0) {
      toast.error("至少勾选一个漏洞");
      return;
    }
    // 上报闸门：未通过 AI 审批（被拒绝）的漏洞一律不得进入报告。
    const blocked = rows.filter((row) => selected.has(row.finding.id) && row.review.verdict === "rejected");
    if (blocked.length > 0) {
      toast.error(`以下漏洞未通过 AI 审批，已阻止上报：${blocked.map((row) => row.enrichment.name).join("、")}`);
      return;
    }
    setGenerating(true);
    try {
      for (const row of rows) {
        if (selected.has(row.finding.id)) addApprovalReview(row.review);
      }
      // 列表接口不带 report 正文；导出前拉详情，补全描述/影响/修复建议。
      const detailed = await Promise.all(
        picked.map(async (finding) => {
          try {
            return await api.getFinding(finding.id, taskId);
          } catch {
            return finding;
          }
        }),
      );
      const record = createReportRecord({
        taskId: task.id,
        taskLabel,
        taskDescription: task.description,
        title: `${taskLabel}·漏洞报告`,
        client: "",
        locale: "zh-CN",
        format: "print",
        findings: detailed,
      });
      onGenerated?.(record);
      onOpenChange(false);
      toast.success(`报告已生成：${record.filename}`);
      router.push(`/function/deliverables/report?id=${record.id}`);
    } catch (error) {
      toast.error(`生成失败：${(error as Error).message}`);
    } finally {
      setGenerating(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileTextIcon className="size-4" />
            导出漏洞报告
          </DialogTitle>
          <DialogDescription>
            按既定模板导出：漏洞标题 / 漏洞危害 / 漏洞描述 / 漏洞复现 / 修复建议。导出前 AI
            审批逐条核查「实际危害」，理论漏洞会被拦截。
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3">
          <Field>
            <FieldLabel>测试任务</FieldLabel>
            <Select value={taskId} onValueChange={setTaskId}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="选择要导出的任务" />
              </SelectTrigger>
              <SelectContent>
                {tasks.map((item) => (
                  <SelectItem key={item.id} value={item.id}>
                    {item.name || item.description}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldDescription>默认只列已确认漏洞；导出时按模板逐条渲染，一个漏洞一节。</FieldDescription>
          </Field>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium">选择漏洞</span>
            <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
              {visible.length} 条
            </Badge>
            <div className="ml-auto flex items-center gap-3">
              <label htmlFor="report-show-all" className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Switch id="report-show-all" checked={showAll} onCheckedChange={setShowAll} />
                显示全部状态
              </label>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-7"
                onClick={() => toggleAll(!allSelected)}
                disabled={visible.length === 0}
              >
                {allSelected ? "取消全选" : "全选"}
              </Button>
            </div>
          </div>

          {taskId && !loading && findings.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/30 px-3 py-2 text-xs">
              <span className="font-medium">AI 审批</span>
              <span className="text-emerald-600 dark:text-emerald-400">通过 {approvalStats.approved}</span>
              <span className="text-amber-600 dark:text-amber-400">需补证 {approvalStats.needsMore}</span>
              <span className="text-red-600 dark:text-red-400">拒绝 {approvalStats.rejected}</span>
              <span className="text-muted-foreground ml-auto">
                {approvalStats.rejected > 0 ? "被拒绝的漏洞已自动取消勾选，补齐实际危害证据后可重审" : "全部可上报"}
              </span>
            </div>
          )}

          {!taskId ? (
            <div className="flex min-h-[12rem] items-center justify-center rounded-lg border border-dashed text-sm text-muted-foreground">
              先选择任务，再勾选要导出的漏洞。
            </div>
          ) : loading ? (
            <div className="flex min-h-[12rem] items-center justify-center rounded-lg border border-dashed text-sm text-muted-foreground">
              <Spinner className="mr-2" /> 加载发现…
            </div>
          ) : visible.length === 0 ? (
            <div className="flex min-h-[12rem] flex-col items-center justify-center gap-2 rounded-lg border border-dashed text-center text-sm text-muted-foreground">
              <CheckIcon className="size-6 opacity-40" />
              该任务暂无已确认漏洞；打开「显示全部状态」可挑选待确认项。
            </div>
          ) : (
            <ScrollArea className="max-h-[46vh] rounded-lg border">
              <div className="divide-y">
                {visible.map(({ finding, enrichment, readiness, snapshot, review }) => {
                  const checked = selected.has(finding.id);
                  const blocked = review.verdict === "rejected";
                  return (
                    <label
                      key={finding.id}
                      htmlFor={`export-finding-${finding.id}`}
                      className={cn(
                        "flex items-start gap-2.5 px-3 py-2.5 transition-colors",
                        blocked ? "opacity-60" : "cursor-pointer",
                        checked && !blocked ? "bg-primary/5" : blocked ? "bg-red-500/5" : "hover:bg-muted/40",
                      )}
                    >
                      <Checkbox
                        id={`export-finding-${finding.id}`}
                        checked={checked}
                        disabled={blocked}
                        onCheckedChange={(value) =>
                          setSelected((prev) => {
                            const next = new Set(prev);
                            if (value === true) next.add(finding.id);
                            else next.delete(finding.id);
                            return next;
                          })
                        }
                        className="mt-0.5"
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span
                            className={cn(
                              "rounded px-1.5 py-0.5 text-[10px] font-medium",
                              finding.severity === "critical"
                                ? "bg-rose-600 text-white"
                                : finding.severity === "high"
                                  ? "bg-red-500/15 text-red-700 dark:text-red-400"
                                  : finding.severity === "medium"
                                    ? "bg-amber-500/15 text-amber-700 dark:text-amber-400"
                                    : "bg-muted text-muted-foreground",
                            )}
                          >
                            {severityLabel(finding.severity)}
                          </span>
                          <span className="truncate text-sm font-medium">{enrichment.name}</span>
                          <code className="text-[10px] text-muted-foreground">#{finding.id}</code>
                          <span className="ml-auto flex shrink-0 items-center gap-1">
                            <ReadinessBadge readiness={readiness} />
                            <button
                              type="button"
                              aria-label="查看 AI 审批详情"
                              onClick={(event) => {
                                event.preventDefault();
                                event.stopPropagation();
                                setApprovalDetail({ snapshot, review });
                              }}
                            >
                              <ApprovalVerdictBadge verdict={review.verdict} score={review.score} />
                            </button>
                          </span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground">
                          <span className="truncate font-mono">{enrichment.target}</span>
                          <span>{statusMeta("finding", finding.status).label}</span>
                          {blocked && <span className="text-red-600 dark:text-red-400">AI 审批拒绝 · 不可上报</span>}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </ScrollArea>
          )}
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button type="button" onClick={() => void generate()} disabled={generating || !taskId || selected.size === 0}>
            {generating ? <Loader2Icon className="animate-spin" /> : <SparklesIcon />}
            {generating ? "生成中" : `导出报告（${selected.size} 个漏洞）`}
          </Button>
        </DialogFooter>
        {approvalDetail && (
          <ApprovalDialog
            open={approvalDetail !== null}
            onOpenChange={(next) => {
              if (!next) setApprovalDetail(null);
            }}
            snapshot={approvalDetail.snapshot}
            findingId={approvalDetail.review.findingId}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
