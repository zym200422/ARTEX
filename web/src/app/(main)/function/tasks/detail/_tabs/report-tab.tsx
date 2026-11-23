"use client";

import * as React from "react";

import Link from "next/link";

import { EyeIcon, FileDownIcon, FileTextIcon, Loader2Icon, SparklesIcon } from "lucide-react";
import { toast } from "sonner";

import { ReportBuilder } from "@/components/delivery/report-builder";
import { SourceHintCard } from "@/components/delivery/source-hint-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { deliveryReadiness, type ReportRecord } from "@/lib/delivery";
import { getDeliveryEnrichment, getDeliveryReproduction, getReports } from "@/lib/delivery-store";
import type { Finding } from "@/lib/types";

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleString("zh-CN", { hour12: false });
}

/**
 * 任务详情「报告」页：交付就绪度 + 历史报告 + 导出入口。
 * 导出的 Word 严格按既有漏洞报告模板（五段），不含其他内容。
 */
export function ReportTab({
  taskId,
  taskDescription,
  taskAssets,
}: {
  taskId: string;
  taskDescription?: string;
  taskAssets?: { label?: string }[];
}) {
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [reports, setReports] = React.useState<ReportRecord[]>([]);
  const [builderOpen, setBuilderOpen] = React.useState(false);
  const [wordBusyId, setWordBusyId] = React.useState<number | null>(null);

  const reload = React.useCallback(() => {
    setReports(getReports().filter((item) => item.task_id === taskId));
  }, [taskId]);

  React.useEffect(() => {
    let active = true;
    api
      .findings(taskId)
      .then((list) => {
        if (active) setFindings(list);
      })
      .catch(() => {
        if (active) setFindings([]);
      });
    reload();
    return () => {
      active = false;
    };
  }, [taskId, reload]);

  const missingReports = React.useMemo(() => findings.filter((f) => !f.report?.trim()).length, [findings]);
  const [backfilling, setBackfilling] = React.useState(false);

  async function backfillReports() {
    setBackfilling(true);
    try {
      const result = await api.backfillFindingReports({ taskId, limit: 50 });
      if (result.started === 0) {
        toast.info(result.missing === 0 ? "该任务的漏洞都已有详细报告" : "没有可补写的漏洞（可能已在补写中）");
      } else {
        toast.success(`已启动 ${result.started} 个漏洞的报告补写，稍后刷新查看`);
      }
    } catch (error) {
      toast.error(`补写失败：${(error as Error).message}`);
    } finally {
      setBackfilling(false);
    }
  }

  const summary = React.useMemo(() => {
    let confirmed = 0;
    let withRepro = 0;
    let withEvidence = 0;
    let ready = 0;
    for (const finding of findings) {
      const readiness = deliveryReadiness(finding, getDeliveryEnrichment(finding), getDeliveryReproduction(finding));
      if (readiness.confirmed) confirmed += 1;
      if (readiness.has_repro) withRepro += 1;
      if (readiness.has_evidence) withEvidence += 1;
      if (readiness.score >= 4) ready += 1;
    }
    const total = findings.length;
    return {
      total,
      confirmed,
      withRepro,
      withEvidence,
      ready,
      pct: total > 0 ? Math.round((ready / total) * 100) : 0,
    };
  }, [findings]);

  const latest = reports[0] ?? null;

  async function downloadWord(record: ReportRecord) {
    setWordBusyId(record.id);
    try {
      const { downloadReportDocx } = await import("@/lib/report-docx");
      await downloadReportDocx(record.snapshot, record.filename.replace(/\.md$/, ".docx"));
      toast.success("Word 报告已生成");
    } catch (error) {
      toast.error(`Word 生成失败：${(error as Error).message}`);
    } finally {
      setWordBusyId(null);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-1.5 text-sm">
              <FileTextIcon className="size-4" />
              报告导出
            </CardTitle>
            <CardDescription>按模板导出：漏洞标题 / 漏洞危害 / 漏洞描述 / 漏洞复现 / 修复建议。</CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            {latest && (
              <Button asChild size="sm" variant="outline">
                <Link href={`/function/deliverables/report?id=${latest.id}`}>
                  <EyeIcon data-icon="inline-start" />
                  预览最新
                </Link>
              </Button>
            )}
            {missingReports > 0 && (
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={backfilling}
                onClick={() => void backfillReports()}
              >
                {backfilling ? <Loader2Icon className="animate-spin" /> : <FileTextIcon className="size-3.5" />}
                {backfilling ? "补写中" : `补写详细报告（${missingReports}）`}
              </Button>
            )}
            <Button type="button" size="sm" onClick={() => setBuilderOpen(true)}>
              <SparklesIcon data-icon="inline-start" />
              导出漏洞报告
            </Button>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              { label: "漏洞总数", value: summary.total },
              { label: "已确认", value: summary.confirmed },
              { label: "含复现", value: summary.withRepro },
              { label: "含证据", value: summary.withEvidence },
            ].map((item) => (
              <div key={item.label} className="rounded-lg border px-3 py-2">
                <div className="text-lg leading-none font-semibold tabular-nums">{item.value}</div>
                <div className="mt-1 text-muted-foreground text-[11px]">{item.label}</div>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-3">
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
              <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${summary.pct}%` }} />
            </div>
            <span className="text-muted-foreground shrink-0 text-xs tabular-nums">
              可交付 {summary.ready}/{summary.total}（{summary.pct}%）
            </span>
          </div>
          <p className="text-muted-foreground text-xs leading-relaxed">
            「可交付」需同时满足：已确认、有结构化复现、有请求/响应证据、有描述/影响/修复。可在发现详情页编辑交付内容后重新导出。
          </p>
        </CardContent>
      </Card>

      <SourceHintCard description={taskDescription} assets={taskAssets} findings={findings} />

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">历史报告</CardTitle>
          <CardDescription>本任务已生成的报告快照。</CardDescription>
        </CardHeader>
        <CardContent>
          {reports.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed py-10 text-sm text-muted-foreground">
              <FileTextIcon className="size-7 opacity-40" />
              还没有生成过报告。
            </div>
          ) : (
            <div className="divide-y">
              {reports.map((record) => (
                <div key={record.id} className="flex flex-wrap items-center gap-2 py-2.5">
                  <FileTextIcon className="size-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{record.title}</div>
                    <div className="truncate text-muted-foreground text-[11px]">
                      {record.filename} · {record.finding_count} 个漏洞 · {fmtTime(record.created_at)}
                    </div>
                  </div>
                  <Button asChild size="icon-sm" variant="ghost" aria-label="预览">
                    <Link href={`/function/deliverables/report?id=${record.id}`}>
                      <EyeIcon />
                    </Link>
                  </Button>
                  <Button
                    type="button"
                    size="icon-sm"
                    variant="ghost"
                    aria-label="导出 Word"
                    disabled={wordBusyId === record.id}
                    onClick={() => void downloadWord(record)}
                  >
                    {wordBusyId === record.id ? <Loader2Icon className="animate-spin" /> : <FileDownIcon />}
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <ReportBuilder open={builderOpen} onOpenChange={setBuilderOpen} presetTaskId={taskId} onGenerated={reload} />
    </div>
  );
}
