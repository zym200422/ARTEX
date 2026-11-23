"use client";

import * as React from "react";

import Link from "next/link";

import { EyeIcon, FileDownIcon, FileTextIcon, Loader2Icon, PlusIcon, SparklesIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { ReportBuilder } from "@/components/delivery/report-builder";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ReportRecord } from "@/lib/delivery";
import { deleteReport, getReports } from "@/lib/delivery-store";

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleString("zh-CN", { hour12: false });
}

function fmtSize(bytes: number): string {
  if (bytes <= 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/**
 * 交付中心：只保留「报告记录 + 导出」。
 * 报告导出严格按用户给定的 docx 模板，不包含封面/目录/公司/方法学等额外内容。
 */
export default function DeliverablesPage() {
  const [reports, setReports] = React.useState<ReportRecord[]>([]);
  const [builderOpen, setBuilderOpen] = React.useState(false);
  const [builderTask, setBuilderTask] = React.useState<string | undefined>(undefined);
  const [pendingDelete, setPendingDelete] = React.useState<ReportRecord | null>(null);
  const [wordBusyId, setWordBusyId] = React.useState<number | null>(null);

  const reload = React.useCallback(() => {
    setReports(getReports());
  }, []);

  React.useEffect(() => {
    reload();
    // 任务详情「导出报告」深链：?task=xxx&new=1
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("new") === "1") {
      setBuilderTask(params.get("task") ?? undefined);
      setBuilderOpen(true);
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, [reload]);

  const stats = React.useMemo(() => {
    const tasks = new Set(reports.map((item) => item.task_id).filter(Boolean));
    const findings = reports.reduce((sum, item) => sum + item.finding_count, 0);
    return { reports: reports.length, tasks: tasks.size, findings };
  }, [reports]);

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

  function confirmDelete() {
    if (!pendingDelete) return;
    deleteReport(pendingDelete.id);
    setPendingDelete(null);
    reload();
    toast.success("报告已删除");
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">报告导出</h1>
          <p className="text-muted-foreground text-sm">
            按固定模板导出：漏洞标题 / 漏洞危害 / 漏洞描述 / 漏洞复现 / 修复建议。
          </p>
        </div>
        <Button type="button" size="sm" onClick={() => setBuilderOpen(true)}>
          <SparklesIcon data-icon="inline-start" />
          导出漏洞报告
        </Button>
      </div>

      <div className="grid grid-cols-3 gap-2">
        {[
          { label: "已生成报告", value: stats.reports },
          { label: "覆盖任务", value: stats.tasks },
          { label: "导出漏洞", value: stats.findings },
        ].map((item) => (
          <Card key={item.label} className="py-0">
            <CardContent className="flex items-center gap-2.5 px-3.5 py-3">
              <span className="flex size-8 items-center justify-center rounded-md bg-muted">
                <FileTextIcon className="size-4 text-muted-foreground" />
              </span>
              <div>
                <div className="text-lg leading-none font-semibold tabular-nums">{item.value}</div>
                <div className="mt-1 text-muted-foreground text-[11px]">{item.label}</div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-sm">报告记录</CardTitle>
            <CardDescription>点击预览检查版式，确认无误后导出 Word。</CardDescription>
          </div>
          <Button size="sm" variant="outline" onClick={() => setBuilderOpen(true)}>
            <PlusIcon data-icon="inline-start" />
            新建报告
          </Button>
        </CardHeader>
        <CardContent className="px-0">
          {reports.length === 0 ? (
            <div className="mx-4 flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed py-16 text-sm text-muted-foreground">
              <FileTextIcon className="size-8 opacity-40" />
              还没有报告。选择任务与已确认漏洞即可导出。
              <Button size="sm" onClick={() => setBuilderOpen(true)}>
                导出漏洞报告
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-4">报告</TableHead>
                  <TableHead>任务</TableHead>
                  <TableHead className="text-center">漏洞</TableHead>
                  <TableHead className="text-right">大小</TableHead>
                  <TableHead>生成时间</TableHead>
                  <TableHead className="pr-4 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((record) => (
                  <TableRow key={record.id}>
                    <TableCell className="pl-4">
                      <div className="flex max-w-[20rem] flex-col">
                        <span className="truncate font-medium" title={record.title}>
                          {record.title}
                        </span>
                        <span className="truncate text-muted-foreground text-[11px]">{record.filename}</span>
                      </div>
                    </TableCell>
                    <TableCell className="max-w-[14rem] truncate text-muted-foreground text-xs">
                      {record.task_label || "—"}
                    </TableCell>
                    <TableCell className="text-center text-xs tabular-nums">{record.finding_count}</TableCell>
                    <TableCell className="text-right text-muted-foreground text-xs tabular-nums">
                      {fmtSize(record.size)}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs whitespace-nowrap">
                      {fmtTime(record.created_at)}
                    </TableCell>
                    <TableCell className="pr-4 text-right">
                      <div className="flex items-center justify-end gap-0.5">
                        <Button asChild size="icon-sm" variant="ghost" aria-label="预览报告">
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
                        <Button
                          type="button"
                          size="icon-sm"
                          variant="ghost"
                          aria-label="删除报告"
                          onClick={() => setPendingDelete(record)}
                        >
                          <Trash2Icon />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <ReportBuilder
        open={builderOpen}
        onOpenChange={(next) => {
          setBuilderOpen(next);
          if (!next) setBuilderTask(undefined);
        }}
        presetTaskId={builderTask}
        onGenerated={reload}
      />

      <AlertDialog open={pendingDelete !== null} onOpenChange={(next) => !next && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除报告「{pendingDelete?.title}」？</AlertDialogTitle>
            <AlertDialogDescription>报告快照会从列表移除；已导出的 Word 不受影响。</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                confirmDelete();
              }}
            >
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
