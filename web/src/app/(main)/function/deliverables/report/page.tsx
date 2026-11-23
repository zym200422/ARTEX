"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { ArrowLeftIcon, FileDownIcon, Loader2Icon } from "lucide-react";
import { toast } from "sonner";

import { ReportDocument } from "@/components/delivery/report-document";
import { Button } from "@/components/ui/button";
import { SidebarTrigger } from "@/components/ui/sidebar";
import type { ReportRecord } from "@/lib/delivery";
import { getReport } from "@/lib/delivery-store";

function ReportPreviewInner() {
  const searchParams = useSearchParams();
  const id = Number(searchParams.get("id") ?? "0");
  const [record, setRecord] = React.useState<ReportRecord | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [wordBusy, setWordBusy] = React.useState(false);

  React.useEffect(() => {
    setRecord(getReport(id));
    setLoaded(true);
  }, [id]);

  async function downloadWord() {
    if (!record) return;
    setWordBusy(true);
    try {
      // docx 体积较大，按需加载，避免影响预览首屏。
      const { downloadReportDocx } = await import("@/lib/report-docx");
      await downloadReportDocx(record.snapshot, record.filename.replace(/\.md$/, ".docx"));
      toast.success("Word 报告已生成");
    } catch (error) {
      toast.error(`Word 生成失败：${(error as Error).message}`);
    } finally {
      setWordBusy(false);
    }
  }

  if (!record) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        <p className="text-muted-foreground">{loaded ? `报告 ${id || "（缺少 id）"} 不存在或已删除` : "加载中…"}</p>
        <Button asChild variant="outline">
          <Link href="/function/deliverables">
            <ArrowLeftIcon /> 返回交付中心
          </Link>
        </Button>
      </div>
    );
  }

  return (
    <div className="flex min-h-svh flex-col bg-slate-100 print:bg-white">
      <header className="sticky top-0 z-10 flex flex-wrap items-center gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur print:hidden lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Button asChild variant="ghost" size="icon" className="size-7">
          <Link href="/function/deliverables">
            <ArrowLeftIcon />
          </Link>
        </Button>
        <div className="min-w-0 flex-1">
          <h1 className="truncate text-sm font-semibold">{record.title}</h1>
          <p className="truncate text-muted-foreground text-xs">
            {record.finding_count} 个漏洞 · {record.filename}
          </p>
        </div>
        <Button type="button" size="sm" disabled={wordBusy} onClick={() => void downloadWord()}>
          {wordBusy ? <Loader2Icon className="animate-spin" /> : <FileDownIcon data-icon="inline-start" />}
          {wordBusy ? "生成中" : "导出 Word"}
        </Button>
      </header>

      <div className="flex-1 overflow-x-auto px-4 py-6 print:p-0">
        <ReportDocument snapshot={record.snapshot} />
      </div>
    </div>
  );
}

// useSearchParams 在静态导出下需要 Suspense 边界。
export default function ReportPreviewPage() {
  return (
    <React.Suspense fallback={null}>
      <ReportPreviewInner />
    </React.Suspense>
  );
}
