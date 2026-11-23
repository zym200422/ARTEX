"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import {
  ArrowLeftIcon,
  ArrowUpRightIcon,
  ClipboardCopyIcon,
  FileCheck2Icon,
  Loader2Icon,
  PencilIcon,
  RadioTowerIcon,
  ShieldAlertIcon,
  SparklesIcon,
} from "lucide-react";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { ApprovalDialog } from "@/components/delivery/approval-panel";
import { EvidenceTraceDialog } from "@/components/delivery/evidence-trace-dialog";
import { FindingDeliveryEditor } from "@/components/delivery/finding-delivery-editor";
import { FindingReproSection } from "@/components/delivery/finding-repro-section";
import { DeliveryChecklist, ReadinessBadge } from "@/components/delivery/readiness-badge";
import { FindingRetestPanel } from "@/components/finding-retest-panel";
import { FindingTrafficPanel } from "@/components/finding-traffic-panel";
import { Markdown } from "@/components/markdown";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import {
  buildFindingMarkdown,
  buildFindingSnapshot,
  type DeliveryEnrichment,
  deliveryReadiness,
  type Reproduction,
} from "@/lib/delivery";
import { getDeliveryEnrichment, getDeliveryReproduction, saveDeliveryReproduction } from "@/lib/delivery-store";
import { buildFallbackReport } from "@/lib/fallback-report";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingStatus, Severity } from "@/lib/types";
import { copyText } from "@/lib/utils";

import { FindingLineageView } from "./lineage";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString("zh-CN");
}

// FieldRow is one label/value line in the right-hand status panel.
function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">{label}</span>
      <div className="flex min-w-0 flex-col items-end gap-1 text-right text-sm">{children}</div>
    </div>
  );
}

function FindingDetailInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const contextTaskId = searchParams.get("context_task") ?? "";
  const [finding, setFinding] = React.useState<Finding | null>(null);
  const [enrichment, setEnrichment] = React.useState<DeliveryEnrichment | null>(null);
  const [reproduction, setReproduction] = React.useState<Reproduction | null>(null);
  const [editOpen, setEditOpen] = React.useState(false);
  const [approvalOpen, setApprovalOpen] = React.useState(false);
  const [traceOpen, setTraceOpen] = React.useState(false);
  const [regenBusy, setRegenBusy] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [tab, setTab] = React.useState("overview");

  const load = React.useCallback(() => {
    if (!id) {
      setLoaded(true);
      return;
    }
    api
      .getFinding(id, contextTaskId || undefined)
      .then((f) => setFinding(f))
      .catch(() => setFinding(null))
      .finally(() => setLoaded(true));
  }, [contextTaskId, id]);
  React.useEffect(() => {
    load();
  }, [load]);

  // 交付内容（富化 + 结构化复现）读本地交付层；缺失时按报告/证据自动推导。
  React.useEffect(() => {
    if (!finding) return;
    setEnrichment(getDeliveryEnrichment(finding));
    setReproduction(getDeliveryReproduction(finding));
  }, [finding]);

  const readiness = React.useMemo(
    () => (finding && enrichment && reproduction ? deliveryReadiness(finding, enrichment, reproduction) : null),
    [finding, enrichment, reproduction],
  );

  const changeSeverity = React.useCallback(
    async (next: Severity) => {
      if (!finding || finding.inherited || next === finding.severity) return;
      const prev = finding.severity;
      setFinding({ ...finding, severity: next });
      try {
        const updated = await api.setFindingSeverity(id, next);
        setFinding(updated);
        toast.success(`严重等级已改为「${statusMeta("severity", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, severity: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  const changeStatus = React.useCallback(
    async (next: FindingStatus) => {
      if (!finding || finding.inherited || next === finding.status) return;
      const prev = finding.status;
      setFinding({ ...finding, status: next });
      try {
        const updated = await api.setFindingStatus(id, next);
        setFinding(updated);
        toast.success(`处理状态已改为「${statusMeta("finding", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, status: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  if (!finding) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        <p className="text-muted-foreground">{loaded ? `未找到发现 ${id}` : "加载中…"}</p>
        {loaded && (
          <Button asChild variant="outline">
            <Link href="/function/findings">
              <ArrowLeftIcon /> 返回发现列表
            </Link>
          </Button>
        )}
      </div>
    );
  }

  // 一键唤起 reporter 补写正式报告；成功后轮询到报告落地再刷新页面数据。
  async function regenerateReport() {
    if (!finding) return;
    setRegenBusy(true);
    try {
      await api.regenerateFindingReport(finding.id);
      toast.success("已唤起报告撰写 agent，正在补写…");
      // 轮询：最多等 3 分钟，每 5 秒查一次是否已有报告。
      for (let i = 0; i < 36; i++) {
        await new Promise((resolve) => setTimeout(resolve, 5000));
        try {
          const status = await api.findingReportStatus(finding.id);
          if (status.has_report) {
            toast.success("详细报告已生成");
            load();
            return;
          }
        } catch {
          // 轮询失败继续重试，直到超时
        }
      }
      toast.info("报告仍在生成中，稍后刷新页面查看");
      load();
    } catch (error) {
      toast.error(`补写失败：${(error as Error).message}`);
    } finally {
      setRegenBusy(false);
    }
  }

  // 详细报告：优先用 agent 提交的正式报告；缺失时按已有证据自动整理一份，
  // 避免「暂无详细报告」挡住交付（富化/复现/证据都是现成的）。
  const officialReport = finding.report?.trim() ?? "";
  const fallbackReport =
    !officialReport && enrichment && reproduction ? buildFallbackReport(finding, enrichment, reproduction) : "";
  const effectiveReport = officialReport || fallbackReport;
  const reportIsFallback = !officialReport && Boolean(fallbackReport);

  const title = enrichment?.name || finding.name || finding.vulnclass || "未分类";

  async function copyFinding() {
    if (!finding || !enrichment || !reproduction) return;
    const ok = await copyText(buildFindingMarkdown(finding, enrichment, reproduction));
    if (ok) toast.success("已复制交付片段（Markdown）");
    else toast.error("复制失败，请手动选择文本");
  }

  return (
    <Tabs value={tab} onValueChange={setTab} className="flex flex-1 flex-col gap-0">
      {/* Sticky header */}
      <header className="sticky top-0 z-10 flex flex-col gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur lg:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <SidebarTrigger className="-ml-1" />
          <Button asChild variant="ghost" size="icon" className="size-7">
            <Link href="/function/findings">
              <ArrowLeftIcon />
            </Link>
          </Button>
          <ShieldAlertIcon className="size-4 text-muted-foreground" />
          <h1 className="max-w-md truncate text-sm font-semibold" title={title}>
            {title}
          </h1>
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">#{finding.id}</code>
          <Separator orientation="vertical" className="mx-1 h-4" />
          <StatusBadge domain="severity" value={finding.severity} dot />
          <StatusBadge domain="finding" value={finding.status} dot />
          {readiness && <ReadinessBadge readiness={readiness} />}
          {finding.inherited && finding.source_task_id && (
            <Badge variant="outline">来源任务 #{finding.source_task_id} · 只读</Badge>
          )}
        </div>
        <TabsList>
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="lineage">链路图</TabsTrigger>
        </TabsList>
      </header>

      {/* Tab content */}
      <div className="flex-1 p-4 lg:p-6">
        {/* 概览：左（摘要 + 证据）/ 右（状态区） */}
        <TabsContent value="overview" className="mt-0">
          <div className="grid gap-4 lg:grid-cols-3">
            {/* 左栏 */}
            <div className="flex flex-col gap-4 lg:col-span-2">
              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <CardTitle className="text-sm">漏洞描述</CardTitle>
                  {enrichment && (
                    <Badge variant="outline" className="text-[10px]">
                      {enrichment.source === "manual" ? "人工整理" : "自动整理"}
                    </Badge>
                  )}
                </CardHeader>
                <CardContent className="space-y-2">
                  {(enrichment?.description?.length ? enrichment.description : [finding.summary || "（无描述）"]).map(
                    (paragraph, index) => (
                      // biome-ignore lint/suspicious/noArrayIndexKey: 描述段落无稳定 id
                      <p key={index} className="text-sm leading-relaxed whitespace-pre-wrap">
                        {paragraph}
                      </p>
                    ),
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">影响分析</CardTitle>
                </CardHeader>
                <CardContent>
                  {enrichment && enrichment.risk_analysis.length > 0 ? (
                    <ol className="ml-5 list-decimal space-y-1.5 text-sm leading-relaxed">
                      {enrichment.risk_analysis.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ol>
                  ) : (
                    <p className="text-sm text-muted-foreground">（暂无影响分析，点击右侧「编辑交付内容」补录）</p>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <CardTitle className="text-sm">复现过程</CardTitle>
                  <Button type="button" size="sm" variant="outline" onClick={() => setEditOpen(true)}>
                    <PencilIcon data-icon="inline-start" />
                    编辑
                  </Button>
                </CardHeader>
                <CardContent>
                  {reproduction ? (
                    <FindingReproSection
                      finding={finding}
                      contextTask={contextTaskId || undefined}
                      reproduction={reproduction}
                    />
                  ) : null}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">修复建议</CardTitle>
                </CardHeader>
                <CardContent>
                  {enrichment && enrichment.remediation.length > 0 ? (
                    <ol className="ml-5 list-decimal space-y-1.5 text-sm leading-relaxed">
                      {enrichment.remediation.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ol>
                  ) : (
                    <p className="text-sm text-muted-foreground">（暂无修复建议）</p>
                  )}
                </CardContent>
              </Card>

              <FindingRetestPanel key={id} findingId={id} readOnly={finding.inherited} onCompleted={load} />

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">证据 / PoC</CardTitle>
                </CardHeader>
                <CardContent>
                  {finding.evidence ? (
                    reproduction && reproduction.steps.length > 0 ? (
                      <details>
                        <summary className="cursor-pointer text-muted-foreground text-xs hover:text-foreground">
                          原始证据（已按步骤整理到「复现过程」）
                        </summary>
                        <pre className="mt-2 max-h-[46vh] overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
                          {finding.evidence}
                        </pre>
                      </details>
                    ) : (
                      <pre className="max-h-[46vh] overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
                        {finding.evidence}
                      </pre>
                    )
                  ) : (
                    <p className="text-sm text-muted-foreground">（无证据）</p>
                  )}
                </CardContent>
              </Card>

              <FindingTrafficPanel
                key={id}
                findingId={id}
                contextTask={contextTaskId || undefined}
                readOnly={finding.inherited}
                onChanged={load}
              />
              {/* 证据下方：详细报告(Markdown 渲染)。缺失时用兜底报告，不显示空白。 */}
              <Card>
                <CardHeader className="flex-row items-center justify-between gap-2">
                  <CardTitle className="flex items-center gap-1.5 text-sm">
                    详细报告
                    {reportIsFallback && (
                      <Badge variant="outline" className="text-[10px] font-normal">
                        自动整理
                      </Badge>
                    )}
                  </CardTitle>
                  <div className="flex items-center gap-1.5">
                    {!officialReport && (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="h-7"
                        disabled={regenBusy}
                        onClick={() => void regenerateReport()}
                      >
                        {regenBusy ? <Loader2Icon className="animate-spin" /> : <SparklesIcon className="size-3.5" />}
                        {regenBusy ? "补写中" : "AI 补写"}
                      </Button>
                    )}
                    {effectiveReport && <CopyButton text={effectiveReport} successMessage="已复制详细报告" />}
                  </div>
                </CardHeader>
                <CardContent>
                  {finding.report_stale ? (
                    <Alert>
                      <AlertDescription>流量证据已变更，详细报告待更新。</AlertDescription>
                    </Alert>
                  ) : null}
                  {reportIsFallback && (
                    <div className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-2.5 text-xs leading-relaxed">
                      <div className="font-medium">该漏洞没有 agent 提交的正式报告</div>
                      <p className="text-muted-foreground mt-1">
                        常见原因：登记漏洞时报告撰写 agent 未能触发（未配置 LLM、agent
                        已停用、或该次调用早于自动触发上线）。
                        下面这份是平台按现有证据自动整理的版本，可直接用；需要专业报告时点右上角「AI 补写」。
                      </p>
                    </div>
                  )}
                  {effectiveReport ? (
                    <Markdown text={effectiveReport} />
                  ) : (
                    <p className="text-sm text-muted-foreground">暂无详细报告。</p>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* 右栏：状态 + 交付 */}
            <div className="flex h-fit flex-col gap-4 lg:sticky lg:top-24">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">状态</CardTitle>
                </CardHeader>
                <CardContent className="divide-y">
                  {/* 漏洞 ID */}
                  <FieldRow label="漏洞 ID">
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                      #{finding.id}
                    </code>
                  </FieldRow>

                  {/* 严重等级 */}
                  <FieldRow label="严重等级">
                    {finding.inherited ? (
                      <StatusBadge domain="severity" value={finding.severity} dot />
                    ) : (
                      <Select value={finding.severity} onValueChange={(v) => changeSeverity(v as Severity)}>
                        <SelectTrigger
                          size="sm"
                          className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0"
                        >
                          <StatusBadge domain="severity" value={finding.severity} dot />
                        </SelectTrigger>
                        <SelectContent position="popper" align="end">
                          <SelectGroup>
                            {SEVERITIES.map((sv) => (
                              <SelectItem key={sv} value={sv}>
                                {statusMeta("severity", sv).label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    )}
                  </FieldRow>

                  {/* 处理状态 */}
                  <FieldRow label="处理状态">
                    {finding.inherited ? (
                      <StatusBadge domain="finding" value={finding.status} dot />
                    ) : (
                      <Select value={finding.status} onValueChange={(v) => changeStatus(v as FindingStatus)}>
                        <SelectTrigger
                          size="sm"
                          className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0"
                        >
                          <StatusBadge domain="finding" value={finding.status} dot />
                        </SelectTrigger>
                        <SelectContent position="popper" align="end">
                          <SelectGroup>
                            {FINDING_STATUSES.map((st) => (
                              <SelectItem key={st} value={st}>
                                {statusMeta("finding", st).label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    )}
                  </FieldRow>

                  {/* 漏洞类型 */}
                  <FieldRow label="漏洞类型">
                    {finding.vulnclass ? (
                      <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{finding.vulnclass}</code>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </FieldRow>

                  {/* 涉及资产 */}
                  <FieldRow label="涉及资产">
                    {finding.assets && finding.assets.length > 0 ? (
                      <div className="flex flex-wrap justify-end gap-1">
                        {finding.assets.map((a) => (
                          <code
                            key={a.id}
                            className="max-w-[16rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                            title={`${a.type} · ${a.label}`}
                          >
                            {a.label}
                          </code>
                        ))}
                      </div>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </FieldRow>

                  {/* 所属任务 */}
                  <FieldRow label="所属任务">
                    {finding.task_id ? (
                      <Link
                        href={`/function/tasks/detail?id=${finding.task_id}`}
                        className="inline-flex max-w-[16rem] items-center gap-1 text-primary hover:underline"
                        title={finding.task_description}
                      >
                        <span className="truncate">{finding.task_description || `#${finding.task_id}`}</span>
                        <ArrowUpRightIcon className="size-3 shrink-0" />
                      </Link>
                    ) : (
                      <span className="text-muted-foreground">—（任务已删除）</span>
                    )}
                  </FieldRow>

                  {/* 发现时间 */}
                  <FieldRow label="发现时间">
                    <span className="tabular-nums">{fmtTime(finding.ts)}</span>
                  </FieldRow>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-1.5 text-sm">
                    <FileCheck2Icon className="size-4" />
                    交付
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground text-xs">交付就绪度</span>
                    {readiness && <ReadinessBadge readiness={readiness} />}
                  </div>
                  {readiness && <DeliveryChecklist readiness={readiness} />}
                  <div className="rounded-md border bg-muted/30 px-2.5 py-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">CVSS</span>
                      <span className="font-medium tabular-nums">{enrichment?.cvss_score.toFixed(1) ?? "—"}</span>
                    </div>
                    <div className="mt-1 break-all font-mono text-[10px] leading-relaxed text-muted-foreground">
                      {enrichment?.cvss_vector || "—"}
                    </div>
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      onClick={() => setEditOpen(true)}
                      disabled={finding.inherited}
                    >
                      <PencilIcon data-icon="inline-start" />
                      编辑交付内容
                    </Button>
                    <Button type="button" size="sm" variant="outline" onClick={() => void copyFinding()}>
                      <ClipboardCopyIcon data-icon="inline-start" />
                      复制交付片段
                    </Button>
                    <Button type="button" size="sm" variant="outline" onClick={() => setTraceOpen(true)}>
                      <RadioTowerIcon data-icon="inline-start" />
                      证据留痕
                    </Button>
                    <Button type="button" size="sm" variant="outline" onClick={() => setApprovalOpen(true)}>
                      <SparklesIcon data-icon="inline-start" />
                      AI 审批
                    </Button>
                    <Button size="sm" asChild disabled={!finding.task_id}>
                      <Link href={`/function/deliverables?task=${encodeURIComponent(finding.task_id ?? "")}&new=1`}>
                        <FileCheck2Icon data-icon="inline-start" />
                        导出报告
                      </Link>
                    </Button>
                  </div>
                  <p className="text-muted-foreground text-[11px] leading-relaxed">
                    报告使用生成时的快照；修改交付内容后需要重新生成。
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        {/* 链路图：从任务初始节点回溯到本漏洞节点的攻击链路 */}
        <TabsContent value="lineage" className="mt-0">
          <FindingLineageView findingId={finding.id} />
        </TabsContent>
      </div>

      {finding && reproduction && (
        <EvidenceTraceDialog
          open={traceOpen}
          onOpenChange={setTraceOpen}
          finding={finding}
          reproduction={reproduction}
          onTraced={(updates) => {
            const next: Reproduction = {
              ...reproduction,
              provenance: reproduction.steps.length > 0 ? reproduction.provenance : "auto",
              steps: reproduction.steps.map((step, index) => {
                const hit = updates.find((item) => item.stepIndex === index);
                if (!hit) return step;
                const rec = hit.record;
                return {
                  ...step,
                  traffic_id: String(rec.id),
                  replay_id: rec.id,
                  response: `HTTP/1.1 ${rec.status}${rec.status_text ? ` ${rec.status_text}` : ""}
${hit.excerpt}`,
                  proves: step.proves ? step.proves : `重放记录 #${rec.id} 已留痕（${rec.duration_ms} ms）`,
                };
              }),
            };
            saveDeliveryReproduction(finding.id, next);
            setReproduction(next);
            load();
          }}
        />
      )}

      {finding && enrichment && reproduction && (
        <ApprovalDialog
          open={approvalOpen}
          onOpenChange={setApprovalOpen}
          snapshot={buildFindingSnapshot(finding, enrichment, reproduction)}
          findingId={finding.id}
        />
      )}

      {enrichment && reproduction && (
        <FindingDeliveryEditor
          finding={finding}
          open={editOpen}
          onOpenChange={setEditOpen}
          enrichment={enrichment}
          reproduction={reproduction}
          onSaved={() => {
            setEnrichment(getDeliveryEnrichment(finding));
            setReproduction(getDeliveryReproduction(finding));
            load();
          }}
        />
      )}
    </Tabs>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <FindingDetailInner />
    </React.Suspense>
  );
}
