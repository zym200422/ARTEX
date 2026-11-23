"use client";

// 证据留痕对话框：把报告/证据里的报文逐条送进数据重放，落平台留痕。
//
// 解决的问题：报告里的报文如果只是文本，工程师拿去做重放可能复现不了
// （缺 Host/缺 Cookie/缺内联响应）。这里把每条报文真实发一次，记录状态码、
// 耗时、关键回显，并把重放记录 id 回填到复现步骤上。

import * as React from "react";

import { CheckCircle2Icon, Loader2Icon, PlayIcon, RadioTowerIcon, XCircleIcon } from "lucide-react";
import { toast } from "sonner";

import { HttpCodeBlock } from "@/components/http-code-block";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { normalizeBurpRequest } from "@/lib/burp-format";
import type { Reproduction } from "@/lib/delivery";
import {
  type ExtractedPacket,
  evidenceExcerpt,
  extractPackets,
  type ReplayTraceResult,
  replayPackets,
} from "@/lib/evidence-replay";
import type { Finding, ReplayRecord } from "@/lib/types";
import { cn } from "@/lib/utils";

// 危害标记：只用于「默认勾选关键报文」，不作为判定依据。
const HARM_HINT =
  /PIKA_|MARK_|uid=|gid=|whoami|nt authority|desktop-|Windows|PHP Version|root:|\[fonts\]|SQLSTATE|Exception/i;

function statusTone(status: number): string {
  if (status >= 500) return "text-red-500";
  if (status >= 400) return "text-amber-500";
  if (status >= 300) return "text-blue-500";
  if (status >= 200) return "text-emerald-500";
  return "text-muted-foreground";
}

/**
 * EvidenceTraceDialog：选中要留痕的报文 → 真实重放 → 查看回显 → 一键回填到复现步骤。
 */
export function EvidenceTraceDialog({
  open,
  onOpenChange,
  finding,
  reproduction,
  onTraced,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  finding: Finding;
  reproduction: Reproduction | null;
  /** 留痕完成后回填：stepIndex → 重放记录（含响应）。record.id 即重放编号。 */
  onTraced: (updates: { stepIndex: number; record: ReplayRecord; excerpt: string }[]) => void;
}) {
  const packets = React.useMemo(
    () => (open ? extractPackets(finding, reproduction) : []),
    [open, finding, reproduction],
  );
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [scheme, setScheme] = React.useState<"" | "http" | "https">("");
  const [host, setHost] = React.useState("");
  const [insecureTls, setInsecureTls] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [results, setResults] = React.useState<ReplayTraceResult[]>([]);

  React.useEffect(() => {
    if (!open) return;
    setResults([]);
    // 只留痕「关键报文」：默认勾复现步骤里的报文；没有结构化步骤时，
    // 仅勾带危害标记（PIKA_/uid=/报错等）的前两条，避免把报告里所有报文都发一遍。
    const stepPackets = packets.filter((packet) => packet.stepIndex >= 0);
    if (stepPackets.length > 0) {
      setSelected(new Set(stepPackets.map((packet) => packet.key)));
    } else {
      const key = packets.filter((packet) => HARM_HINT.test(packet.inlineResponse)).slice(0, 2);
      setSelected(new Set(key.map((packet) => packet.key)));
    }
    const firstHost = packets.find((packet) => packet.host)?.host ?? "";
    setHost(firstHost);
    setScheme(/^https:\/\//i.test(finding.assets?.[0]?.label ?? "") ? "https" : "");
  }, [open, packets, finding.assets]);

  const chosen = packets.filter((packet) => selected.has(packet.key));

  async function run() {
    if (chosen.length === 0) {
      toast.error("先勾选要留痕的报文");
      return;
    }
    setBusy(true);
    try {
      // 统一覆盖 Host：报告里的报文常用 localhost/占位主机，重放时换成实际目标。
      const patched = chosen.map((packet) => {
        if (!host.trim()) return packet;
        const lines = packet.raw.split("\n").map((line) => (/^host\s*:/i.test(line) ? `Host: ${host.trim()}` : line));
        if (!lines.some((line) => /^host\s*:/i.test(line))) lines.splice(1, 0, `Host: ${host.trim()}`);
        return { ...packet, raw: lines.join("\n") };
      });
      const traced = await replayPackets(patched, {
        taskId: finding.task_id,
        scheme,
        insecureTls,
        timeoutSec: 40,
      });
      setResults(traced);
      const ok = traced.filter((item) => !item.record.error && item.record.status > 0).length;
      if (ok === 0) toast.error("全部重放失败，请检查目标主机与协议");
      else toast.success(`已完成 ${ok}/${traced.length} 条重放留痕`);
    } catch (error) {
      toast.error(`留痕失败：${(error as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  function applyToRepro() {
    const updates = results
      .filter((item) => item.packet.stepIndex >= 0 && !item.record.error)
      .map((item) => ({
        stepIndex: item.packet.stepIndex,
        record: item.record,
        excerpt: evidenceExcerpt(item.record),
      }));
    if (updates.length === 0) {
      toast.error("没有可回填的成功重放");
      return;
    }
    onTraced(updates);
    onOpenChange(false);
    toast.success(`已回填 ${updates.length} 条重放证据到复现步骤`);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <RadioTowerIcon className="size-4" />
            证据重放留痕
            {finding.id && <span className="text-muted-foreground font-mono text-xs">#{finding.id}</span>}
          </DialogTitle>
          <DialogDescription>
            把报告/证据里的报文真实重放一次并留痕：成功后可将状态码与关键回显回填到复现步骤，报告里的每条报文都有平台记录可追溯。
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-wrap items-end gap-3">
          <div className="flex min-w-56 flex-1 flex-col gap-1">
            <Label htmlFor="trace-host" className="text-xs text-muted-foreground">
              实际目标主机（覆盖报文里的 Host）
            </Label>
            <Input
              id="trace-host"
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="10.113.76.85 或 localhost"
              className="font-mono text-xs"
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="trace-scheme" className="text-xs text-muted-foreground">
              协议
            </Label>
            <NativeSelect
              id="trace-scheme"
              className="w-32"
              value={scheme}
              onChange={(event) => setScheme(event.target.value as "" | "http" | "https")}
            >
              <NativeSelectOption value="">按报文</NativeSelectOption>
              <NativeSelectOption value="http">HTTP</NativeSelectOption>
              <NativeSelectOption value="https">HTTPS</NativeSelectOption>
            </NativeSelect>
          </div>
          <label htmlFor="trace-insecure" className="flex h-8 items-center gap-2 text-xs">
            <Checkbox
              id="trace-insecure"
              checked={insecureTls}
              onCheckedChange={(value) => setInsecureTls(value === true)}
            />
            忽略证书
          </label>
        </div>

        {packets.length === 0 ? (
          <div className="text-muted-foreground rounded-lg border border-dashed py-10 text-center text-sm">
            未从报告/证据中识别出可重放的 HTTP 报文。
          </div>
        ) : (
          <ScrollArea className="max-h-[38vh] rounded-lg border">
            <div className="divide-y">
              {packets.map((packet) => (
                <PacketRow
                  key={packet.key}
                  packet={packet}
                  checked={selected.has(packet.key)}
                  result={results.find((item) => item.packet.key === packet.key) ?? null}
                  onToggle={(next) =>
                    setSelected((prev) => {
                      const updated = new Set(prev);
                      if (next) updated.add(packet.key);
                      else updated.delete(packet.key);
                      return updated;
                    })
                  }
                />
              ))}
            </div>
          </ScrollArea>
        )}

        {results.length > 0 && (
          <div className="flex flex-col gap-2">
            <div className="text-xs font-medium">重放结果</div>
            {results.map((item) => (
              <div key={`${item.packet.key}-res`} className="rounded-lg border">
                <div className="flex flex-wrap items-center gap-2 border-b px-3 py-1.5">
                  <Badge variant="secondary" className="font-mono text-[10px]">
                    {item.record.method}
                  </Badge>
                  <span className={cn("font-mono text-xs font-semibold tabular-nums", statusTone(item.record.status))}>
                    {item.record.status || "ERR"}
                  </span>
                  <span className="text-muted-foreground font-mono text-[11px]">
                    #{item.record.id} · {item.record.duration_ms} ms
                  </span>
                  <span className="text-muted-foreground ml-auto text-[11px]">{item.packet.origin}</span>
                </div>
                <div className="px-3 py-2">
                  {item.record.error ? (
                    <p className="text-amber-600 text-xs">{item.record.error}</p>
                  ) : (
                    <>
                      <div className="mb-1 text-[11px] font-medium text-muted-foreground">关键回显</div>
                      <pre className="max-h-32 overflow-auto rounded bg-muted px-2 py-1.5 font-mono text-[11px] whitespace-pre-wrap">
                        {evidenceExcerpt(item.record) || "（未检出明显回显）"}
                      </pre>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <DialogFooter className="sm:justify-between">
          <span className="text-muted-foreground text-xs">
            已选 {chosen.length} / {packets.length} 条报文（默认只勾关键报文）
          </span>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              关闭
            </Button>
            {results.length > 0 && (
              <Button type="button" variant="secondary" onClick={applyToRepro}>
                回填到复现步骤
              </Button>
            )}
            <Button type="button" onClick={() => void run()} disabled={busy || chosen.length === 0}>
              {busy ? <Loader2Icon className="animate-spin" /> : <PlayIcon className="size-3.5" />}
              {busy ? "重放中" : `重放并留痕（${chosen.length}）`}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PacketRow({
  packet,
  checked,
  result,
  onToggle,
}: {
  packet: ExtractedPacket;
  checked: boolean;
  result: ReplayTraceResult | null;
  onToggle: (next: boolean) => void;
}) {
  const [expanded, setExpanded] = React.useState(false);
  const ok = result && !result.record.error;
  return (
    <div className={cn("px-3 py-2", checked ? "bg-primary/5" : "")}>
      <div className="flex items-start gap-2">
        <Checkbox checked={checked} onCheckedChange={(value) => onToggle(value === true)} className="mt-0.5" />
        <button type="button" className="min-w-0 flex-1 text-left" onClick={() => setExpanded((value) => !value)}>
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge variant="secondary" className="font-mono text-[10px]">
              {packet.method}
            </Badge>
            <span className="truncate font-mono text-xs">{packet.path}</span>
            {result ? (
              <span className="ml-auto flex shrink-0 items-center gap-1">
                {ok ? (
                  <CheckCircle2Icon className="size-3.5 text-emerald-500" />
                ) : (
                  <XCircleIcon className="size-3.5 text-red-500" />
                )}
                <span className={cn("font-mono text-[11px] tabular-nums", statusTone(result.record.status))}>
                  {result.record.status || "ERR"}
                </span>
              </span>
            ) : (
              <span className="text-muted-foreground ml-auto shrink-0 text-[11px]">{packet.origin}</span>
            )}
          </div>
          <div className="text-muted-foreground mt-0.5 flex flex-wrap gap-x-3 text-[11px]">
            <span>{packet.host || "（报文未写 Host）"}</span>
            <span>{packet.inlineResponse ? "报告含响应片段" : "报告无内联响应"}</span>
            {packet.stepIndex >= 0 && <span className="text-emerald-600 dark:text-emerald-400">关键报文</span>}
          </div>
        </button>
      </div>
      {expanded && (
        <div className="mt-2">
          <HttpCodeBlock raw={normalizeBurpRequest(packet.raw, packet.host || undefined)} />
        </div>
      )}
    </div>
  );
}
