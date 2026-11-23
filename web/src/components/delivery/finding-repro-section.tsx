"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, ExternalLinkIcon, Link2Icon, TerminalIcon } from "lucide-react";
import { toast } from "sonner";

import { HttpCodeBlock } from "@/components/http-code-block";
import { TrafficEvidenceViewer } from "@/components/traffic-evidence-viewer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { normalizeBurpRequest, normalizeBurpResponse } from "@/lib/burp-format";
import type { Reproduction } from "@/lib/delivery";
import type { Finding, FindingTrafficBinding } from "@/lib/types";
import { copyText } from "@/lib/utils";

const PROVENANCE_LABEL: Record<Reproduction["provenance"], string> = {
  manual: "作业期就地记录",
  auto: "由报告/证据整理",
  none: "待补录",
};

/**
 * FindingReproSection 把「复现过程」渲染成交付级分步：
 * 入口点 / 前置条件 / 每步说明 + 请求 + 响应 + 证明点，并把每一步挂回真实流量包。
 */
export function FindingReproSection({
  finding,
  contextTask,
  reproduction,
}: {
  finding: Finding;
  contextTask?: string;
  reproduction: Reproduction;
}) {
  const [bindings, setBindings] = React.useState<FindingTrafficBinding[]>([]);
  const [previewBinding, setPreviewBinding] = React.useState<string | null>(null);
  const [copiedStep, setCopiedStep] = React.useState<number | null>(null);

  React.useEffect(() => {
    let alive = true;
    api
      .findingTraffic(finding.id, contextTask)
      .then((data) => {
        if (alive) setBindings(data.bindings ?? []);
      })
      .catch(() => {
        if (alive) setBindings([]);
      });
    return () => {
      alive = false;
    };
  }, [finding.id, contextTask]);

  const byTraffic = React.useMemo(() => {
    const map = new Map<string, FindingTrafficBinding>();
    for (const binding of bindings) map.set(binding.snapshot.source_traffic_id, binding);
    return map;
  }, [bindings]);

  const steps = reproduction.steps ?? [];
  const hasStructured = steps.length > 0 || Boolean(reproduction.entry_point);

  // Burp 报文需要 Host 兜底：优先入口点 URL 的 host，其次第一个资产 label 里的 host。
  const fallbackHost = React.useMemo(() => {
    const candidates = [reproduction.entry_point ?? "", ...(finding.assets ?? []).map((item) => item.label ?? "")];
    for (const candidate of candidates) {
      const m = /https?:\/\/([^/\s]+)/i.exec(candidate);
      if (m) return m[1];
    }
    return undefined;
  }, [reproduction.entry_point, finding.assets]);

  if (!hasStructured) {
    return (
      <div className="rounded-md border border-dashed px-3 py-6 text-center text-sm text-muted-foreground">
        还没有结构化复现步骤。可点「编辑交付内容」补录，或让 agent 在作业期记录复现过程。
      </div>
    );
  }

  async function copyStep(index: number, request: string, response: string) {
    const text = [`步骤 ${index + 1}`, "", "请求：", request.trim(), "", "响应：", response.trim()].join("\n");
    const ok = await copyText(text);
    if (ok) {
      setCopiedStep(index);
      toast.success(`已复制步骤 ${index + 1}`);
      setTimeout(() => setCopiedStep(null), 1500);
    } else {
      toast.error("复制失败");
    }
  }

  return (
    <div className="min-w-0 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
          {PROVENANCE_LABEL[reproduction.provenance]}
        </Badge>
        <span className="text-muted-foreground text-[11px]">
          {reproduction.steps.length} 个步骤 · {bindings.length} 个已绑定流量包
        </span>
      </div>

      {((reproduction.entry_point ?? "") !== "" || (reproduction.prerequisites?.length ?? 0) > 0) && (
        <div className="rounded-md border bg-muted/30 px-3 py-2.5 text-sm">
          {reproduction.entry_point && (
            <p className="break-words">
              <span className="text-muted-foreground">入口点：</span>
              <code className="break-all rounded bg-background px-1.5 py-0.5 font-mono text-xs">
                {reproduction.entry_point}
              </code>
            </p>
          )}
          {(reproduction.prerequisites?.length ?? 0) > 0 && (
            <div className="mt-1.5">
              <span className="text-muted-foreground text-sm">前置条件：</span>
              <ul className="mt-0.5 ml-5 list-disc text-sm leading-relaxed">
                {reproduction.prerequisites?.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {steps.map((step, index) => {
        const binding = step.traffic_id ? byTraffic.get(step.traffic_id) : undefined;
        return (
          <div key={`${finding.id}-step-${index + 1}`} className="rounded-lg border">
            <div className="flex flex-wrap items-start gap-2 border-b px-3 py-2">
              <span className="shrink-0 rounded bg-primary/10 px-1.5 py-0.5 text-xs font-semibold text-primary tabular-nums">
                步骤 {index + 1}
              </span>
              {step.replay_id && (
                <a
                  href={`/function/replay/?ids=${step.replay_id}`}
                  target="_blank"
                  rel="noopener"
                  className="shrink-0 rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-emerald-700 hover:underline dark:text-emerald-400"
                  title="在数据重放中查看该编号的留痕"
                >
                  重放 #{step.replay_id}
                </a>
              )}
              <div className="min-w-0 flex-1">
                {step.expected && <p className="text-sm leading-relaxed break-words">{step.expected}</p>}
                {step.proves && (
                  <p className="mt-0.5 flex items-start gap-1 text-muted-foreground text-[11px] leading-relaxed">
                    <CheckIcon className="mt-0.5 size-3 shrink-0 text-emerald-600 dark:text-emerald-400" />
                    证明：{step.proves}
                  </p>
                )}
              </div>
              <div className="flex shrink-0 items-center gap-1">
                {binding && (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-7"
                    onClick={() => setPreviewBinding(binding.id)}
                  >
                    <Link2Icon data-icon="inline-start" />
                    原始报文
                  </Button>
                )}
                <Button
                  type="button"
                  size="icon-sm"
                  variant="ghost"
                  aria-label="复制本步报文"
                  onClick={() => void copyStep(index, step.request, step.response)}
                >
                  {copiedStep === index ? <CheckIcon /> : <CopyIcon />}
                </Button>
              </div>
            </div>
            <div className="space-y-2 px-3 py-2.5">
              {step.request.trim() ? (
                <div>
                  <div className="mb-1 flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
                    <TerminalIcon className="size-3" />
                    请求
                  </div>
                  <HttpCodeBlock raw={normalizeBurpRequest(step.request, fallbackHost)} />
                </div>
              ) : (
                <p className="text-muted-foreground text-xs">（未记录逐字请求）</p>
              )}
              {step.response.trim() ? (
                <div>
                  <div className="mb-1 text-[11px] font-medium text-muted-foreground">响应</div>
                  <HttpCodeBlock raw={normalizeBurpResponse(step.response)} />
                </div>
              ) : (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  （未内联响应）
                  {binding && (
                    <button
                      type="button"
                      className="inline-flex items-center gap-1 underline underline-offset-2 hover:text-foreground"
                      onClick={() => setPreviewBinding(binding.id)}
                    >
                      <ExternalLinkIcon className="size-3" />
                      查看绑定的真实流量包
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })}

      {previewBinding && (
        <TrafficEvidenceViewer
          findingId={finding.id}
          bindingId={previewBinding}
          contextTask={contextTask}
          onClose={() => setPreviewBinding(null)}
        />
      )}
    </div>
  );
}
