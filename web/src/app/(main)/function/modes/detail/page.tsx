"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import {
  ArrowLeftIcon,
  ArrowRightIcon,
  CheckIcon,
  ClipboardCopyIcon,
  FlagIcon,
  GaugeIcon,
  ShieldAlertIcon,
  TargetIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { BoxBadge, BoxFlow, CategoryBadge, ExposureBadge, ModeIcon } from "@/components/engagement-badges";
import { ModeRoute } from "@/components/engagement-mode-picker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { buildModeBrief, EXPOSURE_META, modeByKey } from "@/lib/engagement";
import { copyText } from "@/lib/utils";

function GateKindBadge({ kind, manual }: { kind: string; manual: boolean }) {
  const labels: Record<string, string> = {
    artifact: "产物",
    evidence: "证据",
    approval: "审批",
    signal: "信号",
  };
  return (
    <span className="inline-flex shrink-0 items-center gap-1">
      <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
        {labels[kind] ?? kind}
      </Badge>
      {manual && (
        <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
          人工
        </Badge>
      )}
    </span>
  );
}

function ModeDetailInner() {
  const searchParams = useSearchParams();
  const key = searchParams.get("key") ?? "";
  const mode = modeByKey(key);
  const [copied, setCopied] = React.useState(false);

  if (!mode) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 py-20 text-center">
        <p className="text-muted-foreground">模式不存在：{key || "（缺少 key 参数）"}</p>
        <Button asChild variant="outline">
          <Link href="/function/modes">
            <ArrowLeftIcon /> 返回模式库
          </Link>
        </Button>
      </div>
    );
  }

  const gateCount = mode.stages.reduce((sum, stage) => sum + stage.gates.length, 0);

  async function copyBrief() {
    if (!mode) return;
    const ok = await copyText(buildModeBrief(mode));
    if (ok) {
      setCopied(true);
      toast.success("作战简报已复制");
      setTimeout(() => setCopied(false), 1500);
    } else {
      toast.error("复制失败，请手动选择文本");
    }
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-center gap-2">
        <Button asChild variant="ghost" size="sm">
          <Link href="/function/modes">
            <ArrowLeftIcon data-icon="inline-start" />
            模式库
          </Link>
        </Button>
        <span className="text-muted-foreground text-xs">/</span>
        <span className="text-sm font-medium">{mode.name}</span>
      </div>

      <Card className="gap-0 py-0">
        <CardContent className="flex flex-col gap-4 px-5 py-5">
          <div className="flex flex-wrap items-start gap-3">
            <span className="flex size-11 shrink-0 items-center justify-center rounded-xl border bg-muted">
              <ModeIcon modeKey={mode.key} className="size-5" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl font-semibold tracking-tight">{mode.name}</h1>
                <CategoryBadge category={mode.category} />
                <Badge variant="outline">内置模板</Badge>
              </div>
              <p className="mt-1 text-muted-foreground text-sm">{mode.tagline}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button type="button" size="sm" variant="outline" onClick={() => void copyBrief()}>
                {copied ? <CheckIcon data-icon="inline-start" /> : <ClipboardCopyIcon data-icon="inline-start" />}
                {copied ? "已复制" : "复制作战简报"}
              </Button>
              <Button asChild size="sm">
                <Link href={`/function/tasks?mode=${encodeURIComponent(mode.key)}`}>
                  <TargetIcon data-icon="inline-start" />
                  用此模式创建任务
                </Link>
              </Button>
            </div>
          </div>

          <p className="text-sm leading-relaxed text-muted-foreground">{mode.description}</p>

          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border p-3">
              <div className="text-muted-foreground text-[11px]">盒型演进</div>
              <div className="mt-1.5 flex flex-wrap items-center gap-1">
                <BoxFlow from={mode.entry_box} to={mode.target_box} />
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-muted-foreground text-[11px]">暴露强度</div>
              <div className="mt-1.5 flex items-center gap-2">
                <ExposureBadge exposure={mode.exposure} />
                <span className="text-muted-foreground line-clamp-1 text-[11px]">
                  {EXPOSURE_META[mode.exposure].hint}
                </span>
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-muted-foreground text-[11px]">流程规模</div>
              <div className="mt-1.5 flex items-center gap-1.5 text-sm">
                <span className="font-semibold tabular-nums">{mode.stages.length}</span>
                <span className="text-muted-foreground text-xs">阶段</span>
                <span className="text-muted-foreground/40">/</span>
                <span className="font-semibold tabular-nums">{gateCount}</span>
                <span className="text-muted-foreground text-xs">闸门</span>
                <span className="text-muted-foreground/40">/</span>
                <span className="font-semibold tabular-nums">{mode.evolutions.length}</span>
                <span className="text-muted-foreground text-xs">演进</span>
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-muted-foreground text-[11px]">首个意图</div>
              <div className="mt-1.5 flex items-center gap-1.5 text-xs">
                <ZapIcon className="size-3.5 text-amber-500" />
                {mode.seed_first_intent ? "推荐开启（创建即开跑）" : "默认关闭（先规划再执行）"}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="flex min-w-0 flex-col gap-4">
          <Card className="py-0">
            <CardHeader className="px-4 pt-4 pb-2">
              <CardTitle className="text-sm">阶段流水线</CardTitle>
              <CardDescription>未满足闸门不得进入下一阶段；这也是写进任务简报的推进口径。</CardDescription>
            </CardHeader>
            <CardContent className="px-4 py-4">
              <ol className="relative space-y-4">
                {mode.stages.map((stage, index) => (
                  <li key={stage.id} className="relative pl-9">
                    <span className="absolute top-0 left-0 flex size-6 items-center justify-center rounded-full border bg-background text-[11px] font-semibold">
                      {index + 1}
                    </span>
                    {index < mode.stages.length - 1 && (
                      <span className="absolute top-7 bottom-[-1rem] left-[11px] w-px bg-border" aria-hidden />
                    )}
                    <div className="rounded-lg border bg-card p-3">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-sm font-medium">{stage.name}</span>
                        <BoxBadge box={stage.box} />
                        <span className="text-muted-foreground ml-auto text-[11px] tabular-nums">
                          预算 {stage.budget}%
                        </span>
                      </div>
                      <p className="mt-1 text-muted-foreground text-xs leading-relaxed">{stage.intent}</p>
                      <div className="mt-2 flex flex-wrap gap-1">
                        {stage.actions.map((action) => (
                          <span
                            key={action}
                            className="rounded border bg-muted/40 px-1.5 py-0.5 text-[10px] text-muted-foreground"
                          >
                            {action}
                          </span>
                        ))}
                      </div>
                      <Separator className="my-2" />
                      <div className="text-[11px] font-medium text-muted-foreground">闸门</div>
                      <ul className="mt-1 space-y-1">
                        {stage.gates.map((gate) => (
                          <li key={gate.id} className="flex items-start gap-2">
                            <CheckIcon className="mt-0.5 size-3 shrink-0 text-muted-foreground" />
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="text-xs font-medium">{gate.label}</span>
                                <GateKindBadge kind={gate.kind} manual={gate.manual} />
                              </div>
                              <p className="text-muted-foreground text-[11px] leading-relaxed">{gate.criterion}</p>
                            </div>
                          </li>
                        ))}
                      </ul>
                      <div className="mt-2 flex flex-wrap items-center gap-1 text-[11px] text-muted-foreground">
                        <FlagIcon className="size-3" />
                        产出：{stage.deliverables.join("、")}
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>

          <Card className="py-0">
            <CardHeader className="px-4 pt-4 pb-2">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <ZapIcon className="size-4 text-amber-500" />
                演进规则
              </CardTitle>
              <CardDescription>命中信号后切换盒型或模式，把「疑似」变成「已确认」。</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 px-4 py-3">
              {mode.evolutions.length === 0 ? (
                <p className="text-muted-foreground py-3 text-xs">该模式不需要阶段性演进，按固定路线推进即可。</p>
              ) : (
                mode.evolutions.map((rule) => {
                  const targetMode = modeByKey(rule.to_mode);
                  return (
                    <div key={rule.id} className="rounded-lg border p-3">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-xs font-medium">{rule.trigger}</span>
                        <Badge
                          variant={rule.action === "auto" ? "default" : "outline"}
                          className="h-5 px-1.5 text-[10px]"
                        >
                          {rule.action === "auto" ? "自动" : "建议"}
                        </Badge>
                        <span className="text-muted-foreground ml-auto flex items-center gap-1 text-[11px]">
                          {rule.to_box ? (
                            <>
                              盒型
                              <ArrowRightIcon className="size-3" />
                              <BoxBadge box={rule.to_box} className="px-1 py-0 text-[10px]" />
                            </>
                          ) : (
                            "盒型不变"
                          )}
                        </span>
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {rule.signals.map((signal) => (
                          <span
                            key={signal}
                            className="rounded border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                          >
                            {signal}
                          </span>
                        ))}
                      </div>
                      <p className="mt-1.5 text-muted-foreground text-xs leading-relaxed">
                        {rule.rationale}
                        {targetMode && (
                          <Link
                            prefetch={false}
                            href={`/function/modes/detail?key=${encodeURIComponent(targetMode.key)}`}
                            className="text-foreground ml-1.5 underline underline-offset-2"
                          >
                            查看「{targetMode.name}」
                          </Link>
                        )}
                      </p>
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <Card className="py-0">
            <CardHeader className="px-4 pt-4 pb-2">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <TargetIcon className="size-4" />
                适用场景
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 py-3">
              <ul className="space-y-1.5 text-xs text-muted-foreground">
                {mode.fit.map((item) => (
                  <li key={item} className="flex gap-1.5">
                    <span className="mt-1.5 size-1 shrink-0 rounded-full bg-muted-foreground/60" />
                    {item}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <Card className="py-0">
            <CardHeader className="px-4 pt-4 pb-2">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <ShieldAlertIcon className="size-4 text-red-500" />
                硬约束
              </CardTitle>
              <CardDescription>会写入任务简报，planner 不得越界。</CardDescription>
            </CardHeader>
            <CardContent className="px-4 py-3">
              <ul className="space-y-1.5 text-xs text-muted-foreground">
                {mode.constraints.map((item) => (
                  <li key={item} className="flex gap-1.5">
                    <span className="mt-1.5 size-1 shrink-0 rounded-full bg-red-500/60" />
                    {item}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <Card className="py-0">
            <CardHeader className="px-4 pt-4 pb-2">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <GaugeIcon className="size-4" />
                交付物
              </CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-1 px-4 py-3">
              {mode.deliverables.map((item) => (
                <Badge key={item} variant="outline">
                  {item}
                </Badge>
              ))}
            </CardContent>
          </Card>

          <Card className="py-0">
            <CardHeader className="px-4 pt-4 pb-2">
              <CardTitle className="text-sm">默认模板</CardTitle>
              <CardDescription>新建任务时可直接套用。</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 px-4 py-3">
              <div>
                <div className="text-muted-foreground text-[11px]">描述</div>
                <p className="mt-0.5 text-xs leading-relaxed">{mode.default_description}</p>
              </div>
              <div>
                <div className="text-muted-foreground text-[11px]">目标</div>
                <p className="mt-0.5 text-xs leading-relaxed">{mode.default_goal}</p>
              </div>
              <div>
                <div className="text-muted-foreground text-[11px]">路线</div>
                <ModeRoute mode={mode} className="mt-1" />
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

// useSearchParams 需要 Suspense 边界才能在静态导出下正常工作（同任务详情页）。
export default function ModeDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <ModeDetailInner />
    </React.Suspense>
  );
}
