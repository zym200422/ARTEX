"use client";

import * as React from "react";

import {
  ArrowRightIcon,
  CheckIcon,
  ChevronRightIcon,
  CircleIcon,
  GitCompareArrowsIcon,
  LightbulbIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  SwordsIcon,
  TargetIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { BoxBadge, CategoryBadge, ModeIcon } from "@/components/engagement-badges";
import { EngagementModePicker, ModeRoute } from "@/components/engagement-mode-picker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { api } from "@/lib/api";
import {
  advanceEngagementStage,
  applyEvolution,
  BOX_META,
  boxRank,
  type EngagementMode,
  type EngagementStage,
  type EvolutionRule,
  engagementProgress,
  initialEngagementState,
  modeByKey,
  stageByID,
  stageGatesSatisfied,
  type TaskEngagement,
  toggleEngagementGate,
} from "@/lib/engagement";
import {
  type AutoGateContext,
  applyAutoGates,
  autoProgress,
  EMPTY_AUTO_CONTEXT,
  isAutoJudgeable,
} from "@/lib/engagement-auto";
import {
  clearTaskEngagement,
  getTaskEngagement,
  setTaskEngagement,
  subscribeTaskEngagement,
} from "@/lib/engagement-store";
import { cn } from "@/lib/utils";

// 盒型轨道：黑 → 灰 → 白+黑 → 白。当前盒型高亮，越过当前盒型的节点置灰（尚未到达）。
const BOX_TRACK = ["black", "grey", "hybrid", "white"] as const;

function fmtClock(unix: number): string {
  return new Date(unix * 1000).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function stageStatusMeta(status: string): { label: string; className: string } {
  switch (status) {
    case "done":
      return { label: "已完成", className: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400" };
    case "active":
      return { label: "进行中", className: "bg-blue-500/15 text-blue-700 dark:text-blue-400" };
    case "blocked":
      return { label: "受阻", className: "bg-red-500/15 text-red-700 dark:text-red-400" };
    default:
      return { label: "待开始", className: "bg-muted text-muted-foreground" };
  }
}

function StageRail({
  mode,
  state,
  focus,
  onFocus,
}: {
  mode: EngagementMode;
  state: TaskEngagement;
  focus: string;
  onFocus: (stageID: string) => void;
}) {
  return (
    <div className="no-scrollbar -mx-1 flex gap-1 overflow-x-auto px-1 pb-1">
      {mode.stages.map((stage, index) => {
        const record = state.stages.find((item) => item.stage_id === stage.id);
        const done = record?.passed_gates.length ?? 0;
        const active = stage.id === state.current_stage;
        const focused = stage.id === focus;
        const doneFull = done >= stage.gates.length;
        return (
          <button
            key={stage.id}
            type="button"
            onClick={() => onFocus(stage.id)}
            className={cn(
              "flex min-w-[7.5rem] flex-col gap-1 rounded-lg border px-2.5 py-2 text-left transition-colors",
              focused ? "border-primary/60 bg-primary/5" : "border-border hover:bg-muted/40",
            )}
          >
            <div className="flex items-center gap-1.5">
              <span
                className={cn(
                  "flex size-5 shrink-0 items-center justify-center rounded-full border text-[10px] font-semibold",
                  doneFull
                    ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                    : active
                      ? "border-primary bg-primary text-primary-foreground"
                      : "bg-background text-muted-foreground",
                )}
              >
                {doneFull ? <CheckIcon className="size-3" /> : index + 1}
              </span>
              <span className="truncate text-xs font-medium">{stage.short}</span>
              <BoxBadge box={stage.box} className="ml-auto px-1 py-0 text-[9px]" />
            </div>
            <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
              <span className="tabular-nums">
                闸门 {done}/{stage.gates.length}
              </span>
              <span className="text-muted-foreground/40">·</span>
              <span>{active ? "当前" : record?.status === "done" ? "已完成" : "待命"}</span>
            </div>
            <div className="flex gap-0.5">
              {stage.gates.map((gate) => (
                <span
                  key={gate.id}
                  className={cn(
                    "h-0.5 flex-1 rounded-full",
                    (record?.passed_gates ?? []).includes(gate.id) ? "bg-emerald-500" : "bg-muted",
                  )}
                />
              ))}
            </div>
          </button>
        );
      })}
    </div>
  );
}

function BoxTrack({ box, target }: { box: EngagementMode["entry_box"]; target: EngagementMode["entry_box"] }) {
  const currentRank = boxRank(box);
  return (
    <div className="flex flex-wrap items-center gap-1">
      {BOX_TRACK.map((item, index) => (
        <React.Fragment key={item}>
          {index > 0 && <ChevronRightIcon className="size-3 text-muted-foreground/50" />}
          <span
            className={cn(
              "rounded-md border px-1.5 py-0.5 text-[10px] font-medium",
              item === box
                ? BOX_META[item].tone
                : boxRank(item) <= currentRank
                  ? "border-border bg-muted/50 text-muted-foreground"
                  : "border-dashed border-border text-muted-foreground/60",
            )}
          >
            {BOX_META[item].short}
          </span>
          {item === target && <span className="text-[9px] text-muted-foreground">目标</span>}
        </React.Fragment>
      ))}
    </div>
  );
}

function GateList({
  stage,
  passed,
  onToggle,
  autoMap,
}: {
  stage: EngagementStage;
  passed: string[];
  onToggle: (gateID: string, checked: boolean) => void;
  /** gateId → 是否由真实数据自动判定。 */
  autoMap: Record<string, boolean>;
}) {
  return (
    <ul className="space-y-2">
      {stage.gates.map((gate) => {
        const checked = passed.includes(gate.id);
        return (
          <li key={gate.id} className="flex items-start gap-2.5 rounded-lg border p-2.5">
            <Checkbox
              id={`gate-${gate.id}`}
              checked={checked}
              onCheckedChange={(value) => onToggle(gate.id, value === true)}
              className="mt-0.5"
            />
            <div className="min-w-0 flex-1">
              <label htmlFor={`gate-${gate.id}`} className="flex flex-wrap items-center gap-1.5 text-xs font-medium">
                {gate.label}
                {autoMap[gate.id] ? (
                  <Badge variant="outline" className="h-4 px-1 text-[9px]">
                    自动判定
                  </Badge>
                ) : gate.manual ? (
                  <Badge variant="secondary" className="h-4 px-1 text-[9px]">
                    人工确认
                  </Badge>
                ) : (
                  <Badge variant="outline" className="h-4 px-1 text-[9px]">
                    自动自证
                  </Badge>
                )}
                {checked && <CheckIcon className="size-3 text-emerald-600 dark:text-emerald-400" />}
              </label>
              <p className="mt-0.5 text-muted-foreground text-[11px] leading-relaxed">{gate.criterion}</p>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function EvolutionCard({
  rule,
  mode,
  onAdopt,
}: {
  rule: EvolutionRule;
  mode: EngagementMode;
  onAdopt: (rule: EvolutionRule) => void;
}) {
  const targetMode = modeByKey(rule.to_mode);
  const targetStage = rule.to_stage ? stageByID(mode, rule.to_stage) : null;
  return (
    <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
      <div className="flex flex-wrap items-center gap-1.5">
        <ZapIcon className="size-3.5 text-amber-600 dark:text-amber-400" />
        <span className="text-xs font-medium">{rule.trigger}</span>
        <Badge variant={rule.action === "auto" ? "default" : "outline"} className="h-5 px-1.5 text-[10px]">
          {rule.action === "auto" ? "可自动演进" : "建议演进"}
        </Badge>
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-1 text-[11px]">
        {rule.to_box && <BoxBadge box={rule.to_box} />}
        {targetMode && (
          <span className="inline-flex items-center gap-1 rounded-md border bg-background px-1.5 py-0.5">
            <ModeIcon modeKey={targetMode.key} className="size-3" />
            {targetMode.name}
          </span>
        )}
        {rule.to_stage && !targetMode && (
          <span className="text-muted-foreground">阶段 → {targetStage?.name ?? rule.to_stage}</span>
        )}
      </div>
      <p className="mt-1.5 text-muted-foreground text-[11px] leading-relaxed">{rule.rationale}</p>
      <div className="mt-1.5 flex flex-wrap gap-1">
        {rule.signals.map((signal) => (
          <span
            key={signal}
            className="rounded border bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
          >
            {signal}
          </span>
        ))}
      </div>
      <Button type="button" size="sm" variant="outline" className="mt-2 h-7" onClick={() => onAdopt(rule)}>
        <GitCompareArrowsIcon data-icon="inline-start" />
        采纳演进
      </Button>
    </div>
  );
}

export function EngagementTab({ taskId, taskStatus }: { taskId: string; taskStatus?: string }) {
  const [state, setState] = React.useState<TaskEngagement | null>(null);
  const [focus, setFocus] = React.useState<string>("");
  const [assignOpen, setAssignOpen] = React.useState(false);
  const [draftMode, setDraftMode] = React.useState<string | null>(null);
  const [pendingEvolution, setPendingEvolution] = React.useState<EvolutionRule | null>(null);
  // 自动判定上下文：由任务真实数据（资产/发现/报告）推导，驱动闸门自动勾选。
  const [autoCtx, setAutoCtx] = React.useState<AutoGateContext>(EMPTY_AUTO_CONTEXT);
  const manualGatesRef = React.useRef<Set<string>>(new Set());

  // 作战状态只存在浏览器侧：挂载后再读，避免静态导出预渲染与客户端不一致。
  React.useEffect(() => {
    const loaded = getTaskEngagement(taskId);
    setState(loaded);
    setFocus(loaded?.current_stage ?? "");
    return subscribeTaskEngagement(() => {
      const next = getTaskEngagement(taskId);
      setState(next);
      setFocus((current) => current || next?.current_stage || "");
    });
  }, [taskId]);

  const mode = React.useMemo(() => modeByKey(state?.mode), [state?.mode]);

  // 拉取任务真实数据 → 推导闸门是否已满足（资产/发现/证据/报告）。
  // 这样任务跑完时看板会自己走完，不需要手点。
  const loadAutoContext = React.useCallback(async () => {
    try {
      const [assetResp, findingList, engagementStatus] = await Promise.all([
        api.taskAssets(taskId, "", 1, 0).catch(() => ({ assets: [], total: 0 })),
        api.findings(taskId).catch(() => [] as import("@/lib/types").Finding[]),
        api.taskEngagementStatus(taskId).catch(() => null),
      ]);
      const findings = findingList ?? [];
      const terminal = ["done", "failed", "timeout"].includes(taskStatus ?? "");
      const confirmed = findings.filter((f) => ["confirmed", "resolved", "fixed"].includes(f.status)).length;
      const evidenced = findings.filter((f) => Boolean(f.evidence?.trim())).length;
      const reported = findings.filter((f) => Boolean(f.report?.trim())).length;
      const hosts = new Set(findings.flatMap((f) => (f.assets ?? []).map((a) => a.label ?? "")).filter(Boolean));
      setAutoCtx({
        assetCount: assetResp.total ?? 0,
        findingCount: findings.length,
        confirmedCount: confirmed,
        evidencedCount: evidenced,
        reportedCount: reported,
        reproCount: 0,
        taskTerminal: terminal,
        distinctHosts: hosts.size,
        triageDone: Boolean(engagementStatus?.signals?.src_triage_done),
      });
    } catch {
      // 拉取失败保持上一次判定，不影响手动操作
    }
  }, [taskId, taskStatus]);

  React.useEffect(() => {
    void loadAutoContext();
  }, [loadAutoContext]);

  // 上下文变化后把自动判定合并进作战状态（人工勾选/人工闸门保持不动）。
  React.useEffect(() => {
    if (!state || !mode) return;
    const merged = applyAutoGates(mode, state, autoCtx, manualGatesRef.current);
    if (merged !== state) {
      setTaskEngagement(taskId, merged);
      setState(merged);
    }
  }, [autoCtx, mode, state, taskId]);

  function persist(next: TaskEngagement) {
    setTaskEngagement(taskId, next);
    setState(next);
  }

  function assignMode(key: string) {
    const target = modeByKey(key);
    if (!target) return;
    const next = initialEngagementState(target);
    setTaskEngagement(taskId, next);
    setState(next);
    setFocus(next.current_stage);
    setAssignOpen(false);
    setDraftMode(null);
    toast.success(`已启用「${target.name}」作战模式`);
  }

  if (!state || !mode) {
    return (
      <Card className="mx-auto mt-6 max-w-3xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <SwordsIcon className="size-4" />
            本任务尚未指定作战模式
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-muted-foreground text-sm leading-relaxed">
            给任务套一个作战模式后，会得到可推进的阶段路线、逐阶段闸门和盒型演进建议。 典型路径：纯黑盒打点 → 拿到 shell
            / 发现 .git 泄露 → 一键演进为「白加黑」，转入源码定位与线上验证。
          </p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" onClick={() => setAssignOpen(true)}>
              <TargetIcon data-icon="inline-start" />
              指定作战模式
            </Button>
            <Button asChild variant="outline">
              <a href="/function/modes">浏览模式库</a>
            </Button>
          </div>
        </CardContent>
        <AssignDialog
          open={assignOpen}
          onOpenChange={setAssignOpen}
          value={draftMode ?? null}
          onSelect={(next) => setDraftMode(next?.key ?? null)}
          onConfirm={() => draftMode && assignMode(draftMode)}
        />
      </Card>
    );
  }

  const progress = autoProgress(mode, state);
  const currentStage = stageByID(mode, state.current_stage) ?? mode.stages[0];
  const focusedStage = stageByID(mode, focus) ?? currentStage;
  const focusedRecord = state.stages.find((item) => item.stage_id === focusedStage.id);
  const gatesOK = stageGatesSatisfied(mode, state);
  const isLast = mode.stages[mode.stages.length - 1]?.id === state.current_stage;
  const nextStageDef = mode.stages[mode.stages.findIndex((stage) => stage.id === state.current_stage) + 1];
  const suggestions = mode.evolutions.filter(
    (rule) => !state.evolutions.some((event) => event.trigger === rule.trigger),
  );

  function toggleGate(stageID: string, gateID: string, checked: boolean) {
    if (!state) return;
    // 记为用户手点，后续自动判定不再覆盖它
    manualGatesRef.current.add(gateID);
    persist(toggleEngagementGate(state, stageID, gateID, checked));
  }

  function advance() {
    if (!state) return;
    const at = Math.floor(Date.now() / 1000);
    const next = advanceEngagementStage(state, mode!, at);
    if (!next) {
      toast.info("已经是最后一个阶段，完成闸门后即可收尾报告。");
      return;
    }
    persist(next);
    setFocus(next.current_stage);
    toast.success(`已进入「${stageByID(mode!, next.current_stage)?.name ?? "下一阶段"}」`);
  }

  function adopt(rule: EvolutionRule) {
    if (!state) return;
    const at = Math.floor(Date.now() / 1000);
    const next = applyEvolution(state, mode!, rule, at);
    persist(next);
    setFocus(next.current_stage);
    setPendingEvolution(null);
    const nextMode = modeByKey(next.mode);
    toast.success(
      nextMode && nextMode.key !== mode!.key
        ? `已演进到「${nextMode.name}」（${BOX_META[next.box].label}）`
        : `已完成盒型演进（${BOX_META[next.box].label}）`,
    );
  }

  function reset() {
    clearTaskEngagement(taskId);
    setState(null);
    setFocus("");
    toast.success("已清除本任务的作战模式");
  }

  return (
    <div className="flex flex-col gap-4">
      {/* 顶部：模式 + 盒型轨道 + 进度 */}
      <Card className="gap-0 py-0">
        <CardContent className="flex flex-col gap-3 px-4 py-4 lg:px-5">
          <div className="flex flex-wrap items-start gap-3">
            <span className="flex size-10 shrink-0 items-center justify-center rounded-lg border bg-muted">
              <ModeIcon modeKey={mode.key} className="size-5" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-sm font-semibold">{mode.name}</span>
                <CategoryBadge category={mode.category} />
                <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
                  {state.evolutions.length > 0 ? `已演进 ${state.evolutions.length} 次` : "起始盒型"}
                </Badge>
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <BoxTrack box={state.box} target={mode.target_box} />
                <span className="text-muted-foreground text-[11px]">{mode.tagline}</span>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => {
                  manualGatesRef.current.clear();
                  void loadAutoContext();
                  // 立刻用当前上下文重算一次，给出手点反馈
                  const merged = applyAutoGates(mode!, state!, autoCtx, new Set());
                  persist(merged);
                  toast.success("已按任务实际数据重新判定闸门");
                }}
              >
                <RefreshCwIcon data-icon="inline-start" />
                重新判定
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={() => setAssignOpen(true)}>
                <GitCompareArrowsIcon data-icon="inline-start" />
                更换模式
              </Button>
              <Button type="button" size="sm" variant="ghost" onClick={reset}>
                清除
              </Button>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Progress value={progress} className="h-1.5 flex-1" />
            <span className="text-muted-foreground shrink-0 text-xs tabular-nums">闸门进度 {progress}%</span>
          </div>

          <div className="text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
            <span className="flex items-center gap-1">
              <TargetIcon className="size-3" />
              当前阶段：
              <span className="text-foreground font-medium">{currentStage.name}</span>
            </span>
            <span className="flex items-center gap-1">
              <ShieldCheckIcon className="size-3" />
              {currentStage.gates.length} 个闸门 · 已过{" "}
              {state.stages.find((item) => item.stage_id === currentStage.id)?.passed_gates.length ?? 0}
            </span>
            {nextStageDef && <span>下一阶段：{nextStageDef.name}</span>}
          </div>

          {state.next_hint && (
            <div className="flex items-start gap-2 rounded-md border border-blue-500/20 bg-blue-500/5 px-2.5 py-2 text-xs">
              <LightbulbIcon className="mt-0.5 size-3.5 shrink-0 text-blue-600 dark:text-blue-400" />
              <span className="leading-relaxed">{state.next_hint}</span>
            </div>
          )}

          <StageRail mode={mode} state={state} focus={focus} onFocus={setFocus} />
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_23rem]">
        {/* 左：阶段详情 + 闸门 */}
        <div className="flex min-w-0 flex-col gap-4">
          <Card className="gap-0 py-0">
            <CardHeader className="flex flex-row flex-wrap items-center gap-2 px-4 pt-4 pb-2">
              <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
                <CardTitle className="text-sm">{focusedStage.name}</CardTitle>
                <BoxBadge box={focusedStage.box} />
                <span
                  className={cn(
                    "rounded px-1.5 py-0.5 text-[10px] font-medium",
                    stageStatusMeta(focusedRecord?.status ?? "pending").className,
                  )}
                >
                  {focusedStage.id === state.current_stage
                    ? "当前阶段"
                    : stageStatusMeta(focusedRecord?.status ?? "pending").label}
                </span>
                <span className="text-muted-foreground text-[11px]">预算 {focusedStage.budget}%</span>
              </div>
              {focusedStage.id !== state.current_stage && (
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  className="h-7"
                  onClick={() => setFocus(state.current_stage)}
                >
                  回到当前阶段
                </Button>
              )}
            </CardHeader>
            <CardContent className="flex flex-col gap-3 px-4 py-3">
              <p className="text-xs leading-relaxed text-muted-foreground">{focusedStage.intent}</p>
              <div className="flex flex-wrap gap-1">
                {focusedStage.actions.map((action) => (
                  <span
                    key={action}
                    className="rounded border bg-muted/40 px-1.5 py-0.5 text-[10px] text-muted-foreground"
                  >
                    {action}
                  </span>
                ))}
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium">闸门检查</span>
                <span className="text-muted-foreground text-[11px] tabular-nums">
                  {
                    (focusedRecord?.passed_gates ?? []).filter((id) =>
                      focusedStage.gates.some((gate) => gate.id === id),
                    ).length
                  }
                  /{focusedStage.gates.length} 已通过
                </span>
              </div>
              <GateList
                stage={focusedStage}
                passed={focusedRecord?.passed_gates ?? []}
                autoMap={Object.fromEntries(
                  focusedStage.gates.map((gate) => [
                    gate.id,
                    isAutoJudgeable(focusedStage, gate.id) && !manualGatesRef.current.has(gate.id),
                  ]),
                )}
                onToggle={(gateID, checked) => toggleGate(focusedStage.id, gateID, checked)}
              />
              <div className="text-muted-foreground flex flex-wrap items-center gap-1 text-[11px]">
                产出：{focusedStage.deliverables.join("、")}
              </div>
              {focusedStage.id === state.current_stage && (
                <>
                  <Separator />
                  <div className="flex flex-wrap items-center gap-2">
                    <Button type="button" size="sm" onClick={advance} disabled={!gatesOK}>
                      <ArrowRightIcon data-icon="inline-start" />
                      {isLast ? "已是最后阶段" : `推进到「${nextStageDef?.short ?? "下一阶段"}」`}
                    </Button>
                    {!gatesOK && (
                      <span className="text-muted-foreground text-[11px]">
                        还有闸门未通过：
                        {currentStage.gates.length -
                          (state.stages.find((item) => item.stage_id === currentStage.id)?.passed_gates.length ??
                            0)}{" "}
                        项
                      </span>
                    )}
                    {gatesOK && isLast && (
                      <span className="text-muted-foreground text-[11px]">闸门已全部通过，可进入报告收尾。</span>
                    )}
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* 演进时间线 */}
          <Card className="gap-0 py-0">
            <CardHeader className="px-4 pt-4 pb-2">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <GitCompareArrowsIcon className="size-4" />
                盒型演进记录
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 py-3">
              {state.evolutions.length === 0 ? (
                <p className="text-muted-foreground py-2 text-xs">
                  还没有演进记录。当拿到 shell、发现源码泄露或命中开源指纹时，右侧会出现可采纳的演进建议。
                </p>
              ) : (
                <ol className="space-y-3">
                  {state.evolutions.map((event) => (
                    <li key={event.id} className="flex gap-3">
                      <span className="mt-1 flex size-6 shrink-0 items-center justify-center rounded-full border bg-background">
                        <CircleIcon className="size-2.5 fill-primary text-primary" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-xs font-medium">{event.trigger}</span>
                          <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
                            {event.auto ? "自动" : "人工确认"}
                          </Badge>
                          <span className="text-muted-foreground ml-auto text-[10px] tabular-nums">
                            {fmtClock(event.at)}
                          </span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-1 text-[11px] text-muted-foreground">
                          <BoxBadge box={event.from_box} className="px-1 py-0 text-[9px]" />
                          <ArrowRightIcon className="size-3" />
                          <BoxBadge box={event.to_box} className="px-1 py-0 text-[9px]" />
                          {event.from_mode && event.to_mode && event.from_mode !== event.to_mode && (
                            <span className="ml-1">
                              模式 {modeByKey(event.from_mode)?.name ?? event.from_mode} →{" "}
                              {modeByKey(event.to_mode)?.name ?? event.to_mode}
                            </span>
                          )}
                        </div>
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>
        </div>

        {/* 右：演进建议 + 路线 */}
        <div className="flex min-w-0 flex-col gap-4">
          <Card className="gap-0 py-0">
            <CardHeader className="px-4 pt-4 pb-2">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <ZapIcon className="size-4 text-amber-500" />
                演进建议
              </CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 px-4 py-3">
              {suggestions.length === 0 ? (
                <p className="text-muted-foreground py-2 text-xs">当前没有待采纳的演进规则，按阶段路线推进即可。</p>
              ) : (
                suggestions.map((rule) => (
                  <EvolutionCard key={rule.id} rule={rule} mode={mode} onAdopt={setPendingEvolution} />
                ))
              )}
            </CardContent>
          </Card>

          <Card className="gap-0 py-0">
            <CardHeader className="px-4 pt-4 pb-2">
              <CardTitle className="text-sm">路线</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 px-4 py-3">
              <ModeRoute mode={mode} />
              <p className="text-muted-foreground text-[11px] leading-relaxed">
                阶段闸门会写进任务简报，planner 按此推进；手动推进仅记录看板状态，不改变正在运行的探索意图。
              </p>
            </CardContent>
          </Card>
        </div>
      </div>

      <AssignDialog
        open={assignOpen}
        onOpenChange={setAssignOpen}
        value={draftMode ?? state.mode}
        onSelect={(next) => setDraftMode(next?.key ?? null)}
        onConfirm={() => {
          if (draftMode && draftMode !== state.mode) {
            assignMode(draftMode);
          } else {
            setAssignOpen(false);
          }
        }}
        replacing={true}
      />

      {/* 演进确认 */}
      <Dialog open={pendingEvolution != null} onOpenChange={(open) => !open && setPendingEvolution(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>采纳演进：{pendingEvolution?.trigger}</DialogTitle>
            <DialogDescription>
              {pendingEvolution && (
                <>
                  盒型将从 <span className="font-medium">{BOX_META[state.box].label}</span> 切换为{" "}
                  <span className="font-medium">{BOX_META[pendingEvolution.to_box ?? state.box].label}</span>
                  {pendingEvolution.to_mode && (
                    <>，并转入「{modeByKey(pendingEvolution.to_mode)?.name ?? pendingEvolution.to_mode}」模式</>
                  )}
                  。{pendingEvolution.rationale}
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setPendingEvolution(null)}>
              取消
            </Button>
            <Button type="button" onClick={() => pendingEvolution && adopt(pendingEvolution)}>
              确认演进
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function AssignDialog({
  open,
  onOpenChange,
  value,
  onSelect,
  onConfirm,
  replacing = false,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  value: string | null;
  onSelect: (mode: EngagementMode | null) => void;
  onConfirm: () => void;
  replacing?: boolean;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{replacing ? "更换作战模式" : "指定作战模式"}</DialogTitle>
          <DialogDescription>
            {replacing
              ? "更换后会重置阶段进度与闸门记录（已产生的演进记录会保留在本地历史之外）。"
              : "选定后即可按阶段推进；随时可以在同一页面更换。"}
          </DialogDescription>
        </DialogHeader>
        <EngagementModePicker value={value} onSelect={onSelect} allowClear={false} />
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button type="button" onClick={onConfirm} disabled={!value}>
            启用
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
