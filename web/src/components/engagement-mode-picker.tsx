"use client";

import * as React from "react";

import { CheckIcon, InfoIcon, SparklesIcon, XIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { BOX_META, ENGAGEMENT_MODES, type EngagementMode, modeTemplate } from "@/lib/engagement";
import { cn } from "@/lib/utils";

import { BoxFlow, ExposureBadge, ModeIcon } from "./engagement-badges";

/**
 * 作战模式选择器：新建任务与任务详情「更换模式」共用。
 *
 * 选中模式只影响表单预填与简报注入，不改变已有能力；真正的执行约束通过描述注入
 * planner（见 lib/engagement.ts 的 buildModeBrief）。
 */
export function EngagementModePicker({
  value,
  onSelect,
  onApplyTemplate,
  allowClear = true,
  className,
}: {
  value: string | null;
  onSelect: (mode: EngagementMode | null) => void;
  /** 「套用模式简报」：把描述/目标填成模式模板（父组件负责确认是否覆盖）。 */
  onApplyTemplate?: (mode: EngagementMode) => void;
  allowClear?: boolean;
  className?: string;
}) {
  const selected = React.useMemo(() => ENGAGEMENT_MODES.find((mode) => mode.key === value) ?? null, [value]);

  return (
    <Field className={className}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <FieldLabel>作战模式</FieldLabel>
        {allowClear && selected && (
          <Button type="button" variant="ghost" size="sm" onClick={() => onSelect(null)}>
            <XIcon data-icon="inline-start" />
            清除模式
          </Button>
        )}
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {ENGAGEMENT_MODES.map((mode) => {
          const active = mode.key === value;
          return (
            <button
              key={mode.key}
              type="button"
              aria-pressed={active}
              onClick={() => onSelect(active && allowClear ? null : mode)}
              className={cn(
                "group relative flex flex-col gap-1.5 rounded-lg border p-3 text-left transition-colors",
                active
                  ? "border-primary bg-primary/5 ring-1 ring-primary"
                  : "border-border hover:border-primary/40 hover:bg-muted/40",
              )}
            >
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    "flex size-7 shrink-0 items-center justify-center rounded-md border",
                    active ? "border-primary/40 bg-primary/10 text-primary" : "bg-muted text-muted-foreground",
                  )}
                >
                  <ModeIcon modeKey={mode.key} />
                </span>
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{mode.name}</span>
                {active && <CheckIcon className="size-4 shrink-0 text-primary" />}
              </div>
              <p className="line-clamp-2 text-muted-foreground text-xs leading-relaxed">{mode.tagline}</p>
              <div className="flex flex-wrap items-center gap-1">
                <BoxFlow from={mode.entry_box} to={mode.target_box} />
                <ExposureBadge exposure={mode.exposure} className="ml-auto" />
              </div>
            </button>
          );
        })}
      </div>

      <FieldDescription>
        模式决定阶段路线、闸门与硬约束，并自动写入任务描述作为作战简报；不影响已有工具能力。
      </FieldDescription>

      {selected && (
        <div className="rounded-lg border bg-muted/30 p-3">
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            <Badge variant="outline" className="gap-1">
              <SparklesIcon className="size-3" />
              {selected.stages.length} 阶段
            </Badge>
            <Badge variant="outline">{selected.stages.reduce((sum, stage) => sum + stage.gates.length, 0)} 闸门</Badge>
            <Badge variant="outline">{selected.evolutions.length} 条演进</Badge>
            <span className="text-muted-foreground ml-auto flex items-center gap-1">
              {modeTemplate(selected).route}
            </span>
          </div>
          <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
            {selected.constraints.slice(0, 3).map((constraint) => (
              <li key={constraint} className="flex gap-1.5">
                <span className="mt-1.5 size-1 shrink-0 rounded-full bg-muted-foreground/60" />
                <span className="line-clamp-1">{constraint}</span>
              </li>
            ))}
          </ul>
          <div className="mt-2 flex items-center gap-2">
            {onApplyTemplate && (
              <Button type="button" size="sm" variant="outline" onClick={() => onApplyTemplate(selected)}>
                套用模式简报
              </Button>
            )}
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="text-muted-foreground inline-flex items-center gap-1 text-[11px]">
                  <InfoIcon className="size-3" />
                  简报包含阶段闸门与硬约束
                </span>
              </TooltipTrigger>
              <TooltipContent className="max-w-xs">
                创建任务时会把「作战简报」追加到描述末尾：模式、阶段路线、每阶段闸门、硬约束与演进规则。 planner
                读取描述后会按该节奏推进，无需修改后端。
              </TooltipContent>
            </Tooltip>
          </div>
        </div>
      )}
    </Field>
  );
}

/** 模式路线的紧凑展示：阶段短名 + 盒型着色，用于卡片/详情头部。 */
export function ModeRoute({ mode, className }: { mode: EngagementMode; className?: string }) {
  return (
    <div className={cn("flex flex-wrap items-center gap-1", className)}>
      {mode.stages.map((stage, index) => (
        <React.Fragment key={stage.id}>
          {index > 0 && <span className="text-muted-foreground/60 text-[10px]">›</span>}
          <span
            className={cn(
              "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium",
              BOX_META[stage.box].tone,
            )}
            title={`${stage.name}：${stage.intent}`}
          >
            {stage.short}
          </span>
        </React.Fragment>
      ))}
    </div>
  );
}
