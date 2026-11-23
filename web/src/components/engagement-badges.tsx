"use client";

import type { LucideIcon } from "lucide-react";
import {
  ArrowRightIcon,
  Code2Icon,
  CrosshairIcon,
  FileCode2Icon,
  FlagIcon,
  GitCompareIcon,
  ShieldCheckIcon,
  SwordsIcon,
  TrophyIcon,
} from "lucide-react";

import {
  BOX_META,
  type BoxType,
  CATEGORY_META,
  type EngagementCategory,
  type EngagementMode,
  EXPOSURE_META,
  type ExposureLevel,
} from "@/lib/engagement";
import { cn } from "@/lib/utils";

/** 每个模式的代表图标；未知 key 回退到准星。 */
const MODE_ICONS: Record<string, LucideIcon> = {
  src: CrosshairIcon,
  crowdtest: TrophyIcon,
  "code-audit": FileCode2Icon,
  greybox: GitCompareIcon,
  redteam: SwordsIcon,
  ctf: FlagIcon,
  compliance: ShieldCheckIcon,
};

export function ModeIcon({ modeKey, className }: { modeKey: string; className?: string }) {
  const Icon = MODE_ICONS[modeKey] ?? Code2Icon;
  return <Icon className={cn("size-4", className)} />;
}

export function BoxBadge({ box, className }: { box: BoxType; className?: string }) {
  const meta = BOX_META[box];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap",
        meta.tone,
        className,
      )}
      title={meta.description}
    >
      {meta.label}
    </span>
  );
}

/** 盒型流转：起点 == 终点时只显示一个徽章，避免「白加黑 → 白加黑」这种噪音。 */
export function BoxFlow({ from, to, className }: { from: BoxType; to: BoxType; className?: string }) {
  if (from === to) {
    return (
      <span className={cn("inline-flex items-center gap-1", className)}>
        <BoxBadge box={from} />
        <span className="text-muted-foreground text-[10px]">稳态</span>
      </span>
    );
  }
  return (
    <span className={cn("inline-flex items-center gap-1", className)}>
      <BoxBadge box={from} />
      <ArrowRightIcon className="size-3 text-muted-foreground" />
      <BoxBadge box={to} />
    </span>
  );
}

export function ExposureBadge({ exposure, className }: { exposure: ExposureLevel; className?: string }) {
  const meta = EXPOSURE_META[exposure];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap",
        meta.tone,
        className,
      )}
      title={meta.hint}
    >
      {meta.label}
    </span>
  );
}

export function CategoryBadge({ category, className }: { category: EngagementCategory; className?: string }) {
  const meta = CATEGORY_META[category];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border border-transparent px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap",
        meta.tone,
        className,
      )}
    >
      {meta.label}
    </span>
  );
}

/** 模式徽章：图标 + 名称，用于列表行与任务标题旁。 */
export function ModeBadge({ mode, className }: { mode: EngagementMode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border bg-background px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap",
        className,
      )}
      title={mode.tagline}
    >
      <ModeIcon modeKey={mode.key} className="size-3" />
      {mode.name}
    </span>
  );
}
