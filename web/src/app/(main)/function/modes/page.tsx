"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowRightIcon, InfoIcon, PlusIcon, SearchIcon, SparklesIcon, WorkflowIcon } from "lucide-react";

import { BoxBadge, BoxFlow, CategoryBadge, ExposureBadge, ModeIcon } from "@/components/engagement-badges";
import { ModeRoute } from "@/components/engagement-mode-picker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  BOX_META,
  CATEGORY_META,
  ENGAGEMENT_MODES,
  type EngagementCategory,
  type EngagementMode,
} from "@/lib/engagement";
import { cn } from "@/lib/utils";

const CATEGORY_FILTERS: ("all" | EngagementCategory)[] = ["all", "bounty", "audit", "offensive", "compliance", "lab"];

function modeMatches(mode: EngagementMode, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [mode.name, mode.key, mode.tagline, mode.description, ...mode.fit].some((text) =>
    text.toLowerCase().includes(q),
  );
}

function ModeCard({ mode }: { mode: EngagementMode }) {
  const gates = mode.stages.reduce((sum, stage) => sum + stage.gates.length, 0);
  return (
    <Link
      href={`/function/modes/detail?key=${encodeURIComponent(mode.key)}`}
      className="group focus-visible:outline-none"
    >
      <Card className="h-full gap-0 py-0 transition-colors group-hover:border-primary/40 group-focus-visible:ring-2 group-focus-visible:ring-ring/60">
        <CardHeader className="gap-2 px-4 pt-4">
          <div className="flex items-start gap-2.5">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border bg-muted text-foreground">
              <ModeIcon modeKey={mode.key} className="size-4.5" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="truncate text-sm font-semibold">{mode.name}</span>
                <CategoryBadge category={mode.category} />
              </div>
              <p className="mt-0.5 line-clamp-2 text-muted-foreground text-xs leading-relaxed">{mode.tagline}</p>
            </div>
            <ArrowRightIcon className="mt-1 size-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
          </div>
        </CardHeader>
        <CardContent className="flex flex-1 flex-col gap-3 px-4 py-3">
          <ModeRoute mode={mode} />
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <BoxFlow from={mode.entry_box} to={mode.target_box} />
            <ExposureBadge exposure={mode.exposure} className="ml-auto" />
          </div>
        </CardContent>
        <CardFooter className="mt-auto flex items-center gap-2 border-t px-4 py-2.5 text-[11px] text-muted-foreground">
          <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
            {mode.stages.length} 阶段
          </Badge>
          <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
            {gates} 闸门
          </Badge>
          <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
            {mode.evolutions.length} 演进
          </Badge>
          <span className="ml-auto">内置模板</span>
        </CardFooter>
      </Card>
    </Link>
  );
}

export default function ModesPage() {
  const [category, setCategory] = React.useState<"all" | EngagementCategory>("all");
  const [query, setQuery] = React.useState("");

  const stats = React.useMemo(() => {
    const stages = ENGAGEMENT_MODES.reduce((sum, mode) => sum + mode.stages.length, 0);
    const gates = ENGAGEMENT_MODES.reduce(
      (sum, mode) => sum + mode.stages.reduce((inner, stage) => inner + stage.gates.length, 0),
      0,
    );
    const evolutions = ENGAGEMENT_MODES.reduce((sum, mode) => sum + mode.evolutions.length, 0);
    return { stages, gates, evolutions };
  }, []);

  const visible = React.useMemo(
    () =>
      ENGAGEMENT_MODES.filter((mode) => (category === "all" || mode.category === category) && modeMatches(mode, query)),
    [category, query],
  );

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">作战模式</h1>
          <p className="text-muted-foreground text-sm">
            为不同场景选择精细化流程：模式决定阶段路线、闸门与硬约束，盒型随证据演进（黑盒 → 白加黑 → 白盒）。
          </p>
        </div>
        <Button asChild size="sm">
          <Link href="/function/tasks">
            <PlusIcon data-icon="inline-start" />
            新建作战任务
          </Link>
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {[
          { label: "内置模式", value: ENGAGEMENT_MODES.length, icon: WorkflowIcon },
          { label: "阶段", value: stats.stages, icon: SparklesIcon },
          { label: "闸门", value: stats.gates, icon: InfoIcon },
          { label: "演进规则", value: stats.evolutions, icon: ArrowRightIcon },
        ].map((item) => (
          <Card key={item.label} className="py-0">
            <CardContent className="flex items-center gap-2.5 px-3.5 py-3">
              <span className="flex size-8 items-center justify-center rounded-md bg-muted">
                <item.icon className="size-4 text-muted-foreground" />
              </span>
              <div>
                <div className="text-lg leading-none font-semibold tabular-nums">{item.value}</div>
                <div className="mt-1 text-muted-foreground text-[11px]">{item.label}</div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap items-center gap-1 rounded-lg border p-1">
          {CATEGORY_FILTERS.map((item) => {
            const label = item === "all" ? "全部" : CATEGORY_META[item].label;
            const active = category === item;
            return (
              <button
                key={item}
                type="button"
                onClick={() => setCategory(item)}
                className={cn(
                  "rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                  active ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted",
                )}
              >
                {label}
              </button>
            );
          })}
        </div>
        <div className="relative w-full sm:ml-auto sm:w-64">
          <SearchIcon className="text-muted-foreground pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索模式 / 场景 / 关键词"
            className="pl-8"
          />
        </div>
        <span className="text-muted-foreground text-xs tabular-nums">
          {visible.length}/{ENGAGEMENT_MODES.length}
        </span>
      </div>

      {visible.length === 0 ? (
        <div className="text-muted-foreground flex items-center justify-center rounded-lg border border-dashed py-16 text-sm">
          没有匹配的模式。
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {visible.map((mode) => (
            <ModeCard key={mode.key} mode={mode} />
          ))}
        </div>
      )}

      <Card className="py-0">
        <CardHeader className="px-4 pt-4">
          <div className="flex items-center gap-2">
            <InfoIcon className="size-4 text-muted-foreground" />
            <span className="text-sm font-medium">盒型演进：从纯黑盒到白加黑</span>
          </div>
        </CardHeader>
        <CardContent className="grid gap-3 px-4 py-3 sm:grid-cols-2 xl:grid-cols-4">
          {(["black", "grey", "hybrid", "white"] as const).map((box) => (
            <div key={box} className="rounded-lg border p-3">
              <BoxBadge box={box} />
              <p className="mt-2 text-muted-foreground text-xs leading-relaxed">{BOX_META[box].description}</p>
            </div>
          ))}
        </CardContent>
        <CardFooter className="border-t px-4 py-2.5 text-muted-foreground text-xs">
          典型链路：纯黑盒打点 → 拿到 shell / 发现 .git 泄露 / 指纹命中开源框架 →{" "}
          <span className="text-foreground">转入白加黑（源码定位 + 线上验证）</span>
          。这一步通常在任务详情「作战」页一键演进。
        </CardFooter>
      </Card>
    </div>
  );
}
