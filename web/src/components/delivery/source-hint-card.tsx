"use client";

// 「开源指纹 → 源码」提示卡：任务出现过知名靶场/开源系统时，提示取源码转白加黑。
//
// 数据来源：任务的资产 + 发现内容 + 任务描述里的目标 URL。识别命中后给出
// 仓库地址与「优先看的目录」，并提示这是白加黑的最佳切入点。

import * as React from "react";

import { BookOpenIcon, ExternalLinkIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { detectSourceHint, type SourceHint } from "@/lib/source-hints";

export function SourceHintCard({
  description,
  assets,
  findings,
}: {
  description?: string;
  assets?: { label?: string }[];
  findings?: { name?: string; vulnclass?: string; summary?: string }[];
}) {
  const hint: SourceHint | null = React.useMemo(() => {
    const signals: string[] = [];
    if (description) signals.push(description);
    for (const asset of assets ?? []) {
      if (asset.label) signals.push(asset.label);
    }
    for (const finding of findings ?? []) {
      signals.push(finding.name ?? "", finding.vulnclass ?? "", finding.summary ?? "");
    }
    return detectSourceHint(signals);
  }, [description, assets, findings]);

  if (!hint) return null;

  return (
    <Card className="border-sky-500/30 bg-sky-500/5">
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-1.5 text-sm">
          <BookOpenIcon className="size-4 text-sky-600 dark:text-sky-400" />
          识别到开源项目：{hint.name}
          <Badge variant="outline" className="text-[10px]">
            可直接转白加黑
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-xs">
        <p className="text-muted-foreground leading-relaxed">
          目标是公开项目，源码可得。建议先取源码定位到「文件:行号」，再回线上验证——
          这比在黑盒里盲猜参数快一个数量级，报告也能写清根因。
        </p>
        <a
          href={hint.repo}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 font-mono text-sky-700 hover:underline dark:text-sky-400"
        >
          <ExternalLinkIcon className="size-3" />
          {hint.repo}
        </a>
        <div>
          <div className="text-muted-foreground mb-1 text-[11px] font-medium">优先定位</div>
          <ul className="space-y-1 text-muted-foreground">
            {hint.focus.map((item) => (
              <li key={item} className="flex gap-1.5">
                <span className="mt-1.5 size-1 shrink-0 rounded-full bg-muted-foreground/60" />
                <span className="leading-relaxed">{item}</span>
              </li>
            ))}
          </ul>
        </div>
        <p className="text-muted-foreground text-[11px]">
          取源码途径：GitHub 克隆 / 目标泄露的 .git / 备份包 / 容器镜像内目录。
        </p>
      </CardContent>
    </Card>
  );
}
