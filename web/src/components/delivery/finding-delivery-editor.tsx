"use client";

import * as React from "react";

import { PencilIcon, RotateCcwIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import type { DeliveryEnrichment, Reproduction, ReproStep } from "@/lib/delivery";
import {
  resetDeliveryEnrichment,
  resetDeliveryReproduction,
  saveDeliveryEnrichment,
  saveDeliveryReproduction,
} from "@/lib/delivery-store";
import type { Finding } from "@/lib/types";

function linesToArray(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function emptyStep(): ReproStep {
  return { request: "", response: "", expected: "", proves: "" };
}

/**
 * 编辑交付内容：把「AI 分析 / 人工整理」的结果落成结构化字段。
 * 保存后立即影响发现详情与之后生成的报告（报告使用生成时的快照）。
 */
export function FindingDeliveryEditor({
  finding,
  open,
  onOpenChange,
  enrichment,
  reproduction,
  onSaved,
}: {
  finding: Finding;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  enrichment: DeliveryEnrichment;
  reproduction: Reproduction;
  onSaved: () => void;
}) {
  const [name, setName] = React.useState(enrichment.name);
  const [target, setTarget] = React.useState(enrichment.target);
  const [score, setScore] = React.useState(String(enrichment.cvss_score));
  const [vector, setVector] = React.useState(enrichment.cvss_vector);
  const [description, setDescription] = React.useState(enrichment.description.join("\n"));
  const [impact, setImpact] = React.useState(enrichment.risk_analysis.join("\n"));
  const [remediation, setRemediation] = React.useState(enrichment.remediation.join("\n"));
  const [entryPoint, setEntryPoint] = React.useState(reproduction.entry_point ?? "");
  const [prerequisites, setPrerequisites] = React.useState((reproduction.prerequisites ?? []).join("\n"));
  const [steps, setSteps] = React.useState<ReproStep[]>(
    reproduction.steps.length > 0 ? reproduction.steps : [emptyStep()],
  );

  React.useEffect(() => {
    if (!open) return;
    setName(enrichment.name);
    setTarget(enrichment.target);
    setScore(String(enrichment.cvss_score));
    setVector(enrichment.cvss_vector);
    setDescription(enrichment.description.join("\n"));
    setImpact(enrichment.risk_analysis.join("\n"));
    setRemediation(enrichment.remediation.join("\n"));
    setEntryPoint(reproduction.entry_point ?? "");
    setPrerequisites((reproduction.prerequisites ?? []).join("\n"));
    setSteps(reproduction.steps.length > 0 ? reproduction.steps : [emptyStep()]);
  }, [open, enrichment, reproduction]);

  function updateStep(index: number, patch: Partial<ReproStep>) {
    setSteps((current) => current.map((step, i) => (i === index ? { ...step, ...patch } : step)));
  }

  function save() {
    const numericScore = Number(score);
    if (!Number.isFinite(numericScore) || numericScore < 0 || numericScore > 10) {
      toast.error("CVSS 分值需在 0-10 之间");
      return;
    }
    saveDeliveryEnrichment(finding.id, {
      ...enrichment,
      name: name.trim() || enrichment.name,
      target: target.trim(),
      cvss_score: numericScore,
      cvss_vector: vector.trim(),
      description: linesToArray(description),
      risk_analysis: linesToArray(impact),
      remediation: linesToArray(remediation),
      source: "manual",
    });
    saveDeliveryReproduction(finding.id, {
      entry_point: entryPoint.trim() || undefined,
      prerequisites: linesToArray(prerequisites),
      steps: steps.filter((step) => step.request.trim() || step.response.trim() || step.expected.trim()),
      provenance: "manual",
    });
    onOpenChange(false);
    onSaved();
    toast.success("交付内容已保存");
  }

  function reset() {
    resetDeliveryEnrichment(finding.id);
    resetDeliveryReproduction(finding.id);
    onOpenChange(false);
    onSaved();
    toast.success("已恢复为根据报告/证据推导的内容");
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <PencilIcon className="size-4" />
            编辑交付内容
          </DialogTitle>
          <DialogDescription>
            这些字段会进入发现详情与客户报告：名称/资产/CVSS、描述/影响/修复、结构化复现步骤。
          </DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field>
              <FieldLabel>漏洞名称</FieldLabel>
              <Input value={name} onChange={(event) => setName(event.target.value)} />
            </Field>
            <Field>
              <FieldLabel>影响资产</FieldLabel>
              <Input value={target} onChange={(event) => setTarget(event.target.value)} />
            </Field>
          </div>
          <div className="grid gap-3 sm:grid-cols-[8rem_1fr]">
            <Field>
              <FieldLabel>CVSS 分值</FieldLabel>
              <Input
                type="number"
                min={0}
                max={10}
                step={0.1}
                value={score}
                onChange={(event) => setScore(event.target.value)}
              />
            </Field>
            <Field>
              <FieldLabel>CVSS 向量</FieldLabel>
              <Input value={vector} onChange={(event) => setVector(event.target.value)} className="font-mono text-xs" />
            </Field>
          </div>

          <Separator />
          <Field>
            <FieldLabel>漏洞描述（一行一段）</FieldLabel>
            <Textarea
              className="min-h-20"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel>影响分析（一行一条）</FieldLabel>
            <Textarea className="min-h-20" value={impact} onChange={(event) => setImpact(event.target.value)} />
          </Field>
          <Field>
            <FieldLabel>修复建议（一行一条）</FieldLabel>
            <Textarea
              className="min-h-20"
              value={remediation}
              onChange={(event) => setRemediation(event.target.value)}
            />
          </Field>

          <Separator />
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium">复现过程</div>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setSteps((current) => [...current, emptyStep()])}
            >
              添加步骤
            </Button>
          </div>
          <Field>
            <FieldLabel>入口点</FieldLabel>
            <Input
              value={entryPoint}
              onChange={(event) => setEntryPoint(event.target.value)}
              placeholder="例如：https://target/search?q="
              className="font-mono text-xs"
            />
          </Field>
          <Field>
            <FieldLabel>前置条件（一行一条）</FieldLabel>
            <Textarea
              className="min-h-16"
              value={prerequisites}
              onChange={(event) => setPrerequisites(event.target.value)}
              placeholder="例如：持有普通用户 Token"
            />
          </Field>

          {steps.map((step, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: 步骤无稳定 id
            <div key={index} className="rounded-lg border p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold">步骤 {index + 1}</span>
                <Button
                  type="button"
                  size="icon-sm"
                  variant="ghost"
                  aria-label={`删除步骤 ${index + 1}`}
                  onClick={() => setSteps((current) => current.filter((_, i) => i !== index))}
                >
                  <Trash2Icon />
                </Button>
              </div>
              <div className="mt-2 grid gap-2">
                <Field>
                  <FieldLabel className="text-xs">这一步做什么 / 预期结果</FieldLabel>
                  <Input
                    value={step.expected}
                    onChange={(event) => updateStep(index, { expected: event.target.value })}
                  />
                </Field>
                <Field>
                  <FieldLabel className="text-xs">证明什么</FieldLabel>
                  <Input value={step.proves} onChange={(event) => updateStep(index, { proves: event.target.value })} />
                </Field>
                <Field>
                  <FieldLabel className="text-xs">请求报文（逐字）</FieldLabel>
                  <Textarea
                    className="min-h-24 font-mono text-xs"
                    value={step.request}
                    onChange={(event) => updateStep(index, { request: event.target.value })}
                    placeholder={"GET /path HTTP/1.1\nHost: target"}
                  />
                </Field>
                <Field>
                  <FieldLabel className="text-xs">响应报文</FieldLabel>
                  <Textarea
                    className="min-h-24 font-mono text-xs"
                    value={step.response}
                    onChange={(event) => updateStep(index, { response: event.target.value })}
                    placeholder={"HTTP/1.1 200 OK\n..."}
                  />
                </Field>
              </div>
            </div>
          ))}
          <FieldDescription>报告生成时会把这些步骤原样排版进「复现过程」。</FieldDescription>
        </FieldGroup>

        <DialogFooter className="sm:justify-between">
          <Button type="button" variant="ghost" onClick={reset}>
            <RotateCcwIcon data-icon="inline-start" />
            恢复自动整理
          </Button>
          <div className="flex gap-2">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              取消
            </Button>
            <Button type="button" onClick={save}>
              保存
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
