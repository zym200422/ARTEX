// 详细报告兜底生成。
//
// 背景：agent 登记漏洞（report_finding）时如果只写了 name/summary/evidence，
// 没调 report 字段，详情页的「详细报告」就是空的。这里在**前端**按已收集的
// 富化内容 + 结构化复现 + 证据 + 影响/修复，生成一份符合模板的报告，
// 让每个漏洞都有可交付的详细报告；有真实 report 时以真实 report 为准。

import { normalizeBurpRequest, normalizeBurpResponse } from "@/lib/burp-format";
import type { DeliveryEnrichment, Reproduction, ReproStep } from "@/lib/delivery";
import type { Finding } from "@/lib/types";

const SEVERITY_LABEL: Record<string, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
};

function hasRepro(reproduction: Reproduction | null): boolean {
  if (!reproduction) return false;
  return reproduction.steps.length > 0 || Boolean(reproduction.entry_point);
}

/**
 * buildFallbackReport 用富化 + 复现 + 证据拼出详细报告（Markdown）。
 * 只使用已有事实，不虚构请求/响应；缺失的部分明确标注「待补录」。
 */
export function buildFallbackReport(
  finding: Finding,
  enrichment: DeliveryEnrichment,
  reproduction: Reproduction | null,
): string {
  const name = enrichment.name || finding.name || finding.vulnclass || "未命名漏洞";
  const severity = SEVERITY_LABEL[finding.severity] ?? finding.severity;
  const lines: string[] = [];

  lines.push(`# ${name}`, "");

  // 摘要
  lines.push("## 概述", "");
  if (enrichment.description.length > 0) {
    for (const paragraph of enrichment.description) lines.push(paragraph, "");
  } else if (finding.summary) {
    lines.push(finding.summary, "");
  } else {
    lines.push("（暂无描述，可在「编辑交付内容」中补充。）", "");
  }

  // 属性
  lines.push("## 基本信息", "");
  lines.push(`- 漏洞编号：${finding.id}`);
  lines.push(`- 风险等级：${severity}`);
  lines.push(`- CVSS：${enrichment.cvss_score.toFixed(1)} ${enrichment.cvss_vector}`);
  lines.push(`- 影响资产：${enrichment.target}`);
  if (finding.task_id) lines.push(`- 所属任务：#${finding.task_id}`);
  lines.push("");

  // 影响
  lines.push("## 影响与危害", "");
  if (enrichment.risk_analysis.length > 0) {
    enrichment.risk_analysis.forEach((item, index) => lines.push(`${index + 1}. ${item}`));
  } else {
    lines.push("（暂无影响分析，可在「编辑交付内容」中补充。）");
  }
  lines.push("");

  // 复现
  lines.push("## 复现过程", "");
  if (hasRepro(reproduction)) {
    const entry = reproduction?.entry_point;
    if (entry) lines.push(`- 入口点：\`${entry}\``);
    if (reproduction?.prerequisites?.length) {
      lines.push(`- 前置条件：${reproduction.prerequisites.join("；")}`);
    }
    lines.push("");
    reproduction?.steps.forEach((step: ReproStep, index: number) => {
      const replayTag = step.replay_id ? `（重放记录 #${step.replay_id}）` : "";
      lines.push(`**步骤 ${index + 1}**${step.expected ? `：${step.expected}` : ""}${replayTag}`, "");
      if (step.proves) lines.push(`> 证明：${step.proves}`, "");
      if (step.request.trim()) {
        lines.push("```http", normalizeBurpRequest(step.request, enrichment.target), "```", "");
      }
      if (step.response.trim()) {
        lines.push("响应：", "", "```http", normalizeBurpResponse(step.response), "```", "");
      }
    });
  } else if (finding.evidence.trim()) {
    lines.push("以下为 agent 记录的原始证据（尚未整理为分步复现）：", "");
    lines.push("```text", finding.evidence.trim(), "```", "");
  } else {
    lines.push("（暂无复现步骤与证据，建议用「证据留痕」重放关键报文后回填。）", "");
  }

  // 修复
  lines.push("## 修复建议", "");
  if (enrichment.remediation.length > 0) {
    enrichment.remediation.forEach((item, index) => lines.push(`${index + 1}. ${item}`));
  } else {
    lines.push("（暂无修复建议，可在「编辑交付内容」中补充。）");
  }
  lines.push("");

  // 证据留痕索引
  const traced = (reproduction?.steps ?? []).filter((step) => step.replay_id);
  if (traced.length > 0) {
    lines.push("## 重放留痕", "");
    lines.push("本报告的关键报文可在「数据重放」页按编号复查：", "");
    for (const step of traced) {
      lines.push(`- 重放 #${step.replay_id}：${step.expected || step.request.split("\n")[0]}`);
    }
    lines.push("");
  }

  lines.push("---", "", "> 本报告由平台根据已有证据自动整理；如与手工报告冲突，以 agent 提交的正式报告为准。");
  return lines.join("\n");
}
