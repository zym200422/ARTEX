"use client";

// 证据报文 → 数据重放留痕。
//
// 从漏洞（报告 Markdown / 证据原文 / 结构化复现步骤）里抽取可重放的 HTTP 请求：
//   - ```http 代码块里的 METHOD /path HTTP/1.1 + 头部 + body
//   - 直接写在证据里的 POST /path + 参数行
// 抽出来后一键送进 /api/replay（解析→发送→留痕），并把重放记录 id 回填到
// 复现步骤的 traffic_id 上，让「报告里的报文」都有平台留痕。

import { api } from "@/lib/api";
import type { Reproduction } from "@/lib/delivery";
import type { Finding, ReplayRecord } from "@/lib/types";

export interface ExtractedPacket {
  /** 稳定标识：报告第几段 / 复现第几步。 */
  key: string;
  /** 来源描述（例如「复现步骤 1」）。 */
  origin: string;
  method: string;
  path: string;
  host: string;
  /** 可重放的完整报文（Burp 原始格式）。 */
  raw: string;
  /** 报告里给出的响应片段（可能为空）。 */
  inlineResponse: string;
  /** 对应结构化复现步骤的下标（无则 -1）。 */
  stepIndex: number;
}

const REQUEST_LINE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)\s+HTTP\/1\.[01]\s*$/i;

/** 从一段文本里抽出所有 HTTP 请求报文（含其后的响应片段）。 */
function extractFromText(text: string, originPrefix: string, stepIndex: number): ExtractedPacket[] {
  const out: ExtractedPacket[] = [];
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = REQUEST_LINE.exec(lines[i].trim());
    if (!m) continue;
    const method = m[1].toUpperCase();
    const path = m[2];

    // 收集头部，直到空行
    const headers: string[] = [];
    let j = i + 1;
    let host = "";
    for (; j < lines.length; j++) {
      const line = lines[j];
      if (!line.trim()) {
        j += 1;
        break;
      }
      headers.push(line.trimEnd());
      const hostMatch = /^host\s*:\s*(.+)$/i.exec(line.trim());
      if (hostMatch) host = hostMatch[1].trim();
    }
    // 收集 body，直到遇到响应行或分隔
    const bodyLines: string[] = [];
    for (; j < lines.length; j++) {
      const line = lines[j];
      if (/^HTTP\/1\.[01]\s+\d{3}/i.test(line.trim())) break;
      if (/^```/.test(line.trim())) break;
      bodyLines.push(line);
      // 连续两个空行视为 body 结束
      if (bodyLines.length >= 2 && bodyLines[bodyLines.length - 1] === "" && bodyLines[bodyLines.length - 2] === "") {
        break;
      }
    }
    while (bodyLines.length > 0 && bodyLines.at(-1) === "") bodyLines.pop();

    // 紧随其后的响应片段
    const respLines: string[] = [];
    for (let k = j; k < lines.length; k++) {
      const line = lines[k];
      if (/^```/.test(line.trim())) break;
      if (line.trim() && !/^HTTP\/1\.[01]\s+\d{3}/i.test(line.trim()) && respLines.length > 0) break;
      respLines.push(line);
      if (respLines.length > 12) break;
    }
    while (respLines.length > 0 && respLines[respLines.length - 1].trim() === "") respLines.pop();

    const rawLines = [`${method} ${path} HTTP/1.1`];
    rawLines.push(...(headers.length > 0 ? headers : [`Host: ${host || "localhost"}`]));
    rawLines.push("");
    if (bodyLines.length > 0) rawLines.push(...bodyLines);

    out.push({
      key: `${originPrefix}-${i}`,
      origin: `${originPrefix}（第 ${i + 1} 行）`,
      method,
      path,
      host,
      raw: rawLines.join("\n"),
      inlineResponse: respLines.join("\n").trim(),
      stepIndex,
    });
  }
  return out;
}

/** 从漏洞的报告 Markdown + 证据 + 结构化复现里抽取全部可重放报文。 */
export function extractPackets(finding: Finding, reproduction: Reproduction | null): ExtractedPacket[] {
  const seen = new Set<string>();
  const packets: ExtractedPacket[] = [];
  const push = (list: ExtractedPacket[]) => {
    for (const packet of list) {
      const sig = `${packet.method} ${packet.path} ${packet.raw.length}`;
      if (seen.has(sig)) continue;
      seen.add(sig);
      packets.push(packet);
    }
  };

  // 1) 结构化复现步骤：request 原文最可靠
  reproduction?.steps.forEach((step, index) => {
    if (!step.request?.trim()) return;
    const extracted = extractFromText(step.request, `复现步骤 ${index + 1}`, index);
    if (extracted.length > 0) {
      for (const packet of extracted) {
        packet.inlineResponse = packet.inlineResponse || step.response?.trim() || "";
      }
      push(extracted);
      return;
    }
    // 只有一行请求行、没有 HTTP/1.1 的，也拼成可重放报文
    const m = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)/i.exec(step.request.trim());
    if (!m) return;
    push([
      {
        key: `step-${index}`,
        origin: `复现步骤 ${index + 1}`,
        method: m[1].toUpperCase(),
        path: m[2],
        host: "",
        raw: step.request.trim(),
        inlineResponse: step.response?.trim() ?? "",
        stepIndex: index,
      },
    ]);
  });

  // 2) 报告 Markdown（```http 块与裸报文）
  if (finding.report) push(extractFromText(finding.report, "报告", -1));
  // 3) 证据原文
  if (finding.evidence) push(extractFromText(finding.evidence, "证据", -1));

  return packets;
}

export interface ReplayTraceResult {
  record: ReplayRecord;
  packet: ExtractedPacket;
}

/** 逐条重放并留痕；返回成功/失败明细。 */
export async function replayPackets(
  packets: ExtractedPacket[],
  options: { taskId?: string; scheme?: "http" | "https" | ""; insecureTls?: boolean; timeoutSec?: number } = {},
): Promise<ReplayTraceResult[]> {
  const results: ReplayTraceResult[] = [];
  for (const packet of packets) {
    const record = await api.replaySend({
      taskId: options.taskId,
      format: "burp",
      input: packet.raw,
      scheme: options.scheme ?? "",
      timeoutSec: options.timeoutSec ?? 30,
      insecureTls: options.insecureTls ?? false,
    });
    results.push({ record, packet });
  }
  return results;
}

/** 从重放结果里提取「有实际回显」的关键行，用于回填报告的内联响应。 */
export function evidenceExcerpt(record: ReplayRecord, maxLines = 6): string {
  const body = (record.resp_body || "").replace(/\r\n/g, "\n");
  const lines = body.split("\n").map((line) => line.trimEnd());
  const hits: string[] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    // 命令回显标记 / 版本号 / 用户 / 报错 / 数据行
    if (
      /PIKA_|MARK_|uid=|gid=|whoami|nt authority|desktop-|Microsoft Windows|PHP Version|root:|\[fonts\]|SQL|error|Exception|{\s*"/i.test(
        line,
      )
    ) {
      hits.push(line.trim().slice(0, 300));
      if (hits.length >= maxLines) break;
    }
  }
  if (hits.length === 0) {
    // 没有明显标记时，回退到正文前几行非空内容
    for (const line of lines) {
      if (!line.trim()) continue;
      hits.push(line.trim().slice(0, 300));
      if (hits.length >= 3) break;
    }
  }
  return hits.join("\n");
}
