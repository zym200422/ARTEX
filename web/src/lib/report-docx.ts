// 报告导出：严格按用户提供的 xss.docx 模板排版。
//
// 模板结构（无封面 / 目录 / 页眉页脚 / 公司信息）：
//   漏洞标题： <目标 + 漏洞名>
//   漏洞危害： <严重度>
//   漏洞描述： <描述正文 + 代码片段>
//   漏洞复现： <访问地址 / 分步请求响应>
//   修复建议： <逐条建议>
//
// 版式：A4；左右页边距 1.25in、上下 1in；标签用宋体 10.5pt，正文用无衬线 10.5pt，
// 代码用 Consolas 9pt。全部在浏览器端生成，调用方按需动态 import。

import { Document, Packer, PageBreak, Paragraph, TextRun } from "docx";

import type { ReportFindingSnapshot, ReportSnapshot } from "@/lib/delivery";
import type { Severity } from "@/lib/types";

const SERIF = { ascii: "Times New Roman", hAnsi: "Times New Roman", eastAsia: "宋体", cs: "Times New Roman" };
const SANS = { ascii: "Arial", hAnsi: "Arial", eastAsia: "微软雅黑", cs: "Arial" };
const MONO = "Consolas";

const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
};

/** 模板中的标签行（宋体）。 */
function label(text: string): Paragraph {
  return new Paragraph({
    spacing: { after: 0 },
    children: [new TextRun({ text, size: 21, font: SERIF })],
  });
}

/** 正文行：首行缩进 420 twips，与模板一致。 */
function body(text: string, options: { indent?: boolean; color?: string } = {}): Paragraph {
  return new Paragraph({
    spacing: { after: 0 },
    indent: options.indent === false ? undefined : { firstLine: 420 },
    children: [new TextRun({ text, size: 21, font: SANS, color: options.color })],
  });
}

/** 正文中的 `code` 片段按模板风格缩小一号。 */
function richBody(text: string): Paragraph {
  const parts = text.split(/(`[^`]+`)/g).filter(Boolean);
  return new Paragraph({
    spacing: { after: 0 },
    indent: { firstLine: 420 },
    children: parts.map((part) =>
      part.startsWith("`") && part.endsWith("`")
        ? new TextRun({ text: part.slice(1, -1), size: 17, font: SANS })
        : new TextRun({ text: part, size: 21, font: SANS }),
    ),
  });
}

/** 代码块：Consolas 9pt，逐行段落，保持缩进。 */
function code(text: string): Paragraph[] {
  return text
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map(
      (line) =>
        new Paragraph({
          spacing: { after: 0 },
          children: [new TextRun({ text: line || " ", font: MONO, size: 18 })],
        }),
    );
}

function blank(): Paragraph {
  return new Paragraph({ spacing: { after: 0 }, children: [new TextRun({ text: "" })] });
}

function findingTitle(finding: ReportFindingSnapshot): string {
  if (!finding.target) return finding.name;
  if (finding.name.includes(finding.target)) return finding.name;
  return `${finding.target} 存在${finding.name}`;
}

function renderFinding(finding: ReportFindingSnapshot): Paragraph[] {
  const paragraphs: Paragraph[] = [];

  // 漏洞标题
  paragraphs.push(label("漏洞标题："));
  paragraphs.push(body(findingTitle(finding)));

  // 漏洞危害
  paragraphs.push(label("漏洞危害："));
  paragraphs.push(body(SEVERITY_TEXT[finding.severity]));

  // 漏洞描述
  paragraphs.push(label("漏洞描述："));
  if (finding.description.length > 0) {
    for (const paragraph of finding.description) paragraphs.push(richBody(paragraph));
  } else {
    paragraphs.push(body("（暂无描述）"));
  }

  // 复现步骤里的请求/响应作为代码块；模板中的代码片段位置也在这里复用。
  const hasRepro = finding.reproduction.steps.length > 0 || Boolean(finding.reproduction.entry_point);
  if (hasRepro) {
    paragraphs.push(blank(), blank(), label("漏洞复现："));
    const entry = finding.reproduction.entry_point;
    if (entry) {
      if (/^https?:\/\//i.test(entry)) {
        paragraphs.push(body("访问", { indent: false }));
        paragraphs.push(body(entry, { indent: false }));
      } else {
        paragraphs.push(body(`入口点：${entry}`, { indent: false }));
      }
    }
    if ((finding.reproduction.prerequisites?.length ?? 0) > 0) {
      paragraphs.push(body(`前置条件：${finding.reproduction.prerequisites?.join("；")}`, { indent: false }));
    }
    finding.reproduction.steps.forEach((step, index) => {
      paragraphs.push(blank());
      paragraphs.push(body(`步骤 ${index + 1}${step.expected ? `：${step.expected}` : ""}`, { indent: false }));
      if (step.proves) paragraphs.push(body(`证明：${step.proves}`, { indent: false, color: "666666" }));
      if (step.request.trim()) {
        paragraphs.push(body("请求：", { indent: false }));
        paragraphs.push(...code(step.request));
      }
      if (step.response.trim()) {
        paragraphs.push(body("响应：", { indent: false }));
        paragraphs.push(...code(step.response));
      }
    });
  } else if (finding.evidence.trim()) {
    paragraphs.push(blank(), blank(), label("漏洞复现："));
    paragraphs.push(...code(finding.evidence));
  }

  // 详细报告（agent 正式报告或平台自动整理版）
  if (finding.report?.trim()) {
    paragraphs.push(blank(), blank(), label("详细报告："));
    const reportLines = finding.report.replace(/\r\n/g, "\n").split("\n");
    for (const line of reportLines) {
      const trimmed = line.trim();
      if (!trimmed) {
        paragraphs.push(blank());
        continue;
      }
      // 去掉 Markdown 标题前缀，保留文字层级
      const headingMatch = /^(#{1,4})\s+(.*)$/.exec(trimmed);
      if (headingMatch) {
        paragraphs.push(
          new Paragraph({
            spacing: { before: 160, after: 80 },
            children: [new TextRun({ text: headingMatch[2], bold: true, size: 22, font: SANS })],
          }),
        );
        continue;
      }
      // 代码块围栏跳过（代码内容按普通行输出）
      if (/^```/.test(trimmed)) continue;
      paragraphs.push(
        new Paragraph({ spacing: { after: 60 }, children: [new TextRun({ text: line, size: 20, font: SANS })] }),
      );
    }
  }

  // 修复建议
  paragraphs.push(blank(), blank(), label("修复建议："));
  if (finding.remediation.length > 0) {
    finding.remediation.forEach((item, index) => {
      paragraphs.push(body(`${index + 1}. ${item}`, { indent: false }));
    });
  } else {
    paragraphs.push(body("（暂无修复建议）", { indent: false }));
  }

  return paragraphs;
}

/** 生成 .docx：每个漏洞一节，严格按模板字段与版式。 */
export async function buildReportDocx(snapshot: ReportSnapshot): Promise<Blob> {
  const children: Paragraph[] = [];
  snapshot.findings.forEach((finding, index) => {
    if (index > 0) children.push(new Paragraph({ children: [new PageBreak()] }));
    children.push(...renderFinding(finding));
  });
  if (children.length === 0) children.push(body("（无漏洞）"));

  const doc = new Document({
    styles: {
      default: {
        document: {
          run: { font: SERIF, size: 21 },
          paragraph: { spacing: { after: 0 } },
        },
      },
    },
    sections: [
      {
        properties: {
          page: {
            size: { width: 11906, height: 16838 },
            margin: { top: 1440, right: 1800, bottom: 1440, left: 1800 },
          },
        },
        children,
      },
    ],
  });

  return Packer.toBlob(doc);
}

/** 生成并触发下载 .docx。调用方应动态 import 本模块以隔离体积。 */
export async function downloadReportDocx(snapshot: ReportSnapshot, filename: string): Promise<void> {
  const blob = await buildReportDocx(snapshot);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename.endsWith(".docx") ? filename : `${filename}.docx`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
