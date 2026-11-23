"use client";

// 报告预览：与导出的 .docx 严格一致——只保留用户模板里的五个字段，
// 无封面、目录、方法学、工具清单等额外内容。

import type { ReportFindingSnapshot, ReportSnapshot } from "@/lib/delivery";
import type { Severity } from "@/lib/types";

const SERIF = "SimSun, 'Songti SC', 'Noto Serif SC', serif";
const SANS = "'Microsoft YaHei', 'PingFang SC', Arial, sans-serif";
const MONO = "Consolas, 'Courier New', monospace";

const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
};

function InlineText({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`)/g).filter(Boolean);
  return (
    <>
      {parts.map((part, index) =>
        part.startsWith("`") && part.endsWith("`") ? (
          // biome-ignore lint/suspicious/noArrayIndexKey: 文本片段无稳定 id
          <span key={index} style={{ fontFamily: SANS, fontSize: "11px" }}>
            {part.slice(1, -1)}
          </span>
        ) : (
          // biome-ignore lint/suspicious/noArrayIndexKey: 文本片段无稳定 id
          <span key={index}>{part}</span>
        ),
      )}
    </>
  );
}

function findingTitle(finding: ReportFindingSnapshot): string {
  if (!finding.target) return finding.name;
  if (finding.name.includes(finding.target)) return finding.name;
  return `${finding.target} 存在${finding.name}`;
}

function FindingBlock({ finding }: { finding: ReportFindingSnapshot }) {
  return (
    <section className="text-[14px] leading-[1.75] text-slate-900">
      <div style={{ fontFamily: SERIF }}>漏洞标题：</div>
      <div className="pl-10" style={{ fontFamily: SANS }}>
        {findingTitle(finding)}
      </div>

      <div style={{ fontFamily: SERIF }}>漏洞危害：</div>
      <div className="pl-10" style={{ fontFamily: SANS }}>
        {SEVERITY_TEXT[finding.severity]}
      </div>

      <div style={{ fontFamily: SERIF }}>漏洞描述：</div>
      {finding.description.length > 0 ? (
        finding.description.map((paragraph, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: 描述段落无稳定 id
          <p key={index} className="pl-10" style={{ fontFamily: SANS }}>
            <InlineText text={paragraph} />
          </p>
        ))
      ) : (
        <p className="pl-10 text-slate-500" style={{ fontFamily: SANS }}>
          （暂无描述）
        </p>
      )}

      {(finding.reproduction.steps.length > 0 || finding.reproduction.entry_point) && (
        <>
          <div className="h-6" />
          <div style={{ fontFamily: SERIF }}>漏洞复现：</div>
          {finding.reproduction.entry_point && (
            <>
              <div style={{ fontFamily: SANS }}>
                {/^https?:\/\//i.test(finding.reproduction.entry_point) ? "访问" : "入口点："}
              </div>
              <div style={{ fontFamily: SANS }}>{finding.reproduction.entry_point}</div>
            </>
          )}
          {(finding.reproduction.prerequisites?.length ?? 0) > 0 && (
            <div style={{ fontFamily: SANS }}>前置条件：{finding.reproduction.prerequisites?.join("；")}</div>
          )}
          {finding.reproduction.steps.map((step, index) => (
            <div key={`${finding.id}-step-${index + 1}`} className=" mt-3">
              <div style={{ fontFamily: SANS }}>
                步骤 {index + 1}
                {step.expected ? `：${step.expected}` : ""}
              </div>
              {step.proves && (
                <div className="text-slate-500" style={{ fontFamily: SANS }}>
                  证明：{step.proves}
                </div>
              )}
              {step.request.trim() && (
                <>
                  <div style={{ fontFamily: SANS }}>请求：</div>
                  <pre
                    className="m-0 overflow-x-auto whitespace-pre-wrap break-words"
                    style={{ fontFamily: MONO, fontSize: "12px", lineHeight: 1.6 }}
                  >
                    {step.request}
                  </pre>
                </>
              )}
              {step.response.trim() && (
                <>
                  <div style={{ fontFamily: SANS }}>响应：</div>
                  <pre
                    className="m-0 overflow-x-auto whitespace-pre-wrap break-words"
                    style={{ fontFamily: MONO, fontSize: "12px", lineHeight: 1.6 }}
                  >
                    {step.response}
                  </pre>
                </>
              )}
            </div>
          ))}
        </>
      )}

      <div className="h-6" />
      <div style={{ fontFamily: SERIF }}>修复建议：</div>
      {finding.remediation.length > 0 ? (
        finding.remediation.map((item, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: 建议条目无稳定 id
          <div key={index} style={{ fontFamily: SANS }}>
            {index + 1}. {item}
          </div>
        ))
      ) : (
        <div className="text-slate-500" style={{ fontFamily: SANS }}>
          （暂无修复建议）
        </div>
      )}
    </section>
  );
}

/**
 * ReportDocument 与导出的 docx 同版式：A4、左右 1.25in、上下 1in，
 * 每个漏洞一页，仅模板五段。
 */
export function ReportDocument({ snapshot }: { snapshot: ReportSnapshot }) {
  return (
    <article
      className="report-doc mx-auto w-full max-w-[794px] bg-white text-slate-900 shadow-xl ring-1 ring-slate-200 print:max-w-none print:shadow-none print:ring-0"
      style={{ padding: "96px 120px" }}
    >
      {snapshot.findings.map((finding, index) => (
        <div key={`${finding.id}-${index}`} className={index > 0 ? "mt-16 print:break-before-page" : undefined}>
          <FindingBlock finding={finding} />
        </div>
      ))}
      {snapshot.findings.length === 0 && (
        <p className="text-sm text-slate-500" style={{ fontFamily: SANS }}>
          （无漏洞）
        </p>
      )}
    </article>
  );
}
