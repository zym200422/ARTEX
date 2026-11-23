// 上报审批引擎（AI 审批 v1：确定性规则判定 + 综合结论）。
//
// 定位：在漏洞报告「导出/上报」之前，对每个漏洞做一次自动审批。
// 核心红线：必须有对目标服务器或数据的【实际危害】证据 —— 命令回显、数据外带、
// 文件内容、写成功、登录成功、脚本原样回显等；仅凭理论/版本/指纹/缺安全头的
// 「疑似漏洞」一律拦截，不得进入报告。
//
// 规则分为两类：
//   1. 内置规则（builtin）：本文件内置 20 条，用户可在 UI 里启用/停用；
//   2. 自定义规则（custom）：用户在「上报审批」页自己添加，持久化在 approval-store。
//
// 结论三态：approved（通过，可上报）/ needs_more_evidence（需补证）/ rejected（拒绝上报）。

import type { ReportFindingSnapshot } from "@/lib/delivery";
import type { Severity } from "@/lib/types";

export type ApprovalAction = "reject" | "return" | "warn";
export type ApprovalVerdict = "approved" | "needs_more_evidence" | "rejected";

export interface ApprovalRuleMeta {
  id: string;
  name: string;
  group: string;
  action: ApprovalAction;
  /** 判定口径：满足什么算通过。 */
  criterion: string;
}

export interface CustomApprovalRule {
  id: string;
  name: string;
  /** block=命中关键词即违规；require=必须包含关键词。 */
  mode: "block" | "require";
  /** 关键词检索范围。 */
  scope: "any" | "name" | "description" | "evidence";
  keywords: string[];
  action: ApprovalAction;
  enabled: boolean;
  note?: string;
}

export interface RuleHit {
  ruleId: string;
  ruleName: string;
  action: ApprovalAction;
  passed: boolean;
  detail: string;
  custom: boolean;
}

export interface ApprovalReview {
  findingId: string;
  findingName: string;
  verdict: ApprovalVerdict;
  /** 通过率 0-100（含警告规则）。 */
  score: number;
  hits: RuleHit[];
  /** AI 综合结论（一段话）。 */
  summary: string;
  /** 补证清单：未通过的 reject/return 规则的判定口径。 */
  fixes: string[];
  at: number;
}

// ── 实际危害信号库 ────────────────────────────────────────────────────────────
// 只在「响应/证据/描述」里找（刻意排除请求原文，避免 payload 关键字自证）。

const HARM_SIGNALS: { label: string; re: RegExp }[] = [
  {
    label: "返回了他人/全量用户数据（UID/邮箱/手机/订单）",
    re: /your uid|uid:\s?\d|email is|订单号|手机号|收货|身份证|user_id/,
  },
  { label: "命令执行回显", re: /uid=\d|gid=\d|nt authority|desktop-[\w-]+|回显执行结果|命令执行成功/ },
  {
    label: "SQL 报错/语句回显（注入实证）",
    re: /conversion failed|sql syntax|xpath syntax|odbc|sqlstate|执行的sql语句|mysql_|ora-\d+/,
  },
  {
    label: "已获取交互式 shell / 主机控制权",
    re: /semi-interactive|launching|got\s+shell|主机控制|完全控制|system\s*\(/,
  },
  { label: "读取到系统/应用文件内容", re: /\[fonts\]|\[mail\]|\[extensions\]|root:[x*]:|;extension=|\/usr\/local/i },
  { label: "登录成功 / 凭据有效", re: /登录成功|password\s*correct|欢迎来到|hello\s*,\s*\w+/ },
  { label: "脚本标签/事件原样回显", re: /<script|onerror\s*=|javascript:/ },
  { label: "外带/回连（OOB）通道", re: /dnslog|ceye\.|外带|回连|反弹\s?shell/ },
  { label: "写入/上传/修改成功", re: /上传成功|写入成功|修改成功|添加成功|创建成功/ },
  { label: "默认/测试凭据可直接使用", re: /测试账号|默认口令|默认密码|默认凭据|可直接登录/ },
];

const THEORY_RE = /理论|可能存在|疑似|待确认|待验证|需进一步|推测|尚未验证/;

// ── 输入构造 ──────────────────────────────────────────────────────────────────

export interface ReviewInput {
  finding: ReportFindingSnapshot;
  /** 全文（含请求原文），供关键词类规则使用。 */
  text: string;
  /** 危害证据文本（不含请求原文），供实际危害判定使用。 */
  harmText: string;
  /** 命中的实际危害信号（null=未检出）。 */
  hasHarm: string | null;
}

export function buildReviewInput(finding: ReportFindingSnapshot): ReviewInput {
  const stepParts = finding.reproduction.steps.map((step) => `${step.expected}\n${step.proves}\n${step.response}`);
  const harmText = [...finding.description, ...finding.risk_analysis, finding.evidence, ...stepParts]
    .join("\n")
    .toLowerCase();
  const text = [
    finding.name,
    finding.target,
    ...finding.description,
    ...finding.risk_analysis,
    finding.evidence,
    ...finding.reproduction.steps.map((step) => `${step.expected}\n${step.proves}\n${step.request}\n${step.response}`),
  ]
    .join("\n")
    .toLowerCase();
  let hasHarm: string | null = null;
  for (const signal of HARM_SIGNALS) {
    if (signal.re.test(harmText)) {
      hasHarm = signal.label;
      break;
    }
  }
  return { finding, text, harmText, hasHarm };
}

// ── 内置规则 ──────────────────────────────────────────────────────────────────

type RuleResult = { passed: boolean; detail: string } | null; // null = 不适用该发现

interface BuiltinRule extends ApprovalRuleMeta {
  check: (input: ReviewInput) => RuleResult;
}

const BUILTIN_RULES: BuiltinRule[] = [
  // ── 实际危害（核心红线）──
  {
    id: "impact-evidence",
    name: "实际危害证据（核心红线）",
    group: "实际危害",
    action: "reject",
    criterion:
      "证据（响应原文/危害说明）中必须存在实际危害信号：返回他人或敏感数据、命令执行回显、读取到系统文件、登录成功、脚本原样回显、外带回连、写入/修改成功。仅凭理论推断不通过。",
    check: ({ hasHarm }) =>
      hasHarm
        ? { passed: true, detail: `检出实际危害信号：${hasHarm}` }
        : { passed: false, detail: "未检出任何实际危害信号（数据返回/命令回显/文件内容/登录成功/OOB 等）" },
  },
  {
    id: "theoretical-ban",
    name: "理论性发现拦截",
    group: "实际危害",
    action: "reject",
    criterion: "描述/证据含「理论上」「可能存在」「疑似」「待验证」等推测性表述、且没有任何实际危害信号时，不得上报。",
    check: ({ text, hasHarm }) => {
      const hasTheory = THEORY_RE.test(text);
      if (!hasTheory) return { passed: true, detail: "无推测性表述" };
      if (hasHarm) return { passed: true, detail: `虽有推测表述，但已证实实际危害：${hasHarm}` };
      return { passed: false, detail: "存在推测性表述且无实际危害证据，属理论漏洞" };
    },
  },
  {
    id: "not-reproduced",
    name: "未复现/无发现结论拦截",
    group: "实际危害",
    action: "reject",
    criterion: "结论为「未复现」「无法复现」「无发现」「不可达」的测试点不作为漏洞上报。",
    check: ({ text }) => {
      const m = /未复现|未能复现|无法复现|不可达|无发现/.exec(text);
      return m
        ? { passed: false, detail: `发现结论含否定词「${m[0]}」，属未验证或无危害，不得作为漏洞上报` }
        : { passed: true, detail: "结论非未复现/无发现" };
    },
  },
  {
    id: "repro-steps",
    name: "复现步骤完整",
    group: "证据完整性",
    action: "reject",
    criterion: "必须有至少 1 条复现步骤，且步骤中包含可执行的请求原文。",
    check: ({ finding }) => {
      const steps = finding.reproduction.steps;
      if (steps.length === 0) return { passed: false, detail: "没有复现步骤" };
      const withReq = steps.filter((step) => step.request.trim().length > 0);
      if (withReq.length === 0) return { passed: false, detail: "复现步骤缺少请求原文" };
      return { passed: true, detail: `共 ${steps.length} 步，${withReq.length} 步含请求原文` };
    },
  },
  {
    id: "req-resp-pair",
    name: "请求+响应成对证据",
    group: "证据完整性",
    action: "return",
    criterion: "至少 1 条复现步骤同时具备请求与响应原文；缺少响应的步骤需补录。",
    check: ({ finding }) => {
      const steps = finding.reproduction.steps;
      const complete = steps.filter((step) => step.request.trim() && step.response.trim()).length;
      if (complete === 0) return { passed: false, detail: "没有请求+响应成对的步骤" };
      const missing = steps.length - complete;
      return missing > 0
        ? { passed: true, detail: `${complete} 步成对，${missing} 步缺响应（建议补录）` }
        : { passed: true, detail: `${complete} 步全部成对` };
    },
  },
  {
    id: "repeat-high",
    name: "高危建议多次复现",
    group: "证据完整性",
    action: "warn",
    criterion: "严重/高危漏洞建议至少 2 次带响应的稳定复现，避免偶发误报。",
    check: ({ finding }) => {
      if (finding.severity !== "critical" && finding.severity !== "high") return null;
      const complete = finding.reproduction.steps.filter((step) => step.request.trim() && step.response.trim()).length;
      return complete >= 2
        ? { passed: true, detail: `${complete} 次带响应复现` }
        : { passed: false, detail: `高危仅 ${complete} 次带响应复现，建议再复现 1 次以上` };
    },
  },

  // ── 常见误报拦截 ──
  {
    id: "fp-version",
    name: "指纹/版本类发现拦截",
    group: "常见误报",
    action: "reject",
    criterion: "仅凭组件版本/指纹（如「版本过低」「存在某中间件」）而无利用证明的发现不得上报。",
    check: ({ text, hasHarm }) => {
      const hit = /版本(过低|过旧|较老)|outdated|指纹|存在.{0,8}(中间件|框架|组件)/.test(text);
      if (!hit) return null;
      return hasHarm
        ? { passed: true, detail: `虽为版本/指纹类发现，但已证实实际危害：${hasHarm}` }
        : { passed: false, detail: "仅有版本/指纹信息，未证明可利用" };
    },
  },
  {
    id: "fp-baseline",
    name: "安全基线类拦截",
    group: "常见误报",
    action: "reject",
    criterion: "仅缺少安全头（X-Frame-Options/CSP/HttpOnly/HSTS）或点击劫持类基线问题，无实际危害不得上报。",
    check: ({ text, hasHarm }) => {
      const hit =
        /(缺少|未(设置|配置|启用)).{0,16}(x-frame-options|content-security-policy|csp|httponly|hsts|安全头)|点击劫持|clickjacking/.test(
          text,
        );
      if (!hit) return null;
      return hasHarm
        ? { passed: true, detail: `虽为基线问题，但已证实实际危害：${hasHarm}` }
        : { passed: false, detail: "仅安全基线缺失，无实际危害证明" };
    },
  },
  {
    id: "fp-selfxss",
    name: "自我 XSS 拦截",
    group: "常见误报",
    action: "reject",
    criterion: "自我 XSS（只能打自己）或无组合利用路径的 XSS 不得上报。",
    check: ({ text, hasHarm }) => {
      const hit = /self[-\s]?xss|自我\s?xss/.test(text);
      if (!hit) return null;
      return /组合|配合|链式|注入到|存储型|影响他人/.test(text) && hasHarm
        ? { passed: true, detail: "存在组合利用与实际危害" }
        : { passed: false, detail: "自我 XSS 且无组合利用路径" };
    },
  },
  {
    id: "fp-cors",
    name: "CORS 无凭据退回",
    group: "常见误报",
    action: "return",
    criterion: "CORS 配置问题必须证明可携带凭据读取敏感数据，否则退回补证。",
    check: ({ text, hasHarm }) => {
      if (!/cors|跨域资源共享/.test(text)) return null;
      return /(withcredentials|凭证|凭据|cookie|登录态|敏感)/.test(text) || hasHarm
        ? { passed: true, detail: "已说明凭据/敏感数据可达" }
        : { passed: false, detail: "未证明可携带凭据读取敏感数据" };
    },
  },
  {
    id: "fp-jsonp",
    name: "JSONP 无敏感数据拦截",
    group: "常见误报",
    action: "reject",
    criterion: "JSONP 劫持必须返回敏感数据（Token/手机/邮箱等），空数据不得上报。",
    check: ({ text, hasHarm }) => {
      if (!/jsonp/.test(text)) return null;
      return /敏感|手机|邮箱|token|cookie|用户信息/.test(text) || hasHarm
        ? { passed: true, detail: "JSONP 返回敏感数据" }
        : { passed: false, detail: "JSONP 未返回敏感数据" };
    },
  },
  {
    id: "fp-dos",
    name: "DoS/压测类拦截",
    group: "常见误报",
    action: "reject",
    criterion: "拒绝服务/压测/流量放大类发现默认不上报（除非授权明确且已量化影响）。",
    check: ({ text }) => {
      if (!/拒绝服务|\bdos\b|慢速|slowloris|压测|流量放大/.test(text)) return null;
      return /已授权|量化|已批准/.test(text)
        ? { passed: true, detail: "已授权且量化影响" }
        : { passed: false, detail: "DoS 类发现且未见授权/量化说明" };
    },
  },

  // ── 漏洞类型实证 ──
  {
    id: "sqli-proof",
    name: "注入类需数据/报错实证",
    group: "漏洞类型实证",
    action: "return",
    criterion: "注入类发现必须返回非预期数据、报错回显或稳定的盲注差异，否则退回补证。",
    check: ({ text, hasHarm }) => {
      if (!/注入|sqli|sql\s?inject/.test(text)) return null;
      return hasHarm
        ? { passed: true, detail: `已证实：${hasHarm}` }
        : { passed: false, detail: "注入未见数据返回/报错回显/稳定盲注差异" };
    },
  },
  {
    id: "authz-cross",
    name: "越权需跨主体数据",
    group: "漏洞类型实证",
    action: "return",
    criterion: "越权类发现必须体现「跨主体」：A 账号访问/操作了 B 主体的数据，且数据不同。",
    check: ({ text, hasHarm }) => {
      if (!/越权|idor|水平|垂直/.test(text)) return null;
      const cross = /他人|其他用户|另一个|别的用户|跨用户|跨主体|username=\w+|id=\d{1,6}/.test(text);
      return cross && hasHarm
        ? { passed: true, detail: "已体现跨主体数据访问" }
        : { passed: false, detail: "未体现跨主体访问或未返回他人数据" };
    },
  },
  {
    id: "info-real",
    name: "信息泄露需真实敏感内容",
    group: "漏洞类型实证",
    action: "return",
    criterion: "信息泄露必须包含真实敏感内容（密码/凭据/Token/手机/身份证/内网地址等），目录列表/报错页不算。",
    check: ({ text, hasHarm }) => {
      if (!/泄露|敏感信息/.test(text)) return null;
      return /密码|password|账号|凭据|token|secret|密钥|access[_-]?key|手机|身份证|内网地址/.test(text) || hasHarm
        ? { passed: true, detail: "包含真实敏感内容" }
        : { passed: false, detail: "未见真实敏感内容（仅目录列表/报错页等）" };
    },
  },
  {
    id: "rce-proof",
    name: "命令执行必须有回显/OOB",
    group: "漏洞类型实证",
    action: "reject",
    criterion: "命令/代码执行必须有命令回显、副作用或外带回连证据；仅凭响应时间延迟推断不通过。",
    check: ({ text, hasHarm }) => {
      if (!/命令执行|代码执行|\brce\b/i.test(text)) return null;
      return /uid=|whoami|回显|外带|dnslog|反弹|执行成功|写入成功|id=/.test(text) || hasHarm
        ? { passed: true, detail: "已证实命令执行" }
        : { passed: false, detail: "无命令回显/副作用/OOB 证据，仅时间延迟推断不通过" };
    },
  },
  {
    id: "xss-chain",
    name: "XSS 攻击链说明",
    group: "漏洞类型实证",
    action: "warn",
    criterion: "XSS 需说明可达攻击链（如何让其他用户在目标域触发），否则仅作提醒。",
    check: ({ text, hasHarm }) => {
      if (!/xss|跨站脚本/.test(text)) return null;
      if (/钓鱼|链接|会话|cookie|盗取|窃取|打号|影响他人|存储型/.test(text))
        return { passed: true, detail: "已说明攻击链" };
      if (hasHarm && /<script|onerror|javascript:/.test(hasHarm))
        return { passed: true, detail: `脚本已原样回显：${hasHarm}` };
      return { passed: false, detail: "未说明攻击链（如何让其他用户触发）" };
    },
  },

  // ── 范围与合规 ──
  {
    id: "scope-hint",
    name: "授权范围提醒（内网/本地地址）",
    group: "合规与范围",
    action: "warn",
    criterion: "影响资产为内网/本地地址时，需确认其在授权范围内方可上报。",
    check: ({ text }) => {
      const hit = /https?:\/\/(10\.\d|192\.168\.|127\.0\.0\.1|172\.(1[6-9]|2\d|3[01])\.)/.test(text);
      return hit
        ? { passed: false, detail: "目标为内网/本地地址，请确认在授权范围内" }
        : { passed: true, detail: "未发现内网/本地地址" };
    },
  },
  {
    id: "pii-minimize",
    name: "个人数据最小化",
    group: "合规与范围",
    action: "warn",
    criterion: "证据中批量个人手机号（≥20 个）应脱敏后上报。",
    check: ({ finding }) => {
      const phones = finding.evidence.match(/1[3-9]\d{9}/g)?.length ?? 0;
      return phones >= 20
        ? { passed: false, detail: `证据中出现 ${phones} 个手机号，请脱敏` }
        : { passed: true, detail: "个人数据量可接受" };
    },
  },

  // ── 报告质量 ──
  {
    id: "impact-quality",
    name: "影响分析具体化",
    group: "报告质量",
    action: "return",
    criterion: "影响分析不得为空，且不得只有「影响系统安全」这类空话，需说明谁/能做什么/拿到什么。",
    check: ({ finding }) => {
      if (finding.risk_analysis.length === 0) return { passed: false, detail: "影响分析为空" };
      const generic = finding.risk_analysis.filter(
        (item) => /影响(系统|业务)?安全|存在(安全)?风险|危害系统/.test(item) && item.length < 16,
      );
      return generic.length === finding.risk_analysis.length
        ? { passed: false, detail: "影响分析全是空话，需写清具体后果" }
        : { passed: true, detail: "影响分析可用" };
    },
  },
  {
    id: "fix-required",
    name: "修复建议必填",
    group: "报告质量",
    action: "return",
    criterion: "必须有可落地的修复建议（≥1 条），不得为空。",
    check: ({ finding }) =>
      finding.remediation.length === 0
        ? { passed: false, detail: "修复建议为空" }
        : { passed: true, detail: `已有 ${finding.remediation.length} 条修复建议` },
  },
];

export const BUILTIN_RULE_META: ApprovalRuleMeta[] = BUILTIN_RULES.map(({ check: _check, ...meta }) => meta);

export function builtinRuleMeta(id: string): ApprovalRuleMeta | null {
  return BUILTIN_RULE_META.find((rule) => rule.id === id) ?? null;
}

// ── 审批执行 ──────────────────────────────────────────────────────────────────

export interface ReviewOptions {
  /** 被停用的内置规则 id 集合。 */
  disabledRules?: Record<string, boolean>;
  /** 用户自定义规则。 */
  customRules?: CustomApprovalRule[];
}

function scopeText(scope: CustomApprovalRule["scope"], input: ReviewInput): string {
  switch (scope) {
    case "name":
      return input.finding.name;
    case "description":
      return input.finding.description.join("\n");
    case "evidence":
      return [
        input.finding.evidence,
        ...input.finding.reproduction.steps.map((step) => `${step.request}\n${step.response}`),
      ].join("\n");
    default:
      return input.text;
  }
}

export function reviewFinding(finding: ReportFindingSnapshot, options: ReviewOptions = {}): ApprovalReview {
  const input = buildReviewInput(finding);
  const hits: RuleHit[] = [];

  for (const rule of BUILTIN_RULES) {
    if (options.disabledRules?.[rule.id]) continue;
    const result = rule.check(input);
    if (!result) continue;
    hits.push({
      ruleId: rule.id,
      ruleName: rule.name,
      action: rule.action,
      passed: result.passed,
      detail: result.detail,
      custom: false,
    });
  }

  for (const rule of options.customRules ?? []) {
    if (!rule.enabled) continue;
    const target = scopeText(rule.scope, input);
    const keywordHit = rule.keywords.some((keyword) => {
      const k = keyword.trim().toLowerCase();
      return k.length > 0 && target.includes(k);
    });
    const passed = rule.mode === "block" ? !keywordHit : keywordHit;
    hits.push({
      ruleId: rule.id,
      ruleName: rule.name,
      action: rule.action,
      passed,
      detail: passed
        ? rule.mode === "block"
          ? "未命中自定义关键词"
          : "已包含自定义必含关键词"
        : rule.mode === "block"
          ? `命中自定义关键词：${rule.keywords.filter((keyword) => target.includes(keyword.trim().toLowerCase())).join("、")}`
          : "未包含自定义必含关键词",
      custom: true,
    });
  }

  const failedReject = hits.filter((hit) => !hit.passed && hit.action === "reject");
  const failedReturn = hits.filter((hit) => !hit.passed && hit.action === "return");
  const failedWarn = hits.filter((hit) => !hit.passed && hit.action === "warn");

  const verdict: ApprovalVerdict =
    failedReject.length > 0 ? "rejected" : failedReturn.length > 0 ? "needs_more_evidence" : "approved";

  const applicable = hits.length;
  const passed = hits.filter((hit) => hit.passed).length;
  const score = applicable === 0 ? 100 : Math.round((passed / applicable) * 100);

  const verdictText =
    verdict === "approved" ? "通过，可上报" : verdict === "needs_more_evidence" ? "需补充证据后再上报" : "拒绝上报";

  const summaryParts = [
    `AI 审批结论：${verdictText}。`,
    input.hasHarm ? `实际危害证据：${input.hasHarm}。` : "未检出实际危害信号。",
    failedReject.length + failedReturn.length > 0
      ? `未通过规则：${[...failedReject, ...failedReturn].map((hit) => hit.ruleName).join("、")}。`
      : "全部适用规则通过。",
    failedWarn.length > 0 ? `提醒：${failedWarn.map((hit) => hit.ruleName).join("、")}。` : "",
  ];
  const summary = summaryParts.filter(Boolean).join("");

  const fixes = [...failedReject, ...failedReturn].map((hit) => `${hit.ruleName}：${hit.detail}`);

  return {
    findingId: finding.id,
    findingName: finding.name,
    verdict,
    score,
    hits,
    summary,
    fixes,
    at: Math.floor(Date.now() / 1000),
  };
}

export const VERDICT_META: Record<ApprovalVerdict, { label: string; tone: string }> = {
  approved: {
    label: "审批通过",
    tone: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/25",
  },
  needs_more_evidence: {
    label: "需补证",
    tone: "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/25",
  },
  rejected: { label: "拒绝上报", tone: "bg-red-500/15 text-red-700 dark:text-red-400 border-red-500/25" },
};

export const ACTION_META: Record<ApprovalAction, { label: string; tone: string }> = {
  reject: { label: "拒绝", tone: "bg-red-500/15 text-red-700 dark:text-red-400" },
  return: { label: "退回", tone: "bg-amber-500/15 text-amber-700 dark:text-amber-400" },
  warn: { label: "提醒", tone: "bg-sky-500/15 text-sky-700 dark:text-sky-400" },
};

export function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    default:
      return 3;
  }
}
