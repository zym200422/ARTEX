"use client";

// 交付数据的本地持久化层（前端先行）。
//
// 后端当前没有 /report-settings、/reports、/findings/{id}/enrichment 等接口；
// 这里先把组织信息、报告模板、生成记录、富化与复现草稿落在 localStorage，
// 页面即可完整演示「富化 → 复现 → 报告 → 交付」。后端补齐后，把本文件的读写函数
// 换成 api 调用即可（形状已按未来接口设计）。

import {
  buildFindingSnapshot,
  buildReportMarkdown,
  buildReportSnapshot,
  type DeliveryEnrichment,
  demoReportSnapshot,
  deriveEnrichment,
  deriveReproduction,
  type Personnel,
  type ReportLocale,
  type ReportRecord,
  type ReportSettings,
  type ReportTemplate,
  type Reproduction,
  reportFilename,
} from "@/lib/delivery";
import { buildFallbackReport } from "@/lib/fallback-report";
import type { Finding, Severity } from "@/lib/types";

const STORAGE_KEY = "artex_delivery_v2";

interface DeliveryState {
  settings: ReportSettings;
  templates: ReportTemplate[];
  reports: ReportRecord[];
  /** finding.id → 人工编辑后的富化内容。 */
  enrichments: Record<string, DeliveryEnrichment>;
  /** finding.id → 人工编辑后的结构化复现。 */
  reproductions: Record<string, Reproduction>;
}

const DEFAULT_SETTINGS: ReportSettings = {
  company_name: "ARTEX 安全服务团队",
  company_name_en: "ARTEX Security Services",
  logo_path: "",
  personnel: [
    { name: "张工", role: "渗透测试工程师", contact: "zhang@artex.example" },
    { name: "李工", role: "项目负责人", contact: "li@artex.example" },
  ],
  cvss_version: "3.1",
};

function defaultTemplates(): ReportTemplate[] {
  return [
    {
      id: 1,
      name: "标准渗透测试报告",
      company_name: "ARTEX 安全服务团队",
      company_name_en: "ARTEX Security Services",
      logo_path: "",
      personnel: DEFAULT_SETTINGS.personnel,
      cvss_version: "3.1",
      locale: "zh-CN",
    },
    {
      id: 2,
      name: "红队评估报告（繁中）",
      company_name: "ARTEX 紅隊服務",
      company_name_en: "ARTEX Red Team",
      logo_path: "",
      personnel: [{ name: "王工", role: "紅隊隊長", contact: "wang@artex.example" }],
      cvss_version: "3.1",
      locale: "zh-TW",
    },
    {
      id: 3,
      name: "Executive Security Assessment",
      company_name: "ARTEX Security Services",
      company_name_en: "ARTEX Security Services",
      logo_path: "",
      personnel: [{ name: "Alex", role: "Lead Consultant", contact: "alex@artex.example" }],
      cvss_version: "4.0",
      locale: "en-US",
    },
  ];
}

function seedReports(): ReportRecord[] {
  const snapshot = demoReportSnapshot();
  const filename = reportFilename(snapshot);
  return [
    {
      id: 1,
      task_id: "t-acme-web",
      task_label: snapshot.task_label,
      title: snapshot.title,
      client: snapshot.client,
      locale: snapshot.locale,
      format: "print",
      filename,
      size: new Blob([buildReportMarkdown(snapshot)]).size,
      finding_count: snapshot.findings.length,
      company: snapshot.company_name,
      created_at: snapshot.generated_at,
      snapshot,
    },
  ];
}

let cache: DeliveryState | null = null;
let version = 0;
const listeners = new Set<() => void>();

function readStorage(): Partial<DeliveryState> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Partial<DeliveryState>;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function ensure(): DeliveryState {
  if (cache) return cache;
  const stored = readStorage();
  cache = {
    settings: { ...DEFAULT_SETTINGS, ...(stored.settings ?? {}) },
    templates: stored.templates ?? defaultTemplates(),
    reports: stored.reports ?? seedReports(),
    enrichments: stored.enrichments ?? {},
    reproductions: stored.reproductions ?? {},
  };
  return cache;
}

function persist(next: DeliveryState) {
  cache = next;
  version += 1;
  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // 隐私模式/配额满时保持内存态。
    }
  }
  for (const listener of listeners) listener();
}

export function subscribeDelivery(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function deliveryVersion(): number {
  return version;
}

export function deliveryServerVersion(): number {
  return 0;
}

export function getDeliverySettings(): ReportSettings {
  return ensure().settings;
}

export function saveDeliverySettings(patch: Partial<ReportSettings>) {
  const state = ensure();
  persist({ ...state, settings: { ...state.settings, ...patch } });
}

export function getReportTemplates(): ReportTemplate[] {
  return ensure().templates;
}

export function upsertReportTemplate(template: ReportTemplate): ReportTemplate {
  const state = ensure();
  const id = template.id > 0 ? template.id : Math.max(0, ...state.templates.map((item) => item.id)) + 1;
  const next = { ...template, id };
  const exists = state.templates.some((item) => item.id === id);
  const templates = exists ? state.templates.map((item) => (item.id === id ? next : item)) : [...state.templates, next];
  persist({ ...state, templates });
  return next;
}

export function deleteReportTemplate(id: number) {
  const state = ensure();
  persist({ ...state, templates: state.templates.filter((item) => item.id !== id) });
}

export function getReports(): ReportRecord[] {
  return ensure().reports;
}

export function getReport(id: number): ReportRecord | null {
  return ensure().reports.find((item) => item.id === id) ?? null;
}

export function deleteReport(id: number) {
  const state = ensure();
  persist({ ...state, reports: state.reports.filter((item) => item.id !== id) });
}

export function getDeliveryEnrichment(finding: Finding): DeliveryEnrichment {
  return ensure().enrichments[finding.id] ?? deriveEnrichment(finding);
}

export function saveDeliveryEnrichment(findingId: string, enrichment: DeliveryEnrichment) {
  const state = ensure();
  persist({ ...state, enrichments: { ...state.enrichments, [findingId]: { ...enrichment, source: "manual" } } });
}

export function resetDeliveryEnrichment(findingId: string) {
  const state = ensure();
  const enrichments = { ...state.enrichments };
  delete enrichments[findingId];
  persist({ ...state, enrichments });
}

export function getDeliveryReproduction(finding: Finding): Reproduction {
  return ensure().reproductions[finding.id] ?? deriveReproduction(finding);
}

export function saveDeliveryReproduction(findingId: string, reproduction: Reproduction) {
  const state = ensure();
  persist({ ...state, reproductions: { ...state.reproductions, [findingId]: reproduction } });
}

export function resetDeliveryReproduction(findingId: string) {
  const state = ensure();
  const reproductions = { ...state.reproductions };
  delete reproductions[findingId];
  persist({ ...state, reproductions });
}

/** 生成一条报告记录（快照式，后续预览/下载不再依赖后端）。 */
export function createReportRecord(input: {
  taskId?: string;
  taskLabel: string;
  taskDescription: string;
  title: string;
  client: string;
  locale: ReportLocale;
  format: "md" | "print";
  template?: ReportTemplate;
  findings: Finding[];
}): ReportRecord {
  const state = ensure();
  const settings: ReportSettings = input.template
    ? {
        company_name: input.template.company_name,
        company_name_en: input.template.company_name_en,
        logo_path: input.template.logo_path,
        personnel: input.template.personnel,
        cvss_version: input.template.cvss_version,
      }
    : state.settings;
  const snapshots = input.findings.map((finding) => {
    const enrichment = getDeliveryEnrichment(finding);
    const reproduction = getDeliveryReproduction(finding);
    const snapshot = buildFindingSnapshot(finding, enrichment, reproduction);
    // 没有 agent 正式报告时，用平台自动整理版填上，保证导出报告不空。
    if (!snapshot.report) {
      snapshot.report = buildFallbackReport(finding, enrichment, reproduction);
      snapshot.report_source = "auto";
    }
    return snapshot;
  });
  const snapshot = buildReportSnapshot({
    title: input.title,
    client: input.client,
    locale: input.locale,
    taskLabel: input.taskLabel,
    taskDescription: input.taskDescription,
    settings,
    findings: snapshots,
  });
  const markdown = buildReportMarkdown(snapshot);
  const record: ReportRecord = {
    id: Math.max(0, ...state.reports.map((item) => item.id)) + 1,
    task_id: input.taskId,
    task_label: input.taskLabel,
    title: input.title,
    client: input.client,
    locale: input.locale,
    format: input.format,
    filename: reportFilename(snapshot),
    size: new Blob([markdown]).size,
    finding_count: snapshots.length,
    company: settings.company_name,
    created_at: snapshot.generated_at,
    snapshot,
  };
  persist({ ...state, reports: [record, ...state.reports] });
  return record;
}

/** 从现有发现批量初始化富化/复现（演示「AI 分析」的一键结果）。 */
export function primeDeliveryForFindings(findings: Finding[]) {
  const state = ensure();
  const enrichments = { ...state.enrichments };
  const reproductions = { ...state.reproductions };
  for (const finding of findings) {
    if (!enrichments[finding.id]) enrichments[finding.id] = deriveEnrichment(finding);
    if (!reproductions[finding.id]) reproductions[finding.id] = deriveReproduction(finding);
  }
  persist({ ...state, enrichments, reproductions });
}

export function personnelLabel(personnel: Personnel[]): string {
  return personnel.map((p) => `${p.name}（${p.role}）`).join("、");
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}
