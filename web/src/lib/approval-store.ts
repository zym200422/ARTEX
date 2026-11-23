"use client";

// 上报审批数据的本地持久化层（前端先行）。
// 规则启用状态、自定义规则、审批记录都存 localStorage；
// 后端落地后把读写函数换成 /approval-rules、/approval-reviews 等 api 即可。

import type { ApprovalReview, CustomApprovalRule } from "@/lib/approval-engine";

const STORAGE_KEY = "artex_approval_v1";

interface ApprovalState {
  /** 内置规则停用表：ruleId → true(停用)。 */
  ruleDisabled: Record<string, boolean>;
  customRules: CustomApprovalRule[];
  reviews: ApprovalReview[];
}

let cache: ApprovalState | null = null;
let version = 0;
const listeners = new Set<() => void>();
const MAX_REVIEWS = 300;

function readStorage(): Partial<ApprovalState> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Partial<ApprovalState>;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function ensure(): ApprovalState {
  if (cache) return cache;
  const stored = readStorage();
  cache = {
    ruleDisabled: stored.ruleDisabled ?? {},
    customRules: stored.customRules ?? [],
    reviews: stored.reviews ?? [],
  };
  return cache;
}

function persist(next: ApprovalState) {
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

export function subscribeApproval(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function approvalVersion(): number {
  return version;
}

export function approvalServerVersion(): number {
  return 0;
}

// ── 规则启用状态 ──

export function getRuleDisabledMap(): Record<string, boolean> {
  return ensure().ruleDisabled;
}

export function setRuleEnabled(ruleId: string, enabled: boolean) {
  const state = ensure();
  const ruleDisabled = { ...state.ruleDisabled };
  if (enabled) delete ruleDisabled[ruleId];
  else ruleDisabled[ruleId] = true;
  persist({ ...state, ruleDisabled });
}

// ── 自定义规则 ──

export function getCustomRules(): CustomApprovalRule[] {
  return ensure().customRules;
}

export function upsertCustomRule(rule: CustomApprovalRule) {
  const state = ensure();
  const exists = state.customRules.some((item) => item.id === rule.id);
  const customRules = exists
    ? state.customRules.map((item) => (item.id === rule.id ? rule : item))
    : [...state.customRules, rule];
  persist({ ...state, customRules });
}

export function deleteCustomRule(id: string) {
  const state = ensure();
  persist({ ...state, customRules: state.customRules.filter((item) => item.id !== id) });
}

// ── 审批记录 ──

export function getApprovalReviews(): ApprovalReview[] {
  return ensure().reviews;
}

export function addApprovalReview(review: ApprovalReview) {
  const state = ensure();
  // 同一发现同结果不重复记录（保留最近一条）。
  const filtered = state.reviews.filter(
    (item) => !(item.findingId === review.findingId && item.verdict === review.verdict),
  );
  const reviews = [{ ...review }, ...filtered].slice(0, MAX_REVIEWS);
  persist({ ...state, reviews });
}
