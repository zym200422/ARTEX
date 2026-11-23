"use client";

// 任务级作战状态的本地持久化层（前端先行）。
//
// 后端目前只认「描述 + 目标」，不返回作战进度，所以这一层先把状态落在 localStorage，
// 保证页面可点、可演示、可回放。接口形状与 lib/engagement.ts 的 TaskEngagement 完全
// 一致：后端补上 GET/PUT /tasks/{id}/engagement 之后，只需把本文件的三个读写函数换成
// api 调用，UI 无需改动。

import type { BoxType, TaskEngagement } from "@/lib/engagement";

const STORAGE_KEY = "artex_engagements_v1";

type EngagementMap = Record<string, TaskEngagement>;

/** 演示数据：让 mock/demo 和真实后端下的已有任务都有可看的作战态。 */
function demoSeeds(): EngagementMap {
  const now = Math.floor(Date.now() / 1000);
  return {
    "t-acme-web": {
      mode: "greybox",
      box: "hybrid",
      current_stage: "gb-verify",
      stages: [
        { stage_id: "gb-sync", status: "done", passed_gates: ["gb-sync-done"], finished_at: now - 7200 },
        { stage_id: "gb-locate", status: "done", passed_gates: ["gb-locate-list"], finished_at: now - 3600 },
        { stage_id: "gb-verify", status: "active", passed_gates: [], entered_at: now - 3600 },
        { stage_id: "gb-report", status: "pending", passed_gates: [] },
      ],
      evolutions: [
        {
          id: `evo-${now - 28800}-demo-1`,
          trigger: "后台弱口令登录成功（admin / admin123）",
          from_box: "black",
          to_box: "grey",
          from_mode: "src",
          to_mode: "src",
          at: now - 28800,
          auto: false,
        },
        {
          id: `evo-${now - 18000}-demo-2`,
          trigger: "发现 .git 目录泄露并还原源码",
          from_box: "grey",
          to_box: "hybrid",
          from_mode: "src",
          to_mode: "greybox",
          at: now - 18000,
          auto: false,
        },
      ],
      next_hint: "白盒已定位 UploadController.java:88 任意文件上传，待线上回放确认可达性。",
    },
    "t-acme-api": {
      mode: "code-audit",
      box: "white",
      current_stage: "ca-flow",
      stages: [
        {
          stage_id: "ca-intake",
          status: "done",
          passed_gates: ["ca-intake-dep", "ca-intake-entry"],
          finished_at: now - 10800,
        },
        { stage_id: "ca-map", status: "done", passed_gates: ["ca-map-coverage"], finished_at: now - 7200 },
        { stage_id: "ca-sink", status: "done", passed_gates: ["ca-sink-list"], finished_at: now - 5400 },
        { stage_id: "ca-flow", status: "active", passed_gates: [], entered_at: now - 5400 },
        { stage_id: "ca-verify", status: "pending", passed_gates: [] },
        { stage_id: "ca-report", status: "pending", passed_gates: [] },
      ],
      evolutions: [],
      next_hint: "已定位 3 条候选链路，优先验证 OrderMapper.xml 中的动态 SQL 拼接点。",
    },
    "t-shop-pay": {
      mode: "crowdtest",
      box: "black",
      current_stage: "ct-type-fire",
      stages: [
        {
          stage_id: "ct-scope",
          status: "done",
          passed_gates: ["ct-scope-types", "ct-scope-assets"],
          finished_at: now - 21600,
        },
        { stage_id: "ct-type-fire", status: "active", passed_gates: [], entered_at: now - 14400 },
        { stage_id: "ct-submit", status: "pending", passed_gates: [] },
        { stage_id: "ct-mopup", status: "pending", passed_gates: [] },
      ],
      evolutions: [],
      next_hint: "支付回调签名校验缺失（逻辑类首杀未抢），正在构造越权改价 PoC。",
    },
    "t-vpn-edge": {
      mode: "redteam",
      box: "grey",
      current_stage: "rt-enum",
      stages: [
        { stage_id: "rt-foothold", status: "done", passed_gates: ["rt-foothold-done"], finished_at: now - 43200 },
        { stage_id: "rt-persist", status: "done", passed_gates: ["rt-persist-done"], finished_at: now - 39600 },
        { stage_id: "rt-enum", status: "active", passed_gates: [], entered_at: now - 39600 },
        { stage_id: "rt-lateral", status: "pending", passed_gates: [] },
        { stage_id: "rt-report", status: "pending", passed_gates: [] },
      ],
      evolutions: [
        {
          id: `evo-${now - 43200}-demo-3`,
          trigger: "VPN 设备命令注入获取 shell",
          from_box: "black",
          to_box: "grey",
          from_mode: "redteam",
          to_mode: "redteam",
          at: now - 43200,
          auto: false,
        },
      ],
      next_hint: "内网已发现 3 个网段，优先排查 10.20.0.0/24 的域控。",
    },
  };
}

let cache: EngagementMap | null = null;
let version = 0;
const listeners = new Set<() => void>();

function readStorage(): EngagementMap {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as EngagementMap;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function ensure(): EngagementMap {
  if (cache) return cache;
  cache = { ...demoSeeds(), ...readStorage() };
  return cache;
}

function notify() {
  version += 1;
  for (const listener of listeners) listener();
}

export function getTaskEngagement(taskID: string): TaskEngagement | null {
  return ensure()[taskID] ?? null;
}

export function setTaskEngagement(taskID: string, state: TaskEngagement) {
  const next = { ...ensure(), [taskID]: state };
  cache = next;
  if (typeof window !== "undefined") {
    try {
      // 连同 demo 种子一起写回：数据量很小，且用户可能改动了演示任务。
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // 存储不可用（隐私模式/配额满）时保持内存态，页面仍可继续操作。
    }
  }
  notify();
}

export function clearTaskEngagement(taskID: string) {
  const next = { ...ensure() };
  delete next[taskID];
  cache = next;
  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // ignore
    }
  }
  notify();
}

export function subscribeTaskEngagement(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function engagementStoreVersion(): number {
  return version;
}

export function engagementStoreServerVersion(): number {
  return 0;
}

/** 任务列表徽章用：模式 key + 当前盒型。 */
export function taskEngagementBadge(taskID: string): { mode: string; box: BoxType } | null {
  const state = getTaskEngagement(taskID);
  if (!state) return null;
  return { mode: state.mode, box: state.box };
}
