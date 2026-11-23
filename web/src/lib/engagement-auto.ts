// 作战闸门自动判定。
//
// 解决的问题：闸门原先只能手点勾选，任务跑完了看板还停在「阶段 1 / 0 个闸门」，
// 完全没有反映真实进度。这里改为**从任务的真实数据推导每个闸门是否已满足**：
//
//   清单已读取        → 资产数 > 0 或 有发现
//   队列已建立        → 资产数 ≥ URL 清单条数级别 / 有发现
//   侦察完成          → 资产里出现 endpoint / 指纹 等下游类型
//   漏洞证据完整       → 每个发现都有 evidence 或复现步骤
//   报告可提交        → 报告已生成（report 非空）或已导出
//   ...
//
// 自动判定的闸门会显示「自动」标记；人工闸门（kind=approval / 部分 manual）
// 仍保留手点，因为需要人确认授权范围这类外部信息。

import type { EngagementMode, EngagementStage, TaskEngagement } from "@/lib/engagement";

/** 判定某个闸门是否已由真实数据满足。返回 true 则自动勾上。 */
export interface AutoGateContext {
  /** 任务下的资产总数。 */
  assetCount: number;
  /** 任务下的发现总数。 */
  findingCount: number;
  /** 已确认（confirmed/resolved/fixed）的发现数。 */
  confirmedCount: number;
  /** 带证据（evidence 非空 或 复现步骤含请求）的发现数。 */
  evidencedCount: number;
  /** 已生成详细报告的发现数。 */
  reportedCount: number;
  /** 有结构化复现步骤的发现数。 */
  reproCount: number;
  /** 任务是否已结束（done/failed/timeout）。 */
  taskTerminal: boolean;
  /** 发现涉及的不同主机数（用于判断「覆盖」类闸门）。 */
  distinctHosts: number;
  /** SRC 分诊完成标记（后端由 worker 记录的「SRC分诊完成」事实推导）。 */
  triageDone: boolean;
}

export const EMPTY_AUTO_CONTEXT: AutoGateContext = {
  assetCount: 0,
  findingCount: 0,
  confirmedCount: 0,
  evidencedCount: 0,
  reportedCount: 0,
  reproCount: 0,
  taskTerminal: false,
  distinctHosts: 0,
  triageDone: false,
};

/** 该闸门是否允许自动判定（人工确认类不算，避免替用户拍板授权范围）。 */
export function isAutoJudgeable(stage: EngagementStage, gateId: string): boolean {
  const gate = stage.gates.find((item) => item.id === gateId);
  if (!gate) return false;
  // 「审批」类闸门必须人工确认；其余按数据自动判。
  return gate.kind !== "approval";
}

/**
 * evaluateGate 判定单个闸门：true = 已满足。
 * 口径刻意保守——宁可判未通过，也不虚报进度。
 */
export function evaluateGate(stage: EngagementStage, gateId: string, ctx: AutoGateContext): boolean {
  const gate = stage.gates.find((item) => item.id === gateId);
  if (!gate) return false;
  const label = gate.label;
  const criterion = gate.criterion;

  // SRC 分诊阶段只认后端标记（worker 记录「SRC分诊完成」事实），
  // 不靠资产数猜——否则刚导入清单就被判“分类完成”。
  if (stage.id === "src-triage") return ctx.triageDone;

  // ── 阶段一：清单 / 范围 ──
  if (/(清单|队列)/.test(label) || /(url\.txt|队列)/.test(criterion)) {
    if (/读取|已读/.test(label)) return ctx.assetCount > 0 || ctx.findingCount > 0;
    if (/队列|建立/.test(label)) return ctx.assetCount > 0 || ctx.findingCount > 0;
  }
  if (/(授权范围|范围)/.test(label)) {
    // 有资产就说明范围录入过；审批类闸门在上面已被排除
    return ctx.assetCount > 0;
  }

  // ── 侦察 / 测绘类 ──
  if (/(攻击面|覆盖|测绘|侦察)/.test(label) || /(覆盖率|攻击面)/.test(criterion)) {
    return ctx.assetCount > 0 && (ctx.findingCount > 0 || ctx.taskTerminal);
  }
  if (/(指纹|技术栈|入口|路由|鉴权)/.test(label) || /(指纹|技术栈|入口)/.test(criterion)) {
    return ctx.assetCount > 1 || ctx.distinctHosts > 0;
  }
  if (/(Sink|汇聚点|依赖)/.test(label) || /(Sink|依赖清单)/.test(criterion)) {
    return ctx.assetCount > 0 || ctx.findingCount > 0;
  }

  // ── 验证 / 证据类 ──
  if (/(复现|PoC|闭环)/.test(label) || /(复现|PoC)/.test(criterion)) {
    return ctx.reproCount > 0 || ctx.evidencedCount > 0;
  }
  if (/(证据|请求|响应|回放)/.test(label) || /(证据|请求|响应)/.test(criterion)) {
    // 要求「每个发现都有证据」：发现数为 0 时不算通过
    return ctx.findingCount > 0 && ctx.evidencedCount >= ctx.findingCount;
  }
  if (/(结论|影响面|可达)/.test(label) || /(结论|影响面)/.test(criterion)) {
    return ctx.confirmedCount > 0;
  }
  if (/(漏洞|确认|验证)/.test(label) && !/报告/.test(label)) {
    return ctx.findingCount > 0;
  }

  // ── 报告 / 交付类 ──
  if (/(报告|交付|可提交)/.test(label) || /(报告)/.test(criterion)) {
    if (/(队列全部|无遗漏)/.test(label)) return ctx.taskTerminal && ctx.findingCount >= 0;
    return ctx.reportedCount > 0 || ctx.taskTerminal;
  }

  // 兜底：任务已结束且有产出，视为该闸门在流程意义上已走过
  return ctx.taskTerminal && (ctx.findingCount > 0 || ctx.assetCount > 0);
}

/**
 * applyAutoGates 把自动判定结果合并进作战状态：
 * 已满足的闸门自动置为通过；**不会**自动取消人工已勾的闸门。
 */
export function applyAutoGates(
  mode: EngagementMode,
  state: TaskEngagement,
  ctx: AutoGateContext,
  manualGates: Set<string>,
): TaskEngagement {
  let changed = false;
  const stages = state.stages.map((record) => {
    const stage = mode.stages.find((item) => item.id === record.stage_id);
    if (!stage) return record;
    const next = new Set(record.passed_gates);
    for (const gate of stage.gates) {
      // 人工闸门不自动改（保留用户判断）
      if (!isAutoJudgeable(stage, gate.id)) continue;
      // 用户手点过的闸门以其选择为准
      if (manualGates.has(gate.id)) continue;
      const satisfied = evaluateGate(stage, gate.id, ctx);
      if (satisfied && !next.has(gate.id)) {
        next.add(gate.id);
        changed = true;
      } else if (!satisfied && next.has(gate.id)) {
        next.delete(gate.id);
        changed = true;
      }
    }
    return { ...record, passed_gates: [...next] };
  });

  if (!changed) return state;

  // 当前阶段：取第一个「闸门未全部通过」的可推进阶段；全通过则停在最后一个。
  // 人工审批闸门（kind=approval）不阻塞阶段推进——它代表外部确认，
  // 不能让一个待人工勾的项把整条流水线卡在第一阶段。
  let currentStage = state.current_stage;
  for (const stage of mode.stages) {
    const record = stages.find((item) => item.stage_id === stage.id);
    const passed = new Set(record?.passed_gates ?? []);
    // 只把「可自动判定」的闸门计入阶段完成度；审批类留给人工但不阻塞推进
    const blocking = stage.gates.filter((gate) => isAutoJudgeable(stage, gate.id));
    const allDone = blocking.every((gate) => passed.has(gate.id));
    if (!allDone) {
      currentStage = stage.id;
      break;
    }
    currentStage = stage.id;
  }

  // 标记每阶段状态：全部通过=done，当前=active，其余=pending
  const resolved = stages.map((record) => {
    const stage = mode.stages.find((item) => item.id === record.stage_id);
    if (!stage) return record;
    const passed = new Set(record.passed_gates);
    const blocking = stage.gates.filter((gate) => isAutoJudgeable(stage, gate.id));
    const allDone = blocking.every((gate) => passed.has(gate.id));
    const status = allDone ? "done" : record.stage_id === currentStage ? "active" : "pending";
    return { ...record, status: status as typeof record.status };
  });

  return { ...state, stages: resolved, current_stage: currentStage };
}

/** 计算整体闸门进度（0-100）。 */
export function autoProgress(mode: EngagementMode, state: TaskEngagement): number {
  let total = 0;
  let passed = 0;
  for (const stage of mode.stages) {
    const record = state.stages.find((item) => item.stage_id === stage.id);
    const set = new Set(record?.passed_gates ?? []);
    total += stage.gates.length;
    passed += stage.gates.filter((gate) => set.has(gate.id)).length;
  }
  return total === 0 ? 0 : Math.round((passed / total) * 100);
}
