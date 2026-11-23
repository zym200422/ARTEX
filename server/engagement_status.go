package server

// 作战阶段状态（服务端推导）。
//
// 问题背景：作战模式的阶段/闸门原先只写进任务描述，planner 读到的是一段静态
// 文本，既不知道「现在处于哪一阶段」，也没有任何东西提示它「本轮只该推进当前
// 阶段」。结果就是 planner 把整份简报压成一个平行意图，worker 一次性打完全部
// 漏洞——四阶段流水线从未真正发生过。
//
// 本文件把「作战阶段」变成**服务端可计算的状态**：
//   1. 按任务真实数据（资产/发现/证据/报告/意图）推导每个阶段是否完成；
//   2. 把「当前阶段 + 未通过闸门 + 本轮该做什么」注入 planner 的态势提示，
//      让规划天然按阶段推进（软约束，不硬拦）。
//
// 模式定义与前端 lib/engagement.ts 保持一致（key/stage id 相同）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// engagementStage 是阶段定义的精简副本（服务端只需要判断口径）。
type engagementStage struct {
	ID    string
	Name  string
	Short string
	Gates []engagementGate
}

type engagementGate struct {
	ID        string
	Label     string
	Kind      string // artifact|evidence|approval|signal
	Manual    bool
	Criterion string
}

type engagementModeDef struct {
	Key  string
	Name string
	// WorkUnit 是**意图粒度契约**：一条意图只覆盖一个工作单元。这是压制冗余的
	// 结构手段——不让一条意图把整份任务/整批 URL/整个阶段都包进去，而是切成可
	// 独立收尾、互不重叠的单元，planner 按单元派、worker 按单元跑。
	WorkUnit string
	Stages   []engagementStage
}

// engagementModes 与前端内置模式对齐：只保留推导所需的骨架。
// 新增模式时两边同步（key 与 stage id 必须一致）。
var engagementModes = map[string]engagementModeDef{
	"src": {
		Key:  "src",
		Name: "SRC 漏洞挖掘",
		WorkUnit: "分诊阶段允许一条意图覆盖整份 URL 清单，summary 以【分诊】开头，只做每 URL 一次低频只读指纹并形成分类排序，结束时 record_fact 一条含「SRC分诊完成」的事实；" +
			"测试阶段一条意图只对应一个 URL，summary 带原始序号与完整 URL。不同 URL 可由至少 6 个 worker 并行验证，同一规范化 URL 同时只能有一个 worker；按预期收益高且容易验证者优先，同级按原序号。",
		Stages: []engagementStage{
			{ID: "src-intake", Name: "清单解析与队列建立", Short: "清单", Gates: []engagementGate{
				{ID: "src-intake-read", Label: "清单已读取并统计", Kind: "artifact", Criterion: "已读取 url.txt 并记录有效 URL 数"},
				{ID: "src-intake-queue", Label: "队列已建立", Kind: "evidence", Criterion: "每个 URL 有原始序号与初始状态"},
			}},
			{ID: "src-triage", Name: "全清单轻量分诊", Short: "分诊", Gates: []engagementGate{
				{ID: "src-triage-classified", Label: "有效 URL 已完成分类", Kind: "artifact", Manual: true, Criterion: "每个有效 URL 均记录可达性、应用/技术栈、易中难与预期收益"},
				{ID: "src-triage-ordered", Label: "验证队列已按优先级排序", Kind: "artifact", Manual: true, Criterion: "高收益且容易验证的 URL 优先，同级按原序号，且无遗漏"},
			}},
			{ID: "src-recon", Name: "优先 URL 定向侦察", Short: "定向侦察", Gates: []engagementGate{
				{ID: "src-recon-current", Label: "当前 URL 侦察完成", Kind: "evidence", Criterion: "当前 URL 的指纹/入口/参数已记录"},
				{ID: "src-recon-serial", Label: "同 URL 不重复并发", Kind: "approval", Manual: true, Criterion: "不同 URL 可并行；同一规范化 URL 同时最多一个 worker 处理"},
			}},
			{ID: "src-verify", Name: "逐 URL 漏洞验证", Short: "逐条验证", Gates: []engagementGate{
				{ID: "src-verify-conclusion", Label: "当前 URL 有结论", Kind: "evidence", Criterion: "已标记有漏洞/无发现/不可达"},
				{ID: "src-verify-proof", Label: "漏洞证据完整", Kind: "evidence", Manual: true, Criterion: "每个确认漏洞都有可回放请求/响应"},
			}},
			{ID: "src-report", Name: "队列汇总与交付", Short: "汇总", Gates: []engagementGate{
				{ID: "src-report-queue", Label: "队列全部处理完", Kind: "artifact", Manual: true, Criterion: "队列无待测/进行中"},
				{ID: "src-report-ready", Label: "报告可提交", Kind: "artifact", Manual: true, Criterion: "报告含标题/等级/复现/影响/修复"},
			}},
		},
	},
	"crowdtest": {
		Key:  "crowdtest",
		Name: "众测冲刺",
		WorkUnit: "一条意图只对应一个「漏洞类型 × 资产/入口」组合；summary 写清类型与目标资产。" +
			"同类型首杀已提交后不再为它派意图，直接转向未覆盖的组合；不要把多个类型或整份目标塞进一条意图。",
		Stages: []engagementStage{
			{ID: "ct-scope", Name: "规则与首杀解读", Short: "规则", Gates: []engagementGate{
				{ID: "ct-scope-types", Label: "类型清单已排序", Kind: "artifact", Manual: true, Criterion: "已产出目标漏洞类型清单（高危优先）"},
				{ID: "ct-scope-assets", Label: "类型×资产矩阵已建立", Kind: "artifact", Criterion: "每个类型已映射到候选资产/入口"},
			}},
			{ID: "ct-type-fire", Name: "逐类型快打", Short: "快打", Gates: []engagementGate{
				{ID: "ct-type-current", Label: "当前组合有结论", Kind: "evidence", Criterion: "当前类型×资产已有结论"},
				{ID: "ct-type-first", Label: "高危类型优先推进", Kind: "evidence", Criterion: "队列按高危优先且未被抢"},
			}},
			{ID: "ct-submit", Name: "抢首杀提交", Short: "提交", Gates: []engagementGate{
				{ID: "ct-submit-proof", Label: "最小可复现证据", Kind: "evidence", Criterion: "提交材料含请求/响应与影响说明"},
				{ID: "ct-submit-type-done", Label: "类型标记完成", Kind: "artifact", Criterion: "已提交类型在矩阵中标记完成"},
			}},
			{ID: "ct-mopup", Name: "加时补扫", Short: "加时", Gates: []engagementGate{
				{ID: "ct-mopup-time", Label: "窗口结束前收口", Kind: "approval", Manual: true, Criterion: "时间窗结束前停止新测试"},
			}},
		},
	},
	"code-audit": {
		Key:  "code-audit",
		Name: "源码审计",
		WorkUnit: "一条意图只对应一条 source→sink 数据流，或一个 Sink 类别（附文件/目录范围与行号线索）。" +
			"不要按资产铺量，也不要把整份源码审计塞进一条意图；每条意图应能独立给出「文件:行号」级结论。",
		Stages: []engagementStage{
			{ID: "ca-intake", Name: "源码与运行时摸底", Short: "摸底", Gates: []engagementGate{
				{ID: "ca-intake-dep", Label: "依赖清单与版本已产出", Kind: "artifact", Criterion: "已生成依赖清单并标注高危组件"},
				{ID: "ca-intake-entry", Label: "入口形态已确认", Kind: "evidence", Criterion: "已确认 HTTP 入口与鉴权中间件"},
			}},
			{ID: "ca-map", Name: "路由与鉴权测绘", Short: "测绘", Gates: []engagementGate{
				{ID: "ca-map-coverage", Label: "无鉴权路由已穷举", Kind: "evidence", Criterion: "所有未挂鉴权中间件的路由已列出"},
			}},
			{ID: "ca-sink", Name: "危险汇聚点扫描", Short: "Sink", Gates: []engagementGate{
				{ID: "ca-sink-list", Label: "Sink 清单完成", Kind: "artifact", Criterion: "六大类汇聚点均已检索并标注行号"},
			}},
			{ID: "ca-flow", Name: "数据流追踪", Short: "追踪", Gates: []engagementGate{
				{ID: "ca-flow-chain", Label: "至少 1 条完整可控链路", Kind: "evidence", Criterion: "给出 source→sink 完整调用链"},
			}},
			{ID: "ca-verify", Name: "隔离环境复现", Short: "复现", Gates: []engagementGate{
				{ID: "ca-verify-poc", Label: "PoC 可稳定复现", Kind: "evidence", Criterion: "连续两次以上成功执行并留存流量"},
			}},
			{ID: "ca-report", Name: "代码级报告", Short: "报告", Gates: []engagementGate{
				{ID: "ca-report-done", Label: "报告与补丁齐备", Kind: "artifact", Manual: true, Criterion: "含文件:行号、调用链、PoC、修复 diff"},
			}},
		},
	},
	"greybox": {
		Key:  "greybox",
		Name: "白加黑联动",
		WorkUnit: "一条意图只对应一条「源码定位 → 线上验证」的闭链条目（一个可疑点/一条利用链）；" +
			"summary 先写源码位置（文件:行号）再写要验证的线上请求。不要把多个候选点塞进一条意图，也不要只做黑盒猜测。",
		Stages: []engagementStage{
			{ID: "gb-sync", Name: "源码与实例对齐", Short: "对齐", Gates: []engagementGate{
				{ID: "gb-sync-done", Label: "版本一致性已确认", Kind: "evidence", Criterion: "源码版本与线上指纹一致；不一致处已标注影响范围"},
			}},
			{ID: "gb-locate", Name: "白盒定位可疑点", Short: "定位", Gates: []engagementGate{
				{ID: "gb-locate-list", Label: "验证清单已排序", Kind: "artifact", Criterion: "可疑点按「可达概率 × 危害」排序，每个含文件:行号"},
			}},
			{ID: "gb-verify", Name: "黑盒线上验证", Short: "验证", Gates: []engagementGate{
				{ID: "gb-verify-proof", Label: "闭环证据链", Kind: "evidence", Manual: true, Criterion: "源码位置 + 线上请求/响应 + 影响证明三者齐全"},
			}},
			{ID: "gb-report", Name: "闭环报告", Short: "报告", Gates: []engagementGate{
				{ID: "gb-report-done", Label: "报告含双层证据", Kind: "artifact", Manual: true, Criterion: "每条漏洞同时给出源码位置与线上验证流量"},
			}},
		},
	},
}

// engagementSignals 是推导阶段进度所需的真实数据。
type engagementSignals struct {
	Assets        int
	Facts         int
	SRCTriageDone bool `json:"src_triage_done"`
	Findings      int
	Confirmed     int
	Evidenced     int
	Reported      int
	Intents       int
	IntentDone    int
	GoalsMet      int
	GoalsTotal    int
	TaskTerminal  bool
}

// loadEngagementSignals 汇总一个任务的真实数据。
func (s *Server) loadEngagementSignals(ctx context.Context, taskID int64, explorationID int64) engagementSignals {
	sig := engagementSignals{}
	pg := s.m.pg
	if pg == nil {
		return sig
	}
	// 资产：按 task_ids 数组包含本任务
	_ = pg.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE $1 = ANY(task_ids)`, taskID).Scan(&sig.Assets)
	// 发现
	_ = pg.QueryRowContext(ctx, `SELECT count(*),
		count(*) FILTER (WHERE status IN ('confirmed','resolved','fixed')),
		count(*) FILTER (WHERE COALESCE(evidence,'') <> ''),
		count(*) FILTER (WHERE COALESCE(report,'') <> '')
		FROM findings WHERE task_id=$1`, taskID).
		Scan(&sig.Findings, &sig.Confirmed, &sig.Evidenced, &sig.Reported)
	// 意图 / 事实 / 目标（探索节点）
	_ = pg.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE kind='intent'),
		count(*) FILTER (WHERE kind='intent' AND state='done'),
		count(*) FILTER (WHERE kind='fact'),
		count(*) FILTER (WHERE kind='goal' AND state='met'),
		count(*) FILTER (WHERE kind='goal')
		FROM exploration_nodes WHERE exploration_id=$1`, explorationID).
		Scan(&sig.Intents, &sig.IntentDone, &sig.Facts, &sig.GoalsMet, &sig.GoalsTotal)
	// SRC 分诊完成标记：worker 在分诊结束时 record_fact 一条 summary 含
	// 「SRC分诊完成」的事实。阶段推导靠它把“分诊”从未完成推进到完成。
	if explorationID > 0 {
		_ = pg.QueryRowContext(ctx, `SELECT EXISTS(
			SELECT 1 FROM exploration_nodes
			WHERE exploration_id=$1 AND kind='fact' AND COALESCE(payload->>'summary','') LIKE '%SRC分诊完成%'
		)`, explorationID).Scan(&sig.SRCTriageDone)
	}
	// 任务是否终态
	var status string
	if err := pg.QueryRowContext(ctx, `SELECT status FROM tasks WHERE id=$1`, taskID).Scan(&status); err == nil {
		sig.TaskTerminal = status == "done" || status == "failed" || status == "timeout"
	}
	return sig
}

// gateSatisfied 判定单个闸门是否已由数据满足（与前端 engagement-auto.ts 同口径）。
func gateSatisfied(stage engagementStage, gate engagementGate, sig engagementSignals) bool {
	label := gate.Label
	crit := gate.Criterion
	text := label + crit

	switch {
	case stage.ID == "src-triage":
		return sig.SRCTriageDone
	case strings.Contains(text, "清单") || strings.Contains(text, "队列"):
		return sig.Assets > 0 || sig.Findings > 0 || sig.Intents > 0
	case strings.Contains(text, "范围"):
		return sig.Assets > 0
	case strings.Contains(text, "攻击面") || strings.Contains(text, "测绘") || strings.Contains(text, "侦察"):
		return sig.Assets > 0 && (sig.Findings > 0 || sig.TaskTerminal)
	case strings.Contains(text, "指纹") || strings.Contains(text, "入口") || strings.Contains(text, "路由"):
		return sig.Assets > 1 || sig.Findings > 0
	case strings.Contains(text, "版本") || strings.Contains(text, "一致性"):
		return sig.Facts > 0
	case strings.Contains(text, "Sink") || strings.Contains(text, "汇聚点") || strings.Contains(text, "依赖"):
		return sig.Assets > 0 || sig.Findings > 0
	case strings.Contains(text, "复现") || strings.Contains(text, "PoC") || strings.Contains(text, "闭环"):
		return sig.Evidenced > 0
	case strings.Contains(text, "证据") || strings.Contains(text, "请求") || strings.Contains(text, "响应"):
		return sig.Findings > 0 && sig.Evidenced >= sig.Findings
	case strings.Contains(text, "结论") || strings.Contains(text, "影响面") || strings.Contains(text, "可达"):
		return sig.Confirmed > 0
	case strings.Contains(text, "类型") && strings.Contains(text, "矩阵"):
		return sig.Assets > 0
	case strings.Contains(text, "报告") || strings.Contains(text, "交付") || strings.Contains(text, "可提交"):
		return sig.Reported > 0 || sig.TaskTerminal
	}
	// 兜底：任务已结束且有产出
	return sig.TaskTerminal && (sig.Findings > 0 || sig.Assets > 0)
}

// stageSnapshot 是一个阶段的推导结果。
type stageSnapshot struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Short       string   `json:"short"`
	PassedGates []string `json:"passed_gates"`
	FailedGates []string `json:"failed_gates"`
	TotalGates  int      `json:"total_gates"`
	Done        bool     `json:"done"`
}

// deriveEngagement 按模式定义 + 真实数据推导阶段进度。
// 返回 (阶段快照, 当前阶段下标, 是否所有可自动判定闸门都通过)。
func deriveEngagement(mode engagementModeDef, sig engagementSignals) ([]stageSnapshot, int, bool) {
	stages := make([]stageSnapshot, 0, len(mode.Stages))
	current := 0
	allDone := true
	found := false
	for i, stage := range mode.Stages {
		snap := stageSnapshot{ID: stage.ID, Name: stage.Name, Short: stage.Short, TotalGates: len(stage.Gates)}
		blocking := 0
		blockingPassed := 0
		for _, gate := range stage.Gates {
			// 审批类闸门不由数据判定，也不阻塞推进
			if gate.Kind == "approval" {
				snap.FailedGates = append(snap.FailedGates, gate.ID)
				continue
			}
			blocking++
			if gateSatisfied(stage, gate, sig) {
				snap.PassedGates = append(snap.PassedGates, gate.ID)
				blockingPassed++
			} else {
				snap.FailedGates = append(snap.FailedGates, gate.ID)
			}
		}
		snap.Done = blocking == 0 || blockingPassed == blocking
		if !snap.Done && !found {
			current = i
			found = true
		}
		if !snap.Done {
			allDone = false
		}
		stages = append(stages, snap)
	}
	return stages, current, allDone
}

// engagementPlannerHint 生成注入 planner 态势的「作战阶段」段落。
//
// 定位是**软引导**，不是硬性流水线：只给进度与建议焦点，帮 planner 避免把整份
// 简报压成一个平行意图；同时明确保留跨阶段跃迁的合法性——黑盒拿到 shell、确认
// 中高危、识别出开源系统/源码泄露、或时间窗告急时，直接跳到验证/利用/白加黑。
// 经验上「只许当前阶段」这类硬禁令会与动态转向冲突，反而压住 planner 的判断力。
func engagementPlannerHint(mode engagementModeDef, stages []stageSnapshot, current int, sig engagementSignals) string {
	if len(stages) == 0 {
		return ""
	}
	cur := stages[current]
	var b strings.Builder
	b.WriteString("\n\n【作战阶段参考（软引导，不是硬性流水线）】\n")
	if cur.Done {
		b.WriteString(fmt.Sprintf("当前模式：%s｜所有阶段的可自动判定闸门均已满足（阶段推导见下，仍以实测为准）。\n", mode.Name))
	} else {
		b.WriteString(fmt.Sprintf("当前模式：%s｜建议优先阶段：第 %d/%d 阶段「%s」\n",
			mode.Name, current+1, len(stages), cur.Name))
	}
	b.WriteString("阶段进度：")
	for i, st := range stages {
		mark := "○"
		if st.Done {
			mark = "●"
		} else if i == current {
			mark = "◐"
		}
		b.WriteString(fmt.Sprintf("%s%s ", mark, st.Short))
	}
	b.WriteString("\n\n")
	if mode.WorkUnit != "" {
		b.WriteString("【意图粒度（本模式的防冗余规则）】" + mode.WorkUnit + "\n\n")
	}
	b.WriteString("默认把注意力放在当前阶段：这样能避免把整份简报压成一个平行意图、让 worker 一次性打完全套。")
	b.WriteString("但出现下列任一信号时，**可以直接跨阶段推进**（包括跳到验证/利用），不必等闸门满足：\n")
	b.WriteString("- 已拿到 shell / 命令执行 / 任意文件读写等实质突破；\n")
	b.WriteString("- 已确认一个中高危漏洞，继续验证/取证比按部就班更有价值；\n")
	b.WriteString("- 识别出目标是开源系统，或发现源码泄露（.git / 备份包），可直接转白加黑/源码审计；\n")
	b.WriteString("- 任务有时限（众测首杀、时间窗将尽），常规阶段工作应让位给高价值目标。\n")
	b.WriteString("跨阶段时，在 add_intent 的 summary 里写明「跨阶段理由 + 为什么现在做」即可。\n")
	if !cur.Done && len(cur.FailedGates) > 0 {
		b.WriteString("\n当前阶段尚未满足的闸门（缺口参考，不必机械逐条满足）：\n")
		for _, gateID := range cur.FailedGates {
			for _, gate := range mode.Stages[current].Gates {
				if gate.ID == gateID {
					manual := ""
					if gate.Manual {
						manual = "（需人工确认，可先行记录依据）"
					}
					b.WriteString(fmt.Sprintf("   - %s%s：%s\n", gate.Label, manual, gate.Criterion))
					break
				}
			}
		}
	}
	b.WriteString("\n阶段由平台按资产/发现/意图数据自动推导，可能滞后于实况；与实测冲突时以实测为准。\n")
	b.WriteString(fmt.Sprintf("实测数据：资产 %d、事实 %d、发现 %d（已确认 %d、有证据 %d、有报告 %d）、意图 %d（完成 %d）、目标 %d/%d。\n",
		sig.Assets, sig.Facts, sig.Findings, sig.Confirmed, sig.Evidenced, sig.Reported,
		sig.Intents, sig.IntentDone, sig.GoalsMet, sig.GoalsTotal))
	if !cur.Done {
		b.WriteString("没有强信号时，一次把一个阶段做透再进入下一个；有强信号时，跳过顺序优先把机会打穿。\n")
	}
	return b.String()
}

// taskEngagementStatus GET /api/tasks/{id}/engagement-status
//
// 返回服务端推导的作战阶段进度（供前端看板与 planner 提示共用）。
func (s *Server) taskEngagementStatus(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	taskID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, 400, "invalid task id")
		return
	}
	modeKey := strings.TrimSpace(r.URL.Query().Get("mode"))
	if modeKey == "" {
		// 从任务描述里的作战简报反解模式 key
		var desc string
		if s.m.pg != nil {
			_ = s.m.pg.QueryRow(`SELECT description FROM tasks WHERE id=$1`, taskID).Scan(&desc)
		}
		modeKey = detectModeFromDescription(desc)
	}
	mode, ok := engagementModes[modeKey]
	if !ok {
		writeJSON(w, 200, map[string]any{"mode": "", "stages": []any{}, "current_stage": ""})
		return
	}
	var explorationID int64
	if s.m.pg != nil {
		_ = s.m.pg.QueryRow(`SELECT COALESCE(exploration_id,0) FROM tasks WHERE id=$1`, taskID).Scan(&explorationID)
	}
	sig := s.loadEngagementSignals(r.Context(), taskID, explorationID)
	stages, current, allDone := deriveEngagement(mode, sig)
	writeJSON(w, 200, map[string]any{
		"mode":          mode.Key,
		"mode_name":     mode.Name,
		"stages":        stages,
		"current_index": current,
		"current_stage": stages[current].ID,
		"all_done":      allDone,
		"signals":       sig,
	})
}

// detectModeFromDescription 从作战简报里反解模式 key（简报由前端生成，含固定标记）。
func detectModeFromDescription(desc string) string {
	markers := map[string]string{
		"【作战模式】SRC 漏洞挖掘": "src",
		"【作战模式】众测冲刺":     "crowdtest",
		"【作战模式】源码审计":     "code-audit",
		"【作战模式】白加黑联动":    "greybox",
		"【作战模式】红队攻击模拟":   "redteam",
		"【作战模式】CTF 竞赛":   "ctf",
		"【作战模式】合规基线评估":   "compliance",
	}
	for marker, key := range markers {
		if strings.Contains(desc, marker) {
			return key
		}
	}
	return ""
}

// modeHardConstraints 从作战简报里抽取【硬约束】段落的规则行。
//
// 简报由前端 buildModeBrief 生成，格式稳定：段标题独占一行，规则行以「- 」开头，
// 直到下一个【段】或结尾。缺少该段时返回 nil（非模式任务）。这样服务端不必复制
// 一份模式定义——简报本身就是模式规则的唯一来源。
func modeHardConstraints(description string) []string {
	if strings.TrimSpace(description) == "" {
		return nil
	}
	var out []string
	inSection := false
	for _, raw := range strings.Split(description, "\n") {
		line := strings.TrimSpace(raw)
		if line == "【硬约束】" {
			inSection = true
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(line, "【") { // 进入下一段
			break
		}
		rule := ""
		for _, prefix := range []string{"- ", "• "} {
			if strings.HasPrefix(line, prefix) {
				rule = strings.TrimSpace(strings.TrimPrefix(line, prefix))
				break
			}
		}
		if rule != "" {
			out = append(out, rule)
		}
	}
	return out
}

// seedModeConstraints 把作战模式的【硬约束】提升为真正的任务级操作约束
// （task_constraints）。模式不能只是描述里的一段文字：这些规则会进入 planner/worker
// 的系统提示（最高优先级块），经压缩也不会丢，且在任务「约束管理」里可见、可改。
// 已在库中的同文规则跳过，保证幂等。
func (s *Server) seedModeConstraints(t *Task) {
	rules := modeHardConstraints(t.Description)
	if len(rules) == 0 || t.Store == nil {
		return
	}
	existing, _ := t.Store.ListConstraints()
	seen := make(map[string]bool, len(existing))
	for _, c := range existing {
		seen[strings.TrimSpace(c.Text)] = true
	}
	for _, rule := range rules {
		if seen[rule] {
			continue
		}
		kind := "allow"
		for _, bad := range []string{"禁止", "不得", "不允许", "严禁", "切勿", "不可", "不能", "不要", "不做"} {
			if strings.Contains(rule, bad) {
				kind = "deny"
				break
			}
		}
		if _, err := t.Store.AddConstraint(kind, rule, "mode"); err != nil {
			log.Printf("[mode] task %s 写入模式约束失败: %v", t.ID, err)
			return
		}
	}
}

// modeSeedIntent 返回模式任务的种子意图：当前阶段的**第一个最小工作单元**。
//
// 原来的种子意图是「完成整个任务目标 + 整份描述」，一个 worker 会试图把整套
// 流程一次打完——这正是要消除的冗余。模式任务改为只下发第一阶段的第一步，
// 跑完由 worker-done 触发 planner 接着按阶段/粒度派发。
func modeSeedIntent(description string) string {
	switch detectModeFromDescription(description) {
	case "src":
		return "【分诊】读取任务描述里附带的 url.txt，逐行规范化、去重；对每个 URL 做一次低频只读指纹分诊，记录原始序号、可达性、应用/技术栈、易中难与验证优先级，整理成易验证高收益优先的队列，并用 record_fact 记一条 summary 含「SRC分诊完成」的事实；本轮不要发送漏洞 payload。"
	case "crowdtest":
		return "读取任务描述里的计分规则，产出按高危优先排序的漏洞类型清单，并映射到候选资产/入口，建立「类型 × 资产」矩阵（初始状态：待测）；本轮不要开始验证漏洞。"
	case "code-audit":
		return "确认并获取源码（公开仓库 / 泄露的 .git / 备份包 / 镜像），产出依赖清单与高危组件、HTTP 入口与鉴权中间件形态、优先审计目录；本轮不要开始挖漏洞。"
	case "greybox":
		return "确认线上实例与源码版本一致（指纹 / 版本 / 配置比对），产出「代码行 ↔ 线上行为」映射与版本对照表；本轮不要开始验证漏洞。"
	}
	return ""
}

// engagementWorkerCount 返回本任务模式的并发 worker 数（fallback = 全局配置）。
//
// SRC 清单通常很长，单 worker 串行会成为吞吐瓶颈；但“并行”不能以重复 URL 为代价。
// 因此 SRC 至少开 6 个 worker（全局配置更高时沿用更高值），由 claimNext 的 URL 去重
// 保证同一规范化 URL 同时只被一个 worker 处理。其余模式沿用全局并发。
func engagementWorkerCount(description string, fallback int) int {
	if fallback < 1 {
		fallback = 1
	}
	if detectModeFromDescription(description) == "src" && fallback < 6 {
		return 6
	}
	return fallback
}

// engagementHintForTask 给 planner 生成注入文本（任务创建/每轮规划时调用）。
// description 为空时从 tasks 表读取；模式未识别或已有自定义模式时返回空串。
func (s *Server) engagementHintForTask(ctx context.Context, taskID int64, explorationID int64, description string) string {
	if strings.TrimSpace(description) == "" && s.m != nil && s.m.pg != nil {
		_ = s.m.pg.QueryRowContext(ctx, `SELECT description FROM tasks WHERE id=$1`, taskID).Scan(&description)
	}
	key := detectModeFromDescription(description)
	mode, ok := engagementModes[key]
	if !ok {
		return ""
	}
	sig := s.loadEngagementSignals(ctx, taskID, explorationID)
	stages, current, _ := deriveEngagement(mode, sig)
	return engagementPlannerHint(mode, stages, current, sig)
}

// 保留 sql/json 引用（后续扩展读自定义模式定义时需要）。
var (
	_ = sql.ErrNoRows
	_ = json.Marshal
)
