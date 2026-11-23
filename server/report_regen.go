package server

// 漏洞报告补写：为「已登记但没写详细报告」的漏洞重新唤起 reporter agent。
//
// 背景：reporter 由 on_tool_call 触发器在水位线之后被唤起。历史漏洞可能因为
//   ① reporter agent 尚未 seed 完成、② 当时未配置 LLM（chatAgent 为 nil）、
//   ③ 调度器水位线越过该次 report_finding
// 而没有触发，导致 findings.report 为 NULL。本接口提供两个补救路径：
//
//	POST /api/findings/{id}/report/regenerate   触发一次 reporter 撰写该漏洞报告
//	GET  /api/findings/{id}/report/status       查询是否已有报告 / 是否有进行中的补写
//
// 另提供 POST /api/findings/report/backfill?task_id=&limit= 批量补写某任务下
// 所有缺报告的漏洞（按登记时间倒序，默认最多 20 条）。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// reportRegenBusy 记录正在补写的 finding（避免重复触发）。
var (
	reportRegenMu   sync.Mutex
	reportRegenBusy = map[int64]time.Time{}
)

const reportRegenTTL = 10 * time.Minute

func markReportRegen(nodeID int64) bool {
	reportRegenMu.Lock()
	defer reportRegenMu.Unlock()
	if started, ok := reportRegenBusy[nodeID]; ok && time.Since(started) < reportRegenTTL {
		return false
	}
	reportRegenBusy[nodeID] = time.Now()
	return true
}

func clearReportRegen(nodeID int64) {
	reportRegenMu.Lock()
	defer reportRegenMu.Unlock()
	delete(reportRegenBusy, nodeID)
}

func reportRegenActive(nodeID int64) bool {
	reportRegenMu.Lock()
	defer reportRegenMu.Unlock()
	started, ok := reportRegenBusy[nodeID]
	return ok && time.Since(started) < reportRegenTTL
}

// findingReportStatus GET /api/findings/{id}/report/status
func (s *Server) findingReportStatus(w http.ResponseWriter, r *http.Request) {
	nodeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeErr(w, 400, "invalid finding id")
		return
	}
	if s.m.pg == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	// 直接查 findings 表的 report 列（按 node_id 定位，与 update_finding_report 一致）
	var (
		report    string
		updatedAt *time.Time
	)
	row := s.m.pg.QueryRow(`SELECT COALESCE(report,''), created_at FROM findings
		WHERE id=$1 OR node_id=$1 ORDER BY id DESC LIMIT 1`, nodeID)
	if err := row.Scan(&report, &updatedAt); err != nil {
		writeJSON(w, 200, map[string]any{
			"node_id":   nodeID,
			"exists":    false,
			"has_report": false,
			"regenerating": reportRegenActive(nodeID),
			"error":     "找不到该漏洞记录",
		})
		return
	}
	writeJSON(w, 200, map[string]any{
		"node_id":      nodeID,
		"exists":       true,
		"has_report":   strings.TrimSpace(report) != "",
		"report_chars": len([]rune(report)),
		"created_at":   updatedAt,
		"regenerating": reportRegenActive(nodeID),
	})
}

// findingReportRegenerate POST /api/findings/{id}/report/regenerate
//
// 异步触发 reporter。返回 202 + job 状态；前端轮询 status 接口。
// 若 reporter 不可用（未配置 LLM），返回 503 并说明原因，让前端降级到本地生成。
func (s *Server) findingReportRegenerate(w http.ResponseWriter, r *http.Request) {
	nodeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeErr(w, 400, "invalid finding id")
		return
	}
	if s.m.pg == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if s.chatAgentRef() == nil {
		writeErr(w, 503, "未配置可用的 LLM，无法唤起报告撰写 agent；可先用本地自动整理版")
		return
	}
	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil || !reporter.Enabled {
		writeErr(w, 503, "报告撰写 agent 不存在或已停用，请在「Agent」页启用 reporter")
		return
	}

	// 取该漏洞的 task 上下文（用于触发消息里的 task_id/desc/goal）。
	var (
		taskID   int64
		taskDesc string
		taskGoal string
	)
	var realNodeID int64
	row := s.m.pg.QueryRow(`SELECT COALESCE(f.node_id,0), COALESCE(f.task_id,0), COALESCE(t.description,''), COALESCE(t.goal,'')
		FROM findings f LEFT JOIN tasks t ON t.id = f.task_id
		WHERE f.id=$1 OR f.node_id=$1 ORDER BY f.id DESC LIMIT 1`, nodeID)
	_ = row.Scan(&realNodeID, &taskID, &taskDesc, &taskGoal)
	if realNodeID > 0 {
		// 后续按探索节点 id 操作（get_task_node_detail / update_finding_report 都吃它）
		nodeID = realNodeID
	}

	if !markReportRegen(nodeID) {
		writeJSON(w, 202, map[string]any{"node_id": nodeID, "status": "running", "note": "该漏洞的报告补写已在进行中"})
		return
	}

	msg := fmt.Sprintf("请为漏洞节点 #%d 补写详细报告：先用 get_task_node_detail(task_id=%d, id=%d) 读完整证据，"+
		"再用 update_finding_report(finding_id=%d, report=<Markdown 全文>) 保存。", nodeID, taskID, nodeID, nodeID)
	go func() {
		defer clearReportRegen(nodeID)
		s.StartTriggeredRun("reporter", fmt.Sprintf("补写报告 · 漏洞#%d", nodeID), msg, taskID, false, taskDesc, taskGoal)
	}()

	writeJSON(w, 202, map[string]any{"node_id": nodeID, "status": "started"})
}

// findingsReportBackfill POST /api/findings/report/backfill
// body/query: task_id（可选）、limit（默认 20，上限 100）
func (s *Server) findingsReportBackfill(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if s.chatAgentRef() == nil {
		writeErr(w, 503, "未配置可用的 LLM，无法补写报告")
		return
	}
	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil || !reporter.Enabled {
		writeErr(w, 503, "报告撰写 agent 不存在或已停用")
		return
	}

	var req struct {
		TaskID string `json:"task_id"`
		Limit  int    `json:"limit"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	_ = json.Unmarshal(body, &req)
	taskID := strings.TrimSpace(req.TaskID)
	if taskID == "" {
		taskID = strings.TrimSpace(r.URL.Query().Get("task_id"))
	}
	limit := req.Limit
	if limit <= 0 {
		if raw := r.URL.Query().Get("limit"); raw != "" {
			limit, _ = strconv.Atoi(raw)
		}
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	rows, err := s.m.pg.Query(`
		SELECT f.node_id, COALESCE(f.task_id,0), COALESCE(t.description,''), COALESCE(t.goal,'')
		FROM findings f LEFT JOIN tasks t ON t.id = f.task_id
		WHERE f.node_id IS NOT NULL
		  AND COALESCE(f.report,'') = ''
		  AND ($1 = '' OR f.task_id::text = $1)
		ORDER BY f.id DESC
		LIMIT $2`, taskID, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()

	type target struct{ nodeID, taskID int64; desc, goal string }
	var targets []target
	for rows.Next() {
		var item target
		if scanErr := rows.Scan(&item.nodeID, &item.taskID, &item.desc, &item.goal); scanErr == nil {
			targets = append(targets, item)
		}
	}

	started := 0
	for _, item := range targets {
		if !markReportRegen(item.nodeID) {
			continue
		}
		started++
		msg := fmt.Sprintf("请为漏洞节点 #%d 补写详细报告：先用 get_task_node_detail(task_id=%d, id=%d) 读完整证据，"+
			"再用 update_finding_report(finding_id=%d, report=<Markdown 全文>) 保存。", item.nodeID, item.taskID, item.nodeID, item.nodeID)
		go func(it target, m string) {
			defer clearReportRegen(it.nodeID)
			s.StartTriggeredRun("reporter", fmt.Sprintf("补写报告 · 漏洞#%d", it.nodeID), m, it.taskID, false, it.desc, it.goal)
		}(item, msg)
	}
	writeJSON(w, 202, map[string]any{
		"missing": len(targets),
		"started": started,
		"skipped": len(targets) - started,
		"task_id": taskID,
	})
}

// 保留 context 引用（后续用于超时控制）。
var _ = context.Background
