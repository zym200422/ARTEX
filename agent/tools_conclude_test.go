package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// conclude_no_high_impact 是规划器的合法收束出口：必须拒绝 running、必须要求 reason、
// 必须停掉 open 意图、放弃 open 目标，并留下可审计的结论事实。
func TestConcludeNoHighImpact(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("conclude", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "planner")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID

	goalID, err := ts.ts.AddNode(db.KindGoal, map[string]any{"text": "find something"}, 0, "open", "goals", nil)
	if err != nil {
		t.Fatal(err)
	}
	openID, err := ts.ts.AddIntent(map[string]any{"summary": "queued"}, 7, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	call := func(body string) string {
		t.Helper()
		res, err := ts.concludeNoHighImpact().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}
	if got := call(`{"reason":"  "}`); !strings.Contains(got, "reason 必填") {
		t.Fatalf("empty reason must be rejected: %s", got)
	}

	runID, err := ts.ts.AddIntent(map[string]any{"summary": "in flight"}, 7, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.ts.ClaimIntent(runID, "work#1"); err != nil {
		t.Fatal(err)
	}
	if got := call(`{"reason":"all high routes exhausted"}`); !strings.Contains(got, "running") {
		t.Fatalf("running intent must block conclusion: %s", got)
	}
	if err := ts.ts.SetIntentState(runID, "done"); err != nil {
		t.Fatal(err)
	}

	got := call(`{"reason":"上传链、认证绕过、SSRF 均已实测否定（事实 #1/#2）"}`)
	if !strings.Contains(got, "已收束") {
		t.Fatalf("conclusion failed: %s", got)
	}
	if ts.Concluded == "" {
		t.Fatal("Concluded signal not set for the planner round")
	}
	if n, err := ts.ts.GetNode(openID); err != nil || n == nil || n.State != "stopped" {
		t.Fatalf("queued intent not stopped: %+v %v", n, err)
	}
	if g, err := ts.ts.GetNode(goalID); err != nil || g == nil || g.State != "abandoned" {
		t.Fatalf("open goal not abandoned: %+v %v", g, err)
	}
	if active, err := ts.ts.HasOpenGoal(); err != nil || active {
		t.Fatalf("goal still open after conclusion: %v", err)
	}
	if active, err := ts.ts.HasActiveIntent(); err != nil || active {
		t.Fatalf("intents still active after conclusion: %v", err)
	}
	// 结论事实必须留在图里，便于审计为何放弃。
	facts, err := ts.ts.ListByKind(db.KindFact, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range facts {
		var p map[string]any
		_ = json.Unmarshal(f.Payload, &p)
		if s, _ := p["summary"].(string); strings.Contains(s, "无中高危可行方向") {
			found = true
			if p["confidence"] != "inferred" {
				t.Fatalf("conclusion fact must be inferred: %+v", p)
			}
		}
	}
	if !found {
		t.Fatal("conclusion fact missing")
	}

	// 目标已 abandoned 后再调应报“没有 open 目标”，避免重复收束。
	if got := call(`{"reason":"again"}`); !strings.Contains(got, "没有 open 目标") {
		t.Fatalf("second conclusion should be rejected: %s", got)
	}
}

// graph_overview 必须给出分级计数与逐条 severity，规划者才能判断成果价值。
func TestGraphOverviewSeverityVisibility(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("severity overview", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "planner")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID
	for _, in := range []struct{ sev, summary string }{
		{"critical", "RCE via upload"},
		{"high", "auth bypass"},
		{"medium", "IDOR"},
		{"low", "missing CSP"},
		{"", "legacy blank"},
	} {
		if _, err := ts.ts.RecordFinding(t.Context(), db.RecordFindingInput{
			TaskID: task.ID, ExplorationID: ts.ts.ID(), VulnClass: "TEST", Severity: in.sev, Summary: in.summary,
		}); err != nil {
			t.Fatal(err)
		}
	}
	data := ts.graphOverviewData()
	counts, ok := data["findings_by_severity"].(map[string]int)
	if !ok {
		t.Fatalf("findings_by_severity missing: %#v", data["findings_by_severity"])
	}
	want := map[string]int{"critical": 1, "high": 1, "medium": 1, "low": 1, "unknown": 1}
	for k, v := range want {
		if counts[k] != v {
			t.Fatalf("findings_by_severity[%s]=%d, want %d (%v)", k, counts[k], v, counts)
		}
	}
	list, ok := data["finding_list"].([]map[string]any)
	if !ok || len(list) == 0 {
		t.Fatalf("finding_list missing: %#v", data["finding_list"])
	}
	sawSeverity := false
	for _, item := range list {
		if _, ok := item["severity"]; ok {
			sawSeverity = true
		}
	}
	if !sawSeverity {
		t.Fatalf("finding_list must carry severity: %#v", list)
	}
	if data["findings_total"] != 5 {
		t.Fatalf("findings_total=%v, want 5", data["findings_total"])
	}
}
