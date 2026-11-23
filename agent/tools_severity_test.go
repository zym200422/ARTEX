package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestNormalizeFindingSeverity(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"critical", db.SeverityCritical, false},
		{"HIGH", db.SeverityHigh, false},
		{" Medium ", db.SeverityMedium, false},
		{"low", db.SeverityLow, false},
		{"", db.SeverityLow, false},
		{"info", db.SeverityLow, false},
		{"INFORMATIONAL", db.SeverityLow, false},
		{"none", db.SeverityLow, false},
		{"severe", "", true},
		{"highish", "", true},
		{"9.8", "", true},
	}
	for _, c := range cases {
		got, err := normalizeFindingSeverity(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("%q: want error, got %q", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Fatalf("%q: got (%q, %v), want %q", c.in, got, err, c.want)
		}
	}
}

func TestSeverityWakesOnlyAtMediumOrAbove(t *testing.T) {
	if severityAtLeastMedium(db.SeverityLow) || severityAtLeastMedium("") || severityAtLeastMedium("info") {
		t.Fatal("low/unknown must not wake the planner")
	}
	for _, s := range []string{db.SeverityMedium, db.SeverityHigh, db.SeverityCritical} {
		if !severityAtLeastMedium(s) {
			t.Fatalf("%s must wake the planner", s)
		}
	}
}

// add_intent 的硬闸门：priority 必须显式给出且不低于 medium。
func TestAddIntentPriorityGate(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("priority gate", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID
	call := func(body string) string {
		t.Helper()
		res, err := ts.addIntent().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}

	if got := call(`{"summary":"no priority"}`); !strings.Contains(got, "priority 必填") {
		t.Fatalf("missing priority must be rejected: %s", got)
	}
	if got := call(`{"summary":"low value","priority":4}`); !strings.Contains(got, "低于 5") {
		t.Fatalf("priority<5 must be rejected: %s", got)
	}
	if got := call(`{"summary":"high value","priority":9}`); !strings.Contains(got, "intent created") {
		t.Fatalf("priority 9 must be accepted: %s", got)
	}
	// 批量：合法项成功、非法项单独失败（同序 id=0）。
	got := call(`{"intents":[{"summary":"chain step","priority":3},{"summary":"deep path","priority":7}]}`)
	var out struct {
		IDs    []int64           `json:"ids"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("batch output not json: %s", got)
	}
	if len(out.IDs) != 2 || out.IDs[0] != 0 || out.IDs[1] <= 0 {
		t.Fatalf("batch ids wrong: %+v", out)
	}
	if !strings.Contains(out.Errors["0"], "低于 5") {
		t.Fatalf("batch error missing: %+v", out.Errors)
	}
	// 概览里的意图必须带 priority，规划者才能看见自己的定级。
	nodes, err := ts.ts.Frontier(10)
	if err != nil {
		t.Fatal(err)
	}
	compact := compactIntents(nodes, nil, nil)
	if len(compact) == 0 {
		t.Fatal("no intents created")
	}
	if _, ok := compact[0]["priority"]; !ok {
		t.Fatal("compactIntents must expose priority")
	}
}
