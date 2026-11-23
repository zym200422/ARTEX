package agent

import (
	"strings"
	"testing"
)

// 影响优先策略是代码级段：DB 正文怎么改都不能把它删掉，且必须在系统提示最前，
// 这样它压过可编辑正文里的任何相反措辞。
func TestImpactPolicyIsCodeOwned(t *testing.T) {
	if strings.Contains(plannerDefaultTmpl, impactPolicyCommon) {
		t.Fatal("impact policy must not live in the editable planner body")
	}
	if strings.Contains(workerDefaultTmpl, impactPolicyCommon) {
		t.Fatal("impact policy must not live in the editable worker body")
	}
	for _, key := range []string{"medium", "high", "critical", "conclude_no_high_impact"} {
		if !strings.Contains(impactPolicyCommon, key) {
			t.Fatalf("impact policy missing %q", key)
		}
	}
	// planner-only 段给出 priority 映射；worker 段给出 severity 判定口径。
	for _, key := range []string{"medium=5", "high=7", "critical=9"} {
		if !strings.Contains(plannerImpactPolicy(), key) {
			t.Fatalf("planner policy missing priority mapping %q", key)
		}
	}
	if !strings.Contains(workerImpactPolicy(), "critical=可直接 RCE") {
		t.Fatal("worker policy missing severity rubric")
	}
}

// 系统提示组装顺序：影响策略在最前；可编辑正文次之；代码固定尾段仍在最后。
func TestSystemPromptOrdering(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = func(k string) (string, bool) { return "BODY-" + k, true }

	planner := plannerSystem("g", "/data", "/data")
	pi := strings.Index(planner, "影响优先策略")
	bi := strings.Index(planner, "BODY-planner")
	ai := strings.Index(planner, "中间产物输出规约")
	if pi < 0 || bi < 0 || ai < 0 || !(pi < bi && bi < ai) {
		t.Fatalf("planner ordering wrong: policy=%d body=%d artifact=%d", pi, bi, ai)
	}

	worker := workerSystem("", "", "/data", "/data")
	pi = strings.Index(worker, "影响优先策略")
	bi = strings.Index(worker, "BODY-worker")
	ai = strings.Index(worker, "中间产物输出规约")
	if pi < 0 || bi < 0 || ai < 0 || !(pi < bi && bi < ai) {
		t.Fatalf("worker ordering wrong: policy=%d body=%d artifact=%d", pi, bi, ai)
	}
}

// 默认正文也必须表达“只做中高危”的取向量，便于新库直接生效。
func TestDefaultPromptsCarryImpactOrientation(t *testing.T) {
	if !strings.Contains(plannerDefaultTmpl, "低危") || !strings.Contains(plannerDefaultTmpl, "conclude_no_high_impact") {
		t.Fatal("planner default body missing impact orientation")
	}
	if !strings.Contains(plannerDefaultTmpl, "medium=5") {
		t.Fatal("planner default body missing priority mapping")
	}
	if !strings.Contains(workerDefaultTmpl, "只做有实际影响的事") {
		t.Fatal("worker default body missing low-value guard")
	}
	if !strings.Contains(workerDefaultTmpl, "low 默认不单独上报") {
		t.Fatal("worker default body missing low-severity reporting rule")
	}
	if strings.Contains(workerDefaultTmpl, "宁可多报一条") {
		t.Fatal("worker default body still encourages reporting low-value noise")
	}
}
